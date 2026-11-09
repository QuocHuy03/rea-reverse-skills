# AUTOPILOT — autonomous reverse runbook (one entry point)

This is the **single decision graph** an agent follows top-to-bottom to reverse an Android app end-to-end. Every other doc is reference *material*; this is the *control flow*. Each step has: **GOAL**, **RUN** (exact command), **READ** (the JSON field to branch on), **BRANCH**, **GATE** (the pass condition — don't advance until it's met), and **STOP-IF** (surface to a human instead of looping).

The agent keeps one state file, **`rea-state.json`** (below), as its memory. The triage scripts emit `--json` fragments; merge each fragment's top-level key into `rea-state.json`. A resumed run reads the state file and jumps to the first unmet GATE — so a crash, a context reset, or "continue tomorrow" never loses place.

> **Golden discipline:** advance only on a GATE, never on "looks done". Update `rea-state.json` after every step. A **STOP-IF is not permission to quit** — it means run the **Persistence protocol** below (report the exact blocker, then exhaust research — EN *and* the Chinese RE scene — before reporting stuck). Only the short list of **genuine hard stops** (math/hardware walls) ends a run.

---

## rea-state.json — the agent's memory

```json
{
  "target":      { "package": null, "apk": null, "abi": null },
  "fingerprint": { "framework": [], "tls_stack": [], "networking": [], "sdks": [],
                   "obfuscation": null, "route_tags": [], "recommended_next": null },
  "capture":     { "ndjson": null, "requests": 0, "hosts": [], "endpoints": [],
                   "signer_headers": [], "secrets": {}, "encrypted_endpoints": [], "recommended_next": null },
  "offsets":     { "module": null, "found": {}, "missing": [], "out": null },
  "signer":      { "status": "unknown", "family": null, "header": null,
                   "canonical": null, "key": null, "next": null },
  "crypto":      { "bodies_encrypted": null, "algo": null, "status": "unknown" },
  "deliverable": { "client": false, "verified": false },
  "blocked_on":  null
}
```

**Status vocab.** `signer.status`: `unknown → sniffed → classified → reimplemented → verified`. `crypto.status`: `unknown → hooked → reimplemented → verified`. `signer.family`: one of `A|B|C|D|E` from `hard-sign-types.md` (null until classified). `blocked_on`: a STOP-IF reason string when paused for a human.

---

## Phase 0 — preflight & device

- **GOAL** toolchain + a device Frida can attach to.
- **RUN** `python scripts/check-deps.py` → then `python scripts/setup-device.py --connect <ip:port> --frida-server <matched-server> --ca ~/.mitmproxy/mitmproxy-ca-cert.pem`
- **GATE** `check-deps` exits 0; `frida -U -n <any app>` lists processes (frida-server alive, versions match).
- **STOP-IF** no device / no root → report; most of the pipeline needs a rooted emulator or device.

## Phase 1 — triage the APK

- **GOAL** know the stack before spending time.
- **RUN** pull the apk (`adb shell pm path <pkg>` → `adb pull`), then `python scripts/fingerprint.py <apk> --json` → merge into `state.fingerprint`.
- **READ** `fingerprint.route_tags`.
- **BRANCH** on the tags:
  - `obf-kotlin` → `python scripts/recover-kotlin-names.py <decompiled_src>` → `mapping.tsv` **before** hunting the signer.
  - `flutter` / `react-native` / `xamarin` / `unity` → the logic isn't in Java; follow `docs/per-stack-reverse.md` for the right decompiler, but the **capture** path below still applies.
  - `cronet` / `boringssl-fork` → note it; Phase 2 will use offsets, not a proxy.
  - `plain` → standard MITM path in Phase 2.
- **GATE** `state.fingerprint.route_tags` is non-empty.
- **STOP-IF** jadx/REA shows the DEX is packed/加固 (classes missing/encrypted) → **Persistence protocol**: name the packer (梆梆/爱加密/娜迦/腾讯乐固/360/阿里), search `<packer> 脱壳` on kanxue/52pojie, dump the real DEX (FRIDA-DEXDump / Youpk / FART; `docs/china-re-arsenal.md`), then re-run Phase 1. Report the packer + what you tried — don't stop at "packed".

## Phase 2 — capture plaintext traffic

- **GOAL** a `requests.ndjson` with real requests to the target host, bodies included.
- **BRANCH** on `state.fingerprint`:
  - **plain / system TLS** → CA already installed in Phase 0; drive the app through a proxy, OR run `frida -U -f <pkg> -l frida/anti-detect.js -l frida/ssl-unpin.js -l frida/capture-http.js --no-pause` (no proxy, works through pinning).
  - **cronet / boringssl-fork / flutter** → `python scripts/find-ssl-offsets.py <pulled .so> --json` (writes `offsets.json`, merges `state.offsets`) → `python frida/fridacap.py --device <id> --attach <pid> --offsets offsets.json`. Block UDP/443 first to force QUIC→TCP.
- **READ** `offsets.found` (must contain SSL_read/SSL_write or their lowercase) before the cronet path can work.
- **GATE** `state.capture.requests ≥ 1` for the real API host, with non-empty bodies. (Run Phase 3 to populate it.)
- **STOP-IF** the app dies on attach even with `anti-detect.js` → **Persistence protocol**, don't give up: escalate stealth stepwise — renamed frida-server on a non-default port → **ZygiskFrida** (process-less, no ptrace) → KernelSU/APatch+SusFS (`frida/README.md` → anti-Frida); and research the specific vector (`过 frida 检测`, `<app> frida 检测 绕过` on kanxue/52pojie, find the abort caller in REA and NOP it). Try several named methods before reporting; then report each vector you hit and how you tried to beat it.

## Phase 3 — analyze the capture (the router)

- **GOAL** decide what actually has to be reversed.
- **RUN** `python scripts/analyze-capture.py cap/requests.ndjson --json` → merge into `state.capture`.
- **READ** `capture.signer_headers`, `capture.encrypted_endpoints`.
- **BRANCH:**
  - `signer_headers` non-empty → **Phase 4**.
  - `encrypted_endpoints` non-empty → **Phase 5**.
  - both empty → **Phase 6** (endpoints are likely callable directly).
  - both present → Phase 4 then Phase 5 (sign usually wraps the encrypted body).
- **GATE** `state.capture` populated and the branch chosen.

## Phase 4 — reverse the signer (the ladder)

- **GOAL** reproduce the app's signature byte-for-byte, or oracle it.
- **RUN** `frida -U -f <pkg> -l frida/anti-detect.js -l frida/signer-sniffer.js --no-pause`; trigger one signed request. Set `signer.status = sniffed`, record `signer.canonical` + `signer.key` + `signer.header`.
- **READ / CLASSIFY** map the sniffer output to a **family** via `docs/hard-sign-types.md` → "classify in 60s"; set `signer.family` and `signer.status = classified`.
- **BRANCH by family:**
  - **canonical readable (rung 0)** → reimplement in `signer.py` (`signer.status = reimplemented`).
  - **A (argus/ladon, stateful)** → oracle: unidbg (init once, control the counter) or `rpc-signer.js` (`init()` → `sign([...])`). For an obfuscated lib, drive **unidbg MCP** (`unidbg/README.md` → "Let the AI drive it").
  - **B (OLLVM/VMP)** → oracle; or Stalker/unidbg-trace one call to unroll.
  - **C (white-box)** → oracle only.
  - **D (anti-tamper key)** → unidbg with the **original** apk + real env, or read the finalized key on a clean device.
  - **E (attestation/TEE)** → see STOP-IF.
- **GATE** `python scripts/verify-signer.py cap/requests.ndjson --signer signer.py` prints **PASS** over several requests → `signer.status = verified`. (If oracling instead of reimplementing, the gate is: the oracle reproduces the captured signature for the same inputs.)
- **STOP-IF** family **E** with server-required **STRONG** integrity, or white-box **key extraction** is the only path → set `blocked_on` and report the ceiling (`hard-sign-types.md` type E/C). These are not loopable.

## Phase 5 — reverse the encryption

- **GOAL** decrypt a captured response to valid JSON and reproduce encrypt.
- **RUN** `frida -U -f <pkg> -l frida/crypto-dump.js --no-pause`; trigger one encrypted request → read key/IV/mode/plaintext (`crypto.status = hooked`).
- **BRANCH** Java crypto → reimplement in `crypto_util.py`. Native/white-box/`.text`-encrypted → unidbg oracle (`docs/decryption-playbook.md` §2).
- **GATE** your Python `decrypt(captured_response)` → **valid JSON/protobuf**, and `encrypt(known_plaintext)` is byte-identical to the app's → `crypto.status = verified`.

## Phase 6 — build & verify the deliverable

- **GOAL** one stable Python CLI that logs in and calls the endpoints.
- **RUN** scaffold from `templates/cli-skeleton`: `client.py` (one method per endpoint from `state.capture.endpoints`), `signer.py` (verified), `crypto_util.py` (verified), `cli.py`. Set the app's real User-Agent + fixed device fingerprint.
- **GATE** a real call through the CLI returns the expected data; `deliverable.verified = true`.
- **STOP-IF** login needs a captcha/OTP/attestation the pipeline can't solve headless → report what's needed.

---

## Web targets — the parallel ladder (same discipline, web tools)

For a **web app / site** instead of an APK, the phase order, `rea-state.json`, GATE/STOP-IF discipline and the Persistence protocol are identical; only the tools change. Map the phases:

- **W0 preflight** — `curl_cffi` available; a browser you can drive via CDP for bundle reads (REA `list_browser_targets`/`analyze_web_bundle`). **GATE** you can reach the target from your own authorized session.
- **W1 capture + triage** — capture a HAR from your own browser session (DevTools → Save all as HAR). `python scripts/har-analyze.py cap.har --json` (traffic map) + `python scripts/fingerprint-site.py cap.har --json` (stack + vendor) → merge into `state`. **READ** `recommended_route`, `anti_bot_vendors`, `signer_params`.
- **W2 anti-bot** — **READ** `anti_bot_vendors` → `docs/web-anti-bot-ladder.md` for the vendor's exact move (reproduce your session's cookie/token + browser-identical TLS via `curl_cffi impersonate`, or run the vendor's JS as an oracle). **GATE** the API returns 200 from your client. **STOP-IF** the only path is defeating a protection on a target you have no right to → stop (see scope note).
- **W3 signer** — **READ** `signer_params` → find the signer in the JS bundle (REA `export_web_scripts` → `recover_javascript_sources`, or `web/sign-sniffer.js` in your console) → reimplement in Python. **GATE** byte-for-byte match (same verify discipline as mobile).
- **W4 crypto** — encrypted bodies → find the CryptoJS/WebCrypto call in the bundle → port to `pycryptodome`. **GATE** decrypt → valid JSON.
- **W5 build** — `client.py` (`curl_cffi impersonate`, reuse the session) → a real call returns the expected data; `deliverable.verified = true`.

**Scope note (web):** only ever reproduce access **you are authorized to have** (your own account/session, your own site, or an explicitly permitted target). Bulk-circumventing a third party's bot wall or content protection to scrape/download material you have no right to is out of scope — that's a hard stop, not a Persistence-protocol block.

## Persistence protocol — report, then exhaust research before you stop

Most STOP-IFs are **soft blocks**: the app kills the Frida attach, offsets aren't found, the signer `.so` is obfuscated, the packer is unknown. **These are not walls — they are solved problems someone has already written up.** When one fires, do NOT stop. Run this loop, out loud (keep reporting so the human sees persistence, not silence):

1. **Report the exact blocker** — the precise symptom + the string/error/evidence (the abort caller REA shows, the detection string in `/proc`, the missing symbol, the packer name). A vague "it's protected" is not a report.
2. **Name it.** Identify the exact mechanism: which packer/壳 (梆梆/爱加密/娜迦/腾讯乐固/360加固/阿里聚安全/VMP), which anti-Frida vector, which signer family (`hard-sign-types.md`), or — for web — which anti-bot vendor (`web-anti-bot-ladder.md`: Akamai/DataDome/PX/Kasada/jsvmp) and its token. You can't research what you can't name.
3. **Research it — EN *and* the Chinese RE scene (this is where the hard answers live).** The Chinese reverse community has solved almost every Android hardening/anti-Frida/native-signer problem first and documented it. Search, in this order:
   - the exact name + the Chinese technique verb: `<packer名> 脱壳`, `<app> frida 检测 绕过` / `过 frida 检测`, `<lib> unidbg 补环境`, `x-gorgon/x-argus unidbg 签名`, `<壳> 抽取 还原`.
   - the sources: **看雪 `bbs.kanxue.com`**, **吾爱破解 `52pojie.cn`**, CSDN, 先知社区, github CN forks (often the only working unidbg env-patch / unpacker). `docs/china-re-arsenal.md` is the local index of these tools; `docs/reverse-case-studies.md` has worked native-signer cases.
   - EN sources for the same: hexrays/frida codeshare, the `frida/README.md` anti-Frida matrix, the SideChannelMarvels/unidbg docs.
4. **Apply the found technique** (new hook, renamed/patched frida-server, ZygiskFrida, a dumping step, an unidbg 补环境 stub, a byte-pattern for the offset).
5. **Verify** against the phase GATE. Still blocked → go back to (2) with a *more specific* name; try the next method. Budget several distinct approaches before escalating — a single failed attempt is not "exhausted".
6. **Fold the win back in** (self-update): a working hook → `ssl-unpin.js`/`anti-detect.js`; a working offset/pattern → the `find-ssl-offsets` recipe; a new case → `hard-sign-types.md` / `reverse-case-studies.md`, with a dated source note. The next app of this kind is then handled built-in. (Full discipline: `frida/README.md` → "When the bypass fails".)

Only after several named, researched, applied-and-failed attempts do you report **stuck** — and then you report *what you tried and why each failed*, not just "blocked".

## Genuine hard stops (these actually end a run — surface and stop)

1. **STRONG hardware attestation** required by the server (Play Integrity STRONG, TEE-bound key) — not winnable off a certified device; it's the security model, not a missing trick.
2. **White-box key extraction** as the *only* route, with the oracle genuinely closed — research-grade (DCA/DFA); confirm it's in scope before sinking days.
3. **Device/root unavailable**, or a real capability you can't provide (test account, OTP, captcha key, a physical attested device).
4. Anything touching **real user data / credentials outside the authorized target** — stop and ask, always.

Everything else is a soft block → the Persistence protocol, not a stop.

## The loop invariant

After each phase: **write `rea-state.json`**. To resume: read it, find the first GATE not met, continue there. The combination of (fixed phase order) + (JSON branch fields) + (explicit gates) is what lets the agent run this unattended and still be correct — it never advances on vibes, and it never redoes a verified phase.

*Scripts: `check-deps.py`, `setup-device.py`, `fingerprint.py --json`, `recover-kotlin-names.py`, `find-ssl-offsets.py --json`, `analyze-capture.py --json`, `verify-signer.py`. Frida: `anti-detect.js`, `ssl-unpin.js`, `capture-http.js`+`fridacap.py`, `signer-sniffer.js`, `crypto-dump.js`, `rpc-signer.js`. Oracle: `unidbg/UnidbgOracleTemplate.java` (+ MCP). Reference: `per-stack-reverse.md`, `signer-reverse-deepdive.md`, `hard-sign-types.md`, `decryption-playbook.md`, `android-arsenal.md`.*
