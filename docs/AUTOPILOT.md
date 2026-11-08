# AUTOPILOT — autonomous reverse runbook (one entry point)

This is the **single decision graph** an agent follows top-to-bottom to reverse an Android app end-to-end. Every other doc is reference *material*; this is the *control flow*. Each step has: **GOAL**, **RUN** (exact command), **READ** (the JSON field to branch on), **BRANCH**, **GATE** (the pass condition — don't advance until it's met), and **STOP-IF** (surface to a human instead of looping).

The agent keeps one state file, **`rea-state.json`** (below), as its memory. The triage scripts emit `--json` fragments; merge each fragment's top-level key into `rea-state.json`. A resumed run reads the state file and jumps to the first unmet GATE — so a crash, a context reset, or "continue tomorrow" never loses place.

> **Golden discipline:** advance only on a GATE, never on "looks done". Update `rea-state.json` after every step. When a STOP-IF fires, stop and report — don't burn cycles against a wall the model says is a wall (STRONG attestation, white-box key extraction).

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
- **STOP-IF** jadx/REA shows the DEX is packed/加固 (classes missing/encrypted) → dump the real DEX first (FRIDA-DEXDump / Youpk; `docs/china-re-arsenal.md`), then re-run Phase 1. This step is semi-automatic — report what packer REA identifies.

## Phase 2 — capture plaintext traffic

- **GOAL** a `requests.ndjson` with real requests to the target host, bodies included.
- **BRANCH** on `state.fingerprint`:
  - **plain / system TLS** → CA already installed in Phase 0; drive the app through a proxy, OR run `frida -U -f <pkg> -l frida/anti-detect.js -l frida/ssl-unpin.js -l frida/capture-http.js --no-pause` (no proxy, works through pinning).
  - **cronet / boringssl-fork / flutter** → `python scripts/find-ssl-offsets.py <pulled .so> --json` (writes `offsets.json`, merges `state.offsets`) → `python frida/fridacap.py --device <id> --attach <pid> --offsets offsets.json`. Block UDP/443 first to force QUIC→TCP.
- **READ** `offsets.found` (must contain SSL_read/SSL_write or their lowercase) before the cronet path can work.
- **GATE** `state.capture.requests ≥ 1` for the real API host, with non-empty bodies. (Run Phase 3 to populate it.)
- **STOP-IF** the app dies on attach even with `anti-detect.js` → escalate stealth: renamed frida-server on a non-default port, then **ZygiskFrida** (process-less, no ptrace), then KernelSU/APatch+SusFS (`frida/README.md` → anti-Frida). If it still won't attach, report the detection vector REA found — don't loop.

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

## Hard stop conditions (always surface, never loop)

1. **STRONG hardware attestation** required by the server (Play Integrity STRONG, TEE key) — not winnable off a certified device.
2. **White-box key extraction** as the only route (oracle closed) — research-grade (DCA/DFA); confirm it's in scope before starting.
3. **Packed DEX** you can't dump — report the packer, needs a dumping step.
4. **Device/root unavailable**, or the app can't be attached after the full stealth escalation.
5. Anything that looks like **real user data / credentials** outside the authorized target — stop and ask.

## The loop invariant

After each phase: **write `rea-state.json`**. To resume: read it, find the first GATE not met, continue there. The combination of (fixed phase order) + (JSON branch fields) + (explicit gates) is what lets the agent run this unattended and still be correct — it never advances on vibes, and it never redoes a verified phase.

*Scripts: `check-deps.py`, `setup-device.py`, `fingerprint.py --json`, `recover-kotlin-names.py`, `find-ssl-offsets.py --json`, `analyze-capture.py --json`, `verify-signer.py`. Frida: `anti-detect.js`, `ssl-unpin.js`, `capture-http.js`+`fridacap.py`, `signer-sniffer.js`, `crypto-dump.js`, `rpc-signer.js`. Oracle: `unidbg/UnidbgOracleTemplate.java` (+ MCP). Reference: `per-stack-reverse.md`, `signer-reverse-deepdive.md`, `hard-sign-types.md`, `decryption-playbook.md`, `android-arsenal.md`.*
