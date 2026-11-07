---
name: reverse-mobile-app
description: Reverse-engineer the API of an ANDROID app (APK) and build a Python client + a complete system. Standard process — emulator/device + adb, MITM to capture HTTPS (install the CA into the system store), Frida SSL-unpinning when the app pins certs (plus bypassing anti-Frida/anti-root detection when the app exits on attach, and capturing plaintext in-process without a proxy/CA — including stripped-BoringSSL/cronet via offsets), decompile the APK with REA (JADX headless) to find the request signing & decryption mechanism, reimplement the API in Python (curl_cffi/requests) → sync DB → FastAPI → admin UI React. Auto-activates when the user gives an Android app (app name / .apk file / package name) and wants to "reverse an app api", "capture a phone app api", "reverse an app in an emulator/ldplayer", "get an android app api", "emulate an app".
---

You are a reverse-engineering specialist for **Android apps (APKs)**. Goal: use an emulator/device as scaffolding, capture/decrypt HTTPS, **decompile the APK with REA** to find the request signing & encryption mechanism, then **reimplement the entire API in Python** (without opening the app) and assemble it into a system: client → DB → FastAPI → admin UI.

**Target app/info:** $ARGUMENTS

## Principle #1: BE PROACTIVE, DON'T NITPICK WITH QUESTIONS

The user hands you an app and expects you to run the whole thing yourself — install the APK, root, capture traffic, decompile, find the signing/encryption mechanism, rewrite the Python client, and test until it returns real data. DON'T stop to confirm every small step. Decide per the playbook, and fix issues as they come (app pins cert → Frida; encrypted body → decompile for the key; adb drops → reconnect; wrong signing header → re-verify).

Only stop to ask when you hit a situation that genuinely needs a human:
1. **Need a real APK** you can't obtain yourself (Store-only app, no download link) — ask for the `.apk`/`.xapk` file, or ask them to preinstall it in the emulator so you can `adb pull`.
2. **Need a real action in the app** to reveal an unknown flow (OTP login, QR scan) or captcha — state exactly the one action to tap, then keep capturing via mitm yourself.
3. **Need something you can't provide yourself**: test account, OTP/phone number, a live proxy, a captcha-solving API key. Ask once, concisely.
4. **Very heavy hardening** (Frida/root-detection blocking startup, signing algorithm inside an obfuscated native `.so`, integrity attestation/Play Integrity) — report the workload (native hooking/emulation) and ask whether to continue.

Report progress briefly as you hit each major milestone: traffic captured → signing/encryption mechanism found → first API call returning `success` in Python → all endpoints read → sync+UI running.

## Final goal: DROP the emulator → down to 1 CLI

Capturing traffic is only to **understand the protocol**. The deliverable is **1 Python CLI** that builds requests itself, running headless and stable (capture -> solve -> CLI passes = done). No DB, no web UI. If the signing algorithm lives in a native `.so` you can't reverse → fall back to **Frida RPC**: keep one instance of the app running and expose the signing function over `frida` RPC for the CLI to call — clearly note this is a fallback.

## Environment (fill in per your machine — keep as variables)

```bash
# Emulator: LDPlayer / Genymotion / Android Studio AVD / a real device
LD="<path to ldconsole.exe if using LDPlayer>"   # e.g. E:/LDPlayer/LDPlayer9/ldconsole.exe
ADB="<path to adb>"                               # the emulator's adb or platform-tools
# Tools: frida-tools, mitmproxy, openssl, python(pycryptodome, curl_cffi), node
# frida-server MATCHING the `frida --version` and the right ABI (x86_64 for LDPlayer; arm64 for a real device)
FSRV="<path to a version/ABI-matched frida-server>"
```
⚠️ If the machine has multiple JDKs (e.g. another tool's Java 8 at `JAVA_HOME`), make sure tools that need Java 21 (jadx/REA) invoke the right JDK — REA reads its own `JAVA_HOME` from registration (see [rea-setup](https://github.com/QuocHuy03/rea-reverse-skills/blob/main/docs/rea-setup.md)).

## Bundled scripts (ship with this skill) — reach for these first

| Script | Use it when | What it does |
| --- | --- | --- |
| `scripts/fingerprint.py` | **first, before decompiling** | one pass over the APK → UI framework, TLS stack, HTTP lib, SDKs, R8-obfuscation level, and the recommended capture route. Cross-platform (stdlib only). |
| `scripts/recover-kotlin-names.py` | R8-obfuscated Kotlin (classes are `a/b/c`) | rebuilds obf→real class-name map from `@Metadata`/`@DebugMetadata` → `mapping.tsv`; grep it to find the signer by its real name. Cross-platform (stdlib only). |
| `frida/ssl-unpin.js` | app pins certs (no traffic in MITM) | universal unpin: OkHttp `CertificatePinner`/`check$okhttp`, TrustManager, Conscrypt, TrustKit, Cronet builder pins, WebView + native verify surface (BoringSSL `custom_verify`/`cert_verify_callback`/`X509_verify_cert`, covers forks like `libttboringssl`) + Proxygen (Meta) |
| `frida/anti-detect.js` | **app exits/crashes the instant you attach** | hides common anti-Frida vectors (strstr signature-filter, `ptrace` guard) + logs which `/proc` probe fired. **Load FIRST**, before `ssl-unpin.js` |
| `frida/capture-http.js` + `frida/fridacap.py` | want plaintext without a proxy/CA, or MITM is blocked by pinning/custom stack | reads TLS plaintext **in-process** (through pinning); NDJSON, HTTP/1.1 + h2 decoded bodies; `--offsets` hooks stripped BoringSSL/cronet by `base+offset` |
| `scripts/find-ssl-offsets.py` | stripped BoringSSL/cronet (to feed `--offsets`) | parses a pulled `.so` (ELF `.dynsym`+`.symtab`) → auto-writes `offsets.json` with `SSL_read`/`SSL_write`; `--pattern SYM=HEX` byte-sig fallback. Finds what Frida's export scan misses. |
| `unidbg/UnidbgOracleTemplate.java` | signer/crypto is in a `.so` + "căng" (anti-hook / white-box / key never in memory) | template to run the app's native encrypt/decrypt/sign as an **offline oracle** (no device, immune to anti-Frida) — fill 6 placeholders; see `docs/decryption-playbook.md` |
| `scripts/check-deps.py` | **before anything** | preflight the toolchain (adb/frida/mitmproxy/node/openssl + python modules); flags missing + the frida client/server version rule |
| `scripts/setup-device.py` | prep the device | one command: adb connect+root, detect ABI, push+launch a version/ABI-matched frida-server (non-default port/renamed), install the mitm CA into the system store. `--dry-run` to preview |
| `frida/crypto-dump.js` | body/params encrypted or signed | hooks the Java crypto stack (Cipher/Mac/MessageDigest/SecretKeySpec/IvParameterSpec) + native `EVP_*`/`AES_set_*key` → prints key/IV/mode/plaintext live (bundled CryptoFucker role) |
| `frida/signer-sniffer.js` | **reversing a request signer** | reconstructs the exact **canonical string** fed to the hash (joins every `update()` per instance, Java + native `*_Update`) + the HMAC key + a stack trace pointing at the signing method → you *see* what to reimplement instead of guessing field order. The ladder past rung 0: `docs/signer-reverse-deepdive.md` |
| `scripts/analyze-capture.py` | after a capture | turns `requests.ndjson` into a reverse map: endpoints, signature/auth headers, candidate secrets, likely-encrypted-body endpoints |
| `scripts/verify-signer.py` | reimplemented the signer | replays your `sign(request)` over captured requests and checks it matches the app **byte-for-byte** (automates "verify empirically") |

Deep technique docs, the vector→counter matrix, the cronet/offsets recipe, and the **"when a bypass fails → self-diagnose → research → update the scripts" loop**: [`frida/README.md`](https://github.com/QuocHuy03/rea-reverse-skills/blob/main/skills/reverse-mobile-app/frida/README.md). Keep that loop alive — when you solve a new app, fold the hook/offset back into these scripts with a dated note.

---

## Process

### 0. Prepare the device (adb + root)
**Shortcut:** `python scripts/check-deps.py` (preflight the toolchain), then `python scripts/setup-device.py --connect <ip:port> --frida-server <matched-server> --ca ~/.mitmproxy/mitmproxy-ca-cert.pem` does adb connect+root, detects ABI, pushes+launches a version/ABI-matched frida-server, and installs the CA into the system store in one go (run with `--dry-run` first to preview). Manual steps below if you prefer / need to debug one:
```bash
"$ADB" connect 127.0.0.1:5555 && "$ADB" devices   # port depends on the emulator (each extra LDPlayer instance +2: 5557…)
"$ADB" root && "$ADB" shell su -c id              # confirm uid=0(root) — needed to put the CA in the system store & run Frida
"$ADB" shell getprop ro.product.cpu.abi           # abi → pick the right frida-server & .so build
```
LDPlayer: enable Root + ADB in Settings (or `ldconsole modify --index 0 --root 1` then reboot). Enable root accordingly on other emulators.

### 1. Get & decompile the APK (REA is the main tool for reading code)
```bash
# have the file: install
"$ADB" install -r app.apk        # xapk/apks = multiple apks → install-multiple
# app already installed: find the path then pull
"$ADB" shell pm list packages | grep -i <keyword>
"$ADB" shell pm path <package>   # -> /data/app/.../base.apk (+ split_*.apk)
"$ADB" pull <path>/base.apk apk/base.apk
```
**Fingerprint the stack first** — don't sink jadx time into a Flutter/RN app. Run the bundled triage (cross-platform, stdlib-only):
```bash
python scripts/fingerprint.py apk/base.apk    # framework + TLS stack + SDKs + obfuscation + RECOMMENDED ROUTE
```
It flags Flutter (`libflutter.so` → Dart, not Java), React Native (`libhermes.so`/`index.android.bundle`), Xamarin (`assemblies/`), the **TLS stack** (`libsscronet`/`libcronet` → cronet offsets-mode; `libttboringssl` → TikTok fork), the Java HTTP lib (OkHttp/Retrofit/Ktor/Cronet), and R8 obfuscation level — then prints the capture route that actually works. Only a "plain" Java/Kotlin app on the system TLS stack is worth deep jadx time.

**If it flags a non-Java stack, STOP and switch procedures** — jadx is useless on Flutter/RN/Unity/packed. Each has a distinct standardized flow (exact tools + commands: blutter/reFlutter for Flutter, hermes-dec for RN-Hermes, Il2CppDumper for Unity, FRIDA-DEXDump for packed, unidbg for a native signer) in **`docs/per-stack-reverse.md`**. Follow the matching section instead of this one.

Read the code with **REA** (MCP tool `mcp__rea__*`, or CLI `npx -y rea-agents@latest`):
```bash
rea inspect-android-package  apk/base.apk                 # package, manifest, permissions, coverage
rea search-android-classes   apk/base.apk --pattern Sign  # find classes (Sign/Crypto/Token/Api…); empty = list all
rea inspect-android-class    apk/base.apk --class <fqcn>  # members of 1 class
rea inspect-android-method   apk/base.apk --class <fqcn> --method <m>   # DECOMPILE 1 method (--overload-index when overloaded)
rea trace-android-references apk/base.apk --class <fqcn>  # who calls this class/method — trace the signing flow backward
rea inspect-apk-signature    apk/base.apk                 # scheme v1/v2/v3, cert fingerprint
```
**Obfuscated Kotlin (classes renamed to `a/b/c`)? Recover real names BEFORE hunting the signer.** R8 renames classes but can't strip Kotlin's `@Metadata`/`@DebugMetadata`, which still embed the real FQN — so you can rebuild an obfuscated→real map and the signing class usually surfaces by name (`*Repository`/`*Impl`/`*ViewModel`/`*UseCase` recover at ~100%, class names only — not methods):
- **Primary** — `@DebugMetadata(... c = "com.example.AccountRepositoryImpl$fetch$1")`: regex `@DebugMetadata\([^)]*?c\s*=\s*"([^"]+)"`, then `.split('$')[0]`.
- **Fallback** — `@Metadata(... d2 = {"...","Lcom/example/Foo;",...})`: take the first `L([A-Za-z][\w/$]+);` that isn't `kotlin.`/`java.`/`android*`.
- Batch it with the bundled tool: `python scripts/recover-kotlin-names.py <decompiled_src_dir>` → writes `mapping.tsv` (obf→real); then grep that for `Sign|Crypto|Token|Repository|Api` to land the signer by its **real** name. Treat as a strong hint, not gospel (`value class` / `*Kt` facades can land under the wrong file). *(bundled script — own impl; technique popularized by SimoneAvogadro/android-reverse-engineering-skill.)*

Native `.so` (signing algorithm in C) → Ghidra: `rea analyze lib/<abi>/libfoo.so --provider ghidra`, then `rea decompile … --procedure Java_com_foo_Native_sign`. Use the returned `evidence_id` to request a detailed view.

### 2. Capture HTTPS traffic — the crux

**Two routes to plaintext — pick by the app, don't default to proxy:**
- **(A) MITM proxy + system-CA** (below) — simplest; use it for unpinned apps on an emulator you control.
- **(B) In-process TLS hook** (`capture-http.js`/`fridacap.py`, step 3) — no proxy, no CA, **works through pinning** and reads bodies even on a custom stack. Best for pinned, modern (Conscrypt/OkHttp over h2), Flutter, and cronet apps.

Try A first; the moment pinning or a custom stack (Flutter/cronet) gives you an empty capture, jump to B instead of fighting the proxy.

```bash
mitmweb --listen-port 8080        # or mitmdump -p 8080 -s capture.py (run in background)
"$ADB" shell settings put global http_proxy <host_machine_LAN_IP>:8080   # DON'T use 127.0.0.1 (that's the emulator itself)
# remove when done: "$ADB" shell settings put global http_proxy :0
```
Install the mitmproxy CA into the **SYSTEM store** (Android 7+ ignores user CAs). The CA is at `~/.mitmproxy/mitmproxy-ca-cert.pem`:
```bash
H=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem "$H.0"
"$ADB" root && "$ADB" remount                      # if remount fails → "$ADB" disable-verity then reboot
"$ADB" push "$H.0" /system/etc/security/cacerts/ && "$ADB" shell chmod 644 /system/etc/security/cacerts/$H.0
"$ADB" reboot
```
Still no traffic from the app = **CERTIFICATE PINNING** → step 3.

### 3. Bypass SSL Pinning + anti-detection (Frida)
```bash
"$ADB" push "$FSRV" /data/local/tmp/frida-server && "$ADB" shell chmod 755 /data/local/tmp/frida-server
"$ADB" shell su -c "/data/local/tmp/frida-server &"
frida-ps -U | head                                  # seeing processes = OK
frida -U -f <package> -l frida/ssl-unpin.js --no-pause   # universal unpin script (OkHttp/TrustManager/Conscrypt/BoringSSL/Proxygen)
```
A **Flutter** app doesn't listen to the system proxy → hook `ssl_verify_peer_cert` in `libssl.so` + force the Dart proxy (reFlutter/iptables). Objection `android sslpinning disable` is another quick option.

**App exits/crashes the instant you attach = anti-Frida detection, not a bug.** Load the anti-detection helper FIRST (spawn mode), then your unpin:
```bash
frida -U -f <package> -l frida/anti-detect.js -l frida/ssl-unpin.js --no-pause
```
`anti-detect.js` hides the common vectors (strstr signature-filter for `/proc/self/maps`·fd·thread-name scans, `ptrace(PTRACE_TRACEME)` guard) and logs which sensitive `/proc` path the app probed. If it still dies, the check uses raw syscalls / `strcmp` / CRC — **find the detector in REA** (trace the `abort`/`exit`/`kill` caller chain) and NOP it. Also: run frida-server on a **non-default port + renamed binary** (`./fs1337 -l 127.0.0.1:1337`) to beat the `27042/3` + process-name checks.

**Hardened app? Split it into 3 orthogonal gates** — they fail for different reasons: (1) **root detection** (exits before attach) → hide root (Zygisk + Shamiko / Zygisk-Assistant, SusFS); (2) **Frida detection** (dies on attach) → a **patched frida-server** (`strongR-frida` / `phantom-frida`) is the durable fix `anti-detect.js` only approximates; (3) **Play Integrity** → PIF for BASIC/DEVICE, but STRONG (hardware-backed) isn't winnable client-side → real device or reverse the server check. No root / root detected → rootless `objection patchapk` or `apk-mitm` (re-signs the APK, so expect anti-tamper). Full vector→counter matrix + the device-level stack: [frida/README.md](https://github.com/QuocHuy03/rea-reverse-skills/blob/main/skills/reverse-mobile-app/frida/README.md).

**No-proxy / no-CA alternative to step 2 (robust for pinned apps):** instead of MITM, read the plaintext **inside the process** by hooking the TLS layer — no proxy, no CA install, works through pinning:
```bash
frida -U -f <package> -l frida/capture-http.js --no-pause        # quick console triage
python frida/fridacap.py --device <id> --attach <pid> --include <host> --seconds 60 --out cap   # scale: NDJSON, HTTP/1.1+h2 bodies
```
After capturing, `python scripts/analyze-capture.py cap/requests.ndjson` turns the dump into a reverse map — endpoints, signature/auth headers, and likely-encrypted-body endpoints — so you know exactly what to reverse next.
For **stripped/static BoringSSL** apps (cronet — official YouTube/Chrome; Flutter) the export scan finds nothing: block UDP/443 to force QUIC→TCP, get the `SSL_read`/`SSL_write` offsets from the pulled `.so` with REA, then `fridacap.py --offsets offsets.json` (recipe in [frida/README.md](https://github.com/QuocHuy03/rea-reverse-skills/blob/main/skills/reverse-mobile-app/frida/README.md)). Attach **after** the app finishes rendering — early-spawn races EGL init and crashes GPU-heavy apps.

**When a bypass fails on a new app, don't one-off it — run the self-diagnose → research → verify → *update the scripts* loop** (symptom→cause table + the update discipline) in [frida/README.md → "When the bypass fails"](https://github.com/QuocHuy03/rea-reverse-skills/blob/main/skills/reverse-mobile-app/frida/README.md). Fold the working hook/offset back into `ssl-unpin.js`/`capture-http.js`/`anti-detect.js` with a dated source note so the next app of that kind is covered built-in.

### 4. ⚠️ REQUEST SIGNING & ENCRYPTION MECHANISM — THE HEART
Combine the **captured traffic** (which headers exist, sample values) + the **code from REA** (the formula):
1. Grep the header/field names seen in traffic across the code: `sign`, `signature`, `nonce`, `ts`/`timestamp`, `appKey`, `secret`, `token`, `deviceId`, `X-…`. Trace the functions that produce them (`search-android-classes` → `inspect-android-method` → `trace-android-references`). Even when R8 inlines/renames the call site (`client.get("/v1/pay")` → `a.b(c,"/v1/pay")`), the **string literals survive** — grep the literal header-names/endpoint-paths/secret keys directly (`app[_-]?secret`, `signing[_-]?key`, `HmacSHA`, `Mac.getInstance`, `x-signature`) to land on the signer even in obfuscated code.
2. Find the algorithm: `MessageDigest`(MD5/SHA), `Mac`/`HmacSHA256`, `Cipher`(AES/DES — mode ECB/CBC + IV + key), `Base64`. The field order when signing is usually alphabetical or fixed — wrong order = wrong sign.
3. **Key/secret**: a hardcoded constant, `BuildConfig`, `strings.xml`/`assets/`, assembled from multiple pieces, or from a native `.so`. If it's inside a `.so` → hook that function with Frida to print the key instead of reversing C.
4. **See the signed string, don't guess it**: run `frida/signer-sniffer.js` and trigger one signed request → it prints the full **canonical string** (the exact pre-hash bytes, in order, with separators/salt) + the HMAC key + a stack trace to the signing method. The hash algo (HMAC-SHA256/MD5…) is trivial; the canonical string IS the reverse. If the Java canonical is empty/garbage, the string is built in native/obfuscated code — **climb the ladder** (native pre-hash bytes → read the derived key → stateful-input diffing → oracle the `.so`) in **`docs/signer-reverse-deepdive.md`** (rungs 0–5 + "classify your app in 60s"). For the **named hard families** — argus/ladon protobuf (stateful counter), OLLVM/VMP obfuscated native, white-box crypto, anti-tamper-bound key (sign looks right but server rejects silently), TEE/attestation — the exact blocker + move per type is in **`docs/hard-sign-types.md`**; the live-oracle tool is `frida/rpc-signer.js` (`init()` once → `sign([...])`/`signNative(...)`), the offline one is `unidbg/UnidbgOracleTemplate.java`.
5. **ALWAYS verify empirically**: reimplement the signing function in Python, compute the sign for a captured request → it must match the exact value the app sent, then make the real call. Automate this: put your `sign(request)->dict` in a file and run `python scripts/verify-signer.py cap/requests.ndjson --signer signer.py` → it replays over every captured request and reports byte-for-byte match (PASS) or the first mismatch to debug.
6. Encrypted body/response (AES common): find the key+IV+mode → decrypt a captured response into valid JSON with `pycryptodome` to verify. Protobuf → get the `.proto` or reconstruct the field numbers. **Full crypto-cracking procedure — Java hooks → native Frida hooks → unidbg oracle → the hard cases (white-box, `.text`-encrypted `.so`, custom transforms): `docs/decryption-playbook.md`.** Golden rule when crypto is in a `.so` and "căng" (anti-hook / white-box / key never in memory): **don't chase the key — run the app's own encrypt/decrypt as an oracle** (unidbg offline, immune to anti-Frida; or `frida/rpc-signer.js` live). It always works because the app must be able to do it.

### 5. Build the Python CLI (final deliverable)
The deliverable is **1 stable CLI**, no DB/no web UI. Start from the ready skeleton [templates/cli-skeleton](https://github.com/QuocHuy03/rea-reverse-skills/tree/main/templates/cli-skeleton) instead of scratch. Compact structure:
```
<app>/                 # drop the package prefix: com.company.app → app
  client.py            # Client(): login, export/restore session, one get_*/do_* method per endpoint
  signer.py            # the sign() function — verified to MATCH the app
  crypto_util.py       # encrypt_body / decrypt_resp
  captcha_solver.py    # (if there's a captcha) — see https://github.com/QuocHuy03/rea-reverse-skills/blob/main/docs/captcha-solvers.md
  cli.py               # entrypoint: argparse/typer; subcommand login / <action>; prints JSON/plain; exit 0 on pass
  requirements.txt
```
- `curl_cffi impersonate` or `requests`/`httpx`; set the app's correct `User-Agent` + fixed headers (app version, device model, `okhttp/x.y`).
- **Device fingerprint**: `deviceId`/`androidId` must be stable per account (grab it once from the emulator/traffic and keep it fixed — randomizing it per call = you get hit with OTP again).
- `signer.py` (verified to match the app) + `crypto_util.py`. `client.py` reuses the session (saves `session.json`) to avoid re-login.
- **The CLI must be stable**: idempotent, has `--help`, parameters via flags/env (no hardcoded secrets), retry/backoff on network errors, clear exit codes (0 = pass, ≠0 = fail with a message). The goal is exactly what the user wants: **capture -> solve -> CLI passes = done**.
- **Frida-RPC fallback** when the native signing can't be reversed: keep the app running, the CLI calls the signing function over `frida` RPC.

### 6. Before committing
`.gitignore` should hide: `*/apk/`, `*.apk`, `session.json`, `.env`, `*/frida/*.log`, `proxies.txt`, `accounts.txt`, `__pycache__/`. **DO NOT commit the APK** (copyright + size). Grep clean for real credentials/proxies/device-ids/tokens/API keys. `git add` only specific files.

## Reference tools — usage captured locally in `docs/android-arsenal.md` (no external links to rot)

Reach for the bundled scripts first (table up top). When you need more, the arsenal doc holds the **actual command + when-to-use** for every tool below, self-contained:
- **🔑 Reversing the request signer (every app is a different type)** → the full method that doesn't depend on the app: `docs/signer-reverse-deepdive.md`. Rung 0 (see the signed string free via `signer-sniffer.js`) handles most apps; the ladder (native canonical → dynamic key → stateful nonce/counter → obfuscated/anti-tamper → attestation) tells you exactly when to stop reimplementing and start oracling. **The governing decision: can you read the canonical string + key at runtime? yes → reimplement; no → oracle.** Hard named families (argus/ladon, OLLVM/VMP, white-box, anti-tamper key, TEE) with per-type blocker+move: `docs/hard-sign-types.md`.
- **🧙 Signing lives in a native `.so` you can't reverse** → emulate it with `zhkl0228/unidbg` to call the signer as an oracle (no device), or serve it via `anjia0532/unidbg-boot-server`; find the boundary with `chame1eon/jnitrace`; else Frida-RPC fallback (`frida/rpc-signer.js`). *Emulate vs RPC vs reimplement* decision table + real cases (`is-L7N/SignerPy`, `scrapguru/tiktok-argus-androidemu`, `subzeroid/instagrapi`, `simon-weber/gpsoauth`): `docs/reverse-case-studies.md`, arsenal §4.
- **🧧 APK packed/加固 (jadx reads empty)** → dump the real DEX: `hluwa/FRIDA-DEXDump` / `CodingGay/BlackDex`; extraction-based (抽取加固) → `Youlor/Youpk` / `hanbinglengyue/FART`; packer-ID flow in `docs/china-re-arsenal.md`, arsenal §3.
- **Unpin / capture / crypto-hook / anti-detect / Flutter / cronet** → arsenal §1–6: `sensepost/objection`, `shroudedcode/apk-mitm`, `Impact-I/reFlutter`, `r0ysue/r0capture`, `fkie-cad/friTap`, `P4nda0s/CryptoFucker`, `CrackerCat/strongR-frida-android`, `LSPosed` Shamiko, …
- **Captcha** → `docs/captcha-solvers.md`. **Standard methodology** → `OWASP/owasp-mastg` (arsenal §7).

## Getting started
Have the app → do it right away: create a `<app>/` folder → prepare the device → get & decompile the APK (REA) → capture traffic + CA in the system store, Frida if pinned → **find the signing + encryption mechanism and verify in Python** → build `client.py`+`signer.py` → assemble `cli.py` running stably and passing. No app yet → ask exactly one question to get the app name / package / APK file (+ a test account if available).
