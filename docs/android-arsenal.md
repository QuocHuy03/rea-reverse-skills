# Android RE arsenal (self-contained — usage captured locally, no links)

Every tool the mobile-app skill reaches for, with **what it does + when + the actual command**, written out so this survives link-rot. Repo names are given as plain `owner/repo` text (searchable) — deliberately not clickable; the knowledge here is meant to stand on its own. Verify a tool's current flags against its own `--help` before relying on an exact invocation; the *technique* is the durable part.

---

## 1. SSL pinning bypass

**This skill's own `frida/ssl-unpin.js`** is the first reach (universal: OkHttp/Conscrypt/TrustKit/Cronet-pins/WebView + native BoringSSL verify surface + Proxygen). Alternatives/supplements:

- **`sensepost/objection`** — Frida-based runtime explorer. One-shot unpin without writing a script:
  `objection -g <package> explore` then `android sslpinning disable`. Also patches APKs for rootless use (§2). Misses heavily-custom pinning → fall back to a script.
- **`httptoolkit/frida-interception-and-unpinning`** — the strongest all-in-one script set: config block (proxy IP/port + your CA cert as a constant), then it does proxy-redirect + CA injection + multi-library unpinning + some anti-root. Good to lift hooks from when `ssl-unpin.js` misses a library.
- **Universal bypass (pcipolloni)** — the classic one-file script; lives on Frida CodeShare (`@pcipolloni/universal-android-ssl-pinning-bypass-with-frida`), run via `frida --codeshare`. Superseded by the httptoolkit set but still a quick reference.
- **Flutter** (ignores the system proxy, pins in Dart/BoringSSL):
  - **`NVISOsecurity/disable-flutter-tls-verification`** — Frida script hooking BoringSSL `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so`; pattern-scans per arch when the symbol is stripped. `frida -U -f <pkg> -l <script> --no-pause`.
  - **`Impact-I/reFlutter` (`reflutter`)** — repackages the APK patching `libflutter.so` to route traffic through your proxy + trust your CA: `reflutter app.apk` → choose "display traffic", set your IP, it emits a patched APK to install. Needs you to re-sign (uber-apk-signer).
- **`shroudedcode/apk-mitm`** — **no-root** repackage: `apk-mitm app.apk` decodes, rewrites the Network Security Config + patches pinning, rebuilds + re-signs → `app-patched.apk`. Breaks signature/integrity (expect anti-tamper on hardened apps).

## 2. Anti-Frida / root-detection evasion (hardened apps)

Three orthogonal gates — diagnose which fired (see `frida/README.md` → *Anti-Frida detection*):

- **Frida detection** → **patched frida-server** renames the detection artifacts at the binary. The canonical **strongR-frida (`CrackerCat/strongR-frida-android`, releases via `hzzheyang/strongR-frida-android`)** patch set renames these **8**: `frida:rpc` (D-Bus string), `re.frida.server` (service/IO name), `linjector` (named pipe), `frida-agent.so` (agent lib), `frida_agent_main` (export symbol), `gum-js-loop` thread, `gmain` thread, and the "unexpected command" protocol reply. `theqmaks/phantom-frida` is a newer variant (~90 patches/16 vectors, weekly auto-builds with random names); `Ylarod/Florida` is the older/simpler one. Patch files: `AAAA-Project/Patchs`, `hluwa/Patchs`. Usage: grab/build a server, `adb push <randomname> /data/local/tmp/`, `chmod 755`, run on a **non-default port** `./<randomname> -l 127.0.0.1:1337`, connect with `frida -H 127.0.0.1:1337`. Stack with this skill's `anti-detect.js` for leftover in-process `/proc` checks.
- **Root detection** → hide root (orthogonal to Frida): **`LSPosed` Shamiko** (per-app hide via Zygisk — first turn OFF Magisk's "enforce denylist", then add targets to the denylist; Shamiko reads it), or **`snake-4/Zygisk-Assistant`** (works on Magisk/KernelSU/APatch). Kernel-level **SusFS** (+ KernelSU/APatch) is strongest but needs a patched kernel. `Prslc/Florida` + `LSPosed/LSPosed` are also referenced for evasion/hooking.
- **Integrity attestation** (Play Integrity) → **Play Integrity Fix / PIF** modules reach BASIC/DEVICE integrity on many setups; **STRONG (hardware-backed) is not winnable client-side** — the app's *server* verifies a Google-signed token → use a real attested device or reverse the server check.
- **No root / root itself detected** → rootless: `objection patchapk --source app.apk` embeds frida-gadget (re-signs → anti-tamper risk), or `apk-mitm` (§1).

## 3. DEX unpacking (脱壳) — packed / 加固 apps (jadx shows empty)

When REA/jadx reads no code, the DEX is packed. Identify the packer, then dump the real DEX from memory at runtime, then read the dump:

- **`hluwa/FRIDA-DEXDump`** — Frida script that scans process memory for DEX magic and dumps every DEX: `python main.py` (with the app running under frida-server). Fast first try.
- **`CodingGay/BlackDex`** — an on-device app that unpacks another installed app to DEX; good when FRIDA-DEXDump is detected. Install the APK, pick the target, it writes DEX to storage.
- **Extraction-based packing (抽取加固)** — methods come out empty because bodies are restored per-call. Need a runtime that rebuilds them: **`Youlor/Youpk`** (ART-based unpacker ROM/image) or **`hanbinglengyue/FART`** (ART-level fart dump — triggers all methods, dumps full bodies). Both require a matching AOSP/ART build on a device/emulator. See `docs/china-re-arsenal.md` for the packer-identification flow (GDA).

## 4. Native signer reversal (`.so` signing you can't reimplement)

When the sign/token function lives in C/C++ (`libXXX.so`):

- **`chame1eon/jnitrace`** — traces every JNI call to find the signing boundary (which native method the Java calls, with args/returns): `jnitrace -l libXXX.so <package>`. Start here to locate the function.
- **`zhkl0228/unidbg`** — emulates the `.so` on the JVM so you call the signing function as an **oracle** without a device. Load the lib, set up the JNI env, call the export; reproduces X-Argus/X-Gorgon-style signers. The robust path when reimplementing the algorithm is infeasible. **Bundled template to start from: `skills/reverse-mobile-app/unidbg/UnidbgOracleTemplate.java`** (+ README: setup, placeholders, common failures).
- **`anjia0532/unidbg-boot-server`** — wraps a unidbg signer in a Spring-Boot HTTP server so your Python CLI POSTs params and gets the signature back. Turns the emulated signer into a microservice.
- **Frida-RPC fallback** (this skill's `frida/rpc-signer.js` template) — keep one app instance running, expose the native signer over `frida` RPC, call it from Python. Simplest but needs a live device. *(emulate vs RPC vs reimplement decision table: `docs/reverse-case-studies.md`.)*
- Real cases to mirror: `is-L7N/SignerPy` + `scrapguru/tiktok-argus-androidemu` (TikTok signer), `subzeroid/instagrapi` (device fingerprint + session), `simon-weber/gpsoauth` (Google master-token).

## 5. Crypto / signer hooking (find the key + the signed string)

- **`P4nda0s/CryptoFucker`** — Frida script that hooks the whole Android crypto stack (`MessageDigest`, `Mac`, `Cipher`, `SecretKeySpec`, `Signature`) and prints inputs/outputs/keys live. Point it at the app, trigger a signed request, read the HMAC key + the exact pre-hash string → reimplement in Python. Faster than reading decompiled crypto.
- This skill's `frida/dump-signer.js` — a targeted template: set `TARGET_CLASS`/`TARGET_METHOD` to the signer you found, it prints the input string + return value.

## 6. Packet capture through pinning (no proxy)

- This skill's **`frida/capture-http.js` + `frida/fridacap.py`** — reads TLS plaintext in-process (BoringSSL `SSL_read/write` + Conscrypt `ENGINE_SSL_*_direct`), through pinning, no CA; NDJSON with HTTP/1.1 + h2 decoded bodies; `--offsets` for stripped BoringSSL/cronet.
- **`r0ysue/r0capture`** — the well-known alternative: hooks the Java/native SSL layer and dumps a pcap + plaintext for **any** Android app, pinned or not: `python r0capture.py -U -f <package> -p out.pcap`. Spawn only (`-f`), one process at a time.
- **`fkie-cad/friTap`** (`fritap`) — for stripped/static BoringSSL in cronet: pattern-hooks the TLS layer, removes guards (e.g. Ssl_Guard), dumps TLS keys + plaintext pcap: `fritap -m <device> -k keys.log -p out.pcap <pid>`. `fkie-cad` **BoringSecretHunter** (Ghidra/Docker) generates the byte-pattern/offset for a specific `libcronet` build. Pin Frida 16 (friTap ≤2.6.0 isn't fully Frida-17 compatible). Shortcut for YouTube's API: reverse `TeamNewPipe/NewPipe` instead (same InnerTube API, no cronet/anti-tamper).

## 7. Frameworks / standard

- **`frida/frida`** — the instrumentation engine everything above runs on. Client `frida-tools` (`frida`, `frida-ps`, `frida-trace`); server pushed to the device. Client and server versions **must match**; ABI must match the app (x86_64 for most emulators, arm64 for a phone).
- **`skylot/jadx`** — DEX→Java decompiler (REA runs this headless). `jadx -d out app.apk`, or `jadx-gui` to browse. `--deobf` renames obfuscated identifiers deterministically (does NOT recover original names — pair with this skill's `scripts/recover-kotlin-names.py`).
- **`iBotPeaches/Apktool`** — decode/rebuild resources + smali for patching/repackaging: `apktool d app.apk` → edit smali/`res` → `apktool b` → re-sign with `uber-apk-signer`.
- **`pxb1988/dex2jar`** / **`google/enjarify`** — DEX→JAR when you want a JAR for other tools (enjarify handles obfuscated DEX better).
- **`Ch0pin/medusa`** / **`nccgroup/house`** — ready-made Frida hook libraries (medusa: many modules by category; house: web-GUI, hook without scripting).
- **`nowsecure/r2frida`** — radare2 + Frida bridge to inspect/patch a running app's memory from an r2 prompt.
- **`MobSF/Mobile-Security-Framework-MobSF`** — static+dynamic APK analysis platform (one-shot survey: perms, secrets, API-call tracing) — good for a fast first map before going deep.
- **`OWASP/owasp-mastg`** — the standard mobile security testing methodology (the checklist behind all of the above).
