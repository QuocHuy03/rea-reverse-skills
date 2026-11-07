# Per-stack reverse procedures (pick the one `scripts/fingerprint.py` points you to)

The generic flow in `SKILL.md` assumes a **plain Java/Kotlin app on the system TLS stack**. The moment `fingerprint.py` flags a different stack, the procedure changes — the Java decompile is useless and the capture route is different. Follow the matching section below. Each is self-contained (tool names as plain text, actual commands; verify a tool's current flags against its own `--help` — the *procedure* is the durable part). REA has native inspectors for several of these — use them first, then the community tool for depth.

---

## 0. Baseline — plain Java/Kotlin + OkHttp/Retrofit/HttpURLConnection

The `SKILL.md` process as written. Capture: MITM + system-CA, or `frida/capture-http.js` in-process. Code: REA `inspect_android_*`. Obfuscated → `scripts/recover-kotlin-names.py`. Signer: usually Java (§ SKILL step 4). This is the easy case.

---

## 1. Flutter (fingerprint: `lib/*/libflutter.so`)

Flutter code is **Dart compiled to an AOT snapshot**, not Java — jadx shows only a thin Java shell. Two artifacts matter: `lib/arm64-v8a/libflutter.so` (the engine) and `lib/arm64-v8a/libapp.so` (your Dart code as a snapshot).

**Static (read the logic/API):**
1. Pull `libapp.so`. REA first: `identify_flutter_build` (gets the Dart/engine version — critical, the snapshot format changes per SDK) then `inspect_dart_aot` to parse classes/methods.
2. Community depth: **blutter** (use the actively-maintained fork) — `python blutter.py path/to/libapp.so out/`. It embeds a matching Dart VM and outputs: disassembly **with recovered symbols** (`out/asm/`), the object-pool dump (`out/pp.txt`), C++ type headers, and a ready **`out/blutter_frida.js`** hook template. Read `asm/` + `pp.txt` for class/method names and string constants (endpoints, keys).
   - **Limits:** blutter is **ARM64-only** (no ARM32/x86), output is text, and it needs a Dart VM matching the app's SDK — a version mismatch fails, so pull the exact build. Alternative when SDK-matching is painful: **unflutter** (Go static analyzer, no Dart SDK needed) or commercial **JEB Pro** (parses Dart snapshots).

**Traffic (Flutter ignores the system proxy and pins in BoringSSL):**
- Easiest: **reFlutter** — `reflutter app.apk`, choose "display traffic", enter your proxy IP → it repatches `libflutter.so` to route through the proxy + trust your CA; install the patched APK (re-sign). Then read traffic in mitmproxy/Burp.
- Or hook in-process: `frida/ssl-unpin.js` already targets BoringSSL `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so`; pair with an iptables redirect of 443→proxy (Flutter won't honor `settings put global http_proxy`). Or use blutter's generated Frida script to hook the Dart networking method directly.
- Dart stores the pinned cert / API base as string constants in `libapp.so` → `inspect_dart_aot` / blutter's pool dump often hands you the endpoints without any capture.

---

## 2. React Native (fingerprint: `libhermes.so` or `assets/index.android.bundle`)

RN logic is **JavaScript in `assets/index.android.bundle`**, not Java. Two sub-cases — check the header: `file assets/index.android.bundle`.

**(a) Plain JS bundle** ("JavaScript source" / minified JS): just read it. Unminify/unbundle with `j4k0xb/webcrack` or `pionxzh/wakaru`, optionally `jehna/humanify` (LLM rename). Grep the result for `fetch(`/`axios`/base URLs/headers — RN apps rarely sign requests, so this is often the whole job.

**(b) Hermes bytecode** (`file` says "Hermes JavaScript bytecode, version N"): it's compiled — you need a Hermes decompiler, and the **bytecode version N decides the tool**:
1. REA: `analyze_javascript_application` / `recover_javascript_sources` on the bundle.
2. Community: **hermes-dec (P1sec)** — the established option: `hbc-disassembler index.android.bundle out.hasm` (full assembly) and `hbc-decompiler index.android.bundle out.js` (pseudo-code — note: **not valid JS**, it doesn't reconstruct loops/conditionals, but function bodies + strings + call targets are readable). Install via `pipx install hermes-dec` / uv.
3. Newer: **hermes-decomp (Symbiotic)** returns closer-to-real JS, supports bytecode versions ~40–99 (some new opcodes may not lift). **hbctool** — disassemble **and reassemble** (patch a constant then repack the bundle), but narrower version support.
4. Extract endpoints/headers/signing from the disassembly; patch via hbctool if you need to flip a check.

**Traffic:** RN uses the standard OkHttp/`fetch` stack → MITM + system-CA works, or `frida/capture-http.js`. Pinning (if any) is usually standard → `frida/ssl-unpin.js`.

---

## 3. Unity / IL2CPP (fingerprint: `lib/*/libil2cpp.so`, `assets/bin/Data/`)

C# compiled to native via IL2CPP. Two artifacts: `lib/arm64-v8a/libil2cpp.so` (native code) + `assets/bin/Data/Managed/Metadata/global-metadata.dat` (names/types).

1. **Check the metadata version FIRST** — it picks the tool: `xxd global-metadata.dat | head -1` → magic `AF 1B B1 FA`, then the version field (`0x1D`=29, `0x27`=39 for Unity 6 / 6000.x).
2. REA: `inspect_il2cpp_metadata` parses it natively.
3. Community: **Il2CppDumper (Perfare)** for ≤ v29; **roytu's v39 fork** for Unity 6. `Il2CppDumper libil2cpp.so global-metadata.dat out/` → outputs `dump.cs` (full C# class/method dump — read the logic here), `script.json` (address→name map), `il2cpp.h` (struct defs).
4. Load into Ghidra (REA ghidra provider or standalone): open `libil2cpp.so`, run `ghidra_with_struct.py` with `script.json` beside it → every function gets its real name; optionally parse `il2cpp.h` for types. Now decompile the signing/network methods by name.
   - **Encrypted `global-metadata.dat`** (magic wrong / dumper fails) → the game encrypts metadata; you must decrypt it first (per-game, often an XOR/custom scheme found by hooking the loader) before any dumper works.

**Traffic:** Unity networking (UnityWebRequest / BestHTTP / native sockets) usually rides the system TLS or a bundled lib → try `frida/capture-http.js` (auto-probes all modules) first; MITM if it uses the system stack.

---

## 4. Packed / 加固 (fingerprint: obfuscation HIGH + jadx shows empty classes)

The real DEX is encrypted and loaded at runtime — decompilers see stubs. Procedure: **identify packer → dump real DEX from memory → read the dump**.
1. Identify the packer (GDA, or marker libs like `libjiagu`/`libDexHelper`/`libshell`) — see `docs/china-re-arsenal.md`.
2. Dump: **hluwa/FRIDA-DEXDump** (`python main.py` with the app live under frida-server) scans memory for DEX magic and dumps all; or **CodingGay/BlackDex** (on-device app) when FRIDA-DEXDump is detected.
3. **Extraction-based packing (抽取加固)** — method bodies come out empty because they're restored per-call → need an ART-level dumper that triggers every method: **Youlor/Youpk** or **hanbinglengyue/FART** (both need a matching AOSP/ART image).
4. Feed the dumped DEX back to jadx/REA → now you have real code → resume the baseline flow.

Full packer-by-packer detail: `docs/china-re-arsenal.md`.

---

## 5. Native signer (any stack — the sign/token function is in a `.so`)

When the request signature (`sign`, `X-Argus`, `X-Gorgon`, `X-Ladon`, custom HMAC) is computed in C/C++:
1. Find the boundary: `chame1eon/jnitrace` → `jnitrace -l libXXX.so <package>` shows which native method the Java calls, with args/returns.
2. REA: `inspect_native_api` / decompile the export via the ghidra provider (`Java_..._sign` or the registered JNI name).
3. Reproduce it as an **oracle** instead of reimplementing C: **zhkl0228/unidbg** emulates the `.so` on the JVM → call the signer with your params, get the signature. Serve it to your Python CLI via **anjia0532/unidbg-boot-server** (HTTP) or this skill's `frida/rpc-signer.js` (Frida RPC, needs a live device).
4. If you must reimplement: hook the crypto with `P4nda0s/CryptoFucker` to print the exact pre-hash string + key, then port to Python and verify byte-for-byte.

Decision table (emulate vs RPC vs reimplement) + real cases: `docs/reverse-case-studies.md`, `docs/android-arsenal.md` §4.

---

## 6. Xamarin / .NET (fingerprint: `assemblies/`, `libmonodroid.so`)

Code is .NET in `assemblies/*.dll` (sometimes compressed/AOT). Extract the DLLs (if compressed, decompress the `assemblies.blob` / use `pyxamstore`), then decompile with `icsharpcode/ILSpy` or `dnSpyEx/dnSpy` — read C# directly. Traffic rides the system stack → MITM / `frida/capture-http.js`.
