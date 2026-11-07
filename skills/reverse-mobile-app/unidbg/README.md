# unidbg oracle — run an app's native crypto/signer offline

`UnidbgOracleTemplate.java` is a **template** for calling an app's native
`encrypt`/`decrypt`/`sign` function from `libXXX.so` **without a device or Frida**
(so anti-frida / anti-debug / root / integrity checks never run). You don't
recover the key — you call the function the app itself uses. This is the robust
answer for the hard crypto cases in `docs/decryption-playbook.md` §2c and the
native-signer path in `docs/android-arsenal.md` §4. unidbg = `zhkl0228/unidbg`.

## Setup (unidbg is a Maven/JVM project — run this as a test inside it)

1. `git clone` the `zhkl0228/unidbg` repo and open it (JDK 8+, Maven). Build once.
2. Drop the target artifacts in, e.g. `unidbg-android/src/test/resources/target/`:
   `adb pull /data/app/.../base.apk` and the `.so` (`.../lib/arm64-v8a/libnative.so`).
   Prefer **arm64** (unidbg's arm64 path is the most reliable; this template is 64-bit).
3. Put `UnidbgOracleTemplate.java` under `unidbg-android/src/test/java/com/rea/unidbg/`.
4. Edit the 6 `<<< EDIT >>>` placeholders, then run its `main()` (or make it a `@Test`).

## Adapt checklist (what to fill in)

| Placeholder | How to get it |
| --- | --- |
| SIGN_CLASS | the owning Java class (slash form) — from REA `inspect_android_method` / the class that declares the `native` method |
| APK_PATH / SO_PATH | `adb pull` the installed `base.apk` + the matching-ABI `.so` |
| setProcessName | the real package name (some libs read `/proc/self/cmdline`) |
| AndroidResolver level | start 23; bump to 26/29 if `JNI_OnLoad` or a syscall needs newer |
| method name + JNI signature | from `chame1eon/jnitrace` (`jnitrace -l libXXX.so <pkg>`) — it prints the exact `name(args)ret` and whether it's static |
| captured blob | a real ciphertext from `frida/fridacap.py` / mitm, base64'd, to prove the oracle returns valid JSON |

## Workflow

1. `jnitrace` the app to find which native method the Java calls + its signature and args.
2. Fill the template, run it on a captured blob → expect valid JSON plaintext (decrypt) or the exact bytes the app sent (encrypt/sign — verify byte-for-byte).
3. Turn it into a service for your Python CLI: wrap `decrypt()`/`sign()` in an HTTP endpoint (`anjia0532/unidbg-boot-server` does this with Spring-Boot), so `client.py` POSTs params and gets the result. Live-device alternative: `frida/rpc-signer.js`.

## Let the AI drive it — unidbg MCP (self-solve a signer autonomously)

Recent `zhkl0228/unidbg` ships an **MCP server** so an AI agent can debug the emulated lib itself instead of you hand-editing the template each round:

- **Breakpoint mode:** set a breakpoint, run; when it fires the emulator pauses and you type `mcp` (or `mcp 9239` to pick a port) in the console → it starts an MCP server. Wire that port into your MCP client (Cursor etc.). The agent then gets tools to read registers/memory, disassemble, single-step, and trace — so it can *walk the signer live* and report how the canonical string is built, with no source reading.
- **Custom-tools mode:** register your own tools via `McpToolkit` (e.g. "sign(url, body, ts)") → the agent can **re-run the target function with different inputs and compare outputs** without restarting the process, set breakpoints/traces before each call, and diff the results. This is exactly the loop for cracking a **stateful** signer (vary ts/counter, watch the output) or confirming which input feeds the hash.

Practical loop for autonomous solving: template loads the lib + `JNI_OnLoad` → breakpoint at the signer entry → `mcp` → the agent traces one call, identifies the pre-hash bytes / key, varies inputs via a custom tool to confirm, then emits the Python reimplementation (or keeps unidbg as the oracle). Pair with `scripts/verify-signer.py` to prove the result byte-for-byte.

## Common failures & fixes

- **`UnsatisfiedLinkError` / method not found** → `JNI_OnLoad` didn't register it, or wrong signature. Keep `vm.setVerbose(true)` and read the printed `RegisterNatives` list; copy the exact signature.
- **`callStaticObjectMethod ... not support` or a crash in a Java callback** → the lib called back into Java (SystemProperties, getPackageInfo, time, a Java crypto helper). Override that callback in `AbstractJni` (the verbose log prints the exact signature to implement) and return what a real device would.
- **Reads a file / `/proc` / asset and aborts** → provide it: `vm.createDalvikVM(apk)` answers package/signature queries; for arbitrary files add a file-system hook or stub the Java getter.
- **Anti-emulation** (lib probes `svc`/syscalls or missing JNI to detect unidbg) → stub the probed syscall/JNI method in the environment, or fall back to Frida-RPC on a real device (`frida/rpc-signer.js`).
- **ARM32-only `.so`** → use the 32-bit builder (`AndroidEmulatorBuilder.for32Bit()`); some old signers are armeabi-v7a only.

This is for lawful analysis (your own apps / authorized research / CTF).
