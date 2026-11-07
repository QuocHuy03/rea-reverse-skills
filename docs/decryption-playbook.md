# Decryption playbook — cracking encrypted bodies/params (incl. the hard native cases)

For when the traffic is captured but the **body/params/response are encrypted**, or the signer encrypts. Goal: recover plaintext offline and reproduce the encrypt/decrypt in your Python CLI (or call it as an oracle). Ordered easy→hard. Self-contained, no links — verify a tool's current flags with `--help`; the procedure is the durable part.

**Golden rule: you don't always need the key — you need the *function*.** If the key can't be extracted (white-box, anti-hook), stop chasing it and run the app's own encrypt/decrypt as an **oracle** (unidbg offline, or Frida-RPC live). That always works because the app must be able to do it.

---

## 0. Triage — WHERE and WHAT

- **Where:** request body, specific params/headers, response body, or local storage? Diff a captured request against the plaintext you'd expect; Base64/hex blob where JSON should be = app-layer crypto *on top of* TLS. (`frida/capture-http.js` gives you the post-TLS bytes — those are still app-encrypted, which is the point.)
- **What (fingerprint the blob):**
  - length a multiple of 16 + looks random → block cipher (AES/DES), likely CBC/ECB.
  - `Base64`/hex wrapper → strip it first.
  - starts with a fixed 12-byte nonce + ends with a 16-byte tag → AES-GCM.
  - a leading version byte / magic → custom framing around the ciphertext.
  - gzip magic `1f 8b` after decrypt → it's compressed-then-encrypted (or vice-versa).
- **Who does it:** grep the decompiled code for `Cipher`, `AES`, `SecretKeySpec`, `IvParameterSpec`, `doFinal`, `EVP_`, or the header/param name → is the crypto in **Java** (easy) or a **`.so`** (hard)?

---

## 1. Java-layer crypto (the easy case) — hook and read

Everything you need (algo + key + IV + plaintext) passes through `javax.crypto` — hook it and read the arguments. **Just run the bundled `frida/crypto-dump.js`** (`frida -U -f <pkg> -l frida/crypto-dump.js --no-pause`) — it hooks the whole stack at once and prints key/IV/mode/plaintext; it also catches native `EVP_*`/`AES_set_*key`. Under the hood it hooks:
- `javax.crypto.Cipher.getInstance(String)` → the **transformation** string = algo/mode/padding (e.g. `AES/CBC/PKCS5Padding`).
- `javax.crypto.spec.SecretKeySpec.$init(byte[], String)` → the **key** (dump `arg0` as hex).
- `javax.crypto.spec.IvParameterSpec.$init(byte[])` → the **IV**.
- `javax.crypto.Cipher.doFinal(byte[])` → hook `onEnter` for ciphertext/plaintext-in, `onLeave`/retval for the result → you see both sides.
- `javax.crypto.Mac` / `java.security.MessageDigest` → for HMAC/hash signers.

Trigger one real encrypted request, read key+IV+mode+padding, then reimplement in Python (`pycryptodome`) and **verify byte-for-byte** against the captured blob. Key often comes from `BuildConfig`, `strings.xml`, `assets/`, or is assembled from pieces — trace `SecretKeySpec`'s argument back.

---

## 2. Native crypto in a `.so` (the hard case) — escalation ladder

The key/IV getter is `native` → the real work is in `libXXX.so`. Climb only as far as you must:

**(a) Find the boundary.** `chame1eon/jnitrace` → `jnitrace -l libXXX.so <package>` shows which native method the Java calls, with args/returns. Note the export name / offset.

**(b) Hook the native function with Frida and dump in/out.** If the lib uses OpenSSL/BoringSSL, the key+IV are visible at the standard exports — hook them:
- `EVP_DecryptInit_ex` / `EVP_EncryptInit_ex` → args carry the cipher, **key**, and **IV** (read them in `onEnter`).
- `EVP_CipherUpdate` / `EVP_DecryptUpdate` → the data buffers (ciphertext↔plaintext).
- If it's a **custom** export (e.g. `Java_com_x_Native_encrypt`), hook that directly: `onEnter` dump the input `byte[]`, `onLeave` dump the output. `Interceptor.attach(Module.findExportByName('libXXX.so','sym'), {...})`. Hook `dlopen`/`android_dlopen_ext` if the lib loads late.
This gives plaintext for the current session even without understanding the algorithm.

**(c) unidbg oracle — the robust route (no device, immune to anti-Frida).** When the function detects Frida, or you want an offline reusable decryptor, **emulate the `.so`** with `zhkl0228/unidbg`:
1. Load the `.so` into a Dalvik VM, run `JNI_OnLoad`, resolve the owning class (unidbg's `Utilities64` example is the template).
2. Call the encrypt/decrypt by export or address: `call_symbol(module, "encrypt", args…)` or `call_function(addr, typed args…)`; pass a captured ciphertext `byte[]` → get the plaintext back. Set breakpoints/traces first if you need to see intermediate state.
3. Wrap it as a service for your CLI: `anjia0532/unidbg-boot-server` (HTTP POST params → signature/plaintext), or this skill's `frida/rpc-signer.js` for a live-device RPC instead.
This is the answer to "mã hoá căng" — it doesn't need the key at all, and anti-Frida/anti-debug inside the app never runs because there's no device/process to detect. **Bundled starting point: `skills/reverse-mobile-app/unidbg/UnidbgOracleTemplate.java`** (+ its README — setup, the 6 placeholders to fill, common failures/fixes).

**(d) Static read when (b)/(c) are blocked.** REA (`inspect_native_api`, ghidra provider decompile of the export) or Ghidra directly → read the algorithm: constant S-boxes/round constants reveal AES/DES/SM4; a hardcoded key array; a custom XOR/rotate transform. Rebuild it in Python from the decompiled logic, then verify.

---

## 3. Really tough ("mã hoá căng") — and the honest ceiling

- **White-box crypto** (key material never exists as plaintext in memory — tables embed it). Hooking `EVP_*`/`doFinal` finds **no key**; static reading finds only lookup tables. **Don't chase the key** — emulate the whole function as an oracle (§2c unidbg / §2b Frida-RPC). Extracting the key from a white-box is a research-grade attack (differential fault/computation analysis), usually not worth it when the oracle works.
- **`.text`-encrypted / section-encrypted `.so`** (DexProtector/Virbox/packers). The code decrypts itself at runtime, so a static dump is garbage. Let it self-decrypt, then **dump the `.so` from memory** (Frida `Process.findModuleByName(...).base` + dump the range, or FRIDA-DEXDump-style), and feed the dumped lib to unidbg/Ghidra. Virbox-style string protection: solve each decrypted string with unidbg (set a breakpoint after the decrypt stub, read the result).
- **Custom/obfuscated transform** (XOR chains, stream cipher, bit tricks). Recover it by **tracing**: Frida Stalker or unidbg instruction trace over one call, watch the bytes transform, reconstruct the operation. Often it's a simple keystream once unrolled.
- **Double-layer (TLS + app-layer).** `frida/capture-http.js` already strips TLS → you hold the app-layer ciphertext → decrypt that per §1/§2.
- **Asymmetric (RSA/ECC).** For *request* encryption the app embeds a **public** key (findable in code/assets) → reimplement with it. For *signature verify* you only need the public key too. You can't forge an RSA private-key signature — but you rarely need to; you reproduce what the app itself produces.
- **Anti-emulation** (the `.so` detects unidbg via `svc`/syscall quirks, `/proc` reads, or missing JNI funcs). Patch the detection in the unidbg environment (stub the syscall/JNI method it probes) or fall back to Frida-RPC on a real device.

---

## 4. Always verify empirically

- **Decrypt:** your Python decrypt of a captured response → **valid JSON/protobuf**. If it's garbage, the mode/IV/key/padding is wrong (common: ECB vs CBC, wrong IV source, PKCS5 vs NoPadding, Base64 vs hex).
- **Encrypt:** your Python encrypt of a known plaintext → **byte-identical** to what the app sent for the same input (control the nonce/IV to make it deterministic). Only then wire it into `client.py`.
- Protobuf after decrypt → get the `.proto` or reconstruct field numbers from the bytes.

Tools referenced live in `docs/android-arsenal.md` (§4 native signer, §5 crypto hook); the native-signer decision table is in `docs/reverse-case-studies.md`.
