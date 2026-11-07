# Hard sign types — concrete playbooks

`signer-reverse-deepdive.md` gives the ladder; this is rungs 3–5 made concrete. Each hard signer is a *named pattern* with a specific blocker and a specific move. When `signer-sniffer.js` at rung 0 gives you a clean canonical string, you're not here — you reimplement and leave. You're here when the string is hidden, the key isn't real, or the signature carries state.

**The invariant for every hard type below:** you stop trying to *understand* the algorithm and instead *run the app's own function* as an oracle — because the app must be able to compute the signature, so can you, by calling the same code. The only question is *offline* (unidbg) vs *on a live device* (Frida-RPC).

---

## A. Native protobuf device-signer — `x-argus` / `x-gorgon` / `x-ladon` / Shield / Ladon class

**What it is.** TikTok/Douyin and many Chinese SDKs (ByteDance ttEncrypt/Ladon, "Shield"). The header is **not** `HMAC(string)`. It's a **protobuf** assembled in native: `{ app id, device fingerprint, timestamp, URL hash, body hash, a per-session sequence counter }` → encrypted (SM4/AES/custom) → base64. HMAC-SHA256 isn't even in the picture.

**Blockers.** (1) It needs an **init/register** call that runs once at startup and seeds the device info + counter; (2) the signature is **stateful** — a counter increments every call, so the same request signs differently each time; (3) the inputs are **several** (`url`, `body/query`, `timestamp`), not one string; (4) it's native and usually obfuscated.

**Move.**
1. `jnitrace -l libXXX.so <pkg>` → find the JNI method, its exact arg list and return. You'll see something like `Argus.encrypt(int keyver, String url, byte[] data, long ts)` and, earlier, a one-time `Ladon.init(...)` / SDK `register`.
2. **Oracle it, controlling the state yourself:**
   - **unidbg (offline):** load the lib, call `JNI_OnLoad`, call the **init/register once**, then call the signer per request — you set the counter/timestamp explicitly so output is reproducible. This is exactly what `is-L7N/SignerPy` and `scrapguru/tiktok-argus-androidemu` do; use `unidbg/UnidbgOracleTemplate.java` as the base and add the init call + multi-arg signature.
   - **Frida-RPC (live):** `rpc-signer.js` → call `init()` once, then `signNative(...)` per request; the on-device SDK keeps the counter for you. Simpler to stand up, needs the device online.
3. **Verify across MANY requests** with `scripts/verify-signer.py` — a single match can hide a wrong counter; several in a row proves the state handling.

---

## B. OLLVM / VMProtect obfuscated native (control-flow flattening + string encryption)

**What it is.** The sign `.so` is flattened into one giant dispatch loop with opaque predicates; strings are decrypted only at the moment of use. Static reading in Ghidra is near-useless.

**Blockers.** You can't follow the control flow to see how the canonical string is built, and you can't grep the constants (they're encrypted).

**Move.** **Don't deobfuscate.**
- **Preferred — oracle it** (unidbg/RPC). Obfuscation protects the *code*; it does nothing against *running* the code with your inputs.
- **If you truly must reimplement in pure Python** (no device at runtime): trace **one** call — unidbg `emulator.getBackend().traceCode()` or Frida **Stalker** over the single signing invocation — and watch the data transform. Control-flow flattening hides the *shape*, but the *data-flow* is often a plain keystream or standard hash once unrolled. For the strings: set a breakpoint right after each decrypt stub and read the plaintext string out of the register/buffer (same trick beats Virbox/whitebox string protection).

---

## C. White-box crypto signer (the key never exists in memory)

**What it is.** The AES/SM4 key is baked into lookup tables; the cipher runs as table lookups. Hooking `EVP_*` / `Cipher.doFinal` / `Mac` shows **no key** — because there isn't one in the usual sense.

**Blockers.** There is nothing to steal: no `SecretKeySpec`, no key arg, no key in `.rodata` you can use directly.

**Move.** **Oracle only** (unidbg/RPC) — the oracle reproduces the function perfectly without ever naming the key. Extracting the key from a white-box is a **research-grade attack** (differential fault analysis / differential computation analysis); skip it unless breaking the white-box *is* the job. 99% of the time the oracle is the answer and the key is irrelevant.

---

## D. Anti-tamper-bound key (key = f(APK signature / dex CRC / integrity verdict))

**What it is.** The signing key (or a salt) is **derived from the environment**: the APK signing-certificate hash, a DEX/so CRC, or a Play Integrity verdict. The design assumption: a tampered or instrumented app yields a *different* environment value → a *wrong* key.

**Blockers.** This is the nastiest to diagnose because it **fails silently**: your canonical string matches, your algo matches, but the digest differs and the server just says "invalid signature" with no crash and no hook firing. Running under Frida, a re-signed APK, or an emulator all trip it.

**Move.**
1. **Diagnose it:** with `signer-sniffer.js` you confirm canonical + algo are identical to the real app, yet the output digest differs → the key/salt is environment-derived. That mismatch *is* the fingerprint of this type.
2. **unidbg — feed the REAL environment:** unidbg answers `getPackageInfo().signatures`, package name, `SystemProperties` from the artifacts you load — **load the ORIGINAL untampered APK** so the cert hash matches, and override the integrity/`SystemProperties` callbacks to return real-device values (`vm.setVerbose(true)` prints exactly which ones the lib queries). The derived key then comes out correct.
3. **Or read the finalized key on a clean path:** on an **untampered** device with a stealthy setup (`anti-detect.js` + renamed frida-server on a non-default port), hook the point *after* the integrity mix where the key is finalized → you capture the correct key bytes, then reimplement in Python. The art is hooking late enough to be past the integrity derivation but before the hash.

---

## E. Attestation / device-keystore signing (TEE RSA/ECDSA, Play Integrity / DroidGuard)

**What it is.** The signature is produced by a **hardware-backed keystore** key whose private half never leaves the TEE, or the request is gated by a **Play Integrity / DroidGuard** token.

**Blockers.** You cannot extract the private key or forge the token. Hardware **STRONG** attestation is unforgeable off-device *by design* — this is the security model working, not a bug to route around.

**Move — reproduce, don't forge.**
- **Keystore signing:** Frida-RPC the signing call on a **real device** — the TEE performs the operation, you just invoke it with your data (`rpc-signer.js`, point it at the keystore-signing method). The key stays in the TEE; you get valid signatures.
- **Play Integrity / DroidGuard token:** must originate from a **real, certified device**; the token is server-validated and droidguard runs are attested. Automation means a real device in the loop or accepting the ceiling.
- **Request-body RSA with an embedded PUBLIC key** (common and *easy* — don't confuse it with the above): just reimplement with that public key in Python, no device needed.

---

## Decide fast (symptom → family → move)

| Symptom | Family | Move |
|---|---|---|
| sniffer shows a clean canonical string + key | *(rung 0, not hard)* | reimplement in Python |
| header is a base64 protobuf blob; same body → different header every call | **A** argus/ladon | unidbg/RPC oracle, call init once, control the counter |
| sign `.so` is a flattened switch, strings encrypted | **B** OLLVM/VMP | oracle; or Stalker/unidbg-trace one call to unroll |
| `EVP_*`/`doFinal`/`Mac` hooks show no key at all | **C** white-box | oracle only; don't chase the key |
| canonical + algo match the app, but digest differs & server rejects, no crash | **D** anti-tamper key | unidbg with the ORIGINAL apk + real env; or hook the finalized key on a clean device |
| signature from `AndroidKeyStore`/TEE, or an Integrity token header | **E** attestation | RPC the keystore op on a real device; Integrity needs a real device |

## Tools for the hard path

`chame1eon/jnitrace` (find the native boundary + args) → `frida/signer-sniffer.js` native mode (pre-hash bytes even when obfuscated) → `unidbg/UnidbgOracleTemplate.java` (offline oracle, immune to anti-Frida) or `frida/rpc-signer.js` with `init()` + native call (live oracle) → `scripts/verify-signer.py` (run several requests — the only way to catch a stateful counter bug). Deeper native/emulation notes: `docs/decryption-playbook.md §2`, real worked cases in `docs/reverse-case-studies.md`.
