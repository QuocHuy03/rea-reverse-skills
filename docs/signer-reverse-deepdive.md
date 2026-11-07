# Signer reverse — deep dive (when the hash isn't the hard part)

Every app signs its requests differently, but they are all the same *shape*:

```
sign(canonical_string, secret, state)  ->  { x-sign: "...", x-ts: "...", ... }
```

**The hash (HMAC-SHA256, MD5, SHA1…) is never the hard part — it's 2 lines of Python.** The hard part is the three *inputs*, and how well the app hides them:

1. **canonical_string** — which fields, in which order, with which separators/salt, get concatenated before hashing.
2. **secret** — a static key, or something derived at runtime.
3. **state** — timestamp, nonce, counter, server-issued token, device fingerprint that the signature also folds in.

So reversing a signer is not "figure out the crypto." It is: **can I read those three inputs at the moment the app computes them?** If yes → reimplement in Python. If no → stop reversing and run the app's own signer as an **oracle**. This doc is the ladder; climb only as far as the app forces you.

> **The one decision that governs everything:** *Can you read the final canonical string + key at runtime?*
> **Yes** → reimplement (fast, portable, scales to many accounts). **No** (white-box / obfuscated / hidden state) → oracle it (unidbg offline or Frida-RPC live). Don't reverse an algorithm you can reproduce as a function.

---

## Rung 0 — See the signed string for free (the 90% case)

You do **not** read decompiled code to guess the field order. You watch what goes *into* the hash. The bytes passed to `Mac.update` / `MessageDigest.update` **are** the canonical string — exact order, exact separators, exact salt, already assembled by the app.

**Run `frida/signer-sniffer.js`**, trigger one signed request, read the `canonical TEXT="..."` line. That is literally what you reimplement. The `key=` line is your HMAC secret. The `signed at:` stack points at the exact method — open it in jadx only to confirm.

Typical output tells you the whole scheme at a glance:
```
[sign] HMAC key set algo=HmacSHA256 key=6b6579... 
[sign] canonical TEXT="GET/api/v2/user?id=42&ts=1730900000&nonce=ab12...appsecret"
[sign] >>> digest=9f86d0818...   (grep this in your capture)
```
Now you know: fields = `method + path + sorted-query + nonce`, separator = none, salt = `appsecret` appended, algo = HMAC-SHA256, key = those bytes. Reimplement, run `scripts/verify-signer.py` → byte-for-byte. Done.

**This is the whole game for REST / e-commerce / most "sign" apps (Type A/B).** If it works, you never leave rung 0.

---

## Rung 1 — The canonical string is built in native (`libXXX.so`)

`signer-sniffer.js`'s Java hooks show nothing, or show a blob that's already hashed. The string is concatenated inside a `.so`. **Same trick, native level:** the sniffer also hooks `EVP_DigestUpdate` / `HMAC_Update` / `SHA256_Update` — the pre-hash bytes stream through there regardless of how obfuscated the code that built them is. Read the `native ... canonical` line.

If even that is empty, the lib uses a **custom/inlined hash** (statically-linked, stripped, or its own SHA impl). Then:
- `chame1eon/jnitrace` → find the JNI boundary (which native method the Java calls, args in / result out).
- Hook that native function directly: `onEnter` dump the input args, `onLeave` dump the returned signature. You still get input↔output pairs without understanding the middle.
- Still blind (OLLVM / string-built-register-by-register)? → you've hit rung 4; oracle it.

---

## Rung 2 — The secret is dynamic, not a static key

The key isn't sitting in `BuildConfig`/`strings.xml`. It's assembled at runtime: concatenated from pieces, XORed with a constant, derived from the package signature (`PackageManager.getPackageInfo().signatures` → hash), or mixed with `deviceId`/time.

**You rarely need to understand the derivation** — read the *final* key bytes at the instant it's used: the sniffer's `key=` line (from `Mac.init`) or native `EVP_*`/`HMAC` key arg already gives you the derived value. Reimplement with that constant.

**You only need the derivation itself if the key changes per request** (keyed by a server token or rotating seed). Then trace the key source back from `SecretKeySpec`/`Mac.init` — set a Frida backtrace on it, walk to where the bytes are born. Often it's `base_secret XOR f(token)` — recoverable once you see two (key, token) pairs.

---

## Rung 3 — The signature is STATEFUL (nonce / counter / sequence)

Send the **same** request body twice → the signature differs. That means a hidden input beyond the body: a timestamp, a monotonically increasing counter, a server-issued nonce from a prior response, or a per-session sequence number. This is the family of `x-gorgon`/`x-khronos`/`x-argus`/`x-ladon` (TikTok/Douyin) and most anti-replay schemes.

**How to pin down the hidden input:** diff several captured signatures against their inputs (`scripts/analyze-capture.py` surfaces the sig headers). Hold the body constant, vary one thing at a time:
- changes every second, same body → **timestamp** is in the canonical string (the sniffer shows where).
- increments by 1 per request → a **counter** (find its field in the sniffer's canonical line; seed it from the app's value and increment yourself).
- unpredictable, tied to the previous response → a **server nonce**; you must echo it, so capture→extract→feed-forward in your client, not reimplement blindly.

If the state is a protobuf blob built in native with device fingerprint (argus-class): reimplementing is research-grade — **oracle it** (rung 4) unless you have a lot of time.

---

## Rung 4 — Native + obfuscated + anti-tamper-bound (the real wall)

The signer `.so` is OLLVM/VMProtect'd (control-flow flattening, opaque predicates), *and* the key is derived from an integrity check — patch the app or attach Frida and the signature silently goes wrong, with no error. You can spend weeks here and lose.

**Don't. Make the `.so` an oracle — you don't need to understand it, only to run it:**
- **unidbg (offline, immune to anti-Frida/anti-debug):** emulate the lib in a JVM, call the signing export with your inputs, get the signature back. The app's device/Frida/root detections never fire because there is no device or process to detect. Template + setup: `skills/reverse-mobile-app/unidbg/UnidbgOracleTemplate.java` and `docs/decryption-playbook.md §2c`.
- **Frida-RPC (live on a real device):** when unidbg can't satisfy the env (missing JNI, syscall quirks), expose the native signer as an `rpc.exports` function on-device and call it from Python — `frida/rpc-signer.js`. Real device = all env checks pass naturally; the trade-off is you need the device online.
- Serve either behind HTTP (`anjia0532/unidbg-boot-server`) so your Python client just POSTs inputs and gets the signature.

The decision table (emulate vs RPC vs reimplement) and real worked cases (argus, SignerPy, instagrapi, gpsoauth) are in `docs/reverse-case-studies.md` and `docs/android-arsenal.md §4`.

---

## Rung 5 — Env-binding / attestation (you can't forge, only reproduce)

The signature is an **RSA/ECC signing with a device-bound private key** (hardware keystore) or includes a **Play Integrity / SafetyNet** token. The private key never leaves the device (sometimes the TEE); SafetyNet-STRONG can't be won client-side.

You cannot forge these. What you *can* do: reproduce exactly what the app itself produces — call the on-device signing op via Frida-RPC (the key stays in the keystore, you just invoke the sign), or, for attestation gates, drive a real untampered device. For *request-body* RSA (app embeds a **public** key) you simply reimplement with that public key. Know the ceiling: if the server demands STRONG hardware attestation, scripting it off-device is out of scope — that's the design working.

---

## Classify your app in 60 seconds

1. Run `signer-sniffer.js`, trigger one signed request.
2. **Canonical TEXT readable in Java?** → Rung 0, reimplement. *(most apps stop here)*
3. **Only native canonical readable?** → Rung 1, reimplement from the native pre-hash bytes.
4. **Key not static?** → Rung 2, read the derived key live (or trace it if per-request).
5. **Same body → different sig?** → Rung 3, find the stateful input by diffing.
6. **Native, obfuscated, breaks when tampered?** → Rung 4, oracle it (unidbg/RPC).
7. **RSA device key / attestation?** → Rung 5, reproduce on-device or accept the ceiling.

## Always verify (every rung)

Reimplement in Python → `python scripts/verify-signer.py cap/requests.ndjson --signer signer.py` must report **PASS** (byte-for-byte) before you wire the signer into `client.py`. A signer that "looks right" but fails verify is wrong — usually field order, a missing/extra param, the wrong secret, or a timestamp/nonce taken from the wrong place.

---

*Tools referenced: `frida/signer-sniffer.js` (this skill), `frida/crypto-dump.js`, `scripts/analyze-capture.py`, `scripts/verify-signer.py`, `unidbg/UnidbgOracleTemplate.java`. Deeper native/oracle material: `docs/decryption-playbook.md`, `docs/reverse-case-studies.md`, `docs/android-arsenal.md`.*
