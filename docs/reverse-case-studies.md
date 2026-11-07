# Case studies — real reverse-engineering sources & distilled patterns

The open-source projects below are **clients reimplemented from reverse-engineering** the closed APIs of real apps/sites. What you learn here is the **TECHNIQUE** (how requests are signed, device fingerprinting, anti-bot, protobuf, websocket), not "something that works today" — most are pinned to a specific app version and break every time the app updates; a few are archived or DMCA'd. Use them to understand *how people did it*, then apply that to your own target.

> ⚠️ Legal: for reference only, for lawful purposes (interoperability, authorized research, your own app). Many repos violate the original service's ToS — know them so you can avoid them, not to copy blindly.

---

## 1. Social / mobile private-API clients

- davidteather/TikTok-Api — TikTok web wrapper. **technique:** "borrow the signer" — run a real browser (Playwright) so TikTok's own JS signs (X-Bogus/msToken) instead of computing it yourself.
- is-L7N/SignerPy — pure-Python TikTok mobile signer. **technique:** reproduce X-Gorgon/X-Ladon/X-Argus (HMAC/obfuscated hash over request + timestamp) in Python.
- scrapguru/tiktok-argus-androidemu — TikTok mobile signing. **technique:** **emulate the native `libmetasec_ov.so`** (AndroidNativeEmu) to compute X-Argus/X-Ladon/X-Gorgon — no need to reverse the algorithm by hand (pinned to a version).
- carcabot/tiktok-xgnarly-decoded — TikTok web signing. **technique:** reimplement X-Gnarly/X-Bogus (deobfuscated from the web bundle).
- subzeroid/instagrapi — Instagram private API (maintained; formerly adw0rd). **technique:** emulate the mobile app — durable device fingerprint/UUID, `signed_body`, switch Web↔Mobile endpoints to dodge limits, challenge/2FA resolver, export/restore session.
- ping/instagram_private_api — old IG app+web. **technique:** `signed_body`, `rank_token`, device seed (classic, somewhat dated).
- instaloader/instaloader — IG downloader (active). **technique:** reuse a disk-persisted cookie-session + GraphQL `query_hash`, handle rate-limiting.
- d60/twikit — Twitter/X without an API key. **technique:** get a guest-token + internal GraphQL via cookie; export session.
- JustAnotherArchivist/snscrape — Twitter+ scraper. **technique:** guest-token → hidden JSON endpoint.
- dolfies/discord.py-self — Discord self-bot. **technique:** impersonate the official client — `x-super-properties`, spoofed build-number, evade automation detection. (Violates ToS.)
- dolfies/discord-protos — **technique:** reverse the **protobuf** schema of Discord's user-settings.
- tomquirk/linkedin-api — LinkedIn. **technique:** log in for a cookie → call the internal **Voyager** JSON endpoints (taken from data embedded in the page). (Violates ToS.)
- carpedm20/fbchat — Messenger (unmaintained). **technique:** log in like a browser (cookie) + mimic MQTT traffic; cookie-based forks are more realistic.
- madsmtm/sensebook — **doc** of the FB/Messenger MQTT wire-protocol (used as a "spec").

Threads (Meta) — unofficial, break quickly: Danie1/threads-api (archived; borrows instagrapi auth), dmytrostriletskyi/threads-net (web+mobile LSD token), m1guelpf/threads-re (notes-as-code).

## 2. Music / streaming
- librespot-org/librespot — Spotify Connect (Rust, canonical). **technique:** reimplement the full protocol — access-point handshake, Mercury, audio-key exchange, OGG/Vorbis decryption.
- devgianlu/go-librespot — Spotify Connect (Go, full). **technique:** Login5 + dealer **WebSocket** + protobuf (schema in `proto/`).
- hrkfdn/ncspot — ncurses client using librespot (an example of consuming a reversed lib).

## 3. Google / ecosystem auth
- simon-weber/gpsoauth — Google Play Services OAuth (Python). **technique:** Android's **master-token** flow — reproduce the `EncryptedPasswd` RSA signature, then master-token → per-service OAuth token. Has C#/Java/Ruby/C++ ports.

## 4. Unity / IL2CPP
- vfsfitvnm/frida-il2cpp-bridge — Frida module for Unity IL2CPP (active). **technique:** instrument the runtime — dump/trace/hijack IL2CPP classes & methods in a live process, **without** `global-metadata.dat`.
- Perfare/Il2CppDumper — static IL2CPP dumper. **technique:** parse the binary + `global-metadata.dat` into C# structures + scripts for IDA/Ghidra (the static counterpart of the bridge).

## 5. Request-signing / device protocol
- rytilahti/python-miio — Xiaomi miIO/MIoT. **technique:** reverse the binary packets carrying a per-device **token** + an AES handshake; `miiocli cloud` extracts the token from Mi Home.

## 6. Anti-bot token generation (fragile — verify before trusting)
- xvertile/akamai-bmp-generator — generate Akamai **BMP** sensor data (mobile). **technique:** forge the device/behavior telemetry payload the Akamai SDK sends. (Version-pinned, breaks often.)
- NotAnAPI/SensorData.Decryptor — **decrypt** Akamai 2.x sensor-data. **technique:** derive the encryption key from the `bm_sz` cookie to *understand* the payload (not just forge it).

> This group has the most DMCAs/abandonment — study it to understand the technique, don't depend on it.

## 7. WebSocket / realtime
- zerodytrash/TikTok-Live-Connector — TikTok LIVE (Node). **technique:** connect WebCast over WebSocket, decode **protobuf** gifts/comments.
- isaackogan/TikTokLive — Python port. **technique:** handle the **signed WebSocket URL that expires in 30s**, payload compression, protobuf decode.
- tulir/whatsmeow — WhatsApp multi-device (Go). **technique:** full reimplementation — **Noise protocol** handshake, protobuf over WebSocket, Signal E2E.
- WhiskeySockets/Baileys — WhatsApp Web (TS, no browser). **technique:** WebSocket + Noise + protobuf/binary-node (the reference many ports follow).
- sigalor/whatsapp-web-reveng — write-up reversing WA Web (QR pairing, key exchange, message format).
- oxidezap/whatspec — extract the protocol from the WA Web JS bundle into an IR (protobuf/IQ/GraphQL). **technique:** reverse **the whole spec** instead of endpoint by endpoint.

## TLS / fingerprint primitives (used throughout)
- lexiforest/curl_cffi — impersonate TLS/JA3 + HTTP/2(3) in one line via `impersonate=`.
- bogdanfinn/tls-client — Go client that impersonates fingerprints (source of many shared profiles).

---

## 🧙 Heavy techniques ("the wizardry")

### A. Emulate the native `.so` to reproduce signatures — the strongest move for mobile
Instead of reversing the signing algorithm inside the `.so` (usually heavily obfuscated), **load the `.so` straight into an emulator and call the signing function like an oracle** — no phone, no understanding the algorithm, no defeating the obfuscation.
- zhkl0228/unidbg — emulate Android/iOS ARM32/64 `.so` inside the **JVM** + a full JNI API. **How:** `AndroidEmulator` → `VM.loadLibrary(libxxx.so)` → `callJNI_OnLoad` (register natives) → resolve the signing function (by JNI name/symbol) → build the Java arguments in the fake VM → call it, read back the returned String/byte[]. Wrap it in an HTTP endpoint (Spring Boot) → the Python client requests signatures on-demand. **Treat the `.so` as a black-box oracle.**
- qilingframework/qiling — emulate binaries in Python (on top of Unicorn) + OS context (ELF/PE/Mach-O loader, syscalls). Use it when the signing function needs syscalls/filesystem that unidbg doesn't model cleanly.
- unicorn-engine/unicorn — multi-architecture CPU emulator (the lowest-level fallback): map a function's bytes, set registers, `emu_start` over the exact instruction range — when you want to run a single function without JNI/OS scaffolding.
- frida/frida — **native RPC** (instead of emulation): attach to the live app, `rpc.exports` + `NativeFunction` to expose the signing function to the host → the app becomes a "signing server." The device stays in the loop but you avoid reimplementing anything.

### B. Deep Unity / IL2CPP
- Perfare/Il2CppDumper — recover C# metadata from `libil2cpp.so` + `global-metadata.dat`, emit a dummy DLL + IDA/Ghidra scripts.
- Perfare/Zygisk-Il2CppDumper — runtime dump (Zygisk) when the game encrypts `global-metadata.dat` on disk — dump after the game decrypts it in RAM.
- vfsfitvnm/frida-il2cpp-bridge — IL2CPP runtime interop via Frida, no metadata file needed.
- djkaty/Il2CppInspector — replacement/supplement for Il2CppDumper, covers more metadata versions, with clean Ghidra integration.

### C. Trace JNI — find the Java↔native signing boundary
- chame1eon/jnitrace — trace every JNI call the app makes (`RegisterNatives`, `CallXXXMethod`, `GetStringUTFChars`…) to pinpoint **which native function signs** + capture its args/return. The fastest way to find the signing function.
- chame1eon/jnitrace-engine — the `JNIInterceptor.attach` engine to embed into your own Frida script.

### D. Inject Frida-gadget / repackage (no root needed)
- sensepost/objection — `objection patchapk` embeds `frida-gadget.so` into the APK + resigns (auto-adds the INTERNET permission). Weak with split APKs.
- ksg97031/frida-gadget — inject the gadget into an APK/IPA in one command (CI-friendly).
- NickstaDB/patch-apk — wraps objection, handles split/multi-APK.
- ax/apk.sh — all-in-one script to pull/decode/inject/rebuild/sign.

### E. Bypass hardening (cat-and-mouse, verify freshness before use)
- scottyab/rootbeer — a library apps embed to **detect** root (NOT bypass) — know the set of checks (su, BusyBox, test-keys, Magisk paths) so you can hook each one out with Frida.
- KOWX712/PlayIntegrityFix — a maintained PIF fork (passes the BASIC verdict by spoofing build/attestation). ⚠️ The original `chiteroman/PlayIntegrityFix` was **removed from GitHub** — use this fork. Not a root-hider.
- Displax/safetynet-fix — fork extended to Play Integrity. ⚠️ cat-and-mouse.
- Root *hiding* (a different layer from attestation): Shamiko / Zygisk DenyList — mentioned as concepts, no canonical upstream worth linking.

### F. iOS (bonus)
- AloneMonkey/frida-ios-dump — dump a **FairPlay-decrypted** IPA via Frida. ⚠️ broken on Frida 17+, barely maintained — consider `bagbak`.
- KJCracks/Clutch — on-device decrypt (`posix_spawn`) into an IPA (older iOS).
- theos/theos — build system for writing iOS tweaks/hooks (Substrate/Logos).
- nygard/class-dump — reconstruct Obj-C `@interface` headers from a Mach-O (Swift needs other tools).

### G. Protobuf / binary protocol
- marin-m/pbtk — rebuild `.proto` from reflection metadata embedded in a binary (C++/Java/web) + a GUI to edit/fuzz traffic.
- mildsunrise/protobuf-inspector — decode protobuf **without a schema** into a wire-level tree, then annotate it to rebuild the schema incrementally.
- nccgroup/blackboxprotobuf — schema-less encode/decode (PyPI `bbpb`), plugs into Burp/mitmproxy to decode **and re-encode** modified traffic.

### H. Firmware / IoT (bonus)
- ReFirmLabs/binwalk — signature scan + carve the filesystem/kernel; entropy (`-E`) reveals encrypted/compressed regions. The first move.
- onekey-sec/unblob — recursive extraction, more format-accurate than binwalk when containers are nested.
- rampageX/firmware-mod-kit — not just extract but **rebuild/repack** firmware (exotic SquashFS). Helpers: `sasquatch`, `jefferson`, `ubireader`.

---

## 🧭 Decision: emulate the `.so` vs Frida-RPC vs pure rewrite
- **Emulate the native lib (unidbg/Qiling/Unicorn)** when the signing logic lives in an obfuscated `.so`, or you have no device/root. You get an independent signer that scales well (run thousands of accounts server-side, no device) — in exchange you must model enough JNI/OS for the function to run.
- **Frida native-RPC** when you *do* have a device/emulator and want speed: `rpc.exports` + `NativeFunction` turns the live app into a signing oracle in minutes, matching the definition exactly. Downside: each unit of concurrency needs a device, it breaks on app updates/Frida detection, hard to scale.
- **Pure rewrite (read the algorithm → rewrite in Python)** only when the signer is simple/well-understood (e.g. HMAC-SHA256 over sorted params + a static salt pulled from jadx). Fastest & most durable at runtime (no emulator/device) — but a trap if it's heavily obfuscated or has hidden native state.
- **Rule of thumb:** **trace first** (jnitrace / frida-il2cpp-bridge) to find the boundary + see inputs/outputs → try to understand it → if simple, reimplement; if the `.so` is tangled, emulate; if you need it running right now and have a device, Frida-RPC.
- **Hardening is a separate, fragile layer:** bypassing root/Frida/integrity (section E) is cat-and-mouse and often gets pulled from GitHub (e.g. chiteroman's PIF). Pin the right version, expect it to rot, and **prefer emulation** since it sidesteps on-device detection entirely.

---

## Distilled patterns (mapped to lessons)

1. **A signed header = a hash of the request.** X-Gorgon/X-Ladon/X-Argus, IG `signed_body`… = HMAC/obfuscated-hash over (sorted params + body + timestamp + secret/nonce). What to do: find the **secret** + the exact **canonicalization** (field order).
2. **Borrow the signer vs rewrite it** — three escalating tiers: (a) run the real browser/app so it signs itself; (b) **emulate the native `.so`** in a CPU emulator; (c) reimplement the algorithm in pure Python/Go. Trade effort ↔ durability.
3. **Extract the key/algorithm from the native lib.** The real secret lives inside a packed `.so` → get it by decompiling (Ghidra/IDA, Il2CppDumper) or hooking the runtime (Frida) to read the key/output directly.
4. **Durable device fingerprint + register once.** Mint a device-id + UUID (android_id, model, build) once then reuse it — the server ties session/anti-fraud to a stable device (instagrapi, gpsoauth).
5. **Export/restore the session, don't re-login.** Login is the riskiest/most captcha-prone step → serialize the session (cookie/token/device) to disk then restore it (instagrapi, instaloader, twikit).
6. **Guest/cookie token → internal JSON/GraphQL endpoint.** Reversing web: get a guest/cookie token then call the exact endpoint the SPA uses (LinkedIn Voyager, twikit/snscrape).
7. **Impersonate TLS/JA3 + HTTP/2.** Anti-bot inspects both the TLS handshake + HTTP/2 settings → use curl_cffi/tls-client to match a real browser.
8. **Forge anti-bot telemetry.** Akamai/PerimeterX/DataDome wait for a sensor/behavior payload → reproduce it (akamai-bmp-generator) or decrypt it to understand it (SensorData.Decryptor). The most fragile.
9. **Protobuf is the wire format.** Realtime/mobile protocols often serialize protobuf → you must recover the `.proto` (discord-protos, go-librespot, TikTok Live, whatspec) before decoding.
10. **Realtime = WebSocket + a dedicated handshake.** Push/live uses a signed/expiring WebSocket URL (TikTok Live 30s) or a crypto handshake (WhatsApp **Noise**) wrapping protobuf.
11. **Master-token / token-exchange.** One hard-to-get long-lived credential (Google master token via EncryptedPasswd; Xiaomi device token) is exchanged for short-lived per-service tokens.
12. **Extract the whole spec (the meta-move).** The strongest move: parse the JS/native bundle into the **entire protocol surface** (whatspec, sensebook) instead of reversing endpoint by endpoint — turning the reverse into a "living spec."

### Caveats always taught alongside
- Signer/anti-bot repos are version-pinned and break every time the app/vendor updates; many are archived/DMCA'd (pysnap/Snaphax, captcha solvers). Good for learning the **technique**, no guarantee of "works today."
- Ownership is often confused: instagrapi = **subzeroid** (formerly adw0rd); the original fbchat = **carpedm20** (many forks); the canonical frida-il2cpp-bridge = **vfsfitvnm**.
