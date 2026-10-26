# Chinese reverse-engineering arsenal (看雪 kanxue / 52pojie 吾爱破解)

The Chinese Android reverse-engineering scene is strongest at **脱壳 (unpacking 加固-hardened apps)** and **reconstructing native signatures**. This is their own distinct toolset/techniques, complementing [references](references.md) and [reverse-case-studies](reverse-case-studies.md).

> `看雪` (bbs.kanxue.com) and `52pojie 吾爱破解` (52pojie.cn) are **forums/CTF communities**, not GitHub orgs — many tools were born in their threads. A few "star" tools (MT管理器, the original 算法助手) **have no public repo** — downloaded from 52pojie, closed-source.
> ⚠️ Legal note, as with every other doc: for lawful purposes only. Many repos target specific Chinese apps, are version-pinned, and break quickly — learn the **technique**, not "run it as-is".

---

## 1. 脱壳 — Unpacking hardened apps (加固: 360加固 / 爱加密 / 梆梆 Bangcle / 腾讯乐固 Legu / 娜迦 Nagain)
The general idea: the packer decrypts the DEX into RAM before running it → **dump the DEX from memory after decryption**.
- [hluwa/FRIDA-DEXDump](https://github.com/hluwa/FRIDA-DEXDump) — scans the heap for the DEX magic (even broken headers) and dumps. The most common "dump after decryption" primitive. (solid, rarely updated)
- [CodingGay/BlackDex](https://github.com/CodingGay/BlackDex) — **unpacks without root/PC**, runs *as an app* on the device, dumps the DEX of installed or not-yet-installed apps. (Android 5–12; somewhat dated on the latest Android)
- [Youlor/Youpk](https://github.com/Youlor/Youpk) — an unpacker based on **ART active-call (主动调用)**: forces every method to run so the runtime restores the CodeItem, then dumps — handles **抽取加固 (method-body stripping)**, exactly the "DEX dumps but the methods are empty" case. (needs a custom ROM, older Android)
- [hanbinglengyue/FART](https://github.com/hanbinglengyue/FART) — a canonical 自动化脱壳 (automated unpacker) via 主动调用 (active-call) + 还原 CodeItem (CodeItem restoration) (patches AOSP). ⚠️ old (2020, Android 6), the author never published the AOSP diff — the community rebuilt it. After dumping it needs a **repair** (FartRepair in [Simp1er/MobileSec](https://github.com/Simp1er/MobileSec)).
- [Mufanc/DexHunter](https://github.com/Mufanc/DexHunter) — a single-binary Rust dumper that scans for DEX in memory (inspired by FRIDA-DEXDump), no attach needed. (modern)
- [CvvT/dumpDex](https://github.com/CvvT/dumpDex) — dumps DEX via IDA Python (when the packing is in the native layer — the counterpart to Frida's native-debugger dump).
- [westinyang/unpacker-panel](https://github.com/westinyang/unpacker-panel) — a 一键 (one-click) web panel for Youpk.

> History (handle with care, mostly dead/DMCA): `zyq8709/DexHunter` (2015, Dalvik), `CheckPointSW/android_unpacker` (2017), `WrBug/dumpDex` (Xposed, ~6y). `ZjDroid`/`drizzleDumper`/`DexExtractor` — the original repos were taken down, only the names are still worth knowing as references.

## 2. 通杀抓包 — Traffic capture + Chinese-style pinning bypass
- [r0ysue/r0capture](https://github.com/r0ysue/r0capture) — **抓包通杀 (universal capture)**: hooks socket read/write at the Java layer (OkHttp/Retrofit/HttpURLConnection/Volley/WebSocket) *above* TLS → pinning becomes irrelevant. The philosophy: "capture plaintext at the API layer, don't fight the cert." (active; Android 7–11, does not run on emulators)
- [firerpa/lamda](https://github.com/firerpa/lamda) — a full-stack **cloud-phone** framework (remote desktop + UI automation + MITM + built-in Frida) for multi-device reverse/automation. (active; formerly `Rev1si0n/lamda`)

## 3. 算法助手 — Hook crypto to reveal the signing mechanism
- **`算法助手 / Xposed算法助手`** — **no public repo** (freeware, distributed via 52pojie). The technique it teaches: auto-hook `Cipher`/`Mac`/`MessageDigest`/`Signature` and print the key, IV, input, output + call stack → immediately reveals how the app signs/encrypts.
- [P4nda0s/CryptoFucker](https://github.com/P4nda0s/CryptoFucker) — an open-source equivalent of 算法助手 (Xposed): intercepts all `javax.crypto.*`/`javax.security.*` to sniff key/IV/plaintext/ciphertext + stack. (last ~2021)

## 4. 微信小程序逆向 — Reverse WeChat Mini-Program (.wxapkg)
- [wux1an/wxapkg](https://github.com/wux1an/wxapkg) — scans + decrypts + unpacks .wxapkg (Go, GUI/CLI). The best available today. (active)
- [qwerty472123/wxappUnpacker](https://github.com/qwerty472123/wxappUnpacker) — the classic original, reconstructs source from wxapkg. ⚠️ **archived 2021** — use a fork.
- [junxiaqiao/unveilr-v2.0.0](https://github.com/junxiaqiao/unveilr-v2.0.0) — a maintained fork of `unveilr` (TS/Node): decrypt + parse + transform wxapkg back to readable source. (upstream `r3x5ur/unveilr` is now 404)
- [BlackTrace/pc_wxapkg_decrypt](https://github.com/BlackTrace/pc_wxapkg_decrypt) — only the **decryption** step for wxapkg on WeChat PC (Go). ⚠️ old (WeChat PC 2.9.5.31), may need patching.

## 5. Chinese-made decompiler / APK tools
- [charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool) — **GDA (GJoy Dex Analysizer)**: a native C++ decompiler for APK/DEX/ODEX/OAT, with **加固识别 (packer identification)**, taint/var tracking, deobfuscation. Fast, offline, Windows — identify the packer *before* choosing the 脱壳 approach. ⚠️ binary-only, Windows, VMP-packed so AV often false-flags it.
- **MT管理器 (MT Manager)** — a closed-source Android app (edit smali/patch on-device). No repo — download from the official site/52pojie.

## 6. 反检测 — Anti-detection (反Frida / 反调试 / anti-emulator / 反root / multi-instance)
- [Prslc/Florida](https://github.com/Prslc/Florida) — a **detection-evading** frida-server (changes symbols/port/thread) to get past 反Frida (port 27042, `/proc/*/maps`, thread names).
- [lico-n/ZygiskFrida](https://github.com/lico-n/ZygiskFrida) — injects the Frida gadget via **Zygisk** (no APK patching, no ptrace), with a startup delay to evade launch-time checks.
- [Exo1i/MagiskHluda](https://github.com/Exo1i/MagiskHluda) — a Magisk module that runs frida-server stealthily at boot (based on StrongR-Frida).
- [talk114/DetectFrida](https://github.com/talk114/DetectFrida) — a sample from the **detection** side — read it to learn what the app checks (named pipes, thread scanning, comparing memory-vs-disk code) → so you know how to bypass it.
- `dzonerzy/fridantiroot` — this is a **Frida CodeShare** (`frida --codeshare dzonerzy/fridantiroot`), not a repo — a snippet to bypass 反root.

## 7. Xposed / LSPosed for reverse engineering
- [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) — a Zygisk-based Xposed framework (LSPlant engine), for loading Java-layer hook modules (the 算法助手 style) on modern Android.
- [JingMatrix/LSPosed](https://github.com/JingMatrix/LSPosed) — the **live community fork** (rebranded "Vector", supports Android 16) now that upstream has slowed down. Includes **LSPatch** (patches dex+so into the APK so Xposed needs no root).

## 8. unidbg & emulating native signatures (Chinese-made)
- [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg) — emulates `.so` ARM32/64 + JNI/syscall (built on Unicorn), **by a Chinese author**. The canonical answer from the Chinese scene for native-layer signing: emulate the `.so`, then call the signing function directly. (active, now with MCP support)
- [anjia0532/unidbg-boot-server](https://github.com/anjia0532/unidbg-boot-server) — unidbg + Spring Boot = a **signing service over HTTP**: a Python client POSTs params → gets a valid signature back. (the correct name is `anjia0532`, not `anjok07`)

## 9. Learning
- [r0ysue/AndroidSecurityStudy](https://github.com/r0ysue/AndroidSecurityStudy) + [r0ysue/r0capture](https://github.com/r0ysue/r0capture) — a Chinese-language Frida/FART learning path (accompanies r0ysue's books/courses).
- [Simp1er/MobileSec](https://github.com/Simp1er/MobileSec) — Android reverse-engineering notes (hook/frida/unicorn) + a set of useful forks (FartRepair, r0tracer, Frida-Seccomp, Wallbreaker, IDAFrida, BlackObfuscator).
- [user1342/Awesome-Android-Reverse-Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering) — an index of Android RE tools (in English).

---

## 脱壳 workflow (the standard Chinese-scene order: unpack → capture traffic → find the signer)
1. **识别壳 (identify the packer)** — inspect the `.so`/assets for 360/爱加密/梆梆/乐固/娜迦 (GDA identifies it automatically). Decide the 脱壳 approach.
2. **脱壳 (dump DEX)** — cheapest first: `FRIDA-DEXDump` / `BlackDex` dump from memory. If methods are **empty** (抽取加固 / method-body stripping) → step up to active-call `FART`/`Youpk` on a patched ROM, then **repair** the dump (FartRepair).
3. **反编译 (decompile)** — load the DEX into `jadx` (or the Chinese-made `GDA`) to read the Java, find the signing/encryption point. (With REA: `rea inspect-android-method` on the unpacked DEX if it is readable.)
4. **抓包 (capture traffic)** — `r0capture` captures the real signed requests (through pinning).
5. **定位签名 (locate the signer)** — hook crypto with `算法助手`/`P4nda0s/CryptoFucker` (Java layer) and/or jnitrace if the signing is in a native `.so`, to obtain the key/IV/algorithm.
6. **模拟还原 (emulate the native signer)** — if signing lives in a `.so` → load it into `zhkl0228/unidbg`, call the signing function directly, expose it via `anjia0532/unidbg-boot-server` so a Python client can request signatures.
   (Throughout: use `LSPosed` + a detection-evading frida-server like `Florida`/`ZygiskFrida` to get past 反Frida/反调试/反root so the hooks can run.)
