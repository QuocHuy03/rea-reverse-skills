# Chinese reverse-engineering arsenal (看雪 kanxue / 52pojie 吾爱破解)

The Chinese Android reverse-engineering scene is strongest at **脱壳 (unpacking 加固-hardened apps)** and **reconstructing native signatures**. This is their own distinct toolset/techniques, complementing [references](references.md) and [reverse-case-studies](reverse-case-studies.md).

> `看雪` (bbs.kanxue.com) and `52pojie 吾爱破解` (52pojie.cn) are **forums/CTF communities**, not GitHub orgs — many tools were born in their threads. A few "star" tools (MT管理器, the original 算法助手) **have no public repo** — downloaded from 52pojie, closed-source.
> ⚠️ Legal note, as with every other doc: for lawful purposes only. Many repos target specific Chinese apps, are version-pinned, and break quickly — learn the **technique**, not "run it as-is".

---

## 1. 脱壳 — Unpacking hardened apps (加固: 360加固 / 爱加密 / 梆梆 Bangcle / 腾讯乐固 Legu / 娜迦 Nagain)
The general idea: the packer decrypts the DEX into RAM before running it → **dump the DEX from memory after decryption**.
- hluwa/FRIDA-DEXDump — scans the heap for the DEX magic (even broken headers) and dumps. The most common "dump after decryption" primitive. (solid, rarely updated)
- CodingGay/BlackDex — **unpacks without root/PC**, runs *as an app* on the device, dumps the DEX of installed or not-yet-installed apps. (Android 5–12; somewhat dated on the latest Android)
- Youlor/Youpk — an unpacker based on **ART active-call (主动调用)**: forces every method to run so the runtime restores the CodeItem, then dumps — handles **抽取加固 (method-body stripping)**, exactly the "DEX dumps but the methods are empty" case. (needs a custom ROM, older Android)
- hanbinglengyue/FART — a canonical 自动化脱壳 (automated unpacker) via 主动调用 (active-call) + 还原 CodeItem (CodeItem restoration) (patches AOSP). ⚠️ old (2020, Android 6), the author never published the AOSP diff — the community rebuilt it. After dumping it needs a **repair** (FartRepair in Simp1er/MobileSec).
- Mufanc/DexHunter — a single-binary Rust dumper that scans for DEX in memory (inspired by FRIDA-DEXDump), no attach needed. (modern)
- CvvT/dumpDex — dumps DEX via IDA Python (when the packing is in the native layer — the counterpart to Frida's native-debugger dump).
- westinyang/unpacker-panel — a 一键 (one-click) web panel for Youpk.

> History (handle with care, mostly dead/DMCA): `zyq8709/DexHunter` (2015, Dalvik), `CheckPointSW/android_unpacker` (2017), `WrBug/dumpDex` (Xposed, ~6y). `ZjDroid`/`drizzleDumper`/`DexExtractor` — the original repos were taken down, only the names are still worth knowing as references.

## 2. 通杀抓包 — Traffic capture + Chinese-style pinning bypass
- r0ysue/r0capture — **抓包通杀 (universal capture)**: hooks socket read/write at the Java layer (OkHttp/Retrofit/HttpURLConnection/Volley/WebSocket) *above* TLS → pinning becomes irrelevant. The philosophy: "capture plaintext at the API layer, don't fight the cert." (active; Android 7–11, does not run on emulators)
- firerpa/lamda — a full-stack **cloud-phone** framework (remote desktop + UI automation + MITM + built-in Frida) for multi-device reverse/automation. (active; formerly `Rev1si0n/lamda`)

## 3. 算法助手 — Hook crypto to reveal the signing mechanism
- **`算法助手 / Xposed算法助手`** — **no public repo** (freeware, distributed via 52pojie). The technique it teaches: auto-hook `Cipher`/`Mac`/`MessageDigest`/`Signature` and print the key, IV, input, output + call stack → immediately reveals how the app signs/encrypts.
- P4nda0s/CryptoFucker — an open-source equivalent of 算法助手 (Xposed): intercepts all `javax.crypto.*`/`javax.security.*` to sniff key/IV/plaintext/ciphertext + stack. (last ~2021)

## 4. 微信小程序逆向 — Reverse WeChat Mini-Program (.wxapkg)
- wux1an/wxapkg — scans + decrypts + unpacks .wxapkg (Go, GUI/CLI). The best available today. (active)
- qwerty472123/wxappUnpacker — the classic original, reconstructs source from wxapkg. ⚠️ **archived 2021** — use a fork.
- junxiaqiao/unveilr-v2.0.0 — a maintained fork of `unveilr` (TS/Node): decrypt + parse + transform wxapkg back to readable source. (upstream `r3x5ur/unveilr` is now 404)
- BlackTrace/pc_wxapkg_decrypt — only the **decryption** step for wxapkg on WeChat PC (Go). ⚠️ old (WeChat PC 2.9.5.31), may need patching.

## 5. Chinese-made decompiler / APK tools
- charles2gan/GDA-android-reversing-Tool — **GDA (GJoy Dex Analysizer)**: a native C++ decompiler for APK/DEX/ODEX/OAT, with **加固识别 (packer identification)**, taint/var tracking, deobfuscation. Fast, offline, Windows — identify the packer *before* choosing the 脱壳 approach. ⚠️ binary-only, Windows, VMP-packed so AV often false-flags it.
- **MT管理器 (MT Manager)** — a closed-source Android app (edit smali/patch on-device). No repo — download from the official site/52pojie.

## 6. 反检测 — Anti-detection (反Frida / 反调试 / anti-emulator / 反root / multi-instance)
- Prslc/Florida — a **detection-evading** frida-server (changes symbols/port/thread) to get past 反Frida (port 27042, `/proc/*/maps`, thread names).
- lico-n/ZygiskFrida — injects the Frida gadget via **Zygisk** (no APK patching, no ptrace), with a startup delay to evade launch-time checks.
- Exo1i/MagiskHluda — a Magisk module that runs frida-server stealthily at boot (based on StrongR-Frida).
- talk114/DetectFrida — a sample from the **detection** side — read it to learn what the app checks (named pipes, thread scanning, comparing memory-vs-disk code) → so you know how to bypass it.
- `dzonerzy/fridantiroot` — this is a **Frida CodeShare** (`frida --codeshare dzonerzy/fridantiroot`), not a repo — a snippet to bypass 反root.

## 7. Xposed / LSPosed for reverse engineering
- LSPosed/LSPosed — a Zygisk-based Xposed framework (LSPlant engine), for loading Java-layer hook modules (the 算法助手 style) on modern Android.
- JingMatrix/LSPosed — the **live community fork** (rebranded "Vector", supports Android 16) now that upstream has slowed down. Includes **LSPatch** (patches dex+so into the APK so Xposed needs no root).

## 8. unidbg & emulating native signatures (Chinese-made)
- zhkl0228/unidbg — emulates `.so` ARM32/64 + JNI/syscall (built on Unicorn), **by a Chinese author**. The canonical answer from the Chinese scene for native-layer signing: emulate the `.so`, then call the signing function directly. (active, now with MCP support)
- anjia0532/unidbg-boot-server — unidbg + Spring Boot = a **signing service over HTTP**: a Python client POSTs params → gets a valid signature back. (the correct name is `anjia0532`, not `anjok07`)

## 9. Learning
- r0ysue/AndroidSecurityStudy + r0ysue/r0capture — a Chinese-language Frida/FART learning path (accompanies r0ysue's books/courses).
- Simp1er/MobileSec — Android reverse-engineering notes (hook/frida/unicorn) + a set of useful forks (FartRepair, r0tracer, Frida-Seccomp, Wallbreaker, IDAFrida, BlackObfuscator).
- user1342/Awesome-Android-Reverse-Engineering — an index of Android RE tools (in English).

---

## 脱壳 workflow (the standard Chinese-scene order: unpack → capture traffic → find the signer)
1. **识别壳 (identify the packer)** — inspect the `.so`/assets for 360/爱加密/梆梆/乐固/娜迦 (GDA identifies it automatically). Decide the 脱壳 approach.
2. **脱壳 (dump DEX)** — cheapest first: `FRIDA-DEXDump` / `BlackDex` dump from memory. If methods are **empty** (抽取加固 / method-body stripping) → step up to active-call `FART`/`Youpk` on a patched ROM, then **repair** the dump (FartRepair).
3. **反编译 (decompile)** — load the DEX into `jadx` (or the Chinese-made `GDA`) to read the Java, find the signing/encryption point. (With REA: `rea inspect-android-method` on the unpacked DEX if it is readable.)
4. **抓包 (capture traffic)** — `r0capture` captures the real signed requests (through pinning).
5. **定位签名 (locate the signer)** — hook crypto with `算法助手`/`P4nda0s/CryptoFucker` (Java layer) and/or jnitrace if the signing is in a native `.so`, to obtain the key/IV/algorithm.
6. **模拟还原 (emulate the native signer)** — if signing lives in a `.so` → load it into `zhkl0228/unidbg`, call the signing function directly, expose it via `anjia0532/unidbg-boot-server` so a Python client can request signatures.
   (Throughout: use `LSPosed` + a detection-evading frida-server like `Florida`/`ZygiskFrida` to get past 反Frida/反调试/反root so the hooks can run.)

Also for 脱壳: GuoQiang1993/Frida-Apk-Unpack — Frida script hooking `libart.so` `OpenMemory`/`OpenCommon` (Android N+) to grab the in-RAM dex address and export it; full dex for ordinary packers, 指令 dump + patch still needed for method-stripping. (tested only to ~Android 7.1)

---

# PART II — Web / JS 逆向 (爬虫逆向)

PART I is Android-native. But the gate we keep hitting on web/mobile APIs — **风控 (risk control)** like DataDome, 瑞数 (Rushi), 极验 (Geetest), 数美 (ishumei), 易盾 (Yidun) — is **JS-based**, and the Chinese 爬虫逆向 scene has a distinct toolset for it. Core philosophy, in order of preference:
1. **纯算法还原** — read the JS, rewrite the signing/encryption as clean Python/Node. Cleanest, most portable. (what we did for Garena's password algo)
2. **扣代码 (code extraction)** — when the JS is too tangled to rewrite, *extract the exact functions* and run them unchanged in Node, feeding fake inputs. Faster than rewriting; brittle to updates.
3. **补环境 (environment patching)** — when the extracted JS reads hundreds of browser globals (`navigator`, `document`, `window`, canvas/WebGL fingerprints) to resist headless execution, you *supply a fake browser environment* in Node so the JS runs and emits the token/cookie. This is the standard answer to heavy anti-bot JS.

> ⚠️ **Boundary (same as the rest of this repo, stated plainly here because PART II edges into it):** 补环境 / 验证码 tooling is used to drive an **anti-bot gate headlessly** — that is bot-check circumvention. This section documents *what the scene uses and how it's categorized* as reference, the same way PART I catalogs 脱壳 tools. It is not a recipe to defeat a specific site's protection, and building a working DataDome/Geetest bypass is out of scope. Use only where you are authorized (your own property, pentest with scope, CTF).

## 10. 扣代码 + AST 还原 — deobfuscation & restoration
- sml2h3/ast_tools — Babel-based JS **AST restoration** framework with built-in strategies for common obfuscation (string arrays, control-flow flattening, dead code). The de-facto starting point. Forks: kuustudio/ast_tools, 123weizheng/ast_tools. (author's code self-described as "a bit messy", PRs welcome)
- LouisSina/decodeObfuscator / xiajun325/decodeobfuscator — one-click restore specifically for `javascript-obfuscator`-style output. (plugin-based; chokes on extreme cases)
- 2833844911/cy_jsvmp — a **JSVMP** implementation (ES5→custom bytecode + private interpreter, control-flow flattening, constant-pool encryption). Protection-side, but the canonical artifact to study to understand how a jsvmp target is structured before you trace it.

## 11. 补环境框架 — Node environment-patching (the DataDome-class technique)
- Leviathangk/js-sandbox-env-framework — **JS逆向沙箱化补环境框架**: Node `vm` + recursive `Proxy` auto-proxy, environment injection, AI-assisted env completion, CLI proxy monitor, collects a real browser env via DrissionPage. The most feature-complete one; multiple active forks (GrandTofu needs Node 22.8+, lasawang).
- bnmgh1/NodeSandbox — Node 补环境 framework with a **patched `vm` source** to reduce detection points, jsdom wrapped in. (updated 2024)
- LingerInside/sdenv — jsdom-based full browser-env emulation (fork of `pysunday/sdenv`); tuned so **瑞数 (Rushi) VMP** cookies match a real browser after fixing `Math.random` and loading select plugins.
- bnmgh1/node-sandbox — a lighter companion sandbox.

## 12. 验证码 / 风控 — captcha & risk-control (⚠️ boundary section — reference only)
- sml2h3/ddddocr (PyPI) — the famous **offline** universal OCR SDK (sml2h3 + kerlomz): text (`ocr=True`), slider-gap detection (`ocr=False`), object detection (`det=True`). API-wrapped by ddddocr-fastapi / ocr_api_server. (≤ Python 3.12, 64-bit)
- mengpengfei/SliderCracker — pure-JS slider-captcha catalogue (极验2/美团/京东/易盾/数美/…); several platforms' key JS intentionally removed, left to the user.
- bwim0912/ShuMeiSlide — a 补环境 study repo for 数美/极验/易盾 slider + risk control, with a self-made **补环境-detection** tool (useful inverted: shows what checks a sandbox must satisfy).

## 13. AI 辅助逆向 — AI-assisted reverse (the new meta, relevant to this skills repo)
- DiscoverBox/awesome-ai-reverse — curated index of AI-assisted RE: MCP servers, Skills, agents across web/binary/mobile/traffic.
- 715494637/reverse-skill — a Web-JS-reverse **Skill** repo (request-chain location, AST restore, JSVMP, worker, WASM, webpack/runtime, protocol semantics) — same shape as this repo's skills.
- WhiteNightShadow/hello_js_reverse_skill — AI-powered JS-reverse Skill for Claude Code / claude.ai (crypto restore, obfuscation, dynamic cookie, WASM, protocol); plus firefox-reverse (SpiderMonkey-level non-invasive JSVMP/WASM trace) and camoufox-reverse-mcp (anti-detect browser MCP with a `compare_env` fingerprint diff vs Node/jsdom).

---

## Web-JS 逆向 workflow (the standard 爬虫逆向 order)
1. **定位 (locate)** — find the request, then XHR/fetch breakpoint or hook to reach the function that builds the signed param/cookie.
2. **脱混淆 (deobfuscate)** — run the JS through `ast_tools` / `decodeObfuscator` to get readable code; identify jsvmp if present (`cy_jsvmp` structure as reference).
3. **还原 vs 扣代码** — rewrite the algorithm cleanly if small (preferred); otherwise extract the exact functions to run in Node.
4. **补环境 (patch env)** — if the extracted JS needs browser globals, run it under `js-sandbox-env-framework` / `NodeSandbox` / `sdenv`, filling fingerprints until output matches a real browser. *(This is the anti-bot-circumvention step — the boundary above applies.)*
5. **验证 (verify)** — compare the Node-produced token/signature against a real captured one before trusting it, then port into the Python client.

> Mapping to our stack: step 1–3 = exactly how Garena's CryptoJS password algo was reversed into `signer.py` (pure 还原, no env needed). Step 4 is where a **DataDome** gate would sit — and is precisely the step we do **not** automate.

---

# PART III — Unity IL2CPP 手游逆向 (mobile-game reversing)

Most big Chinese mobile games (and AoV / Liên Quân) are **Unity + IL2CPP**: C# is compiled to native `libil2cpp.so`, and the class/method/string names live in `global-metadata.dat`. Reversing one = recover that metadata, map it onto the `.so`, then read/hook the C#. The hardened ones **encrypt or relocate `global-metadata.dat` and `libil2cpp.so`** and decrypt them at runtime (exactly what we observed on LQM: `libmain.so` hooks `il2cpp_init` + `unity_fileaccessor_read`, and there is no plain metadata in the APK).

## 14. IL2CPP metadata dumping
- Perfare/Il2CppDumper — **the canonical static dumper**: reads `libil2cpp.so` + `global-metadata.dat` → DLL stubs (names/signatures, no code bodies) + a `script.json` + IDA/Ghidra scripts + a `il2cpp.h`. Works only when metadata is **plaintext**. Official README states it does **not** handle encrypted metadata (sends you to cracking forums). (中文 README)
- Perfare/Zygisk-Il2CppDumper — **runtime dumper as a Zygisk module** on a rooted device: dumps from the live process so it **ignores `global-metadata.dat` encryption**. The standard answer for protected games.
- qaqql/frida-il2cppdumper — **Frida runtime dumper** (Node.js): defeats most metadata + `il2cpp.so` encryption via **主动调用 (active-call)**, so even decrypt-on-run packers dump. (author: not recommended on emulators)
- **frida-il2cpp-bridge** (vfsfitvnm; verify current repo) — not a one-shot dumper but a **runtime IL2CPP interop framework** for Frida: enumerate classes, read fields, call/hook C# methods live. The go-to for dynamic work once you have the metadata. Il2CppInspector (djkaty) is the richer English-scene static alternative to Il2CppDumper.
- Game-specific forks worth reading for technique: hengle/il2cppdumper-gi, Macrohard-X/Il2CppDumper.
- Defense POV (to understand what you're up against): NetEase Yidun — how to harden IL2CPP (protecting metadata + `libil2cpp.so`).

## 15. Lua layer — xLua / LuaJIT decompile
Many CN Unity games put gameplay/hotfix logic in **Lua** (LQM ships `libxlua.so`). The Lua source is compiled to bytecode and often encrypted; once decrypted, decompile it:
- Jeong-Min-Cho/unluac — unluac fork that **natively handles xLua's modified Lua 5.3 bytecode** (xLua = Tencent's Lua 5.3 bridge for Unity). Fix the header, map int/float constant tags, decompile.
- **ljd** (NightNord/ljd, fix fork `zzwlpx/ljd`) — the classic **LuaJIT** decompiler (good readability, patchy compatibility). bobsayshilol/luajit-decomp — `luajit -bl` → bytecode list → parse.
- unluac-rs — Rust multi-dialect (Lua 5.1–5.5, LuaJIT 2.1, Luau), still beta.

## 16. ⚠️ Anti-cheat (TGPA / ACE / TenProtect) — the gate, out of scope here
To attach Frida / run the runtime dumpers above against a protected game you must get past the game's **anti-cheat** (Tencent `libtgpa.so`/ACE, `libwukong.so`, emulator+root+Frida detection). **This repo does not document anti-cheat bypass** — that's the cheating/circumvention line, and we hold it (our LQM emulator ban came from exactly this layer). Research the dumpers on **your own Unity builds** or unprotected targets; against a live protected game, bypassing ACE to dump is out of scope.

---

## IL2CPP 手游 workflow (Chinese-scene order)
1. **取 metadata + so** — pull `libil2cpp.so` + `global-metadata.dat` from the APK/splits or the app data dir.
2. **plaintext?** → `Il2CppDumper` static dump → DLL stubs + IDA/Ghidra script. Done.
3. **encrypted / relocated?** (our LQM case) → runtime dump with `Zygisk-Il2CppDumper` or `frida-il2cppdumper` on a **rooted real device** (not emulator) — after `il2cpp_init`, metadata is decrypted in RAM.  *(Requires getting past anti-cheat — §16 boundary.)*
4. **load** the dump into Ghidra/IDA (apply `script.json` + `il2cpp.h`) → readable C# classes/methods.
5. **Lua logic** → extract `*.lua`/`*.bytes`, decrypt, decompile with the xLua `unluac` fork / `ljd`.
6. **dynamic** → `frida-il2cpp-bridge` to hook C# methods, observe params, trace the real logic.

> Mapping to LQM: step 1 showed the pulled splits have **no** plain `libil2cpp.so`/`global-metadata.dat` (`libmain.so` hooks `il2cpp_init`/`unity_fileaccessor_read` → decrypt-on-read). So only step 3 (runtime dump on a real device) would work — and it runs straight into ACE (§16). The in-match transport is ENet UDP (`libaovnet.so`), separate from the HTTP auth we already reversed.

---

# Appendix — 手机端一条龙 (on-device apps) + the standard SOP

A distinctive part of the Chinese scene: the whole loop — decompile → patch smali → recompile → re-sign — runs **on the phone itself**, no PC. These are closed-source apps (from 52pojie / official sites, not GitHub), so treat downloads with care.

## 17. On-device all-in-one apps (手机端工具)
- **MT管理器 (MT Manager)** — the canonical on-device **逆向工作站**: DEX ↔ Smali decompile/recompile, APK edit + repackage + re-sign, resource/AndroidManifest edit, string search, diff/patch, 超级混淆. Some advanced features are VIP. The tool every Chinese tutorial assumes.
- **NP管理器 (NP Manager)** (githubXiaowangzi/NP-Manager) — a free MT-alike: Dex edit, Smali highlight, Smali↔Dex/Jar conversion, **APK 加固判断 (packer identification)**, batch class deletion, multiple signature schemes. Commonly used to replace MT's VIP-only functions. (actively versioned; v3.1.4x, 2024)
- **HttpCanary (抓包) / lamda** — on-device HTTPS capture; firerpa/lamda (§2) is the cloud-phone framework that packages capture + Frida + automation for running this loop at scale.
- *(Memory editors like GameGuardian exist for games but are cheat-oriented — outside this repo's scope.)*

## The standard 方法思路 (general app-reverse SOP, the "一条龙")
The routine every CN tutorial converges on (canonical teaching example: the `豆瓣_sig` signature case):
1. **环境 + 抓包配置** — emulator/real device + proxy; for apps that ignore the system proxy, force traffic with SocksDroid / iptables.
2. **抓包定位接口** — capture to identify the endpoint and which params are encrypted/signed (`sign`, `token`, `ts`, `nonce`…).
3. **静态分析** — JADX for the Java layer, IDA/Ghidra for `.so`; (REA: `inspect_android_method` / `analyze`).
4. **全局搜索** — grep the param name / crypto call to locate where the signature is built.
5. **Hook 验证** — Frida-hook that function to confirm inputs→output (算法助手 / CryptoFucker for the crypto primitives).
6. **Python 复现 + 验证** — reimplement the algorithm, recompute a captured request's signature, and **require an exact match** before trusting it.

> This is exactly the loop this repo's skills automate — and the loop we ran on Garena: capture (step 2) → JADX/SSO-JS (step 3–4) → confirm the CryptoJS transform (step 5) → `signer.py` reproduces it (step 6). The only step we refuse is when step 1/2 sits behind an anti-bot or anti-cheat gate (DataDome, ACE) — see the boundary notes in PART II §12 and PART III §16.

## 18. The device layer — emulators / 免root 虚拟框架 / 云手机 (where you run the target)
Reversing needs a controllable device to run the app in. The Chinese scene uses three tiers, escalating as the target's anti-detection gets stronger:

**(a) PC emulators** — `LDPlayer 雷电`, `MuMu 网易`, `Nox 夜神`, `MEmu 逍遥`, BlueStacks. x86_64 + Houdini for ARM `.so` translation; pre-rooted, Frida-ready, easy. **But detectable**: x86 arch, known libc/kernel, GPU/driver fingerprints → games with anti-cheat ban them (our LQM/ACE emulator ban). See CacheEmulatorChecker / anti-bluestacks for *how* they're spotted (simplest: ARM-vs-x86 check).

**(b) 免root 虚拟框架 (app-virtualization containers)** — run the target app *inside another app you control*, hooking **without rooting the phone**:
- asLody/VirtualApp — the Virtual Engine: 免root Java+Native hook, silent install, ptrace-debug the inner process, built-in Xposed. The foundation of the genre. (business ver → Android 14; non-commercial license on the open one)
- android-hacker/VirtualXposed — VirtualApp + epic → Xposed modules with no root (Android 5–10; can't modify system, no resource hook).
- **太极 TaiChi** — 免root/root Xposed via repackage/virtualization (closed source, from its site).
- LSPosed/LSPatch — different approach: repackage the APK, inject dex+so so Xposed runs root-free (needs a PC to patch).

**(c) 云手机 (cloud phones) — real ARM** — real ARM hardware in the cloud, so emulator checks (ARM/x86, libc/kernel, GPU) pass. The escalation for games that ban emulators: `Redfinger`, Huawei `CPH`, or self-hosted firerpa/lamda (§2) with Frida + MITM + automation built in.

> ⚠️ Boundary: these are the substrate for *running* a target to analyze it. Using them specifically to **defeat an anti-cheat and cheat in a live game** is out of scope (PART III §16). For LQM: the emulator (a) got ACE-banned; the scene's answer is a hidden-Magisk **real ARM device** or an ARM **cloud phone** (c) to even run the game for a runtime IL2CPP dump — which still has to get past ACE, the step we do not cover.
