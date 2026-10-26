# Reference repos & tools

A verified list of real GitHub repos/tools that complement REA for each reverse-engineering area. REA handles decompilation + reading evidence; the repos below handle the runtime/unpacking/deobfuscation/anti-bot work that REA does not.

## 1. Android — SSL pinning bypass & Frida
- [frida/frida](https://github.com/frida/frida) — dynamic instrumentation engine; every unpinning script runs on it.
- [sensepost/objection](https://github.com/sensepost/objection) — a mobile runtime explorer on top of Frida; `android sslpinning disable` in one command, no repackaging needed.
- [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) — the best all-in-one script set available today: proxy redirect, CA injection, multi-library unpinning, plus anti-Frida/anti-root bypass.
- [httptoolkit/frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning) — the Android-only predecessor; still a good reference for pinning hooks.
- [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) — hooks BoringSSL `session_verify_cert_chain` for **Flutter** apps (Flutter ignores the system proxy).
- [Impact-I/reFlutter](https://github.com/Impact-I/reFlutter) — patches `libflutter.so` so Flutter routes through your proxy + trusts your CA.
- [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) — the **no-root** approach: decode the APK, modify the Network Security Config + patch pinning, then rebuild/re-sign.

> The classic "Universal Android SSL Pinning Bypass" script (pcipolloni) lives on [Frida CodeShare](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/), not in a dedicated repo — it has been superseded by the httptoolkit set.

## 2. Android — tooling
- [skylot/jadx](https://github.com/skylot/jadx) — DEX→Java decompiler + GUI (REA JADX runs this engine headless).
- [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) — decode/rebuild resources + smali; needed when patching & repackaging.
- [Ch0pin/medusa](https://github.com/Ch0pin/medusa) — a dynamic analysis framework on Frida with many ready-made hook modules.
- [nccgroup/house](https://github.com/nccgroup/house) — web-GUI runtime analysis on Frida; hook methods without writing a script.
- [nowsecure/r2frida](https://github.com/nowsecure/r2frida) — radare2 + Frida bridge, inspect/patch the memory of a running app.
- [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — a static+dynamic APK/IPA analysis platform with API-call tracing.
- [pxb1988/dex2jar](https://github.com/pxb1988/dex2jar) · [google/enjarify](https://github.com/google/enjarify) — DEX→JAR (enjarify handles obfuscated DEX better).
- [google/smali](https://github.com/google/smali) — the standard smali/baksmali assembler/disassembler.

## 3. Native (Windows exe/dll, .so)
- [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) — SRE suite + decompiler (the REA ghidra provider runs this engine).
- [mandiant/Ghidrathon](https://github.com/mandiant/Ghidrathon) — adds Python 3 scripting to Ghidra.
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — an MCP server that exposes Ghidra to an LLM agent (decompile/rename/analyze) — fits the Claude Code flow.
- [AllsafeCyberSecurity/awesome-ghidra](https://github.com/AllsafeCyberSecurity/awesome-ghidra) — an index of Ghidra scripts/plugins by task.
- [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) — open-source Windows user-mode debugger (dynamic analysis/unpacking).
- [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) — identifies the packer/compiler/protector (Themida/VMProtect/UPX…).
- [hasherezade/pe-bear](https://github.com/hasherezade/pe-bear) · [erocarrera/pefile](https://github.com/erocarrera/pefile) — view/edit PE structures (GUI / Python).
- [ergrelet/unlicense](https://github.com/ergrelet/unlicense) — dynamic unpacking + IAT rebuild for Themida/WinLicense 2.x/3.x.
- [angr/angr](https://github.com/angr/angr) — binary analysis + symbolic execution (deobfuscation, solving checks).
- [radareorg/radare2](https://github.com/radareorg/radare2) + [rizinorg/cutter](https://github.com/rizinorg/cutter) — a CLI + GUI RE framework (a Ghidra alternative).

> ⚠️ **There is no stable, multi-version open-source unpacker for VMProtect** — be honest with the user if you run into it. `unlicense` mainly handles Themida/WinLicense.

## 4. .NET
- [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) — the leading open-source .NET decompiler.
- [dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) — the maintained community build of dnSpy: decompile + edit + debug assemblies live. A daily driver.
- [de4dot/de4dot](https://github.com/de4dot/de4dot) — the classic .NET deobfuscator/unpacker (decrypt strings, clean up control flow).
- [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) — a deobfuscator specialized for Eziriz .NET Reactor.
- [dnSpyEx/dnlib](https://github.com/dnSpyEx/dnlib) — a library to read/write .NET metadata (scripted assembly edits).

## 5. Electron / JavaScript
- [electron/asar](https://github.com/electron/asar) — a CLI to list/extract/pack `app.asar`.
- [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) — unpacks webpack/browserify into individual modules + reverses obfuscator.io. The strongest first pass.
- [pionxzh/wakaru](https://github.com/pionxzh/wakaru) — a "JS decompiler" that unminifies Terser/Babel/SWC/TS + unpacks bundles, with a web UI.
- [jehna/humanify](https://github.com/jehna/humanify) — renames minified variables with an LLM (AST-safe); run it after webcrack.
- [relative/synchrony](https://github.com/relative/synchrony) — deobfuscates javascript-obfuscator / obfuscator.io.
- [rarecoil/unwebpack-sourcemap](https://github.com/rarecoil/unwebpack-sourcemap) — reconstructs the source tree from an exposed `.map` (always check for sourcemaps first — a free full recovery).

## 6. Web API — anti-bot & TLS fingerprint
- [lexiforest/curl_cffi](https://github.com/lexiforest/curl_cffi) — a Python HTTP client that impersonates a browser's TLS/JA3 + HTTP/2. The number-one choice for Python.
- [FlorianREGAZ/Python-Tls-Client](https://github.com/FlorianREGAZ/Python-Tls-Client) — a Python wrapper over tls-client with JA3/HTTP2 presets.
- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — a TLS-fingerprint client in Go, the base for many wrappers.
- [daijro/hrequests](https://github.com/daijro/hrequests) — a "requests replacement" with TLS fingerprinting + headless-browser rendering.
- [deedy5/primp](https://github.com/deedy5/primp) — a Rust-based Python client that impersonates JA3/JA4/HTTP2.
- [ultrafunkamsterdam/undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) — a Selenium ChromeDriver patched to evade bot detection.
- [ultrafunkamsterdam/nodriver](https://github.com/ultrafunkamsterdam/nodriver) — the CDP-based successor to UC, async, stealthier.
- [Kaliiiiiiiiii-Vinyzu/patchright-python](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python) — patches Playwright to remove CDP leaks (Runtime.enable…), Chromium-only. (Node: `patchright-nodejs`.)
- [AtuboDad/playwright_stealth](https://github.com/AtuboDad/playwright_stealth) — a stealth port to Playwright-Python (only basic anti-detection).
- [daijro/camoufox](https://github.com/daijro/camoufox) — an anti-detect Firefox that spoofs the fingerprint (a non-Chromium approach).
- [rebrowser/rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) — patches Puppeteer/Playwright to block runtime-leak detection.
- [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) — a scriptable intercepting proxy; write a Python addon to capture/replay/modify traffic.

> Prefer the maintained options (patchright, nodriver, curl_cffi); `playwright_stealth`/`buster` update slowly.

## 7. Captcha solving
- [2captcha/2captcha-python](https://github.com/2captcha/2captcha-python) — the official 2Captcha Python client (reCAPTCHA, Turnstile, FunCaptcha, GeeTest…).
- [capsolver/capsolver-python](https://github.com/capsolver/capsolver-python) — the official CapSolver Python SDK (`pip install capsolver`).
- [QIN2DIM/hcaptcha-challenger](https://github.com/QIN2DIM/hcaptcha-challenger) — solves hCaptcha with a local ONNX/vision model (no paid service needed).
- [sarperavci/GoogleRecaptchaBypass](https://github.com/sarperavci/GoogleRecaptchaBypass) — solves reCAPTCHA v2 via the audio challenge in Python (no paid API).
- [dessant/buster](https://github.com/dessant/buster) — an extension that solves reCAPTCHA audio via speech-to-text (updates slowly).

> Paid services (NextCaptcha / 2captcha / CapSolver / EzCaptcha / Capzy): see [captcha-solvers.md](captcha-solvers.md).

## 8. Learning RE / awesome lists
- [tylerha97/awesome-reversing](https://github.com/tylerha97/awesome-reversing) — the classic RE list (books, tools, challenges).
- [alphaSeclab/awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering) — a huge multi-platform catalog.
- [wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering) — a heavily forked awesome-RE list.
- [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida) — Frida scripts/tools/talks.
- [mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering) — a hands-on ARM/x86 RE tutorial along a learning path.
- [OWASP/owasp-mastg](https://github.com/OWASP/owasp-mastg) — the OWASP Mobile App Security Testing Guide: the standard methodology for testing RE/pinning on Android/iOS.
