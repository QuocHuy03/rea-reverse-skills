# Repo & công cụ tham khảo

Danh sách công cụ/repo GitHub thật, đã verify, bổ trợ REA cho từng mảng reverse. REA lo decompile + đọc evidence; các repo dưới lo phần runtime/unpack/deobfuscate/anti-bot mà REA không làm.

## 1. Android — SSL pinning bypass & Frida
- [frida/frida](https://github.com/frida/frida) — engine instrumentation động; mọi script unpin chạy trên nó.
- [sensepost/objection](https://github.com/sensepost/objection) — runtime mobile explorer trên Frida; `android sslpinning disable` 1 lệnh, không cần repackage.
- [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) — bộ script all-in-one tốt nhất hiện nay: redirect proxy, nạp CA, unpin đa thư viện, kèm bypass anti-Frida/anti-root.
- [httptoolkit/frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning) — bản tiền nhiệm Android-only; vẫn là tham khảo tốt các hook pinning.
- [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) — hook BoringSSL `session_verify_cert_chain` cho app **Flutter** (Flutter bỏ qua proxy hệ thống).
- [Impact-I/reFlutter](https://github.com/Impact-I/reFlutter) — patch `libflutter.so` để Flutter đi qua proxy + tin CA của bạn.
- [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) — hướng **no-root**: decode APK, sửa Network Security Config + patch pinning rồi build/sign lại.

> Script kinh điển "Universal Android SSL Pinning Bypass" (pcipolloni) nằm trên [Frida CodeShare](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/), không phải repo riêng — đã bị bộ httptoolkit thay thế.

## 2. Android — tooling
- [skylot/jadx](https://github.com/skylot/jadx) — DEX→Java decompiler + GUI (REA JADX dùng engine này headless).
- [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) — decode/rebuild resource + smali; cần khi patch & repackage.
- [Ch0pin/medusa](https://github.com/Ch0pin/medusa) — framework phân tích động trên Frida, nhiều module hook sẵn.
- [nccgroup/house](https://github.com/nccgroup/house) — runtime analysis web-GUI trên Frida; hook method không cần viết script.
- [nowsecure/r2frida](https://github.com/nowsecure/r2frida) — cầu nối radare2 + Frida, soi/patch memory app đang chạy.
- [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — nền tảng phân tích tĩnh+động APK/IPA, có trace API call.
- [pxb1988/dex2jar](https://github.com/pxb1988/dex2jar) · [google/enjarify](https://github.com/google/enjarify) — DEX→JAR (enjarify khoẻ hơn với DEX obfuscate).
- [google/smali](https://github.com/google/smali) — assembler/disassembler smali/baksmali chuẩn.

## 3. Native (Windows exe/dll, .so)
- [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) — SRE suite + decompiler (REA provider ghidra dùng engine này).
- [mandiant/Ghidrathon](https://github.com/mandiant/Ghidrathon) — thêm Python 3 scripting vào Ghidra.
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — MCP server expose Ghidra cho LLM agent (decompile/rename/analyze) — hợp với luồng Claude Code.
- [AllsafeCyberSecurity/awesome-ghidra](https://github.com/AllsafeCyberSecurity/awesome-ghidra) — index script/plugin Ghidra theo task.
- [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) — debugger user-mode Windows mã nguồn mở (phân tích động/unpack).
- [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) — nhận diện packer/compiler/protector (Themida/VMProtect/UPX…).
- [hasherezade/pe-bear](https://github.com/hasherezade/pe-bear) · [erocarrera/pefile](https://github.com/erocarrera/pefile) — xem/sửa cấu trúc PE (GUI / Python).
- [ergrelet/unlicense](https://github.com/ergrelet/unlicense) — unpack động + rebuild IAT cho Themida/WinLicense 2.x/3.x.
- [angr/angr](https://github.com/angr/angr) — phân tích nhị phân + symbolic execution (deobfuscate, giải check).
- [radareorg/radare2](https://github.com/radareorg/radare2) + [rizinorg/cutter](https://github.com/rizinorg/cutter) — framework RE CLI + GUI (thay thế Ghidra).

> ⚠️ **VMProtect không có unpacker mã nguồn mở nào ổn định/đa phiên bản** — thành thật với user nếu gặp. `unlicense` lo Themida/WinLicense là chính.

## 4. .NET
- [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) — decompiler .NET mã nguồn mở hàng đầu.
- [dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) — bản cộng đồng duy trì của dnSpy: decompile + sửa + debug assembly live. Dùng hằng ngày.
- [de4dot/de4dot](https://github.com/de4dot/de4dot) — deobfuscator/unpacker .NET kinh điển (giải string, dọn control-flow).
- [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) — deobfuscator chuyên Eziriz .NET Reactor.
- [dnSpyEx/dnlib](https://github.com/dnSpyEx/dnlib) — thư viện đọc/ghi metadata .NET (script sửa assembly).

## 5. Electron / JavaScript
- [electron/asar](https://github.com/electron/asar) — CLI list/extract/pack `app.asar`.
- [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) — unpack webpack/browserify ra từng module + reverse obfuscator.io. Pass đầu tiên mạnh nhất.
- [pionxzh/wakaru](https://github.com/pionxzh/wakaru) — "JS decompiler" unminify Terser/Babel/SWC/TS + unpack bundle, có web UI.
- [jehna/humanify](https://github.com/jehna/humanify) — đổi tên biến minified bằng LLM (AST-safe); chạy sau webcrack.
- [relative/synchrony](https://github.com/relative/synchrony) — deobfuscate javascript-obfuscator / obfuscator.io.
- [rarecoil/unwebpack-sourcemap](https://github.com/rarecoil/unwebpack-sourcemap) — dựng lại source tree từ `.map` lộ ra (luôn check sourcemap trước — recover free toàn bộ).

## 6. Web API — anti-bot & TLS fingerprint
- [lexiforest/curl_cffi](https://github.com/lexiforest/curl_cffi) — HTTP client Python impersonate TLS/JA3 + HTTP/2 của browser. Lựa chọn số 1 cho Python.
- [FlorianREGAZ/Python-Tls-Client](https://github.com/FlorianREGAZ/Python-Tls-Client) — wrapper Python trên tls-client, preset JA3/HTTP2.
- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — client TLS-fingerprint bằng Go, nền cho nhiều wrapper.
- [daijro/hrequests](https://github.com/daijro/hrequests) — "requests thay thế", TLS fingerprint + render headless-browser.
- [deedy5/primp](https://github.com/deedy5/primp) — client Python nền Rust, impersonate JA3/JA4/HTTP2.
- [ultrafunkamsterdam/undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) — Selenium ChromeDriver vá né bot-detection.
- [ultrafunkamsterdam/nodriver](https://github.com/ultrafunkamsterdam/nodriver) — kế nhiệm UC dựa CDP, async, stealth hơn.
- [Kaliiiiiiiiii-Vinyzu/patchright-python](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python) — vá Playwright bỏ CDP leak (Runtime.enable…), Chromium-only. (Node: `patchright-nodejs`.)
- [AtuboDad/playwright_stealth](https://github.com/AtuboDad/playwright_stealth) — port stealth sang Playwright-Python (chỉ chống detection cơ bản).
- [daijro/camoufox](https://github.com/daijro/camoufox) — Firefox anti-detect spoof fingerprint (hướng không-Chromium).
- [rebrowser/rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) — vá Puppeteer/Playwright chặn runtime-leak detection.
- [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) — proxy chặn bắt scriptable; viết addon Python capture/replay/sửa traffic.

> Ưu tiên bản đang được duy trì (patchright, nodriver, curl_cffi); `playwright_stealth`/`buster` cập nhật chậm.

## 7. Giải captcha
- [2captcha/2captcha-python](https://github.com/2captcha/2captcha-python) — client Python chính thức 2Captcha (reCAPTCHA, Turnstile, FunCaptcha, GeeTest…).
- [capsolver/capsolver-python](https://github.com/capsolver/capsolver-python) — SDK Python chính thức CapSolver (`pip install capsolver`).
- [QIN2DIM/hcaptcha-challenger](https://github.com/QIN2DIM/hcaptcha-challenger) — giải hCaptcha bằng model ONNX/vision local (không cần dịch vụ trả phí).
- [sarperavci/GoogleRecaptchaBypass](https://github.com/sarperavci/GoogleRecaptchaBypass) — giải reCAPTCHA v2 qua audio-challenge bằng Python (không API trả phí).
- [dessant/buster](https://github.com/dessant/buster) — extension giải reCAPTCHA audio bằng speech-to-text (cập nhật chậm).

> Dịch vụ trả phí (NextCaptcha / 2captcha / CapSolver / EzCaptcha / Capzy): xem [captcha-solvers.md](captcha-solvers.md).

## 8. Học RE / awesome lists
- [tylerha97/awesome-reversing](https://github.com/tylerha97/awesome-reversing) — list RE kinh điển (sách, tool, challenge).
- [alphaSeclab/awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering) — catalog cực lớn đa nền tảng.
- [wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering) — awesome RE được fork nhiều.
- [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida) — script/tool/talk Frida.
- [mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering) — tutorial RE ARM/x86 thực hành theo lộ trình.
- [OWASP/owasp-mastg](https://github.com/OWASP/owasp-mastg) — OWASP Mobile App Security Testing Guide: phương pháp chuẩn test RE/pinning Android/iOS.
