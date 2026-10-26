# Case studies — source reverse thật & pattern chắt lọc

Các project mã nguồn mở dưới đây là **client dựng lại từ việc reverse** API đóng của app/site thật. Học ở đây là **KỸ THUẬT** (cách ký request, device fingerprint, anti-bot, protobuf, websocket), không phải để "chạy được hôm nay" — phần lớn pin theo version app và vỡ mỗi lần app cập nhật; vài cái đã archive hoặc bị DMCA. Dùng để hiểu *cách người ta làm*, rồi áp vào mục tiêu của bạn.

> ⚠️ Pháp lý: chỉ tham khảo cho mục đích hợp pháp (interoperability, nghiên cứu được uỷ quyền, app của chính bạn). Nhiều repo vi phạm ToS của dịch vụ gốc — biết để tránh, không phải để copy mù.

---

## 1. Social / mobile private-API clients

- [davidteather/TikTok-Api](https://github.com/davidteather/TikTok-Api) — wrapper web TikTok. **Kỹ thuật:** "mượn signer" — chạy browser thật (Playwright) để chính JS của TikTok ký (X-Bogus/msToken) thay vì tự tính.
- [is-L7N/SignerPy](https://github.com/is-L7N/SignerPy) — TikTok mobile signer thuần Python. **Kỹ thuật:** tái tạo X-Gorgon/X-Ladon/X-Argus (HMAC/hash obfuscate trên request + timestamp) bằng Python.
- [scrapguru/tiktok-argus-androidemu](https://github.com/scrapguru/tiktok-argus-androidemu) — TikTok mobile signing. **Kỹ thuật:** **emulate native `libmetasec_ov.so`** (AndroidNativeEmu) để tính X-Argus/X-Ladon/X-Gorgon — khỏi reverse thuật toán bằng tay (pin theo version).
- [carcabot/tiktok-xgnarly-decoded](https://github.com/carcabot/tiktok-xgnarly-decoded) — TikTok web signing. **Kỹ thuật:** reimplement X-Gnarly/X-Bogus (deobfuscate từ bundle web).
- [subzeroid/instagrapi](https://github.com/subzeroid/instagrapi) — Instagram private API (duy trì; trước là adw0rd). **Kỹ thuật:** giả lập app mobile — device fingerprint/UUID bền, `signed_body`, đổi endpoint Web↔Mobile né limit, resolver challenge/2FA, export/restore session.
- [ping/instagram_private_api](https://github.com/ping/instagram_private_api) — IG app+web cũ. **Kỹ thuật:** `signed_body`, `rank_token`, seed device (kinh điển, hơi cũ).
- [instaloader/instaloader](https://github.com/instaloader/instaloader) — downloader IG (active). **Kỹ thuật:** reuse cookie-session lưu đĩa + GraphQL `query_hash`, xử rate-limit.
- [d60/twikit](https://github.com/d60/twikit) — Twitter/X không cần API key. **Kỹ thuật:** lấy guest-token + GraphQL nội bộ qua cookie; export session.
- [JustAnotherArchivist/snscrape](https://github.com/JustAnotherArchivist/snscrape) — scraper Twitter+. **Kỹ thuật:** guest-token → JSON endpoint ngầm.
- [dolfies/discord.py-self](https://github.com/dolfies/discord.py-self) — Discord self-bot. **Kỹ thuật:** giả client chính chủ — `x-super-properties`, spoof build-number, tránh detect automation. (Vi phạm ToS.)
- [dolfies/discord-protos](https://github.com/dolfies/discord-protos) — **Kỹ thuật:** reverse schema **protobuf** user-settings của Discord.
- [tomquirk/linkedin-api](https://github.com/tomquirk/linkedin-api) — LinkedIn. **Kỹ thuật:** login lấy cookie → gọi endpoint **Voyager** JSON nội bộ (lấy từ data nhúng trong trang). (Vi phạm ToS.)
- [carpedm20/fbchat](https://github.com/carpedm20/fbchat) — Messenger (không duy trì). **Kỹ thuật:** login như browser (cookie) + mimic traffic MQTT; fork cookie-based thực tế hơn.
- [madsmtm/sensebook](https://github.com/madsmtm/sensebook) — **doc** wire-protocol/MQTT của FB/Messenger (dùng như "spec").

Threads (Meta) — unofficial, vỡ nhanh: [Danie1/threads-api](https://github.com/Danie1/threads-api) (archived; mượn auth instagrapi), [dmytrostriletskyi/threads-net](https://github.com/dmytrostriletskyi/threads-net) (LSD token web+mobile), [m1guelpf/threads-re](https://github.com/m1guelpf/threads-re) (notes-as-code).

## 2. Music / streaming
- [librespot-org/librespot](https://github.com/librespot-org/librespot) — Spotify Connect (Rust, canonical). **Kỹ thuật:** reimplement full protocol — handshake access-point, Mercury, trao đổi audio-key, giải mã OGG/Vorbis.
- [devgianlu/go-librespot](https://github.com/devgianlu/go-librespot) — Spotify Connect (Go, full). **Kỹ thuật:** Login5 + dealer **WebSocket** + protobuf (schema trong `proto/`).
- [hrkfdn/ncspot](https://github.com/hrkfdn/ncspot) — client ncurses dùng librespot (ví dụ consume lib reversed).

## 3. Google / ecosystem auth
- [simon-weber/gpsoauth](https://github.com/simon-weber/gpsoauth) — Google Play Services OAuth (Python). **Kỹ thuật:** luồng **master-token** của Android — tái tạo chữ ký RSA `EncryptedPasswd`, rồi master-token → per-service OAuth token. Có port C#/Java/Ruby/C++.

## 4. Unity / IL2CPP
- [vfsfitvnm/frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) — module Frida cho Unity IL2CPP (active). **Kỹ thuật:** instrument runtime — dump/trace/hijack class & method IL2CPP trên process sống, **không cần** `global-metadata.dat`.
- [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) — dumper IL2CPP tĩnh. **Kỹ thuật:** parse binary + `global-metadata.dat` ra cấu trúc C# + script cho IDA/Ghidra (đối trọng tĩnh của bridge).

## 5. Request-signing / device protocol
- [rytilahti/python-miio](https://github.com/rytilahti/python-miio) — Xiaomi miIO/MIoT. **Kỹ thuật:** reverse gói nhị phân có **token** per-device + handshake AES; `miiocli cloud` rút token từ Mi Home.

## 6. Anti-bot token gen (mong manh — verify trước khi tin)
- [xvertile/akamai-bmp-generator](https://github.com/xvertile/akamai-bmp-generator) — sinh sensor data Akamai **BMP** (mobile). **Kỹ thuật:** giả payload telemetry device/behavior SDK Akamai gửi. (Pin version, vỡ thường xuyên.)
- [NotAnAPI/SensorData.Decryptor](https://github.com/NotAnAPI/SensorData.Decryptor) — **giải mã** sensor-data Akamai 2.x. **Kỹ thuật:** suy key mã hoá từ cookie `bm_sz` để *hiểu* payload (không chỉ giả).

> Nhóm này DMCA/bỏ hoang nhiều nhất — xem để hiểu kỹ thuật, đừng phụ thuộc.

## 7. WebSocket / realtime
- [zerodytrash/TikTok-Live-Connector](https://github.com/zerodytrash/TikTok-Live-Connector) — TikTok LIVE (Node). **Kỹ thuật:** nối WebCast qua WebSocket, decode **protobuf** gift/comment.
- [isaackogan/TikTokLive](https://github.com/isaackogan/TikTokLive) — port Python. **Kỹ thuật:** xử **URL WebSocket có ký + hết hạn 30s**, nén payload, decode protobuf.
- [tulir/whatsmeow](https://github.com/tulir/whatsmeow) — WhatsApp multi-device (Go). **Kỹ thuật:** reimplement full — handshake **Noise protocol**, protobuf trên WebSocket, E2E Signal.
- [WhiskeySockets/Baileys](https://github.com/WhiskeySockets/Baileys) — WhatsApp Web (TS, không browser). **Kỹ thuật:** WebSocket + Noise + protobuf/binary-node (bản tham chiếu nhiều project port theo).
- [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) — write-up reverse WA Web (QR pairing, key exchange, format message).
- [oxidezap/whatspec](https://github.com/oxidezap/whatspec) — trích protocol từ bundle JS WA Web ra IR (protobuf/IQ/GraphQL). **Kỹ thuật:** reverse **cả spec** thay vì từng endpoint.

## TLS / fingerprint primitives (dùng xuyên suốt)
- [lexiforest/curl_cffi](https://github.com/lexiforest/curl_cffi) — impersonate TLS/JA3 + HTTP/2(3) 1 dòng `impersonate=`.
- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — client Go impersonate fingerprint (nguồn nhiều profile dùng chung).

---

## 🧙 Kỹ thuật nặng ("pháp sư")

### A. Emulate native `.so` để tái tạo chữ ký — đòn mạnh nhất cho mobile
Thay vì reverse thuật toán ký trong `.so` (thường obfuscate nặng), **nạp thẳng `.so` vào emulator rồi gọi hàm ký như một oracle** — không cần điện thoại, không cần hiểu thuật toán, không cần phá obfuscate.
- [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg) — emulate `.so` Android/iOS ARM32/64 trong **JVM** + API JNI đầy đủ. **Cách làm:** `AndroidEmulator` → `VM.loadLibrary(libxxx.so)` → `callJNI_OnLoad` (đăng ký native) → resolve hàm ký (theo tên JNI/symbol) → dựng tham số Java trong VM giả → gọi, đọc String/byte[] trả về. Bọc trong HTTP endpoint (Spring Boot) → client Python xin chữ ký on-demand. **Treat `.so` như hộp đen oracle.**
- [qilingframework/qiling](https://github.com/qilingframework/qiling) — emulate binary bằng Python (trên Unicorn) + ngữ cảnh OS (loader ELF/PE/Mach-O, syscall). Dùng khi hàm ký cần syscall/filesystem mà unidbg không mô hình gọn.
- [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) — CPU emulator đa kiến trúc (fallback thấp nhất): map bytes của 1 hàm, set register, `emu_start` qua đúng khoảng lệnh — khi muốn chạy 1 hàm không cần scaffolding JNI/OS.
- [frida/frida](https://github.com/frida/frida) — **native RPC** (thay cho emulate): attach app sống, `rpc.exports` + `NativeFunction` expose hàm ký ra host → app thành "server ký". Device vẫn trong vòng lặp nhưng khỏi reimplement.

### B. Unity / IL2CPP sâu
- [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) — khôi phục metadata C# từ `libil2cpp.so` + `global-metadata.dat`, xuất dummy DLL + script IDA/Ghidra.
- [Perfare/Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper) — dump runtime (Zygisk) khi game mã hoá `global-metadata.dat` trên đĩa — dump sau khi game giải mã trong RAM.
- [vfsfitvnm/frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) — interop runtime IL2CPP qua Frida, không cần metadata file.
- [djkaty/Il2CppInspector](https://github.com/djkaty/Il2CppInspector) — thay thế/bổ sung Il2CppDumper, phủ nhiều version metadata hơn, tích hợp Ghidra sạch.

### C. Trace JNI — tìm biên ký Java↔native
- [chame1eon/jnitrace](https://github.com/chame1eon/jnitrace) — trace mọi JNI call app gọi (`RegisterNatives`, `CallXXXMethod`, `GetStringUTFChars`…) để chỉ ra **hàm native nào ký** + bắt arg/return. Cách nhanh nhất tìm hàm ký.
- [chame1eon/jnitrace-engine](https://github.com/chame1eon/jnitrace-engine) — engine `JNIInterceptor.attach` để nhúng vào script Frida của bạn.

### D. Inject Frida-gadget / repackage (không cần root)
- [sensepost/objection](https://github.com/sensepost/objection) — `objection patchapk` nhúng `frida-gadget.so` vào APK + resign (tự thêm quyền INTERNET). Yếu với split APK.
- [ksg97031/frida-gadget](https://github.com/ksg97031/frida-gadget) — inject gadget vào APK/IPA 1 lệnh (hợp CI).
- [NickstaDB/patch-apk](https://github.com/NickstaDB/patch-apk) — bọc objection, xử được split/multi-APK.
- [ax/apk.sh](https://github.com/ax/apk.sh) — script all-in-one pull/decode/inject/rebuild/sign.

### E. Bypass hardening (mèo-vờn-chuột, verify độ tươi trước khi dùng)
- [scottyab/rootbeer](https://github.com/scottyab/rootbeer) — thư viện **detect** root app nhúng (KHÔNG phải bypass) — biết tập check (su, BusyBox, test-keys, path Magisk) để hook vô hiệu từng cái bằng Frida.
- [KOWX712/PlayIntegrityFix](https://github.com/KOWX712/PlayIntegrityFix) — fork PIF đang duy trì (qua BASIC verdict bằng spoof build/attestation). ⚠️ Bản gốc `chiteroman/PlayIntegrityFix` đã **bị gỡ khỏi GitHub** — dùng fork này. Không phải root-hider.
- [Displax/safetynet-fix](https://github.com/Displax/safetynet-fix) — fork mở rộng sang Play Integrity. ⚠️ cat-and-mouse.
- Root *hiding* (lớp khác attestation): Shamiko / Zygisk DenyList — nhắc khái niệm, không có upstream canonical đáng link.

### F. iOS (bonus)
- [AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) — dump IPA **đã giải mã** FairPlay qua Frida. ⚠️ hỏng trên Frida 17+, ít duy trì — cân nhắc `bagbak`.
- [KJCracks/Clutch](https://github.com/KJCracks/Clutch) — decrypt on-device (`posix_spawn`) ra IPA (iOS cũ).
- [theos/theos](https://github.com/theos/theos) — build system viết tweak/hook iOS (Substrate/Logos).
- [nygard/class-dump](https://github.com/nygard/class-dump) — tái tạo header `@interface` Obj-C từ Mach-O (Swift cần tool khác).

### G. Protobuf / binary protocol
- [marin-m/pbtk](https://github.com/marin-m/pbtk) — dựng lại `.proto` từ reflection metadata nhúng trong binary (C++/Java/web) + GUI sửa/fuzz traffic.
- [mildsunrise/protobuf-inspector](https://github.com/mildsunrise/protobuf-inspector) — decode protobuf **không cần schema** ra cây wire-level, rồi annotate dần dựng lại schema.
- [nccgroup/blackboxprotobuf](https://github.com/nccgroup/blackboxprotobuf) — encode/decode schema-less (PyPI `bbpb`), nhúng Burp/mitmproxy để decode **và re-encode** sửa traffic.

### H. Firmware / IoT (bonus)
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — scan signature + carve filesystem/kernel; entropy (`-E`) phát hiện vùng mã hoá/nén. Nước đi đầu tiên.
- [onekey-sec/unblob](https://github.com/onekey-sec/unblob) — extract đệ quy, chính xác format hơn binwalk khi container lồng nhau.
- [rampageX/firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit) — không chỉ extract mà **rebuild/repack** firmware (SquashFS lạ). Helper: `sasquatch`, `jefferson`, `ubireader`.

---

## 🧭 Quyết định: emulate `.so` vs Frida-RPC vs viết lại thuần
- **Emulate native-lib (unidbg/Qiling/Unicorn)** khi logic ký nằm trong `.so` obfuscate hoặc không có device/root. Được signer độc lập, scale tốt (chạy ngàn account server-side, không device) — đổi lại phải mô hình đủ JNI/OS để hàm chạy.
- **Frida native-RPC** khi *có* device/emulator và muốn nhanh: `rpc.exports` + `NativeFunction` biến app sống thành oracle ký trong vài phút, đúng theo định nghĩa. Nhược: mỗi đơn vị concurrency cần 1 device, vỡ khi app update/detect Frida, khó scale.
- **Viết lại thuần (đọc thuật toán → rewrite Python)** chỉ khi signer đơn giản/đã hiểu (vd HMAC-SHA256 trên sorted params + salt tĩnh lấy từ jadx). Nhanh & bền nhất lúc chạy (không emulator/device) — nhưng là bẫy nếu obfuscate nặng hoặc có state native ẩn.
- **Quy tắc ngón tay cái:** **trace trước** (jnitrace / frida-il2cpp-bridge) tìm biên + thấy input/output → thử hiểu → đơn giản thì reimplement; `.so` rối thì emulate; cần chạy ngay & có device thì Frida-RPC.
- **Hardening là lớp riêng & dễ hỏng:** bypass root/Frida/integrity (mục E) là mèo-vờn-chuột, hay bị gỡ khỏi GitHub (vd PIF của chiteroman). Pin đúng version, chờ nó rot, và **ưu tiên emulate** vì né hẳn detection trên device.

---

## Pattern chắt lọc (ánh xạ sang bài học)

1. **Signed header = hash của request.** X-Gorgon/X-Ladon/X-Argus, IG `signed_body`… = HMAC/hash-obfuscate trên (params sắp xếp + body + timestamp + secret/nonce). Việc cần làm: tìm **secret** + đúng **cách canonicalize** (thứ tự field).
2. **Mượn signer vs viết lại** — 3 nấc tăng dần: (a) chạy browser/app thật để nó tự ký; (b) **emulate native `.so`** trong CPU emulator; (c) reimplement thuật toán thuần Python/Go. Đánh đổi công sức ↔ độ bền.
3. **Rút key/thuật toán từ native lib.** Secret thật nằm trong `.so` đóng gói → lấy bằng decompile (Ghidra/IDA, Il2CppDumper) hoặc hook runtime (Frida) đọc key/output trực tiếp.
4. **Device fingerprint bền + đăng ký 1 lần.** Mint device-id + UUID (android_id, model, build) 1 lần rồi tái dùng — server gắn session/anti-fraud theo device ổn định (instagrapi, gpsoauth).
5. **Export/restore session, không login lại.** Login là bước rủi ro/captcha nhất → serialize session (cookie/token/device) ra đĩa rồi restore (instagrapi, instaloader, twikit).
6. **Guest/cookie token → endpoint JSON/GraphQL nội bộ.** Reverse web: lấy guest/cookie token rồi gọi đúng endpoint SPA dùng (LinkedIn Voyager, twikit/snscrape).
7. **Impersonate TLS/JA3 + HTTP/2.** Anti-bot soi cả handshake TLS + HTTP/2 settings → dùng curl_cffi/tls-client khớp browser thật.
8. **Giả telemetry anti-bot.** Akamai/PerimeterX/DataDome chờ payload sensor/behavior → tái tạo (akamai-bmp-generator) hoặc giải mã để hiểu (SensorData.Decryptor). Mong manh nhất.
9. **Protobuf là wire format.** Protocol realtime/mobile hay serialize protobuf → phải phục hồi `.proto` (discord-protos, go-librespot, TikTok Live, whatspec) trước khi decode.
10. **Realtime = WebSocket + handshake riêng.** Push/live dùng WebSocket URL có ký/hết hạn (TikTok Live 30s) hoặc handshake crypto (WhatsApp **Noise**) bọc protobuf.
11. **Master-token / token-exchange.** 1 credential dài hạn khó lấy (Google master token qua EncryptedPasswd; Xiaomi device token) đổi lấy token ngắn hạn per-service.
12. **Trích cả spec (meta-move).** Đòn mạnh nhất: parse bundle JS/native ra **toàn bộ protocol surface** (whatspec, sensebook) thay vì reverse từng endpoint — biến reverse thành "spec sống".

### Caveat luôn dạy kèm
- Repo signer/anti-bot pin theo version, vỡ mỗi lần app/vendor update; nhiều cái archived/DMCA (pysnap/Snaphax, captcha solver). Tốt để học **kỹ thuật**, không đảm bảo "chạy hôm nay".
- Ownership hay nhầm: instagrapi = **subzeroid** (trước adw0rd); fbchat gốc = **carpedm20** (nhiều fork); frida-il2cpp-bridge canonical = **vfsfitvnm**.
