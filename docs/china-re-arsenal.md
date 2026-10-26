# Kho vũ khí reverse Trung Hoa (看雪 kanxue / 52pojie 吾爱破解)

Giới reverse Android Trung Quốc mạnh nhất ở mảng **脱壳 (unpack app đã 加固)** và **tái tạo chữ ký native**. Đây là bộ công cụ/kỹ thuật riêng của họ, bổ sung cho [references](references.md) và [reverse-case-studies](reverse-case-studies.md).

> `看雪` (bbs.kanxue.com) và `52pojie 吾爱破解` (52pojie.cn) là **forum/CTF community**, không phải GitHub org — nhiều tool sinh ra từ thread của họ. Vài tool "ngôi sao" (MT管理器, 算法助手 bản gốc) **không có repo công khai** — tải từ 52pojie, closed-source.
> ⚠️ Pháp lý như mọi doc khác: chỉ cho mục đích hợp pháp. Nhiều repo nhắm app TQ cụ thể, pin version, hỏng nhanh — học **kỹ thuật**, không phải "chạy liền".

---

## 1. 脱壳 — Unpack app đã gia cố (加固: 360加固 / 爱加密 / 梆梆 Bangcle / 腾讯乐固 Legu / 娜迦 Nagain)
Ý tưởng chung: packer giải mã DEX vào RAM rồi mới chạy → **dump DEX từ memory sau khi giải mã**.
- [hluwa/FRIDA-DEXDump](https://github.com/hluwa/FRIDA-DEXDump) — quét heap tìm magic DEX (cả header vỡ) rồi dump. Primitive "dump sau giải mã" phổ biến nhất. (ổn, ít cập nhật)
- [CodingGay/BlackDex](https://github.com/CodingGay/BlackDex) — **unpack không cần root/PC**, chạy *như 1 app* trên máy, dump DEX của app đã/ chưa cài. (Android 5–12; hơi cũ với Android mới nhất)
- [Youlor/Youpk](https://github.com/Youlor/Youpk) — 脱壳机 dựa **ART chủ động gọi (主动调用)**: ép mọi method chạy để runtime khôi phục CodeItem rồi dump — trị **抽取加固 (strip method-body)**, đúng lúc "DEX dump ra nhưng method rỗng". (cần ROM custom, Android cũ hơn)
- [hanbinglengyue/FART](https://github.com/hanbinglengyue/FART) — 自动化脱壳 chuẩn mực theo 主动调用 + 还原 CodeItem (patch AOSP). ⚠️ cũ (2020, Android 6), tác giả không public diff AOSP — cộng đồng tự dựng lại. Dump xong cần **repair** (FartRepair trong [Simp1er/MobileSec](https://github.com/Simp1er/MobileSec)).
- [Mufanc/DexHunter](https://github.com/Mufanc/DexHunter) — dumper 1 binary Rust quét DEX trong memory (cảm hứng FRIDA-DEXDump), không cần attach. (hiện đại)
- [CvvT/dumpDex](https://github.com/CvvT/dumpDex) — dump DEX bằng IDA Python (khi pack ở tầng native — đối trọng native-debugger của Frida dump).
- [westinyang/unpacker-panel](https://github.com/westinyang/unpacker-panel) — web panel 一键 cho Youpk.

> Lịch sử (thận trọng, hầu hết chết/DMCA): `zyq8709/DexHunter` (2015, Dalvik), `CheckPointSW/android_unpacker` (2017), `WrBug/dumpDex` (Xposed, ~6y). `ZjDroid`/`drizzleDumper`/`DexExtractor` — repo gốc đã gỡ, chỉ còn giá trị tham khảo tên.

## 2. 通杀抓包 — Bắt gói + bypass pinning kiểu TQ
- [r0ysue/r0capture](https://github.com/r0ysue/r0capture) — **抓包通杀**: hook socket read/write tầng Java (OkHttp/Retrofit/HttpURLConnection/Volley/WebSocket) *trên* TLS → pinning vô nghĩa. Triết lý: "bắt plaintext ở tầng API, đừng đánh nhau với cert". (active; Android 7–11, không chạy emulator)
- [firerpa/lamda](https://github.com/firerpa/lamda) — framework **cloud-phone** full-stack (remote desktop + UI automation + MITM + Frida built-in) cho reverse/automation nhiều máy. (active; trước tên `Rev1si0n/lamda`)

## 3. 算法助手 — Hook crypto lộ cơ chế ký
- **`算法助手 / Xposed算法助手`** — **không có repo công khai** (freeware, phát qua 52pojie). Kỹ thuật dạy: auto-hook `Cipher`/`Mac`/`MessageDigest`/`Signature` in ra key, IV, input, output + call stack → lộ ngay app ký/mã hoá thế nào.
- [P4nda0s/CryptoFucker](https://github.com/P4nda0s/CryptoFucker) — bản mã nguồn mở tương đương 算法助手 (Xposed): chặn mọi `javax.crypto.*`/`javax.security.*` sniff key/IV/plaintext/ciphertext + stack. (last ~2021)

## 4. 微信小程序逆向 — Reverse WeChat Mini-Program (.wxapkg)
- [wux1an/wxapkg](https://github.com/wux1an/wxapkg) — quét + giải mã + giải nén .wxapkg (Go, GUI/CLI). Tốt nhất hiện nay. (active)
- [qwerty472123/wxappUnpacker](https://github.com/qwerty472123/wxappUnpacker) — bản gốc kinh điển, dựng lại source từ wxapkg. ⚠️ **archived 2021** — dùng fork.
- [junxiaqiao/unveilr-v2.0.0](https://github.com/junxiaqiao/unveilr-v2.0.0) — fork đang duy trì của `unveilr` (TS/Node): decrypt + parse + transform wxapkg về source đọc được. (upstream `r3x5ur/unveilr` nay 404)
- [BlackTrace/pc_wxapkg_decrypt](https://github.com/BlackTrace/pc_wxapkg_decrypt) — chỉ bước **giải mã** wxapkg trên WeChat PC (Go). ⚠️ cũ (WeChat PC 2.9.5.31), có thể cần patch.

## 5. Decompiler / APK tool quốc sản
- [charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool) — **GDA (GJoy Dex Analysizer)**: decompiler native C++ cho APK/DEX/ODEX/OAT, kèm **加固识别 (nhận diện packer)**, taint/var tracking, deobfuscate. Nhanh, offline, Windows — nhận diện packer *trước* khi chọn cách脱壳. ⚠️ binary-only, Windows, VMP nên hay bị AV báo nhầm.
- **MT管理器 (MT Manager)** — app Android closed-source (sửa smali/patch on-device). Không repo — tải site chính/52pojie.

## 6. 反检测 — Anti-detection (反Frida / 反调试 / 反模拟器 / 反root / 多开)
- [Prslc/Florida](https://github.com/Prslc/Florida) — frida-server **bản né detect** (đổi symbol/port/thread) để qua 反Frida (port 27042, `/proc/*/maps`, tên thread).
- [lico-n/ZygiskFrida](https://github.com/lico-n/ZygiskFrida) — inject Frida gadget qua **Zygisk** (không patch APK, không ptrace), có delay khởi động để né check lúc launch.
- [Exo1i/MagiskHluda](https://github.com/Exo1i/MagiskHluda) — module Magisk chạy frida-server stealth lúc boot (dựa StrongR-Frida).
- [talk114/DetectFrida](https://github.com/talk114/DetectFrida) — mẫu phía **detect** — đọc để biết app check gì (named pipe, quét thread, so code memory-vs-disk) → biết đường bypass.
- `dzonerzy/fridantiroot` — là **Frida CodeShare** (`frida --codeshare dzonerzy/fridantiroot`), không phải repo — snippet bypass 反root.

## 7. Xposed / LSPosed cho reverse
- [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) — framework Xposed nền Zygisk (engine LSPlant), để nạp module hook tầng Java (kiểu 算法助手) trên Android hiện đại.
- [JingMatrix/LSPosed](https://github.com/JingMatrix/LSPosed) — **fork cộng đồng đang sống** (rebrand "Vector", hỗ trợ Android 16) khi upstream chậm lại. Kèm **LSPatch** (patch dex+so vào APK để Xposed không cần root).

## 8. unidbg & emulate chữ ký native (国产)
- [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg) — emulate `.so` ARM32/64 + JNI/syscall (nền Unicorn), **tác giả Trung Quốc**. Câu trả lời chuẩn của scene TQ cho ký tầng native: emulate `.so` rồi gọi thẳng hàm ký. (active, có hỗ trợ MCP mới)
- [anjia0532/unidbg-boot-server](https://github.com/anjia0532/unidbg-boot-server) — unidbg + Spring Boot = **dịch vụ ký qua HTTP**: client Python POST params → nhận chữ ký hợp lệ. (tên đúng là `anjia0532`, không phải `anjok07`)

## 9. Học tập
- [r0ysue/AndroidSecurityStudy](https://github.com/r0ysue/AndroidSecurityStudy) + [r0ysue/r0capture](https://github.com/r0ysue/r0capture) — lộ trình học Frida/FART tiếng Trung (đi kèm sách/khoá r0ysue).
- [Simp1er/MobileSec](https://github.com/Simp1er/MobileSec) — ghi chú reverse Android (hook/frida/unicorn) + tập fork hữu ích (FartRepair, r0tracer, Frida-Seccomp, Wallbreaker, IDAFrida, BlackObfuscator).
- [user1342/Awesome-Android-Reverse-Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering) — index tool RE Android (tiếng Anh).

---

## 脱壳 workflow (thứ tự chuẩn scene TQ: unpack → bắt gói → tìm signer)
1. **识别壳 (nhận diện packer)** — soi `.so`/assets tìm 360/爱加密/梆梆/乐固/娜迦 (GDA tự nhận diện). Quyết định cách脱壳.
2. **脱壳 (dump DEX)** — rẻ trước: `FRIDA-DEXDump` / `BlackDex` dump từ memory. Method **rỗng** (抽取加固) → leo lên active-call `FART`/`Youpk` trên ROM patch, rồi **repair** dump (FartRepair).
3. **反编译** — nạp DEX vào `jadx` (hoặc quốc sản `GDA`) đọc Java, tìm điểm ký/mã hoá. (Với REA: `rea inspect-android-method` trên DEX đã脱 nếu đọc được.)
4. **抓包** — `r0capture` bắt request đã ký thật (xuyên pinning).
5. **定位签名 (tìm signer)** — hook crypto bằng `算法助手`/`P4nda0s/CryptoFucker` (tầng Java) và/hoặc jnitrace nếu ký ở native `.so`, lấy key/IV/thuật toán.
6. **模拟还原 (emulate signer native)** — ký nằm trong `.so` → nạp vào `zhkl0228/unidbg`, gọi thẳng hàm ký, expose qua `anjia0532/unidbg-boot-server` cho client Python xin chữ ký.
   (Suốt quá trình: dùng `LSPosed` + frida-server né detect như `Florida`/`ZygiskFrida` để qua 反Frida/反调试/反root cho hook chạy được.)
