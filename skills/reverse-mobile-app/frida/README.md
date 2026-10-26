# Frida scripts

- **ssl-unpin.js** — universal SSL pinning bypass. Java layer (TrustManager, HostnameVerifier, OkHttp `CertificatePinner` kể cả bản obfuscate, Conscrypt) + native BoringSSL (`SSL_[CTX_]set_custom_verify`), có hook `android_dlopen_ext`/`dlopen` để bắt `.so` nạp muộn (spawn mode) và polling dự phòng.
- **dump-signer.js** — TEMPLATE hook hàm ký request để lộ chuỗi-đầu-vào + output. Sửa `TARGET_CLASS`/`TARGET_METHOD` theo class tìm được bằng REA.

Kỹ thuật tham khảo thêm:
- Timing qua `dlopen` + quét class OkHttp obfuscate: học từ [danieldev23/frida-ssl-bypass](https://github.com/danieldev23/frida-ssl-bypass).
- Bí thì dùng kèm các bản cộng đồng mạnh hơn: [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/), hoặc `objection android sslpinning disable`.

Đây là script dùng cho phân tích hợp pháp (app của chính bạn / nghiên cứu được uỷ quyền / CTF). Tuân thủ luật & giấy phép phần mềm.
