# Cài & cấu hình REA (lõi phân tích dùng chung)

[REA](https://github.com/morluto/rea) (`rea-agents`) là CLI + MCP server để reverse-engineer: decompile, đọc evidence có cấu trúc, bắt & phân tích traffic. Ba skill trong repo này đều gọi REA cho khâu đọc code / phân tích binary.

REA **không tự cài** các engine phân tích (Ghidra, JADX, Java, IDA…). Bạn mang theo engine, REA điều phối.

## 1. Cài REA làm MCP server

Yêu cầu **Node.js ≥ 22.23.4** (hoặc 24.x ≥ 24.22.1, hoặc ≥ 26.12.1). Kiểm tra `node --version`; nếu thấp hơn thì nâng (vd `winget upgrade OpenJS.NodeJS.22`).

```bash
# đăng ký REA cho Claude Code (dùng gạch dưới: claude_code)
npx -y rea-agents@latest setup --client claude_code --dry-run   # xem trước
npx -y rea-agents@latest setup --client claude_code --yes       # áp dụng
```

Lệnh này thêm server `rea` vào `~/.claude.json` và cài skill `reverse-engineer-anything` của REA. **Khởi động lại Claude Code / IDE** để tool `mcp__rea__*` xuất hiện (kiểm tra bằng `/mcp`).

Client khác: thay `claude_code` bằng `codex`, `cursor`, `vscode`, `gemini_cli`, `windsurf`, `opencode`…

## 2. Gắn engine phân tích (tuỳ loại mục tiêu)

Đặt các biến môi trường dưới đây ở **User scope** (shell mới tự có) hoặc để `rea setup` nhúng vào registration. REA đọc chúng khi khởi động.

### JDK 21 đầy đủ — cần cho cả Ghidra lẫn JADX
Phải là **full JDK** (có `jdk.compiler`), không phải JRE. Kiểm: `java --list-modules | grep jdk.compiler`.
```
JAVA_HOME = <đường dẫn JDK 21>      # vd C:\Users\<you>\scoop\apps\temurin21-jdk\current
```

### Ghidra 12.1.x — phân tích native (exe/dll/.so, .NET NativeAOT)
Tải bản REA pin (hiện **12.1.4**, không dùng 12.2) từ [releases của Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases), giải nén, rồi:
```
GHIDRA_INSTALL_DIR = <thư mục ghidra_12.1.4_PUBLIC>
```

### JADX headless 0.7.1 — phân tích APK (Android)
Tải JAR `jadx-headless-mcp-0.7.1-all.jar` từ [1013503897/jadx-headless-mcp release v0.7.1](https://github.com/1013503897/jadx-headless-mcp/releases/tag/v0.7.1) (REA verify theo sha256 cố định), rồi:
```
REA_JADX_MCP_JAR = <đường dẫn tuyệt đối tới jadx-headless-mcp-0.7.1-all.jar>
```

### (Tuỳ chọn) IDA / Kuna
Native nâng cao — xem `docs/ida-provider.md` / `docs/kuna-provider.md` trong repo REA. Không bắt buộc.

## 3. Kiểm tra sẵn sàng

```bash
rea doctor --format json            # hoặc: npx -y rea-agents@latest doctor
```
Nhìn `providerInspections[]`: provider nào `available: true` là dùng được. `rea providers` liệt kê chi tiết khả năng từng provider.

## 4. Dùng qua CLI (không cần MCP)

Mọi tool đều chạy được dạng CLI — tiện khi MCP chưa nạp hoặc muốn script:
```bash
npx -y rea-agents@latest <command> [args]
# vd:
npx -y rea-agents@latest inspect-android-package app.apk
npx -y rea-agents@latest analyze target.exe --provider ghidra
npx -y rea-agents@latest --help         # danh sách đầy đủ ~200 lệnh
```
Mẹo token: thêm `--token-limit N` / `--format json` khi output to; mỗi kết quả trả `evidence_id` để xin view chi tiết thay vì gọi lại cả lệnh.

## Nguyên tắc đọc kết quả REA

REA tách rõ **quan sát được** (observation) vs **suy luận** (inference) vs **chưa biết** (unknown), kèm `evidence_id`. Khi kết luận, bám đúng ba mức đó — đừng coi phân tích tĩnh là đã quan sát hành vi runtime. Verify lại bằng thực nghiệm (chạy thử request đã dựng, so khớp giá trị app thật gửi) trước khi tin.
