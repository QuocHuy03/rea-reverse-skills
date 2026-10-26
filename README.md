# rea-reverse-skills

Bộ **Claude Code skills** để reverse-engineer **app Windows, app Android (mobile) và web app** — lấy protocol/API của phần mềm rồi dựng lại client + hệ thống quản lý. Lõi phân tích dùng [**REA**](https://github.com/morluto/rea) (`rea-agents`): decompile headless + đọc evidence có cấu trúc (JADX cho APK, Ghidra cho native, phân tích JS/Electron, bắt & đọc traffic).

> Mục tiêu cuối của mọi skill: **bỏ được app gốc** — dựng client (thường là Python) tự tạo request từ đầu (tự ký, tự mã hoá), đồng bộ dữ liệu vào DB, lên API + dashboard. App/emulator/Frida chỉ là giàn giáo lúc reverse.

## Có gì trong repo

| Skill | Mục tiêu | Lõi phân tích |
|---|---|---|
| [`reverse-windows-app`](skills/reverse-windows-app/SKILL.md) | App desktop Windows: native PE/exe/dll, .NET, Electron | REA Ghidra / managed / JS, process & network capture |
| [`reverse-mobile-app`](skills/reverse-mobile-app/SKILL.md) | App Android (APK) chạy trong emulator | REA JADX + mitm/Frida + rebuild client |
| [`reverse-web-app`](skills/reverse-web-app/SKILL.md) | Web app / site API | REA web-bundle / HAR / browser scenario + rebuild client |

Tài liệu chung:
- [`docs/rea-setup.md`](docs/rea-setup.md) — cài & cấu hình REA + các provider (Ghidra, JADX, JDK), portable.

## Cài vào Claude Code

Skill của Claude Code nằm ở `~/.claude/skills/<tên>/SKILL.md` (toàn cục) hoặc `.claude/skills/` trong project. Clone repo rồi copy (hoặc symlink) từng thư mục skill:

```bash
git clone https://github.com/QuocHuy03/rea-reverse-skills
# copy toàn bộ skill vào thư mục skill cá nhân
cp -r rea-reverse-skills/skills/* ~/.claude/skills/
```

Windows (PowerShell):
```powershell
git clone https://github.com/QuocHuy03/rea-reverse-skills
Copy-Item rea-reverse-skills\skills\* "$env:USERPROFILE\.claude\skills\" -Recurse
```

Sau đó mở Claude Code, gõ `/reverse-windows-app`, `/reverse-mobile-app`, hoặc `/reverse-web-app` — hoặc chỉ cần mô tả mục tiêu, skill tự kích hoạt theo `description`.

## Yêu cầu

- **Claude Code** (CLI hoặc IDE extension).
- **REA** đã đăng ký làm MCP server — xem [`docs/rea-setup.md`](docs/rea-setup.md). Không có REA thì các skill vẫn mô tả quy trình, nhưng phần decompile/evidence sẽ phải làm thủ công bằng công cụ ngoài.
- Công cụ theo từng loại mục tiêu (emulator cho mobile, v.v.) — ghi trong từng skill, đều để dạng **biến môi trường / placeholder** để bạn tự điền đường dẫn máy mình.

## Lưu ý pháp lý

Chỉ dùng cho mục đích hợp pháp: phân tích phần mềm của chính bạn, nghiên cứu bảo mật được uỷ quyền, CTF, học tập, khả năng tương tác. Tuân thủ giấy phép phần mềm và luật sở tại. Không commit APK/binary bản quyền, credential, token, hay proxy thật lên repo.
