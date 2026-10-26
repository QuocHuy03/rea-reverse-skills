# rea-reverse-skills

A set of **Claude Code skills** for reverse-engineering **Windows apps, Android (mobile) apps, and web apps** — capture and decode a program's protocol/API, then reimplement it as a **stable Python CLI**. The analysis core uses [**REA**](https://github.com/morluto/rea) (`rea-agents`): headless decompilation + reading structured evidence (JADX for APKs, Ghidra for native, JS/Electron analysis, traffic capture and inspection).

> The end goal of every skill: **be able to drop the original app** — a (Python) **CLI** that builds requests from scratch (signs them itself, encrypts itself, solves captchas itself), runs headless, has clear exit codes, and repeats reliably. No DB, no web dashboard. The app/emulator/Frida are only scaffolding during reversing.

## What's in the repo

| Skill | Goal | Analysis core |
|---|---|---|
| [`reverse-windows-app`](skills/reverse-windows-app/SKILL.md) | Windows desktop apps: native PE/exe/dll, .NET, Electron | REA Ghidra / managed / JS, process & network capture |
| [`reverse-mobile-app`](skills/reverse-mobile-app/SKILL.md) | Android apps (APK) running in an emulator | REA JADX + mitm/Frida + rebuild client |
| [`reverse-web-app`](skills/reverse-web-app/SKILL.md) | Web app / site API | REA web-bundle / HAR / browser scenario + rebuild client |

Shared documentation:
- [`docs/rea-setup.md`](docs/rea-setup.md) — install & configure REA + its providers (Ghidra, JADX, JDK), portable.
- [`docs/captcha-solvers.md`](docs/captcha-solvers.md) — solve captchas via a service (NextCaptcha / 2captcha / CapSolver / EzCaptcha / Capzy).
- [`docs/references.md`](docs/references.md) — GitHub repos & tools that complement REA for each area (unpin/Frida, Ghidra, .NET, deobfuscate JS, anti-bot/TLS, captcha, awesome-lists).
- [`docs/reverse-case-studies.md`](docs/reverse-case-studies.md) — **real reverse-engineering cases** (TikTok signer, instagrapi, librespot, WhatsApp, gpsoauth…) + heavy techniques (emulating `.so` with unidbg, IL2CPP, jnitrace) + **distilled patterns** + a decision table for *emulate vs Frida-RPC vs reimplement*.
- [`docs/china-re-arsenal.md`](docs/china-re-arsenal.md) — **the Chinese reverse-engineering arsenal** (看雪/52pojie): 脱壳 (unpacking) apps with 加固 (hardening) (FRIDA-DEXDump/BlackDex/Youpk/FART), r0capture, 算法助手, reversing 微信小程序 (WeChat Mini-Program), anti-detection, unidbg-server + a full **脱壳 (unpacking) workflow**.

## Install into Claude Code

Claude Code skills live at `~/.claude/skills/<name>/SKILL.md` (global) or `.claude/skills/` inside a project. Clone the repo, then copy (or symlink) each skill directory:

```bash
git clone https://github.com/QuocHuy03/rea-reverse-skills
# copy all skills into your personal skills directory
cp -r rea-reverse-skills/skills/* ~/.claude/skills/
```

Windows (PowerShell):
```powershell
git clone https://github.com/QuocHuy03/rea-reverse-skills
Copy-Item rea-reverse-skills\skills\* "$env:USERPROFILE\.claude\skills\" -Recurse
```

Then open Claude Code and type `/reverse-windows-app`, `/reverse-mobile-app`, or `/reverse-web-app` — or just describe your goal and the skill activates automatically based on its `description`.

## Requirements

- **Claude Code** (CLI or IDE extension).
- **REA** registered as an MCP server — see [`docs/rea-setup.md`](docs/rea-setup.md). Without REA the skills still describe the workflow, but the decompile/evidence steps will have to be done manually with external tools.
- Tools for each target type (an emulator for mobile, etc.) — documented in each skill, all given as **environment variables / placeholders** so you fill in your own machine's paths.

## Legal notice

Use only for lawful purposes: analyzing your own software, authorized security research, CTFs, learning, interoperability. Comply with software licenses and local law. Do not commit copyrighted APKs/binaries, credentials, tokens, or real proxies to the repo.
