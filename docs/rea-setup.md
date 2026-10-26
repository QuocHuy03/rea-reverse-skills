# Install & configure REA (the shared analysis core)

[REA](https://github.com/morluto/rea) (`rea-agents`) is a CLI + MCP server for reverse engineering: decompile, read structured evidence, capture and analyze traffic. All three skills in this repo call REA for the code-reading / binary-analysis steps.

REA does **not install** the analysis engines itself (Ghidra, JADX, Java, IDA…). You bring the engine; REA orchestrates it.

## 1. Install REA as an MCP server

Requires **Node.js ≥ 22.23.4** (or 24.x ≥ 24.22.1, or ≥ 26.12.1). Check with `node --version`; if it's lower, upgrade (e.g. `winget upgrade OpenJS.NodeJS.22`).

```bash
# register REA for Claude Code (use an underscore: claude_code)
npx -y rea-agents@latest setup --client claude_code --dry-run   # preview
npx -y rea-agents@latest setup --client claude_code --yes       # apply
```

This command adds the `rea` server to `~/.claude.json` and installs REA's `reverse-engineer-anything` skill. **Restart Claude Code / your IDE** so the `mcp__rea__*` tools appear (verify with `/mcp`).

Other clients: replace `claude_code` with `codex`, `cursor`, `vscode`, `gemini_cli`, `windsurf`, `opencode`…

## 2. Attach analysis engines (depending on target type)

Set the environment variables below at **User scope** (new shells pick them up automatically), or have `rea setup` embed them into the registration. REA reads them at startup.

### Full JDK 21 — needed for both Ghidra and JADX
Must be a **full JDK** (includes `jdk.compiler`), not a JRE. Check: `java --list-modules | grep jdk.compiler`.
```
JAVA_HOME = <path to JDK 21>      # e.g. C:\Users\<you>\scoop\apps\temurin21-jdk\current
```

### Ghidra 12.1.x — native analysis (exe/dll/.so, .NET NativeAOT)
Download the version REA pins to (currently **12.1.4**, do not use 12.2) from [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases), extract it, then:
```
GHIDRA_INSTALL_DIR = <ghidra_12.1.4_PUBLIC folder>
```

### JADX headless 0.7.1 — APK analysis (Android)
Download the `jadx-headless-mcp-0.7.1-all.jar` JAR from [1013503897/jadx-headless-mcp release v0.7.1](https://github.com/1013503897/jadx-headless-mcp/releases/tag/v0.7.1) (REA verifies it against a fixed sha256), then:
```
REA_JADX_MCP_JAR = <absolute path to jadx-headless-mcp-0.7.1-all.jar>
```

### (Optional) IDA / Kuna
Advanced native — see `docs/ida-provider.md` / `docs/kuna-provider.md` in the REA repo. Not required.

## 3. Check readiness

```bash
rea doctor --format json            # or: npx -y rea-agents@latest doctor
```
Look at `providerInspections[]`: any provider with `available: true` is usable. `rea providers` lists each provider's capabilities in detail.

## 4. Use via the CLI (no MCP needed)

Every tool also runs as a CLI — handy when MCP isn't loaded yet or you want to script it:
```bash
npx -y rea-agents@latest <command> [args]
# e.g.:
npx -y rea-agents@latest inspect-android-package app.apk
npx -y rea-agents@latest analyze target.exe --provider ghidra
npx -y rea-agents@latest --help         # full list of ~200 commands
```
Token tip: add `--token-limit N` / `--format json` when output is large; each result returns an `evidence_id` so you can request a detailed view instead of re-running the whole command.

## Principles for reading REA results

REA clearly separates **observation** vs **inference** vs **unknown**, each with an `evidence_id`. When you draw a conclusion, stick to those three levels — don't treat static analysis as if you had observed runtime behavior. Verify experimentally (run the request you built, match it against the values the real app sends) before trusting it.
