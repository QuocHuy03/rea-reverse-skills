#!/usr/bin/env python3
"""
check-deps.py — preflight the reverse toolchain before you start, so you don't
hit "command not found" / "no module" in the middle of a capture.

    python check-deps.py

Checks the binaries and Python modules the mobile-app skill uses, prints an
OK/MISSING table, and exits non-zero if a CRITICAL one is absent. Cross-platform.
"""
import sys, shutil, subprocess, importlib, argparse

# (name, critical?)  — binaries looked up on PATH
BINS = [("adb", True), ("frida", True), ("frida-ps", False), ("mitmdump", False),
        ("mitmproxy", False), ("node", False), ("openssl", False), ("jadx", False)]
# (import_name, pip_name, critical?)
MODS = [("frida", "frida-tools", True), ("hpack", "hpack", False),
        ("hyperframe", "hyperframe", False), ("Crypto", "pycryptodome", False),
        ("curl_cffi", "curl_cffi", False), ("requests", "requests", False)]


def ver(cmd):
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=8)
        return (out.stdout or out.stderr).strip().splitlines()[0][:40]
    except Exception:
        return ""


def main():
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    argparse.ArgumentParser(description="Preflight the reverse toolchain.").parse_args()

    missing_critical = []
    print("=== binaries (PATH) ===")
    for name, crit in BINS:
        path = shutil.which(name)
        if path:
            print("  OK      %-10s %s" % (name, ver(name) or path))
        else:
            tag = "MISSING!" if crit else "missing "
            print("  %s %-10s %s" % (tag, name, "(required)" if crit else "(optional)"))
            if crit: missing_critical.append(name)

    print("=== python modules ===")
    print("  OK      python     %s" % sys.version.split()[0])
    for mod, pip, crit in MODS:
        try:
            importlib.import_module(mod)
            print("  OK      %-10s" % mod)
        except Exception:
            tag = "MISSING!" if crit else "missing "
            print("  %s %-10s pip install %s %s" % (tag, mod, pip, "(required)" if crit else "(optional)"))
            if crit: missing_critical.append(mod)

    print("-" * 50)
    # frida client/server version reminder (can't check server without a device)
    fv = ver("frida")
    if fv:
        print("NOTE: frida client = %s — frida-server on the device MUST match this version." % fv)
    if missing_critical:
        print("RESULT: missing critical: %s" % ", ".join(missing_critical))
        return 1
    print("RESULT: all critical deps present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
