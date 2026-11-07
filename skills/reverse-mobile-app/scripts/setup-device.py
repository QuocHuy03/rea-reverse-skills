#!/usr/bin/env python3
"""
setup-device.py — one command to get the device ready for capture, instead of
the fiddly manual dance (the #1 source of "why is nothing working").

Does, in order (each step optional via flags):
  connect adb -> pick device -> adb root -> detect ABI -> check frida client vs
  server version -> push+launch the right frida-server -> install the mitm CA
  into the SYSTEM store (openssl subject_hash_old -> push -> chmod -> reboot).

    python setup-device.py --frida-server path/to/frida-server-16.2.1-android-arm64
    python setup-device.py --connect 127.0.0.1:5555 --frida-server fs --port 1337
    python setup-device.py --ca ~/.mitmproxy/mitmproxy-ca-cert.pem        # CA step only
    python setup-device.py --frida-server fs --dry-run                    # print, don't run

--dry-run prints every command without executing (safe to inspect first).
Needs `adb` on PATH (or --adb); the CA step needs `openssl`. Cross-platform.
"""
import sys, os, subprocess, argparse, shutil

# Android ABI -> frida-server arch token (and a hint for the .so you'll pull)
ABI_ARCH = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm",
            "x86_64": "x86_64", "x86": "x86"}


class Dev:
    def __init__(self, args):
        self.a = args
        self.adb_bin = args.adb or "adb"
        self.dry = args.dry_run

    def sh(self, cmd, capture=False, check=False):
        print("  $ " + " ".join(cmd))
        if self.dry:
            return ""
        r = subprocess.run(cmd, capture_output=True, text=True)
        if capture:
            return (r.stdout or "").strip()
        if r.stdout.strip(): print(r.stdout.strip())
        if r.returncode and r.stderr.strip(): print(r.stderr.strip(), file=sys.stderr)
        if check and r.returncode:
            raise SystemExit("  ^ command failed (rc=%d)" % r.returncode)
        return ""

    def adb(self, *a, **k):
        base = [self.adb_bin]
        if self.a.device:
            base += ["-s", self.a.device]
        return self.sh(base + list(a), **k)

    def run(self):
        a = self.a
        if a.connect:
            self.sh([self.adb_bin, "connect", a.connect])
        print("[1] device")
        self.adb("devices")
        print("[2] root")
        self.adb("root")
        uid = self.adb("shell", "id", capture=True)
        if uid and "uid=0" not in uid:
            print("  WARN: not root (%s) — CA-into-system-store and frida-server need root." % uid)

        print("[3] ABI")
        abi = self.adb("shell", "getprop", "ro.product.cpu.abi", capture=True) or "?"
        arch = ABI_ARCH.get(abi.strip(), "?")
        print("  device ABI = %s  -> frida-server arch = %s  (pull .so from lib/%s/)" % (abi, arch, abi))

        if a.frida_server:
            self.push_frida(arch)
        if a.ca:
            self.install_ca()
        print("done." + ("  (dry-run — nothing was executed)" if self.dry else ""))

    def push_frida(self, arch):
        a = self.a
        print("[4] frida-server")
        if not self.dry and not os.path.isfile(a.frida_server):
            print("  WARN: %s not found on host." % a.frida_server)
        # version sanity: client vs the server filename / --version
        client = ""
        try:
            client = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=8).stdout.strip()
        except Exception:
            pass
        if client:
            print("  frida client = %s" % client)
            base = os.path.basename(a.frida_server)
            if client and client not in base:
                print("  NOTE: ensure the server is frida %s too — a version mismatch is the usual 'failed to attach'." % client)
        dst = "/data/local/tmp/" + (a.server_name or "frida-server")
        self.adb("push", a.frida_server, dst)
        self.adb("shell", "chmod", "755", dst)
        srvver = self.adb("shell", dst, "--version", capture=True)
        if srvver and client and srvver.strip() != client:
            print("  WARN: server=%s but client=%s -> MISMATCH, they must match." % (srvver.strip(), client))
        # launch detached (nohup+setsid so it survives the adb shell closing — the
        # classic "frida-server dies right after launch"). stdio to /dev/null or su blocks.
        listen = "-l 127.0.0.1:%d" % a.port if a.port else ""
        launch = "nohup setsid %s %s </dev/null >/dev/null 2>&1 &" % (dst, listen)
        print("  launching (background, detached): su -c '%s'" % launch)
        if not self.dry:
            self.adb("shell", "su", "-c", launch)
        if a.port:
            print("  connect with:  frida -H 127.0.0.1:%d   (or forward: adb forward tcp:%d tcp:%d)" % (a.port, a.port, a.port))

    def install_ca(self):
        a = self.a
        print("[5] mitm CA -> system store")
        if not shutil.which("openssl"):
            print("  WARN: openssl not on PATH — needed to compute the cert hash. Skipping.")
            return
        if not self.dry and not os.path.isfile(a.ca):
            print("  WARN: CA file %s not found." % a.ca); return
        h = ""
        if not self.dry:
            r = subprocess.run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
                                "-in", a.ca], capture_output=True, text=True)
            h = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            if not h:
                print("  WARN: could not compute subject_hash_old."); return
        else:
            h = "<hash>"
        tmp = os.path.join(os.path.dirname(os.path.abspath(a.ca)) if not self.dry else ".", h + ".0")
        print("  hash=%s -> %s" % (h, tmp))
        if not self.dry:
            shutil.copyfile(a.ca, tmp)
        self.adb("root"); self.adb("remount")
        self.adb("push", tmp, "/system/etc/security/cacerts/")
        self.adb("shell", "chmod", "644", "/system/etc/security/cacerts/%s.0" % h)
        print("  CA pushed. REBOOT to apply:  adb reboot   (Android 7+ ignores user-store CAs — system store is required)")


def main():
    ap = argparse.ArgumentParser(description="Prep an Android device for capture (adb+root, frida-server, mitm CA).")
    ap.add_argument("--adb", help="path to adb (default: adb on PATH)")
    ap.add_argument("--device", help="adb device id (e.g. 127.0.0.1:5555)")
    ap.add_argument("--connect", help="adb connect host:port first")
    ap.add_argument("--frida-server", help="host path to a version/ABI-matched frida-server to push+launch")
    ap.add_argument("--server-name", help="rename the pushed server (evade name-based detection)")
    ap.add_argument("--port", type=int, default=0, help="listen on a non-default port (beats 27042 checks)")
    ap.add_argument("--ca", help="mitmproxy CA pem to install into the SYSTEM store")
    ap.add_argument("--dry-run", action="store_true", help="print commands without executing")
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    Dev(ap.parse_args()).run()


if __name__ == "__main__":
    main()
