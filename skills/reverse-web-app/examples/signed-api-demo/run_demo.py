#!/usr/bin/env python3
"""
run_demo.py — prove the reverse pipeline end-to-end: start the target, let the
reversed client sign+call+decrypt, and verify the reimplemented signer matches
the target byte-for-byte. Doubles as a smoke test for the skill's tooling.

    python run_demo.py        # exit 0 = PASS
"""
import subprocess, socket, sys, os, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def wait_port(host, port, tries=60):
    for _ in range(tries):
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    srv = subprocess.Popen([sys.executable, os.path.join(HERE, "target_server.py")])
    try:
        if not wait_port("127.0.0.1", 8799):
            print("FAIL: target_server did not come up"); return 1

        import client, target_server
        # 1) byte-for-byte signer check (what verify-signer automates for mobile)
        ts = "1700000000"
        mine = client.sign("GET", "/api/data", ts)
        theirs = target_server.sign("GET", "/api/data", ts, "")
        print("signer check : mine=%s" % mine)
        print("               app =%s" % theirs)
        if mine != theirs:
            print("FAIL: signer mismatch"); return 1
        print("  -> PASS: signer reproduces the target byte-for-byte")

        # 2) full round trip: sign -> call -> decrypt real data
        data = client.get_data()
        print("\nclient round-trip -> decrypted response:")
        print(data)
        ok = isinstance(data, dict) and data.get("user") == "demo" and data.get("balance") == 1234
        print("\nRESULT:", "PASS - headless client signed, called, and decrypted real data." if ok else "FAIL")
        return 0 if ok else 1
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    sys.exit(main())
