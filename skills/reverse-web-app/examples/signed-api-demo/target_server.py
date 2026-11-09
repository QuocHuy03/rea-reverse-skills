#!/usr/bin/env python3
"""
target_server.py — a LOCAL stand-in for a "signed + encrypted" web API, so the
reverse pipeline can be demonstrated/tested end-to-end without touching anyone
else's site. It behaves like a real target: every /api/data request must carry a
correct HMAC-SHA256 signature over a canonical string, and the response body is
AES-CBC encrypted. The client under examples/ "reverses" this (reimplements the
signer + decryptor) and must match byte-for-byte.

Run:  python target_server.py           # listens on 127.0.0.1:8799
Pure stdlib + pycryptodome (Crypto).  Localhost only; authorized by construction.
"""
import json, time, hmac, hashlib, base64, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# "secrets" that a real reverse would have to recover from the bundle:
SIGN_SECRET = b"s3cr3t_app_key_v1"
AES_KEY = b"0123456789abcdef0123456789abcdef"   # 32 bytes
AES_IV = b"iviviviviviviviv"                      # 16 bytes
HOST, PORT = "127.0.0.1", 8799


def canonical(method, path, ts, body):
    # the exact string the server signs — order + separators matter (this is the
    # thing a reverse must rediscover by watching the hash input).
    return "%s\n%s\n%s\n%s" % (method, path, ts, body or "")


def sign(method, path, ts, body):
    return hmac.new(SIGN_SECRET, canonical(method, path, ts, body).encode(), hashlib.sha256).hexdigest()


def encrypt_body(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    ct = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(raw, 16))
    return base64.b64encode(ct).decode()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/api/data"):
            ts = self.headers.get("x-ts", "")
            got = self.headers.get("x-sign", "")
            want = sign("GET", self.path.split("?")[0], ts, "")
            if not ts or not hmac.compare_digest(got, want):
                return self._send(401, json.dumps({"error": "bad signature"}))
            # skew check like a real anti-replay gate
            try:
                if abs(int(ts) - int(time.time())) > 300:
                    return self._send(401, json.dumps({"error": "stale ts"}))
            except ValueError:
                return self._send(401, json.dumps({"error": "bad ts"}))
            payload = {"user": "demo", "balance": 1234, "items": ["a", "b", "c"], "ts": ts}
            return self._send(200, json.dumps({"enc": encrypt_body(payload)}))
        return self._send(404, json.dumps({"error": "not found"}))


def main():
    srv = HTTPServer((HOST, PORT), H)
    print("target_server listening on http://%s:%d" % (HOST, PORT))
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()


if __name__ == "__main__":
    main()
