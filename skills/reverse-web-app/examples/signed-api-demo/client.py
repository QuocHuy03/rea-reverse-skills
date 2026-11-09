#!/usr/bin/env python3
"""
client.py — the REVERSED client for target_server.py: it reimplements the signer
and the body decryptor (the two things a real reverse recovers from the bundle)
and calls the API headless, returning decrypted data. This is the deliverable the
web skill aims at: capture -> understand -> a standalone client that signs itself.

In a real job these constants/algorithm come from reversing the JS bundle
(web/sign-sniffer.js shows the canonical string + key). Here they're what the
reverse "found". The point: no browser, byte-for-byte correct, returns real data.

    python client.py
Pure stdlib + pycryptodome.
"""
import json, time, hmac, hashlib, base64, urllib.request
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BASE = "http://127.0.0.1:8799"
# recovered by the reverse (sign-sniffer canonical + bundle key):
SIGN_SECRET = b"s3cr3t_app_key_v1"
AES_KEY = b"0123456789abcdef0123456789abcdef"
AES_IV = b"iviviviviviviviv"


def sign(method, path, ts, body=""):
    canonical = "%s\n%s\n%s\n%s" % (method, path, ts, body or "")
    return hmac.new(SIGN_SECRET, canonical.encode(), hashlib.sha256).hexdigest()


def decrypt_body(enc_b64):
    ct = base64.b64decode(enc_b64)
    raw = unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ct), 16)
    return json.loads(raw)


def get_data():
    path = "/api/data"
    ts = str(int(time.time()))
    req = urllib.request.Request(BASE + path, method="GET")
    req.add_header("x-ts", ts)
    req.add_header("x-sign", sign("GET", path, ts))
    with urllib.request.urlopen(req, timeout=10) as r:
        envelope = json.loads(r.read().decode())
    return decrypt_body(envelope["enc"])


if __name__ == "__main__":
    data = get_data()
    print("decrypted response:")
    print(json.dumps(data, indent=2))
