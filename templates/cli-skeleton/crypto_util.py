"""crypto_util.py — body/response encryption helpers recovered from the target.

Fill in KEY / IV / mode from what you found while reversing (jadx / REA /
Frida hook). Verify by decrypting one captured response into valid JSON
BEFORE trusting it. These are the most common schemes; adapt as needed.
"""
from __future__ import annotations

import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# TODO: replace with the real values recovered from the app.
KEY = b"0123456789abcdef"      # 16/24/32 bytes
IV = b"0123456789abcdef"       # 16 bytes (CBC only)


def aes_cbc_encrypt(plaintext: bytes, key: bytes = KEY, iv: bytes = IV) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes = KEY, iv: bytes = IV) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)


def aes_ecb_encrypt(plaintext: bytes, key: bytes = KEY) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, AES.block_size))


def aes_ecb_decrypt(ciphertext: bytes, key: bytes = KEY) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)


def encrypt_body(plaintext: str) -> str:
    """Encrypt a request body -> base64 string. Adapt to the target's scheme."""
    return base64.b64encode(aes_cbc_encrypt(plaintext.encode())).decode()


def decrypt_resp(b64_ciphertext: str) -> str:
    """Decrypt a base64 response body -> plaintext string."""
    return aes_cbc_decrypt(base64.b64decode(b64_ciphertext)).decode()
