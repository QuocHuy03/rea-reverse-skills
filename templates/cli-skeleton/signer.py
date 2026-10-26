"""signer.py — request signing recovered from the target. THE HEART.

Reimplement the app/site's signature here, then prove it with
`verify_against_capture()` on a real captured request BEFORE calling live
endpoints. A wrong field order or a missing nonce = a wrong signature.

Typical shape: sign = HMAC/hash over (sorted params + body + ts + nonce + secret).
Replace the body of `sign()` with the exact algorithm you recovered.
"""
from __future__ import annotations

import hashlib
import hmac
import time

# TODO: replace with the real secret recovered from the app (string literal,
# BuildConfig, assembled from parts, or extracted from a native .so via Frida).
SECRET = "REPLACE_ME"


def canonical(params: dict) -> str:
    """Canonicalize params into the exact string the app signs.

    Most apps sort keys alphabetically and join as k=v&k=v. Some use a fixed
    order or a different separator — match the app EXACTLY.
    """
    return "&".join(f"{k}={params[k]}" for k in sorted(params))


def sign(params: dict, body: str = "", ts: int | None = None, nonce: str = "") -> dict:
    """Return the signature headers to attach to a request.

    This is a PLACEHOLDER (HMAC-SHA256 over canonical+body+ts+nonce+secret).
    Replace with the recovered algorithm; keep the return shape = the headers
    the app actually sends.
    """
    ts = ts if ts is not None else int(time.time() * 1000)
    base = f"{canonical(params)}{body}{ts}{nonce}{SECRET}"
    sig = hmac.new(SECRET.encode(), base.encode(), hashlib.sha256).hexdigest()
    return {"x-ts": str(ts), "x-nonce": nonce, "x-sign": sig}


def verify_against_capture(expected_sign: str, params: dict, body: str, ts: int, nonce: str) -> bool:
    """Sanity check: recompute the signature for a CAPTURED request and compare.

    Call this with values pulled from a real captured request. It must return
    True before you trust `sign()` for live calls.
    """
    got = sign(params, body, ts, nonce).get("x-sign")
    ok = hmac.compare_digest(got or "", expected_sign)
    print(f"[verify] {'MATCH' if ok else 'MISMATCH'} got={got} expected={expected_sign}")
    return ok
