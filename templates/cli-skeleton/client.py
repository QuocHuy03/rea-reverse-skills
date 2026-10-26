"""client.py — the reimplemented API client.

Builds requests from scratch: TLS impersonation (curl_cffi), signed headers
(signer.py), optional body encryption (crypto_util.py), and session
persistence so you don't re-login every run. Add one get_*/do_* method per
endpoint you reversed, each with a docstring noting its quirks.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from curl_cffi import requests  # TLS/JA3 + HTTP2 impersonation

import signer

BASE_URL = os.getenv("BASE_URL", "https://api.example.com")
SESSION_FILE = Path(os.getenv("SESSION_FILE", "session.json"))
IMPERSONATE = os.getenv("IMPERSONATE", "chrome")


class Client:
    def __init__(self) -> None:
        self.session = requests.Session(impersonate=IMPERSONATE)
        # Stable per-account identity. Recover the real field names/values from
        # traffic; keep them CONSTANT per account (random = new device = OTP).
        self.device = {"device_id": "", "model": "", "app_version": ""}
        self.token: str | None = None

    # --- session persistence -------------------------------------------------
    def save_session(self) -> None:
        SESSION_FILE.write_text(json.dumps(
            {"token": self.token, "device": self.device,
             "cookies": dict(self.session.cookies)}, ensure_ascii=False))

    def load_session(self) -> bool:
        if not SESSION_FILE.exists():
            return False
        data = json.loads(SESSION_FILE.read_text())
        self.token = data.get("token")
        self.device = data.get("device", self.device)
        for k, v in (data.get("cookies") or {}).items():
            self.session.cookies.set(k, v)
        return bool(self.token)

    # --- low-level request with signing + retry ------------------------------
    def _request(self, method: str, path: str, params: dict | None = None,
                 body: str = "", retries: int = 3) -> requests.Response:
        params = params or {}
        headers = {"User-Agent": "okhttp/4.12.0"}          # match the real app
        headers.update(signer.sign(params, body))
        if self.token:
            headers["Authorization"] = self.token
        url = f"{BASE_URL}{path}"
        last = None
        for attempt in range(retries):
            try:
                r = self.session.request(method, url, params=params,
                                         data=body or None, headers=headers,
                                         timeout=30)
                if r.status_code < 500:
                    return r
                last = RuntimeError(f"HTTP {r.status_code}")
            except Exception as e:  # network/transport
                last = e
            time.sleep(2 ** attempt)                        # backoff
        raise last or RuntimeError("request failed")

    # --- auth ---------------------------------------------------------------
    def login(self, username: str, password: str) -> None:
        """Reversed login flow. Fill in path/fields; store token + persist."""
        r = self._request("POST", "/login",
                           params={"username": username, "password": password})
        data = r.json()
        self.token = data.get("token")  # adapt to real response shape
        if not self.token:
            raise RuntimeError(f"login failed: {data}")
        self.save_session()

    # --- endpoints (one method each; add as you reverse them) ---------------
    def get_profile(self) -> dict:
        """GET /profile. Example — replace with real endpoints."""
        return self._request("GET", "/profile").json()
