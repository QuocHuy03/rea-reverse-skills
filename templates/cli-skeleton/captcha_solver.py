"""captcha_solver.py — multi-provider captcha solving.

Providers share two API shapes: in/res (2captcha, nextcaptcha) and
createTask/getTaskResult (capsolver, ezcaptcha, capzy). See
docs/captcha-solvers.md. Set CAPTCHA_PROVIDER + CAPTCHA_API_KEY in env.
"""
from __future__ import annotations

import os
import time

import requests  # or use the client's session

PROVIDER = os.getenv("CAPTCHA_PROVIDER", "capsolver")
API_KEY = os.getenv("CAPTCHA_API_KEY")

_CREATE_TASK_BASE = {
    "capsolver": "https://api.capsolver.com",
    "ezcaptcha": "https://api.ezcaptcha.com",
    "capzy": "https://api.capzy.ai",
}
_IN_RES_BASE = {
    "2captcha": "https://api.2captcha.com",
    "nextcaptcha": "https://api.nextcaptcha.com",
}


def solve_recaptcha_v2(site_key: str, page_url: str, timeout_s: int = 120) -> str:
    """Return a g-recaptcha-response token. Raises on failure/timeout.

    Change the task `type` for other captchas: ReCaptchaV3TaskProxyLess,
    HCaptchaTaskProxyLess, AntiTurnstileTaskProxyLess, etc. If the site binds
    the token to an IP, use the proxy task variants.
    """
    if not API_KEY:
        raise RuntimeError("Missing CAPTCHA_API_KEY (env)")

    if PROVIDER in _CREATE_TASK_BASE:
        base = _CREATE_TASK_BASE[PROVIDER]
        tid = requests.post(f"{base}/createTask", json={
            "clientKey": API_KEY,
            "task": {"type": "ReCaptchaV2TaskProxyLess",
                     "websiteURL": page_url, "websiteKey": site_key},
        }).json()["taskId"]
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            time.sleep(3)
            res = requests.post(f"{base}/getTaskResult",
                                json={"clientKey": API_KEY, "taskId": tid}).json()
            if res.get("status") == "ready":
                return res["solution"]["gRecaptchaResponse"]
        raise TimeoutError("captcha timeout")

    if PROVIDER in _IN_RES_BASE:
        base = _IN_RES_BASE[PROVIDER]
        tid = requests.post(f"{base}/in.php", data={
            "key": API_KEY, "method": "userrecaptcha",
            "googlekey": site_key, "pageurl": page_url, "json": 1,
        }).json()["request"]
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            time.sleep(5)
            res = requests.get(f"{base}/res.php", params={
                "key": API_KEY, "action": "get", "id": tid, "json": 1,
            }).json()
            if res.get("status") == 1:
                return res["request"]
        raise TimeoutError("captcha timeout")

    raise ValueError(f"Unknown CAPTCHA_PROVIDER: {PROVIDER}")
