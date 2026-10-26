# Solving captchas (captcha_solver.py)

When the reverse-engineering flow hits a captcha (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, image/funcaptcha…), solve it via a captcha-solving service's API. They all follow the same model: **submit a task → poll until done → get a token**, then insert the token into the request exactly as a real browser would send it.

> You need the service's **API key** (the user registers and tops it up themselves). The skill asks for the key when it reaches this step; **do not hardcode the key into committed code** — read it from env/`.env`.

## Supported services (pick one, all equivalent)

| Service | Domain | Notes |
|---|---|---|
| **NextCaptcha** | nextcaptcha.com | API close to 2captcha's; supports reCAPTCHA/hCaptcha/Turnstile |
| **2captcha** | 2captcha.com | The most popular; full docs, many ready-made libs (`2captcha-python`) |
| **CapSolver** | capsolver.com | Fast, strong on reCAPTCHA v3/Turnstile/FunCaptcha; `createTask`/`getTaskResult` endpoints |
| **EzCaptcha** | ezcaptcha.com | Cheap, CapSolver-style API (`createTask`) |
| **Capzy** | capzy.ai | API **identical to CapSolver** (`createTask`/`getTaskResult`, only change base_url → `https://api.capzy.ai`); has a `pip install capzy` SDK (`.solve()`); token-bound from ~$0.40/1k, $0.10 free to test. hCaptcha in development |

## Two API styles

**a) 2captcha / NextCaptcha style** (in → out, 2-step GET/POST):
```python
# submit
r = requests.post("https://api.2captcha.com/in.php", data={
    "key": API_KEY, "method": "userrecaptcha",
    "googlekey": SITE_KEY, "pageurl": PAGE_URL, "json": 1,
}).json()
task_id = r["request"]
# poll
while True:
    time.sleep(5)
    res = requests.get("https://api.2captcha.com/res.php",
        params={"key": API_KEY, "action": "get", "id": task_id, "json": 1}).json()
    if res["status"] == 1:
        token = res["request"]; break
```

**b) CapSolver / EzCaptcha style** (createTask → getTaskResult, JSON):
```python
base = "https://api.capsolver.com"   # ezcaptcha: https://api.ezcaptcha.com
tid = requests.post(f"{base}/createTask", json={
    "clientKey": API_KEY,
    "task": {"type": "ReCaptchaV2TaskProxyLess",
             "websiteURL": PAGE_URL, "websiteKey": SITE_KEY},
}).json()["taskId"]
while True:
    time.sleep(3)
    res = requests.post(f"{base}/getTaskResult",
        json={"clientKey": API_KEY, "taskId": tid}).json()
    if res["status"] == "ready":
        token = res["solution"]["gRecaptchaResponse"]; break
```

## Sample captcha_solver.py (multi-provider)

```python
import os, time, requests

PROVIDER = os.getenv("CAPTCHA_PROVIDER", "capsolver")   # capsolver|ezcaptcha|capzy|2captcha|nextcaptcha
API_KEY  = os.getenv("CAPTCHA_API_KEY")

def solve_recaptcha_v2(site_key: str, page_url: str) -> str:
    """Return the g-recaptcha-response token. Raise on failure/timeout."""
    if not API_KEY:
        raise RuntimeError("Missing CAPTCHA_API_KEY (env)")
    if PROVIDER in ("capsolver", "ezcaptcha", "capzy"):   # same createTask/getTaskResult shape
        base = {"capsolver": "https://api.capsolver.com",
                "ezcaptcha": "https://api.ezcaptcha.com",
                "capzy":     "https://api.capzy.ai"}[PROVIDER]
        tid = requests.post(f"{base}/createTask", json={
            "clientKey": API_KEY,
            "task": {"type": "ReCaptchaV2TaskProxyLess",
                     "websiteURL": page_url, "websiteKey": site_key}}).json()["taskId"]
        for _ in range(40):
            time.sleep(3)
            res = requests.post(f"{base}/getTaskResult",
                json={"clientKey": API_KEY, "taskId": tid}).json()
            if res.get("status") == "ready":
                return res["solution"]["gRecaptchaResponse"]
        raise TimeoutError("captcha timeout")
    else:  # 2captcha / nextcaptcha
        base = {"2captcha": "https://api.2captcha.com",
                "nextcaptcha": "https://api.nextcaptcha.com"}[PROVIDER]
        tid = requests.post(f"{base}/in.php", data={
            "key": API_KEY, "method": "userrecaptcha",
            "googlekey": site_key, "pageurl": page_url, "json": 1}).json()["request"]
        for _ in range(40):
            time.sleep(5)
            res = requests.get(f"{base}/res.php", params={
                "key": API_KEY, "action": "get", "id": tid, "json": 1}).json()
            if res.get("status") == 1:
                return res["request"]
        raise TimeoutError("captcha timeout")
```

Change `type` according to the captcha kind: `ReCaptchaV2TaskProxyLess`, `ReCaptchaV3TaskProxyLess`, `HCaptchaTaskProxyLess`, `AntiTurnstileTaskProxyLess`… (see each provider's docs). If the site checks the token's IP → use a task with a proxy (`...Task` instead of `...ProxyLess`) and pass the proxy.

**No-service fallback:** drive a real browser (Playwright) through the captcha screen, obtain the token after solving it manually/automatically, and feed it back to the CLI — slow, only when stuck.
