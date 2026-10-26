# Giải captcha (captcha_solver.py)

Khi luồng reverse vướng captcha (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, image/funcaptcha…), dùng dịch vụ giải captcha qua API. Tất cả đều cùng mô hình: **gửi task → poll tới khi xong → lấy token**, rồi nhét token vào request như browser thật gửi.

> Cần **API key** của dịch vụ (user tự đăng ký + nạp tiền). Skill hỏi key khi tới bước này; **không hardcode key vào code commit** — đọc từ env/`.env`.

## Dịch vụ hỗ trợ (chọn 1, đều tương đương)

| Dịch vụ | Domain | Ghi chú |
|---|---|---|
| **NextCaptcha** | nextcaptcha.com | API gần giống 2captcha; có reCAPTCHA/hCaptcha/Turnstile |
| **2captcha** | 2captcha.com | Phổ biến nhất, docs đầy đủ, nhiều lib sẵn (`2captcha-python`) |
| **CapSolver** | capsolver.com | Nhanh, mạnh reCAPTCHA v3/Turnstile/FunCaptcha; endpoint `createTask`/`getTaskResult` |
| **EzCaptcha** | ezcaptcha.com | Rẻ, API kiểu CapSolver (`createTask`) |
| **Capzy** | capzy.ai | API **y hệt CapSolver** (`createTask`/`getTaskResult`, chỉ đổi base_url → `https://api.capzy.ai`); có SDK `pip install capzy` (`.solve()`); token-bound từ ~$0.40/1k, tặng $0.10 test. hCaptcha đang phát triển |

## Hai kiểu API

**a) Kiểu 2captcha / NextCaptcha** (in → out, 2 bước GET/POST):
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

**b) Kiểu CapSolver / EzCaptcha** (createTask → getTaskResult, JSON):
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

## Mẫu captcha_solver.py (đa nhà cung cấp)

```python
import os, time, requests

PROVIDER = os.getenv("CAPTCHA_PROVIDER", "capsolver")   # capsolver|ezcaptcha|capzy|2captcha|nextcaptcha
API_KEY  = os.getenv("CAPTCHA_API_KEY")

def solve_recaptcha_v2(site_key: str, page_url: str) -> str:
    """Trả về g-recaptcha-response token. Raise nếu fail/timeout."""
    if not API_KEY:
        raise RuntimeError("Thiếu CAPTCHA_API_KEY (env)")
    if PROVIDER in ("capsolver", "ezcaptcha", "capzy"):   # cùng shape createTask/getTaskResult
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

Đổi `type` theo loại captcha: `ReCaptchaV2TaskProxyLess`, `ReCaptchaV3TaskProxyLess`, `HCaptchaTaskProxyLess`, `AntiTurnstileTaskProxyLess`… (xem docs từng nhà cung cấp). Nếu site soi IP token → dùng task có proxy (`...Task` thay vì `...ProxyLess`) + truyền proxy.

**Fallback không dịch vụ:** chạy browser thật (Playwright) qua đúng màn captcha, lấy token sau khi giải tay/tự động, đưa về CLI — chậm, chỉ khi bí.
