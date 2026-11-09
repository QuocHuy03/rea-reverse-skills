# signed-api-demo — the web reverse pipeline, end-to-end, on a local target

A self-contained, authorized-by-construction demo: a local API that behaves like
a real "hard" target (HMAC-SHA256 request signing + AES-CBC encrypted body), and
the **reversed client** that signs itself, calls it headless, and decrypts the
response. It proves the skill's claims with running code and doubles as a smoke
test. Nothing leaves localhost.

## Run

```
python run_demo.py        # exit 0 = PASS
```

Expected output: the reimplemented signer matches the target **byte-for-byte**,
then the client signs → calls → decrypts and prints real data (`user/balance/…`).

## What maps to a real reverse

| File | Real-world analogue |
| --- | --- |
| `target_server.py` | the site you're reversing (you don't have its source; here we do, to generate the fixture) |
| `target_server.canonical()` | the exact string the app signs — in a real job you recover this with `web/sign-sniffer.js` (watch the hash input) |
| `SIGN_SECRET`, `AES_KEY/IV` | constants you'd recover from the JS bundle (REA `export_web_scripts` → `recover_javascript_sources`) |
| `client.py` (`sign`, `decrypt_body`) | `signer.py` + `crypto_util.py` in the real deliverable |
| `run_demo.py` signer check | what `verify-signer` automates: prove the reimplemented signer == the app before trusting it |
| `client.get_data()` | the final headless `client.py` — no browser, signs itself, returns data |

## The pipeline it exercises (per SKILL.md / AUTOPILOT.md "Web targets")

capture → `har-analyze.py` / `fingerprint-site.py` locate the signed endpoint →
`web/sign-sniffer.js` reveals the canonical string + key → reimplement signer +
crypto in Python → **verify byte-for-byte** → `client.py` calls the real API.

This fixture starts at "you've recovered the algorithm" and proves the client
half runs correctly. Swap in a target you are authorized to reverse to do the
discovery half for real.
