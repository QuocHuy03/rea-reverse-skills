# CLI skeleton

A ready-to-adapt starting point for the **deliverable** every skill in this
repo targets: a single stable Python CLI that talks to a reversed API. Copy
this folder, rename it after your target, and fill in the pieces you recovered
while reversing — don't start from scratch.

```
cli.py            # entrypoint: subcommands, exit codes, JSON/plain output
client.py         # Client(): session persistence, curl_cffi impersonation, signed + retried requests
signer.py         # sign() — THE HEART; verify against a real capture before trusting it
crypto_util.py    # AES body/response encryption helpers (if the target encrypts)
captcha_solver.py # multi-provider captcha (only if the target has captcha)
requirements.txt
.env.example      # copy to .env; never commit the real .env
```

## Use

```bash
pip install -r requirements.txt
cp .env.example .env            # then fill in BASE_URL etc.
python cli.py login --username u --password p
python cli.py profile --json
```

## Fill-in order (matches the skills)

1. **signer.py** — reimplement the recovered signature, then
   `verify_against_capture()` against one real captured request. Must MATCH
   before anything else.
2. **crypto_util.py** — if bodies/responses are encrypted, set KEY/IV/mode and
   decrypt one captured response into valid JSON to confirm.
3. **client.py** — set `BASE_URL`, the real `User-Agent`/headers, the stable
   per-account `device` identity, the `login()` flow, and one `get_*`/`do_*`
   method per endpoint.
4. **cli.py** — add one subcommand per action. Keep it idempotent, headless,
   with clear exit codes (0 = pass).

## Notes

- Keep the per-account device/fingerprint **stable** (persisted), or the server
  treats each call as a new device and re-triggers OTP/anti-fraud.
- Prefer reusing the saved session over re-login (login is the risky step).
- If the signer lives in a native `.so` you can't reimplement, see
  `docs/reverse-case-studies.md` (emulate with unidbg) or use the Frida
  native-RPC fallback (`skills/reverse-mobile-app/frida/rpc-signer.js`).
- Never commit `.env`, `session.json`, credentials, or real proxies.
