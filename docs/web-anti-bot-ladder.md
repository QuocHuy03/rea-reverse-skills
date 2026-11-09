# Web anti-bot ladder — identify the vendor, then the move

On the web, the hard part usually isn't the request signer — it's the **anti-bot vendor** guarding the origin. Each vendor is a named, well-documented system; `scripts/har-analyze.py` tells you which one you're facing (from cookies/headers/paths). This is the web analogue of `hard-sign-types.md`: symptom → vendor → the exact move. Consolidated from `reverse-case-studies.md`, `china-re-arsenal.md`, `captcha-solvers.md` so it's in one place.

**The invariant:** you don't out-code the detector — you either (a) send a browser-identical TLS/JA3 + header order with the vendor's valid cookie/token (reproduce), or (b) generate the vendor's sensor/token payload the way its JS does, or (c) solve it in a real browser once and hand the token/cookie back to your client. Start with the cheapest that works. **Capture everything from your own authorized browser session; this doc is about reproducing your own access, not defeating protection on a target you have no right to.**

**First, always:** `curl_cffi` with `impersonate="chrome"` (JA3/HTTP2 fingerprint) + exact header order + a real `User-Agent`. Many "anti-bot" blocks are just TLS-fingerprint checks and fall to this alone. Only climb the ladder when a specific vendor cookie/challenge appears.

---

## Cloudflare — cookies `cf_clearance`, `__cf_bm`; header `cf-ray`; "Just a moment…" / `/cdn-cgi/challenge`

- **Managed Challenge / Turnstile:** the gate issues `cf_clearance` after a JS/Turnstile challenge. `__cf_bm` is a short-lived bot-management cookie (~30 min).
- **Move:** `cf_clearance` is bound to your **IP + User-Agent + TLS fingerprint** — so you must reuse all three consistently. Reproduce with `curl_cffi impersonate` + the exact UA that earned the cookie. For the challenge itself: solve Turnstile via a captcha service (`captcha-solvers.md`: CapSolver/2captcha/NextCaptcha support Turnstile) or a real browser (`nodriver`/`patchright`/`camoufox`) once, then carry `cf_clearance` forward. Keep the IP stable (residential proxy); rotating IP invalidates the clearance.
- **Note:** Cloudflare only challenges some routes (HTML navigation) and leaves JSON APIs open once you hold the cookie — grab it on first load, reuse for the API calls.

## Akamai Bot Manager — cookies `_abck`, `bm_sz`, `ak_bmsc`, `bm_mi`

- **`_abck` is the verdict cookie.** It must be "validated": the client POSTs a **sensor_data** telemetry blob to the Akamai endpoint, and a valid sensor flips `_abck` to a passing state (a trailing `~0~` vs `~-1~` pattern is the usual tell).
- **Move:** generate a valid **sensor_data** payload. Public generators exist (`xvertile/akamai-bmp-generator` for the mobile BMP variant; web sensor generators circulate on github/kanxue). Flow: GET page → get `bm_sz` → build sensor → POST to the Akamai script URL → `_abck` validates → proceed. For mobile Akamai it's the **BMP** protobuf (`akamai-bmp-generator`). Hard to hand-roll; reuse a maintained generator or solve-in-browser + reuse cookies.

## DataDome — cookie `datadome`; header `x-datadome`; JSON `{"url":"…geo.captcha-delivery.com…"}`

- **Move:** on block, DataDome returns a **slider/puzzle captcha** at `captcha-delivery.com`. Solve via a service that supports DataDome (CapSolver/2captcha — `captcha-solvers.md`) → get a fresh `datadome` cookie → attach to subsequent requests. The cookie is IP+UA bound → stable residential proxy + matching UA via `curl_cffi`. DataDome also fingerprints TLS → `impersonate` is mandatory, plain `requests` is instantly flagged.

## PerimeterX / HUMAN — cookies `_px`, `_px2`, `_px3`, `_pxhd`; header `x-px`

- **`_px3` is the token**, produced by PX's VM-obfuscated JS collecting device signals.
- **Move:** two options — (a) solve the PX captcha (`px-captcha`) via a service → cookie, or (b) use a **_px3 generator** (circulate on github/kanxue; VM-heavy, often version-pinned). Reproduce UA + TLS. HUMAN (renamed PerimeterX) tightened this; browser-solve + cookie reuse is the robust path when a generator isn't maintained.

## Kasada — headers `x-kpsdk-ct`, `x-kpsdk-cd`, `x-kpsdk-v`; script `/ips.js`, endpoint `/tl`

- **How it works:** `/ips.js` ships a VM that computes `x-kpsdk-ct` (a token) and `x-kpsdk-cd` (a solved payload) POSTed to `/tl`; the server then trusts subsequent requests carrying those headers.
- **Move:** Kasada is heavily VM-obfuscated — hand-reversing is research-grade. Realistic routes: a **Kasada solver service** (some captcha providers add Kasada; check current `captcha-solvers.md` providers) or run `/ips.js` in a headless browser (`nodriver`/`patchright`) to mint `x-kpsdk-*`, then reuse on API calls. Treat like jsvmp below: emulate/run its VM, don't reimplement.

## Imperva / Incapsula — cookies `incap_ses_*`, `visid_incap_*`, `reese84`, `nlbi_*`; path `/_Incapsula_Resource`

- **`reese84`** is the current token (from a challenge script `utmvc`/`_Incapsula_Resource?SWJIYLWA=…`). Older sites use the `___utmvc` cookie flow.
- **Move:** the challenge JS computes a payload POSTed back to `/_Incapsula_Resource`, which sets `reese84`. Solve by running the challenge script (browser or a maintained `reese84` generator on github/kanxue), get the cookie, reuse with `curl_cffi impersonate`. Incapsula also does TLS fingerprinting → impersonate required.

## ByteDance jsvmp — params `X-Bogus` / `a_bogus` / `msToken` (TikTok/Douyin web, and clones)

- **This is the web `x-argus`.** A VM-based obfuscated JS (jsvmp) computes `X-Bogus`/`a_bogus` over the request params + `msToken` (collected device/env signals). The query is rejected without a valid value, and it's **stateful** (ties to `msToken`, sometimes a counter).
- **Move:** **don't reimplement the VM — run it.** (a) Execute the site's own `a_bogus`/`X-Bogus` JS in a JS runtime (Node + the extracted vmp function, or a headless browser) feeding your params, get the value back — the JS analogue of a unidbg oracle. (b) Public implementations exist (`x-bogus`/`a_bogus` generators on github/kanxue; see `reverse-case-studies.md`). Fetch a fresh `msToken` the same way the page does. For the VM internals, the Chinese RE scene (kanxue/52pojie: search `a_bogus 算法 还原`, `jsvmp 扣代码`) has the deob writeups.

---

## Decide fast (symptom → vendor → move)

| Cookie / header / marker | Vendor | Move |
|---|---|---|
| `cf_clearance`, `__cf_bm`, `cf-ray`, "Just a moment" | Cloudflare | solve Turnstile/challenge once → reuse `cf_clearance` (IP+UA+TLS bound) |
| `_abck`, `bm_sz`, `ak_bmsc` | Akamai | generate valid `sensor_data` → validate `_abck` (use a maintained generator) |
| `datadome` cookie, `x-datadome` | DataDome | solve slider via service → reuse `datadome` cookie + impersonate |
| `_px3`, `_pxhd`, `x-px` | PerimeterX/HUMAN | `_px3` generator or browser-solve → reuse cookie |
| `x-kpsdk-ct/cd`, `/ips.js`, `/tl` | Kasada | run `/ips.js` VM (browser/solver) → mint `x-kpsdk-*` |
| `reese84`, `incap_ses`, `/_Incapsula_Resource` | Imperva | run the challenge JS → `reese84` cookie |
| `X-Bogus`/`a_bogus`/`msToken` params | ByteDance jsvmp | run the vmp JS as an oracle (Node/browser); don't reimplement |
| none, but plain `requests` gets 403 | TLS fingerprinting only | `curl_cffi impersonate="chrome"` + real UA + header order |

## Tools (client + solve + deobf)

Reproduce TLS: `lexiforest/curl_cffi` (impersonate — #1), `deedy5/primp`, `FlorianREGAZ/Python-Tls-Client`. Browser-solve + cookie harvest: `ultrafunkamsterdam/nodriver`, `Kaliiiiiiiiii-Vinyzu/patchright-python`, `daijro/camoufox`. Captcha/Turnstile/DataDome: providers in `captcha-solvers.md`. Deobfuscate the vendor/sign JS: `j4k0xb/webcrack`, `pionxzh/wakaru`, `relative/synchrony`. jsvmp/VM reversing writeups: kanxue `bbs.kanxue.com`, 52pojie `52pojie.cn`.

*The deeper principle for the VM-based ones (Kasada, jsvmp, PX): same as native signers — if you can't cheaply reimplement, **run the vendor's own code as an oracle** (headless browser or extracted JS in Node) and reuse its output. Reproduce your own authorized session; don't attack access you weren't granted.*
