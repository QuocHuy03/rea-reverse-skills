#!/usr/bin/env python3
"""
har-analyze.py — turn a browser HAR into a REVERSE MAP for a web target, so you
know what to attack instead of scrolling DevTools. The web analogue of the mobile
skill's analyze-capture.py.

    python har-analyze.py capture.har
    python har-analyze.py capture.har --host api.target.com
    python har-analyze.py capture.har --json          # rea-state-style fragment (for autopilot)

Reports: hosts + API endpoints, which requests carry SIGNATURE params/headers
(sign/nonce/ts/token/x-bogus/a_bogus/msToken…), the ANTI-BOT vendor in play
(Cloudflare/Akamai/DataDome/PerimeterX/Kasada/Imperva/jsvmp — from cookies +
headers), and endpoints whose body looks ENCRYPTED. Pure stdlib.
Capture the HAR yourself from your own browser session (DevTools Network ->
Save all as HAR). This tool only reads that file; it does not touch the site.
"""
import sys, json, re, math, base64, argparse
from collections import defaultdict, Counter

SIG = re.compile(r"(^sign$|signature|nonce|timestamp|^ts$|_token|x-?s-?common|x-?sign|x-?sig|"
                 r"x-bogus|a_bogus|x-gorgon|x-argus|mstoken|x-?mstoken|x-?tt|x-?s-?query|verifyfp|"
                 r"x-?secsdk|x-?ladon|appkey|app-?id|device-?id|x-?nonce|x-?ts|x-?requested-?with)", re.I)
SECRETISH = re.compile(r"^[A-Za-z0-9+/=_\-]{16,}$")

# anti-bot vendor fingerprints: cookie-name / header-name / path markers -> vendor
VENDOR_COOKIE = {
    "cf_clearance": "Cloudflare", "__cf_bm": "Cloudflare", "__cflb": "Cloudflare",
    "_abck": "Akamai Bot Manager", "bm_sz": "Akamai Bot Manager", "ak_bmsc": "Akamai Bot Manager", "bm_mi": "Akamai Bot Manager",
    "datadome": "DataDome",
    "_px": "PerimeterX/HUMAN", "_px2": "PerimeterX/HUMAN", "_px3": "PerimeterX/HUMAN", "pxhd": "PerimeterX/HUMAN", "_pxhd": "PerimeterX/HUMAN",
    "incap_ses": "Imperva/Incapsula", "visid_incap": "Imperva/Incapsula", "reese84": "Imperva/Incapsula", "nlbi": "Imperva/Incapsula",
    "kpsdk": "Kasada",
}
VENDOR_HDR = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-akamai-transformed": "Akamai Bot Manager",
    "x-datadome": "DataDome", "x-dd-b": "DataDome",
    "x-px": "PerimeterX/HUMAN", "x-px-authorization": "PerimeterX/HUMAN",
    "x-kpsdk-ct": "Kasada", "x-kpsdk-cd": "Kasada", "x-kpsdk-v": "Kasada",
    "x-iinfo": "Imperva/Incapsula",
}
VENDOR_PARAM = {"x-bogus": "ByteDance jsvmp (x-bogus/a_bogus)", "a_bogus": "ByteDance jsvmp (x-bogus/a_bogus)", "msToken": "ByteDance jsvmp (x-bogus/a_bogus)"}
VENDOR_PATH = {"/_incapsula_resource": "Imperva/Incapsula", "/ips.js": "Kasada", "/cdn-cgi/challenge": "Cloudflare",
               "/_sec/": "generic-bot-wall", "px-captcha": "PerimeterX/HUMAN"}


def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


def looks_encrypted(body):
    if not body: return False
    s = body.strip()
    try: json.loads(s); return False
    except Exception: pass
    raw = s.encode("utf-8", "replace")
    if SECRETISH.match(s) and len(s) % 4 == 0:
        try: raw = base64.b64decode(s, validate=True)
        except Exception: pass
    e = entropy(raw)
    printable = sum(1 for x in raw[:256] if 32 <= x < 127 or x in (9, 10, 13))
    ratio = printable / max(min(len(raw), 256), 1)
    return e > 4.6 and ratio < 0.85


def hv(headers):
    """HAR header list -> dict(lowername->value)."""
    return {h.get("name", "").lower(): h.get("value", "") for h in (headers or [])}


def main():
    ap = argparse.ArgumentParser(description="Summarize a HAR into a web reverse map: endpoints, signer params, anti-bot vendor, encrypted bodies.")
    ap.add_argument("har", help="path to a .har saved from DevTools (Network -> Save all as HAR)")
    ap.add_argument("--host", help="only this host (substring)")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable fragment (for an autopilot)")
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    args = ap.parse_args()

    try:
        with open(args.har, encoding="utf-8", errors="replace") as f:
            har = json.load(f)
        entries = har["log"]["entries"]
    except Exception as e:
        print("ERROR reading HAR %s: %s" % (args.har, e), file=sys.stderr); return 2

    hosts = Counter(); endpoints = Counter(); sig_hits = Counter()
    secrets = defaultdict(set); enc_eps = Counter(); vendors = Counter()
    xhr_hosts = Counter(); n = 0

    for e in entries:
        req = e.get("request", {}); resp = e.get("response", {})
        url = req.get("url", "") or ""
        m = re.match(r"https?://([^/]+)(/[^?]*)", url)
        host = m.group(1) if m else ""
        path = m.group(2) if m else ""
        if args.host and args.host not in host: continue
        n += 1; hosts[host] += 1

        reqh = hv(req.get("headers")); resph = hv(resp.get("headers"))
        # cookies: request cookies + response Set-Cookie
        cookie_names = set(c.get("name", "") for c in (req.get("cookies") or []))
        cookie_names |= set(c.get("name", "") for c in (resp.get("cookies") or []))
        sc = resph.get("set-cookie", "")
        for mm in re.finditer(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", sc):
            cookie_names.add(mm.group(1))

        # --- anti-bot vendor detection ---
        for cn in cookie_names:
            for key, ven in VENDOR_COOKIE.items():
                if key in cn.lower(): vendors[ven] += 1
        for hn in list(reqh) + list(resph):
            v = VENDOR_HDR.get(hn)
            if v: vendors[v] += 1
        low_url = url.lower()
        for pk, ven in VENDOR_PATH.items():
            if pk in low_url: vendors[ven] += 1
        qs = url.split("?", 1)[1] if "?" in url else ""
        for pk, ven in VENDOR_PARAM.items():
            if pk.lower() in qs.lower() or pk.lower() in reqh: vendors[ven] += 1
        if resp.get("status") in (403, 429) and ("just a moment" in (resph.get("server", "") + sc).lower()
                                                 or resph.get("server", "").lower() == "cloudflare"):
            vendors["Cloudflare"] += 1

        # treat XHR/fetch + api-ish paths as endpoints
        rtype = (e.get("_resourceType") or "").lower()
        is_api = rtype in ("xhr", "fetch") or re.search(r"/(api|ajax|graphql|v\d|rpc|gateway)/", path)
        if is_api:
            endpoints[(req.get("method", "?"), host, path)] += 1
            xhr_hosts[host] += 1
            # signer params/headers
            for hn, vv in reqh.items():
                if SIG.search(hn):
                    sig_hits[hn] += 1
                    if isinstance(vv, str) and SECRETISH.match(vv): secrets[hn].add(vv[:24] + ("…" if len(vv) > 24 else ""))
            for qp in re.findall(r"[?&]([^=]+)=", url):
                if SIG.search(qp): sig_hits[qp.lower()] += 1
            body = (req.get("postData", {}) or {}).get("text", "")
            if looks_encrypted(body): enc_eps[(req.get("method", "?"), host, path)] += 1
            rbody = (resp.get("content", {}) or {}).get("text", "")
            if looks_encrypted(rbody): enc_eps[("RESP", host, path)] += 1

    # recommended next
    nxt = None
    if vendors:
        top_v = vendors.most_common(1)[0][0]
        nxt = "anti-bot: %s -> docs/web-anti-bot-ladder.md (find the vendor section for the exact move); use curl_cffi impersonate for TLS/JA3" % top_v
    elif sig_hits:
        nxt = "signed requests (params: %s) -> find the signer in the JS bundle (REA export-web-scripts / web/sign-sniffer.js), reimplement, verify byte-for-byte" % ", ".join(sorted(sig_hits))
    elif enc_eps:
        nxt = "encrypted bodies -> find the CryptoJS/WebCrypto call in the bundle; port to pycryptodome"
    else:
        nxt = "no anti-bot / signing detected -> endpoints likely callable directly with curl_cffi impersonate + a real UA"

    if args.json:
        print(json.dumps({"capture": {
            "har": args.har, "requests": n,
            "hosts": [h for h, _ in hosts.most_common()],
            "api_endpoints": [[mm, h, p, c] for (mm, h, p), c in endpoints.most_common(80)],
            "signer_params": [k for k, _ in sig_hits.most_common()],
            "secrets": {k: sorted(v) for k, v in secrets.items()},
            "anti_bot_vendors": [v for v, _ in vendors.most_common()],
            "encrypted_endpoints": [[mm, h, p, c] for (mm, h, p), c in enc_eps.most_common(40)],
            "recommended_next": nxt,
        }}, indent=2))
        return 0

    bar = "=" * 72
    o = sys.stdout
    o.write(bar + "\nHAR map: %s  (%d requests)\n" % (args.har, n) + bar + "\n")
    o.write("\nANTI-BOT VENDOR (beat this first — see docs/web-anti-bot-ladder.md):\n")
    if vendors:
        for v, c in vendors.most_common(): o.write("  %5d  %s\n" % (c, v))
    else:
        o.write("  (none detected — plain site; curl_cffi impersonate likely enough)\n")
    o.write("\nAPI ENDPOINTS (method host path):\n")
    for (mm, h, p), c in endpoints.most_common(50): o.write("  %5d  %-6s %s%s\n" % (c, mm, h, p))
    o.write("\nSIGNATURE params/headers (reverse these):\n")
    if sig_hits:
        for k, c in sig_hits.most_common():
            ex = ("  e.g. " + ", ".join(sorted(secrets[k])[:2])) if secrets.get(k) else ""
            o.write("  %5d  %s%s\n" % (c, k, ex))
    else:
        o.write("  (none obvious — may sign in body or not at all)\n")
    o.write("\nLIKELY-ENCRYPTED bodies:\n")
    if enc_eps:
        for (mm, h, p), c in enc_eps.most_common(30): o.write("  %5d  %-6s %s%s\n" % (c, mm, h, p))
    else:
        o.write("  (none — bodies look like plain JSON)\n")
    o.write("\nNEXT: " + nxt + "\n" + bar + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
