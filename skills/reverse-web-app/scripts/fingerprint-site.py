#!/usr/bin/env python3
"""
fingerprint-site.py — triage a web target from a saved HAR BEFORE you sink time
in. The web analogue of the mobile skill's fingerprint.py.

One pass over the HAR tells you: the front-end framework/bundler, the server/CDN
tech, the anti-bot vendor, and the recommended route. Pair with har-analyze.py
(which maps the traffic); this one classifies the stack.

    python fingerprint-site.py capture.har
    python fingerprint-site.py capture.har --json      # machine-readable fragment

Pure stdlib. Reads your own saved HAR only; it does not touch the site.
"""
import sys, json, re, argparse
from collections import Counter

# front-end framework markers: in the document HTML or in script URLs
HTML_MARKERS = {
    "Next.js": [re.compile(r"__NEXT_DATA__|/_next/static/")],
    "Nuxt": [re.compile(r"window\.__NUXT__|/_nuxt/")],
    "Remix": [re.compile(r"__remixContext")],
    "SvelteKit": [re.compile(r"__sveltekit|/_app/immutable/")],
    "Angular": [re.compile(r"ng-version=|/runtime\.[0-9a-f]+\.js")],
    "Vue": [re.compile(r"data-v-[0-9a-f]{8}|__VUE__")],
    "React (generic)": [re.compile(r"data-reactroot|__REACT_DEVTOOLS")],
    "Gatsby": [re.compile(r"___gatsby")],
}
SCRIPT_MARKERS = {
    "Next.js": re.compile(r"/_next/static/"),
    "Nuxt": re.compile(r"/_nuxt/"),
    "Turbopack": re.compile(r"/chunks/turbopack-"),
    "Webpack": re.compile(r"/static/js/|chunk\.[0-9a-f]+\.js"),
    "Vite": re.compile(r"/assets/index-[0-9A-Za-z_]+\.js"),
}
VENDOR_COOKIE = {"cf_clearance": "Cloudflare", "__cf_bm": "Cloudflare", "_abck": "Akamai",
                 "datadome": "DataDome", "_px3": "PerimeterX/HUMAN", "_pxhd": "PerimeterX/HUMAN",
                 "reese84": "Imperva", "incap_ses": "Imperva", "kpsdk": "Kasada"}
VENDOR_HDR = {"cf-ray": "Cloudflare", "x-datadome": "DataDome", "x-kpsdk-ct": "Kasada",
              "x-iinfo": "Imperva", "x-px": "PerimeterX/HUMAN"}


def hv(headers):
    return {h.get("name", "").lower(): h.get("value", "") for h in (headers or [])}


def main():
    ap = argparse.ArgumentParser(description="Fingerprint a web target from a HAR -> framework, server/CDN, anti-bot vendor, route.")
    ap.add_argument("har", help="path to a .har from DevTools")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable fragment")
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    args = ap.parse_args()

    try:
        with open(args.har, encoding="utf-8", errors="replace") as f:
            entries = json.load(f)["log"]["entries"]
    except Exception as e:
        print("ERROR reading HAR %s: %s" % (args.har, e), file=sys.stderr); return 2

    frameworks = set(); bundlers = set(); servers = Counter(); cdns = set(); vendors = Counter()
    main_host = None

    for e in entries:
        req = e.get("request", {}); resp = e.get("response", {})
        url = req.get("url", "") or ""
        reqh = hv(req.get("headers")); resph = hv(resp.get("headers"))
        ctype = resph.get("content-type", "")

        # script-URL markers
        for fw, pat in SCRIPT_MARKERS.items():
            if pat.search(url):
                (bundlers if fw in ("Turbopack", "Webpack", "Vite") else frameworks).add(fw)
        # document HTML markers
        if "text/html" in ctype:
            if main_host is None:
                m = re.match(r"https?://([^/]+)", url)
                if m: main_host = m.group(1)
            body = (resp.get("content", {}) or {}).get("text", "") or ""
            for fw, pats in HTML_MARKERS.items():
                if any(p.search(body) for p in pats): frameworks.add(fw)
        # server / CDN / powered-by
        srv = resph.get("server", "")
        if srv: servers[srv] += 1
        if "cloudflare" in srv.lower() or "cf-ray" in resph: cdns.add("Cloudflare")
        if resph.get("x-vercel-id") or "vercel" in resph.get("server", "").lower(): cdns.add("Vercel")
        if resph.get("x-amz-cf-id") or "cloudfront" in srv.lower(): cdns.add("CloudFront")
        if resph.get("x-powered-by"): servers[resph["x-powered-by"]] += 1
        # anti-bot vendor
        cnames = set(c.get("name", "") for c in (req.get("cookies") or []))
        cnames |= set(c.get("name", "") for c in (resp.get("cookies") or []))
        for mm in re.finditer(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", resph.get("set-cookie", "")):
            cnames.add(mm.group(1))
        for cn in cnames:
            for key, ven in VENDOR_COOKIE.items():
                if key in cn.lower(): vendors[ven] += 1
        for hn in list(reqh) + list(resph):
            if hn in VENDOR_HDR: vendors[VENDOR_HDR[hn]] += 1

    fw = sorted(frameworks); bd = sorted(bundlers); vd = [v for v, _ in vendors.most_common()]

    # recommended route
    if vd:
        route = "anti-bot %s present -> docs/web-anti-bot-ladder.md for the vendor move; always curl_cffi impersonate" % vd[0]
    elif fw and any("Next" in x or "Nuxt" in x or "Remix" in x for x in fw):
        route = "SSR/meta-framework (%s) -> data often in __NEXT_DATA__/__NUXT__ or /api routes; read the inline JSON + the API, bundle in /_next or /_nuxt" % ", ".join(fw)
    elif fw:
        route = "SPA (%s) -> logic is in the JS bundle; export+read it (REA export-web-scripts) to find the signer/crypto" % ", ".join(fw)
    else:
        route = "plain/SSR site -> hit the API directly with curl_cffi impersonate + real UA"

    if args.json:
        print(json.dumps({"fingerprint": {
            "har": args.har, "main_host": main_host,
            "framework": fw, "bundler": bd,
            "server": [s for s, _ in servers.most_common(5)], "cdn": sorted(cdns),
            "anti_bot_vendors": vd, "recommended_route": route,
        }}, indent=2))
        return 0

    bar = "=" * 64
    print(bar + "\nSite fingerprint: %s  (host %s)\n" % (args.har, main_host or "?") + bar)
    print("Framework   :", ", ".join(fw) or "(none detected — SSR/plain or unknown)")
    print("Bundler     :", ", ".join(bd) or "(n/a)")
    print("Server/tech :", ", ".join(s for s, _ in servers.most_common(5)) or "(none)")
    print("CDN         :", ", ".join(sorted(cdns)) or "(none)")
    print("Anti-bot    :", ", ".join(vd) or "(none detected)")
    print("-" * 64)
    print("RECOMMENDED ROUTE:\n  -", route)
    print(bar)
    return 0


if __name__ == "__main__":
    sys.exit(main())
