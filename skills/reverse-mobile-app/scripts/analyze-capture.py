#!/usr/bin/env python3
"""
analyze-capture.py — turn fridacap's requests.ndjson into a REVERSE MAP so you
know what to attack, instead of scrolling raw JSON.

    python analyze-capture.py cap/requests.ndjson
    python analyze-capture.py cap/requests.ndjson --host api.target.com

Reports: endpoints (method+host+path), which requests carry SIGNATURE headers
(x-sign/nonce/ts/token…), header values that LOOK LIKE SECRETS/keys, and
endpoints whose body is likely ENCRYPTED (high-entropy, not JSON). Pure stdlib.
"""
import sys, json, re, math, base64, argparse
from collections import defaultdict, Counter

SIG_HDR = re.compile(r"(sign|signature|nonce|timestamp|^ts$|token|hmac|digest|"
                     r"x-.*-(sign|sig|auth)|appkey|app-?id|secret|device-?id|x-ss-|x-argus|x-gorgon|x-ladon)", re.I)
SECRETISH = re.compile(r"^[A-Za-z0-9+/=_\-]{16,}$")   # long opaque value → candidate key/token


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def looks_encrypted(body):
    """True if body is non-empty, not valid JSON/text, and high-entropy (or a b64 blob that decodes to high-entropy)."""
    if not body:
        return False
    s = body.strip()
    try:
        json.loads(s); return False            # plain JSON → not encrypted
    except Exception:
        pass
    raw = s.encode("utf-8", "replace")
    # if it's base64, decode and test the bytes
    if SECRETISH.match(s) and len(s) % 4 == 0:
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception:
            pass
    e = entropy(raw)
    printable = sum(1 for x in raw[:256] if 32 <= x < 127 or x in (9, 10, 13))
    ratio = printable / max(min(len(raw), 256), 1)
    return e > 4.6 and ratio < 0.85            # random-ish and not mostly text


def main():
    ap = argparse.ArgumentParser(description="Summarize fridacap requests.ndjson into a reverse map.")
    ap.add_argument("ndjson", help="path to requests.ndjson")
    ap.add_argument("--host", help="only this host (substring)")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable rea-state.json 'capture' fragment (for AUTOPILOT)")
    args = ap.parse_args()
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

    endpoints = Counter()
    sig_hdrs = Counter()
    secrets = defaultdict(set)         # header name -> set of values seen
    enc_endpoints = Counter()
    hosts = Counter()
    hdr_names = defaultdict(Counter)   # host -> header-name counts
    n_req = 0

    with open(args.ndjson, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("kind") != "request":
                continue
            host = r.get("host", "") or ""
            if args.host and args.host not in host:
                continue
            n_req += 1
            hosts[host] += 1
            path = (r.get("path", "") or "").split("?")[0]
            endpoints[(r.get("method", "?"), host, path)] += 1
            headers = r.get("headers", {}) or {}
            for k, v in headers.items():
                hdr_names[host][k.lower()] += 1
                if SIG_HDR.search(k):
                    sig_hdrs[k.lower()] += 1
                    if isinstance(v, str) and SECRETISH.match(v):
                        secrets[k.lower()].add(v[:24] + ("…" if len(v) > 24 else ""))
            if looks_encrypted(r.get("body")):
                enc_endpoints[(r.get("method", "?"), host, path)] += 1

    if args.json:
        top_ep = endpoints.most_common(1)
        nxt = None
        if sig_hdrs:
            ep = ("%s %s%s" % top_ep[0][0]) if top_ep else "a signed endpoint"
            nxt = ("signer present (headers: %s) -> run `frida -U -f <pkg> -l frida/signer-sniffer.js --no-pause`, "
                   "trigger %s, classify the family via docs/hard-sign-types.md ('classify in 60s'); "
                   "reimplement signer.py -> python scripts/verify-signer.py <ndjson> --signer signer.py (must PASS)"
                   % (", ".join(sorted(sig_hdrs)), ep))
        elif enc_endpoints:
            nxt = "no sign headers but bodies look encrypted -> crypto-dump.js then docs/decryption-playbook.md"
        else:
            nxt = "no signing/encryption detected -> endpoints are likely callable directly; build client.py"
        frag = {"capture": {
            "ndjson": args.ndjson, "requests": n_req,
            "hosts": [h for h, _ in hosts.most_common()],
            "endpoints": [[m, h, p, c] for (m, h, p), c in endpoints.most_common(60)],
            "signer_headers": [k for k, _ in sig_hdrs.most_common()],
            "secrets": {k: sorted(v) for k, v in secrets.items()},
            "encrypted_endpoints": [[m, h, p, c] for (m, h, p), c in enc_endpoints.most_common(40)],
            "recommended_next": nxt,
        }}
        print(json.dumps(frag, indent=2))
        return 0

    out = sys.stdout
    bar = "=" * 70
    out.write(bar + "\nCapture map: %s  (%d requests)\n" % (args.ndjson, n_req) + bar + "\n")
    out.write("\nHOSTS:\n")
    for h, c in hosts.most_common():
        out.write("  %5d  %s\n" % (c, h or "(none)"))
    out.write("\nENDPOINTS (method host path):\n")
    for (m, h, p), c in endpoints.most_common(60):
        out.write("  %5d  %-6s %s%s\n" % (c, m, h, p))
    out.write("\nSIGNATURE/AUTH HEADERS seen (reverse these first):\n")
    if sig_hdrs:
        for k, c in sig_hdrs.most_common():
            vals = ("  e.g. " + ", ".join(sorted(secrets[k])[:3])) if secrets.get(k) else ""
            out.write("  %5d  %s%s\n" % (c, k, vals))
    else:
        out.write("  (none — app may sign in the body or not at all)\n")
    out.write("\nLIKELY-ENCRYPTED BODY endpoints (decrypt these — see decryption-playbook.md):\n")
    if enc_endpoints:
        for (m, h, p), c in enc_endpoints.most_common(40):
            out.write("  %5d  %-6s %s%s\n" % (c, m, h, p))
    else:
        out.write("  (none detected — bodies look like plain JSON/text)\n")
    out.write(bar + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
