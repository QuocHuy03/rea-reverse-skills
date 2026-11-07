#!/usr/bin/env python3
"""
verify-signer.py — prove your reimplemented signer matches the app, automatically.

You write `signer.py` with a function  sign(request) -> dict  that returns the
header(s) it computes for a request (request = a parsed fridacap NDJSON record:
keys method,url,host,path,headers,body). This tool replays your sign() over real
captured requests and checks the output BYTE-FOR-BYTE against what the app sent.
Green = your algorithm is correct; red = shows the first mismatch to debug.

    python verify-signer.py cap/requests.ndjson --signer signer.py
    python verify-signer.py cap/requests.ndjson --signer signer.py --headers x-sign,x-ts --host api.target.com

This automates SKILL step 4.5 ("ALWAYS verify empirically"). Pure stdlib.
NOTE: it imports and runs your --signer file (your own code).
"""
import sys, json, argparse, importlib.util


def load_func(path, name):
    spec = importlib.util.spec_from_file_location("user_signer", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, name, None)
    if not callable(fn):
        raise SystemExit("no callable %s() in %s" % (name, path))
    return fn


def main():
    ap = argparse.ArgumentParser(description="Verify a reimplemented signer against captured requests.")
    ap.add_argument("ndjson", help="fridacap requests.ndjson")
    ap.add_argument("--signer", required=True, help="path to your signer.py (must define sign(request)->dict)")
    ap.add_argument("--func", default="sign", help="function name (default sign)")
    ap.add_argument("--headers", help="comma list of header names to compare (default: all keys your sign() returns)")
    ap.add_argument("--host", help="only requests to this host (substring)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N requests (0 = all)")
    args = ap.parse_args()
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

    sign = load_func(args.signer, args.func)
    want = [h.strip().lower() for h in args.headers.split(",")] if args.headers else None

    total = ok = 0
    first_fail = None
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
            if args.host and args.host not in (r.get("host", "") or ""):
                continue

            try:
                produced = sign(r) or {}
            except Exception as e:
                first_fail = first_fail or ("sign() raised on %s %s: %r" % (r.get("method"), r.get("url"), e))
                total += 1
                continue
            produced = {k.lower(): str(v) for k, v in produced.items()}
            captured = {k.lower(): str(v) for k, v in (r.get("headers", {}) or {}).items()}
            keys = want or list(produced.keys())
            if not keys:
                continue
            total += 1
            mism = [k for k in keys if produced.get(k) != captured.get(k)]
            if not mism:
                ok += 1
            elif first_fail is None:
                lines = ["MISMATCH on %s %s" % (r.get("method"), r.get("url"))]
                for k in mism:
                    lines.append("    %-16s yours=%r" % (k, produced.get(k)))
                    lines.append("    %-16s app  =%r" % ("", captured.get(k)))
                first_fail = "\n".join(lines)
            if args.limit and total >= args.limit:
                break

    print("=" * 60)
    print("verified %d/%d requests match" % (ok, total))
    if ok == total and total:
        print("RESULT: PASS — signer reproduces the app byte-for-byte.")
        return 0
    if total == 0:
        print("RESULT: no matching requests found (check --host / the capture).")
        return 1
    print("RESULT: FAIL — first mismatch:\n" + (first_fail or "(no detail)"))
    print("Hint: wrong field order, missing/extra param, wrong secret, or ts/nonce taken from the wrong place.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
