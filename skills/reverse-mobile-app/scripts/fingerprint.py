#!/usr/bin/env python3
"""
fingerprint.py — triage an Android APK BEFORE you sink time into it.

One pass over the .apk (zip entries + a scan of the DEX bytes for class
descriptors) tells you: the UI framework, the networking stack, notable SDKs,
and how obfuscated the Java is — then prints the capture route that actually
works for this app (which beats defaulting to a MITM proxy and getting nothing).

Cross-platform (pure stdlib, runs on the Windows box too — no bash/.ps1 split).
    python fingerprint.py app.apk
    python fingerprint.py app.xapk          # xapk/apks: scans the inner base apk too
Idea borrowed + extended from SimoneAvogadro/android-reverse-engineering-skill
(fingerprint.sh); here it also classifies the TLS stack → the capture route.
"""
import sys, re, zipfile, argparse, io, json

# filename markers (checked against the zip's entry names)
FILE_MARKERS = {
    "Flutter":         [re.compile(r"lib/[^/]+/libflutter\.so$")],
    "React Native":    [re.compile(r"lib/[^/]+/libhermes\.so$"), re.compile(r"assets/index\.android\.bundle$"),
                        re.compile(r"lib/[^/]+/libjsc\.so$")],
    "Xamarin/.NET":    [re.compile(r"lib/[^/]+/libmonodroid\.so$"), re.compile(r"^assemblies/")],
    "Cordova/Ionic":   [re.compile(r"assets/www/")],
    "Unity":           [re.compile(r"lib/[^/]+/libunity\.so$")],
}
# TLS / networking stack markers → each maps to a capture route (see SKILL step 2/3)
TLS_FILE_MARKERS = {
    "cronet (ByteDance libsscronet)": [re.compile(r"lib/[^/]+/libsscronet\.so$")],
    "cronet (Chromium libcronet)":    [re.compile(r"lib/[^/]+/libcronet[.\w]*\.so$"), re.compile(r"lib/[^/]+/libmonochrome\.so$")],
    "BoringSSL fork (libttboringssl)":[re.compile(r"lib/[^/]+/libttboringssl\.so$")],
    "OpenSSL/BoringSSL (bundled)":    [re.compile(r"lib/[^/]+/lib(ssl|crypto|boringssl)\.so$")],
    "Flutter (BoringSSL in libflutter)": [re.compile(r"lib/[^/]+/libflutter\.so$")],
}
# class-descriptor markers scanned inside the DEX bytes (Lpkg/Sub/Class;)
DEX_MARKERS = {
    "OkHttp":            b"Lokhttp3/",
    "Retrofit":          b"Lretrofit2/",
    "Ktor":              b"Lio/ktor/",
    "Volley":            b"Lcom/android/volley/",
    "Apollo (GraphQL)":  b"Lcom/apollographql/",
    "Cronet (Java)":     b"Lorg/chromium/net/",
    "Koin (DI)":         b"Lorg/koin/",
    "Hilt/Dagger (DI)":  b"Ldagger/hilt/",
    "kotlinx.serialization": b"Lkotlinx/serialization/",
    "Conscrypt":         b"Lorg/conscrypt/",
}
SDK_MARKERS = {
    "Firebase":  b"Lcom/google/firebase/", "AppsFlyer": b"Lcom/appsflyer/",
    "Sentry":    b"Lio/sentry/",           "Datadog":   b"Lcom/datadog/",
    "Stripe":    b"Lcom/stripe/",          "Mixpanel":  b"Lcom/mixpanel/",
    "Intercom":  b"Lio/intercom/",         "TrustKit":  b"Lcom/datatheorem/",
    "Braze":     b"Lcom/braze/",           "Adjust":    b"Lcom/adjust/",
}
DESC_RE = re.compile(rb"L([a-z][A-Za-z0-9_]{0,1})/[A-Za-z0-9_/$]+;")   # top segment ≤2 chars → obfuscation signal


def _apk_bytes(path):
    """Return (namelist, dex_blobs). For xapk/apks, descend into the inner base apk."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        inner = [n for n in names if n.endswith(".apk") and ("base" in n.lower() or n.count("/") == 0)]
        if inner and not any(n.endswith(".dex") for n in names):
            with z.open(sorted(inner, key=len)[0]) as f:
                return _apk_bytes(io.BytesIO(f.read()))   # recurse into base.apk
        dex = b"".join(z.read(n) for n in names if n.endswith(".dex"))
    return names, dex


def main():
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows console is cp1252 by default
    except Exception: pass
    ap = argparse.ArgumentParser(description="Fingerprint an Android APK -> framework, TLS stack, SDKs, obfuscation, capture route.")
    ap.add_argument("apk", help="path to .apk / .xapk / .apks")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable rea-state.json 'fingerprint' fragment (for AUTOPILOT)")
    args = ap.parse_args()

    try:
        names, dex = _apk_bytes(args.apk)
    except Exception as e:
        print("ERROR reading %s: %s" % (args.apk, e), file=sys.stderr)
        return 2

    def file_hit(markers):
        return [k for k, pats in markers.items() if any(any(p.search(n) for n in names) for p in pats)]
    def dex_hit(markers):
        return [k for k, sig in markers.items() if sig in dex]

    frameworks = file_hit(FILE_MARKERS)
    tls = file_hit(TLS_FILE_MARKERS)
    net = dex_hit(DEX_MARKERS)
    sdks = dex_hit(SDK_MARKERS)

    # obfuscation: fraction of class descriptors whose top package segment is ≤2 chars
    top = DESC_RE.findall(dex)
    obf_level, obf_note = "LOW", "readable package names"
    if top:
        n = len(set(top))
        if n > 150:  obf_level, obf_note = "HIGH", "%d distinct short (<=2-char) top packages - heavily R8-obfuscated" % n
        elif n > 40: obf_level, obf_note = "MODERATE", "%d distinct short top packages - partly obfuscated" % n

    # --- machine-branchable route tags + the single next command (used by AUTOPILOT) ---
    tags, nxt = [], None
    if "Flutter" in frameworks:
        tags.append("flutter"); nxt = "decompile with blutter/reFlutter; python scripts/find-ssl-offsets.py <libflutter.so> --symbols ssl_read,ssl_write --out offsets.json ; then fridacap.py --offsets"
    if "React Native" in frameworks:
        tags.append("react-native"); nxt = nxt or "read assets/index.android.bundle (Hermes -> hermes-dec/hbctool); logic is JS, not smali"
    if "Xamarin/.NET" in frameworks:
        tags.append("xamarin"); nxt = nxt or "decompile assemblies/*.dll with ILSpy/dotPeek"
    if "Unity" in frameworks:
        tags.append("unity"); nxt = nxt or "Il2CppDumper on libil2cpp.so + global-metadata.dat"
    if any("cronet" in t for t in tls):
        tags.append("cronet"); nxt = nxt or "block UDP/443; python scripts/find-ssl-offsets.py <libcronet/libsscronet.so> --out offsets.json ; then fridacap.py --offsets offsets.json"
    if "BoringSSL fork (libttboringssl)" in tls:
        tags.append("boringssl-fork"); nxt = nxt or "anti-detect.js FIRST; ssl-unpin.js auto-hooks libttboringssl; signer is native (X-Argus/Gorgon) -> hard-sign-types.md type A"
    if obf_level in ("HIGH", "MODERATE") and not frameworks:
        tags.append("obf-kotlin"); nxt = nxt or "python scripts/recover-kotlin-names.py <decompiled_src> BEFORE hunting the signer"
    if not tags:
        tags.append("plain"); nxt = "MITM + system CA (setup-device.py --ca); if pinned: ssl-unpin.js; fallback capture-http.js"

    if args.json:
        print(json.dumps({"fingerprint": {
            "apk": args.apk, "framework": frameworks, "tls_stack": tls, "networking": net,
            "sdks": sdks, "obfuscation": obf_level, "route_tags": tags, "recommended_next": nxt,
        }}, indent=2))
        return 0

    print("=" * 64)
    print("APK fingerprint:", args.apk)
    print("=" * 64)
    print("UI framework   :", ", ".join(frameworks) or "native Android (Java/Kotlin)")
    print("TLS stack      :", ", ".join(tls) or "system libssl / Conscrypt (default)")
    print("Networking     :", ", ".join(net) or "(none of the common Java HTTP libs detected)")
    print("Notable SDKs   :", ", ".join(sdks) or "(none flagged)")
    print("Obfuscation    :", obf_level, "-", obf_note)
    print("-" * 64)

    # --- recommend a route (mirrors SKILL steps) ---
    route = []
    if "Flutter" in frameworks:
        route.append("Flutter -> Dart, NOT Java. Decompile with blutter/reFlutter; TLS lives in libflutter's BoringSSL "
                     "-> hook ssl_verify / use capture-http.js offsets. jadx on the Java shell is near-useless.")
    if "React Native" in frameworks:
        route.append("React Native -> logic is in assets/index.android.bundle (JS, possibly Hermes bytecode -> hbctool). "
                     "Read the bundle, not smali.")
    if "Xamarin/.NET" in frameworks:
        route.append("Xamarin -> code is in assemblies/*.dll -> decompile with ILSpy/dotPeek, not jadx.")
    if any("cronet" in t for t in tls):
        route.append("cronet detected -> system MITM often misses it + QUIC is invisible. Block UDP/443 (force QUIC->TCP), "
                     "then capture-http.js --offsets on the pulled .so (SKILL step 3). ssl-unpin.js also hits the Java Cronet pins.")
    if "BoringSSL fork (libttboringssl)" in tls:
        route.append("libttboringssl (Douyin/TikTok fork) -> ssl-unpin.js auto-hooks it; expect aggressive anti-Frida "
                     "-> load anti-detect.js FIRST; signing is native (X-Argus/X-Gorgon) = separate job.")
    if obf_level in ("HIGH", "MODERATE") and not frameworks:
        route.append("Obfuscated Kotlin -> recover class names from @Metadata/@DebugMetadata BEFORE hunting the signer (SKILL step 1).")
    if not route:
        route.append("Plain Java/Kotlin on the system TLS stack → standard path: MITM + system-CA (step 2); "
                     "if pinned, ssl-unpin.js; capture-http.js is the no-proxy fallback.")
    print("RECOMMENDED ROUTE:")
    for r in route:
        print("  -", r)
    print("-" * 64)
    print("Full per-stack procedure (exact tools + commands): docs/per-stack-reverse.md")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
