#!/usr/bin/env python3
"""
recover-kotlin-names.py — rebuild real class names from R8-obfuscated Kotlin.

R8 renames classes to `a/b/c` but CANNOT strip Kotlin's `@Metadata` /
`@DebugMetadata` annotations, which still embed the real fully-qualified names.
This walks the decompiled Java sources, pulls the real FQN out of those
annotations per file, and writes an obfuscated->real map so the signing /
repository / viewmodel classes surface by name.

    python recover-kotlin-names.py <decompiled_sources_dir> [out_dir]

Outputs in <out_dir> (default <src>/../names):
    mapping.tsv    obf_fqn <tab> real_fqn <tab> file
    mapping.json   { "a.b.c": "com.example.Foo", ... }
    by_package/<pkg>.txt    real <tab> obf <tab> file, grouped by real package

Class names only (not methods/fields). Treat as a strong hint, not gospel:
value classes and top-level *Kt facades can land under the wrong file.
Cross-platform, stdlib only. Technique from Kotlin @Metadata (idea popularized by
SimoneAvogadro/android-reverse-engineering-skill); this is an independent impl.
"""
import sys, os, re, json, argparse

# @DebugMetadata(... c = "com.example.Foo$bar$1") — the primary, most reliable source.
# Use .*? (not [^)]*?) so the match survives a ')' inside an earlier field (d1's
# protobuf strings / n={} param names commonly contain ')').
RE_DEBUG   = re.compile(r'@DebugMetadata\(.*?\bc\s*=\s*"([^"]+)"', re.S)
# @Metadata(... d2 = {"...","Lcom/example/Foo;",...}) — fallback; scan the d2 array.
RE_DTWO    = re.compile(r'@Metadata\(.*?\bd2\s*=\s*\{([^}]*)\}', re.S)
RE_LCLASS  = re.compile(r'L([A-Za-z][\w/$]+);')
# some builds store d2 entries already dotted and unwrapped: "com.example.Foo"
RE_DOTTED  = re.compile(r'"([a-z][\w.]*\.[A-Z]\w+)"')
# jadx leaves this comment when it recovers a name from debug info.
RE_RENAMED = re.compile(r'/\*\s*renamed from:\s*([\w.$]+)\s*\*/')

# don't bother mapping unobfuscated stdlib/third-party packages.
SKIP = ("kotlin.", "kotlinx.", "androidx.", "android.", "java.", "javax.",
        "com.google.", "okhttp3.", "okio.", "retrofit2.", "dagger.",
        "org.jetbrains.", "org.intellij.", "com.squareup.")


def _accept_dtwo(group):
    """First non-stdlib class name inside a d2 group, L...; form or dotted form."""
    for m in RE_LCLASS.finditer(group):
        cand = m.group(1).replace("/", ".").split("$", 1)[0]
        if "." in cand and not cand.startswith(("kotlin.", "java.", "android")):
            return cand
    for m in RE_DOTTED.finditer(group):
        cand = m.group(1).split("$", 1)[0]
        if not cand.startswith(("kotlin.", "java.", "android")):
            return cand
    return None


def recover_one(text):
    """Return (real_fqn, how) for one file's source, or (None, None)."""
    m = RE_DEBUG.search(text)
    if m:
        return m.group(1).split("$", 1)[0], "debug_meta"
    m = RE_DTWO.search(text)
    if m:
        cand = _accept_dtwo(m.group(1))
        if cand:
            return cand, "d2"
    m = RE_RENAMED.search(text)
    if m:
        return m.group(1), "renamed"
    return None, None


def main():
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    ap = argparse.ArgumentParser(description="Recover real Kotlin class names from @Metadata in decompiled sources.")
    ap.add_argument("src", help="decompiled sources dir (jadx/REA output, the folder with package dirs)")
    ap.add_argument("out", nargs="?", help="output dir (default <src>/../names)")
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    if not os.path.isdir(src):
        print("ERROR: not a directory: %s" % src, file=sys.stderr); return 2
    out = os.path.abspath(args.out) if args.out else os.path.join(os.path.dirname(src), "names")
    os.makedirs(os.path.join(out, "by_package"), exist_ok=True)

    mapping, file_of = {}, {}
    counts = {"debug_meta": 0, "d2": 0, "renamed": 0}
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            path = os.path.join(root, fn)
            obf = os.path.relpath(path, src)[:-5].replace(os.sep, ".")
            if obf.startswith(SKIP):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            real, how = recover_one(text)
            if real and real != obf:
                mapping[obf] = real
                file_of[obf] = os.path.relpath(path, src)
                counts[how] += 1

    # write mapping.tsv + mapping.json
    with open(os.path.join(out, "mapping.tsv"), "w", encoding="utf-8") as f:
        f.write("obf_fqn\treal_fqn\tfile\n")
        for obf in sorted(mapping):
            f.write("%s\t%s\t%s\n" % (obf, mapping[obf], file_of[obf]))
    with open(os.path.join(out, "mapping.json"), "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    # group by real package
    buckets = {}
    for obf, real in mapping.items():
        pkg = real.rsplit(".", 1)[0] if "." in real else "(default)"
        buckets.setdefault(pkg, []).append((real, obf, file_of[obf]))
    for pkg, rows in buckets.items():
        safe = os.path.basename(pkg).replace(".", "_") or "default"
        with open(os.path.join(out, "by_package", safe + ".txt"), "w", encoding="utf-8") as f:
            for real, obf, fl in sorted(rows):
                f.write("%s\t%s\t%s\n" % (real, obf, fl))

    print("Recovered %d class names (debug_meta=%d, d2=%d, renamed=%d)"
          % (len(mapping), counts["debug_meta"], counts["d2"], counts["renamed"]))
    print("Real packages: %d" % len(buckets))
    print("Wrote %s\\mapping.tsv, mapping.json, by_package/" % out)
    print("Tip: grep mapping.tsv for Sign|Crypto|Token|Repository|Api to find the signer by its REAL name.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
