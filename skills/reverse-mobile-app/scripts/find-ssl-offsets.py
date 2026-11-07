#!/usr/bin/env python3
"""
find-ssl-offsets.py — auto-build the offsets.json for capture-http.js / fridacap.py.

Reads a pulled .so (libcronet / libttboringssl / libflutter / any bundled
BoringSSL) and finds SSL_read / SSL_write by parsing the ELF symbol tables —
BOTH .dynsym AND .symtab. That matters: Frida's Module.findExportByName only
sees .dynsym (dynamic exports), so a lib that keeps the functions in .symtab
looks "stripped" at runtime but the offsets are right there in the file. This
tool reads them straight off disk and writes the JSON fridacap.py --offsets wants.

    python find-ssl-offsets.py libcronet.117.0.5938.0.so
    python find-ssl-offsets.py libnative.so --symbols SSL_read,SSL_write,ssl_log_secret
    python find-ssl-offsets.py lib.so --module libcronet.117.so --out offsets.json
    python find-ssl-offsets.py lib.so --pattern SSL_read=1F2003D5FD7BBFA9F44F01A9  # byte-sig fallback

If the symbols are truly stripped (no .symtab either), pass --pattern SYM=HEX to
byte-scan the executable sections (friTap-style prologue signatures); the tool
reports the virtual offset of the first match. Cross-platform, stdlib only.
Output is base-relative offsets (absolute:false) = offset from the module base,
exactly what capture-http.js resolves against Process.findModuleByName(...).base.
"""
import sys, os, json, struct, argparse, re

# ELF constants
SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM = 2, 3, 11
SHF_EXECINSTR = 0x4
MACHINE = {0x28: "arm", 0xB7: "arm64", 0x03: "x86", 0x3E: "x86_64", 0x08: "mips"}


class ELF:
    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.data = data
        self.is64 = data[4] == 2
        self.le = data[5] == 1
        self.e = "<" if self.le else ">"
        self.machine = MACHINE.get(struct.unpack_from(self.e + "H", data, 18)[0], "?")
        self.is_dyn = struct.unpack_from(self.e + "H", data, 16)[0] == 3  # ET_DYN
        if self.is64:
            (self.shoff,) = struct.unpack_from(self.e + "Q", data, 40)
            self.shentsize, self.shnum, self.shstrndx = struct.unpack_from(self.e + "HHH", data, 58)
        else:
            (self.shoff,) = struct.unpack_from(self.e + "I", data, 32)
            self.shentsize, self.shnum, self.shstrndx = struct.unpack_from(self.e + "HHH", data, 46)
        self.sections = [self._shdr(self.shoff + i * self.shentsize) for i in range(self.shnum)]

    def _shdr(self, off):
        d, e = self.data, self.e
        if self.is64:
            name, typ, flags, addr, offset, size, link, info, align, entsize = \
                struct.unpack_from(e + "IIQQQQIIQQ", d, off)
        else:
            name, typ, flags, addr, offset, size, link, info, align, entsize = \
                struct.unpack_from(e + "IIIIIIIIII", d, off)
        return dict(name=name, type=typ, flags=flags, addr=addr, offset=offset,
                    size=size, link=link, entsize=entsize)

    def _cstr(self, base, idx):
        end = self.data.find(b"\x00", base + idx)
        return self.data[base + idx:end].decode("utf-8", "replace")

    def symbols(self):
        """Yield (name, st_value) from every SYMTAB/DYNSYM section."""
        for sh in self.sections:
            if sh["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            strtab = self.sections[sh["link"]]["offset"]
            ent = sh["entsize"] or (24 if self.is64 else 16)
            n = sh["size"] // ent if ent else 0
            for i in range(n):
                off = sh["offset"] + i * ent
                if self.is64:
                    st_name, _info, _other, _shndx, st_value = \
                        struct.unpack_from(self.e + "IBBHQ", self.data, off)
                else:
                    st_name, st_value, _size, _info, _other, _shndx = \
                        struct.unpack_from(self.e + "IIIBBH", self.data, off)
                if st_name == 0 or st_value == 0:
                    continue
                yield self._cstr(strtab, st_name), st_value

    def exec_ranges(self):
        """(file_offset, size, vaddr) of executable sections, for pattern scanning."""
        out = []
        for sh in self.sections:
            if sh["flags"] & SHF_EXECINSTR and sh["size"]:
                out.append((sh["offset"], sh["size"], sh["addr"]))
        return out

    def scan_pattern(self, hexpat):
        """Return the virtual offset of the first match of a hex byte pattern
        (no wildcards) within an executable section, or None."""
        pat = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", hexpat))
        for foff, size, vaddr in self.exec_ranges():
            idx = self.data.find(pat, foff, foff + size)
            if idx != -1:
                return vaddr + (idx - foff)   # file offset -> virtual offset
        return None


def main():
    ap = argparse.ArgumentParser(description="Auto-build offsets.json (SSL_read/SSL_write) from a .so for fridacap.py --offsets.")
    ap.add_argument("so", help="path to the pulled .so (libcronet/libttboringssl/libflutter/…)")
    ap.add_argument("--symbols", default="SSL_read,SSL_write", help="comma list to find (default SSL_read,SSL_write)")
    ap.add_argument("--module", help="on-device module name for the JSON key (default: the .so basename)")
    ap.add_argument("--out", help="write JSON here (default: stdout)")
    ap.add_argument("--pattern", action="append", default=[],
                    help="SYM=HEX byte-signature fallback for a stripped symbol (repeatable)")
    args = ap.parse_args()

    try:
        with open(args.so, "rb") as f:
            elf = ELF(f.read())
    except Exception as e:
        print("ERROR reading %s: %s" % (args.so, e), file=sys.stderr)
        return 2

    want = [s.strip() for s in args.symbols.split(",") if s.strip()]
    pats = {}
    for p in args.pattern:
        if "=" in p:
            k, v = p.split("=", 1); pats[k.strip()] = v.strip()

    found, how = {}, {}
    # 1) symbol tables (.dynsym + .symtab) — reliable
    symmap = {}
    for name, val in elf.symbols():
        if name in want and name not in symmap:
            symmap[name] = val
    for s in want:
        if s in symmap:
            found[s] = symmap[s]; how[s] = "symbol"
    # 2) byte-pattern fallback for whatever's still missing
    for s in want:
        if s not in found and s in pats:
            off = elf.scan_pattern(pats[s])
            if off is not None:
                found[s] = off; how[s] = "pattern"

    module = args.module or os.path.basename(args.so)
    if not elf.is_dyn:
        print("WARN: %s is not ET_DYN; st_value may not be a base-relative offset." % args.so, file=sys.stderr)

    print("ELF: %s  arch=%s  %s-bit  %s" %
          (os.path.basename(args.so), elf.machine, 64 if elf.is64 else 32,
           "shared-object" if elf.is_dyn else "executable"), file=sys.stderr)
    for s in want:
        if s in found:
            print("  %-12s 0x%x  (via %s)" % (s, found[s], how[s]), file=sys.stderr)
        else:
            print("  %-12s NOT FOUND  (stripped? pass --pattern %s=<hex> or find it in REA)" % (s, s), file=sys.stderr)

    if not found:
        print("No offsets found — nothing written.", file=sys.stderr)
        return 1

    obj = {module: {s: {"addr": "0x%x" % found[s], "absolute": False} for s in found}}
    text = json.dumps(obj, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote %s" % args.out, file=sys.stderr)
        print("  use: python fridacap.py --device <id> --attach <pid> --offsets %s" % args.out, file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
