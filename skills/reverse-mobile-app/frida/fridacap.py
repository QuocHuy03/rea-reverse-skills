#!/usr/bin/env python3
"""
fridacap.py — scale-friendly HTTP(S) capture harness for capture-http.js.

Hooks BoringSSL SSL_read/SSL_write inside the target process(es) (no proxy,
no CA, works through pinning) and writes one NDJSON record per HTTP request /
response. Built for capturing across MANY apps/sites at once.

Examples:
  # one app, spawn fresh, 30s, follow child processes (cronet net-service, etc.)
  python fridacap.py --spawn com.example.app --follow --seconds 30

  # attach to everything already running (broad recon)
  python fridacap.py --attach-all --seconds 60 --exclude googleapis.com

  # a specific running app by name, until Ctrl-C, only one host
  python fridacap.py --attach "Chrome" --include example.com

Device: defaults to the USB/first device (LDPlayer over TCP shows up as USB too);
override with --device 127.0.0.1:5557.
"""
import argparse, sys, os, time, json, zlib, re, datetime, threading
import frida
try:
    import hpack
    from hyperframe.frame import Frame, HeadersFrame, ContinuationFrame, DataFrame
    H2_OK = True
except Exception:
    H2_OK = False

H2_BODY_CAP = 256 * 1024     # max body bytes kept per h2 message (JSON payloads fit; big downloads are cut)


class H2Conn:
    """Decode one direction of an HTTP/2 connection's plaintext byte stream into
    full messages (HPACK-decoded headers + reassembled DATA body). Modern apps
    (OkHttp/cronet) speak h2, where the request line lives in Huffman-coded HPACK
    and the body rides in DATA frames — so hooking only shows binary frames. This
    turns a stream back into method/path/authority + the POST/JSON body (the part
    you actually need to replay a signed API call). Needs the stream from its
    start (connections opened after we attach), because HPACK is stateful.

    feed() returns a list of completed messages {headers, body, cut}; a message
    completes on END_STREAM. flush() returns streams that got headers but no
    END_STREAM before capture ended, so nothing in-flight is silently lost."""
    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def __init__(self):
        self.buf = b""
        self.dec = hpack.Decoder()
        self.streams = {}    # sid -> {frag, hdr, body:bytearray, cut, hdr_done}
        self.ok = True

    def _st(self, sid):
        s = self.streams.get(sid)
        if s is None:
            s = self.streams[sid] = {"frag": b"", "hdr": None, "body": bytearray(),
                                     "cut": False, "hdr_done": False}
        return s

    def feed(self, data):
        out = []
        if not self.ok:
            return out
        self.buf += data
        if self.buf.startswith(self.PREFACE):
            self.buf = self.buf[len(self.PREFACE):]
        while len(self.buf) >= 9:
            try:
                fr, length = Frame.parse_frame_header(memoryview(self.buf[:9]))
            except Exception:
                self.ok = False; break           # not really h2 / desynced
            if len(self.buf) < 9 + length:
                break
            payload = self.buf[9:9 + length]; self.buf = self.buf[9 + length:]
            try:
                fr.parse_body(memoryview(payload))
            except Exception:
                continue
            if isinstance(fr, (HeadersFrame, ContinuationFrame)):
                s = self._st(fr.stream_id)
                s["frag"] += fr.data
                if "END_HEADERS" in fr.flags:
                    try:
                        s["hdr"] = dict(self.dec.decode(s["frag"])); s["hdr_done"] = True
                    except Exception:
                        self.ok = False; continue
                    s["frag"] = b""
                if "END_STREAM" in fr.flags:
                    out.append(self._finish(fr.stream_id))
            elif isinstance(fr, DataFrame):
                s = self._st(fr.stream_id)
                room = H2_BODY_CAP - len(s["body"])
                if room > 0:
                    s["body"] += fr.data[:room]
                if len(fr.data) > room:
                    s["cut"] = True
                if "END_STREAM" in fr.flags:
                    out.append(self._finish(fr.stream_id))
        return [m for m in out if m]

    def _finish(self, sid):
        s = self.streams.pop(sid, None)
        if not s or not s["hdr"]:
            return None
        return {"headers": s["hdr"], "body": bytes(s["body"]), "cut": s["cut"]}

    def flush(self):
        """Emit streams that received headers but no END_STREAM (capture cut mid-flight)."""
        out = []
        for sid in list(self.streams):
            s = self.streams[sid]
            if s["hdr_done"] and s["hdr"]:
                m = self._finish(sid)
                if m:
                    m["cut"] = m["cut"] or bool(m["body"])  # likely incomplete
                    out.append(m)
        return out

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "capture-http.js")
METHOD_RE = re.compile(rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE) ")

# Attaching Frida to core system processes (zygote, system_server, HALs) and
# enabling spawn-gating on top can kill system_server (DeadSystemException).
# --attach-all therefore only touches real app processes.
_SKIP_PREFIX = ("android.hardware", "android.hidl", "android.system", "android.process",
                "vendor.", "android.ext.", "com.android.se")
_SKIP_EXACT = {"system_server", "zygote", "zygote64", "usap32", "usap64"}

def is_app_proc(name):
    if not name or "." not in name:      # native daemons: netd, logd, vold, surfaceflinger…
        return False
    if name in _SKIP_EXACT:
        return False
    for p in _SKIP_PREFIX:
        if name.startswith(p):
            return False
    return True


def now_iso():
    return datetime.datetime.now().isoformat(timespec="milliseconds")


def parse_headers(block: bytes):
    """block = bytes up to (not incl.) the blank line. Returns (first_line, {hdr:val})."""
    lines = block.split(b"\r\n")
    first = lines[0].decode("latin1", "replace") if lines else ""
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            hdrs[k.decode("latin1", "replace").strip().lower()] = v.decode("latin1", "replace").strip()
    return first, hdrs


class Capture:
    def __init__(self, args):
        self.args = args
        self.inc = [s for s in (args.include or []) if s]
        self.exc = [s for s in (args.exclude or []) if s]
        # Stripped-BoringSSL hooking (libcronet/libflutter): static base+offset
        # from REA (preferred) and/or prologue byte-patterns. Passed to the agent
        # via configure() so it hooks SSL_read/SSL_write by raw address.
        self.offsets = self._load_json(args.offsets, "offsets")
        self.patterns = self._load_json(args.patterns, "patterns")
        os.makedirs(args.out, exist_ok=True)
        self.nd = open(os.path.join(args.out, "requests.ndjson"), "a", encoding="utf-8")
        self.lock = threading.Lock()
        self.sessions = {}          # pid -> session
        self.conn_host = {}         # (pid,conn) -> last request host (to tag responses)
        self.h2conns = set()        # (pid,conn) known to speak HTTP/2
        self.h2_out = {}            # (pid,conn) -> H2Conn for requests
        self.h2_in = {}             # (pid,conn) -> H2Conn for responses
        self.count = 0
        self.raw_dir = os.path.join(args.out, "raw") if args.raw else None
        if self.raw_dir:
            os.makedirs(self.raw_dir, exist_ok=True)

    @staticmethod
    def _load_json(path, what):
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            print("loaded %s for %d module(s): %s" % (what, len(d), ", ".join(d.keys())))
            return d
        except Exception as e:
            print("WARN: could not load --%s %s: %s" % (what, path, e), file=sys.stderr)
            return None

    # ---- filtering ----
    def allow(self, host):
        h = host or ""
        if self.inc and not any(s in h for s in self.inc):
            return False
        if self.exc and any(s in h for s in self.exc):
            return False
        return True

    # ---- record output ----
    def write(self, rec):
        with self.lock:
            self.nd.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.nd.flush()
            self.count += 1

    # ---- message handling (per process) ----
    def on_message(self, pid, msg, data):
        if msg.get("type") == "error":
            print("ERR[%s]| %s" % (pid, msg.get("stack", msg)), file=sys.stderr)
            return
        p = msg.get("payload")
        if not isinstance(p, dict):
            return
        if p.get("t") == "log":
            return
        if p.get("t") != "tls" or data is None:
            # script status console.logs arrive as 'log' type, handled by frida; ignore
            return
        conn = (pid, p.get("conn"))
        if self.raw_dir:
            self._dump_raw(conn, p.get("dir"), data)
        head, _, body = data.partition(b"\r\n\r\n")

        if p.get("dir") == "out" and METHOD_RE.match(data):
            first, hdrs = parse_headers(head)
            parts = first.split(" ")
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else ""
            ver = parts[2] if len(parts) > 2 else ""
            host = hdrs.get("host", "")
            self.conn_host[conn] = host
            if not self.allow(host):
                return
            rec = {
                "ts": now_iso(), "pid": pid, "conn": p.get("conn"), "kind": "request",
                "method": method, "url": ("https://" + host + path) if host else path,
                "host": host, "path": path, "http_version": ver, "headers": hdrs,
                "body_len": len(body),
                "body": body.decode("utf-8", "replace") if body and len(body) < 8192 else None,
            }
            self.write(rec)
            print("[%s] >>> %-6s %s" % (pid, method, rec["url"]))

        elif p.get("dir") == "in" and data.startswith(b"HTTP/"):
            first, hdrs = parse_headers(head)
            host = self.conn_host.get(conn, "")
            if not self.allow(host):
                return
            parts = first.split(" ", 2)
            status = (parts[1] + " " + parts[2]) if len(parts) > 2 else first
            gzip = "gzip" in hdrs.get("content-encoding", "")
            preview = None
            if body:
                raw = body
                if gzip:
                    try:
                        raw = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                    except Exception:
                        raw = None
                if raw is not None:
                    preview = raw[:2048].decode("utf-8", "replace")
            rec = {
                "ts": now_iso(), "pid": pid, "conn": p.get("conn"), "kind": "response",
                "status": status, "host": host, "headers": hdrs,
                "body_len": len(body), "gzip": gzip, "body_preview": preview,
            }
            self.write(rec)
            ct = hdrs.get("content-type", "").split(";")[0]
            print("[%s] <<< %-16s %-28s %s" % (pid, status, host, ct))

        elif H2_OK and p.get("dir") == "out" and (conn in self.h2conns or data.startswith(H2Conn.PREFACE)):
            self.h2conns.add(conn)
            hc = self.h2_out.get(conn) or self.h2_out.setdefault(conn, H2Conn())
            for msg in hc.feed(data):
                self._emit_h2_request(pid, conn, p.get("conn"), msg)

        elif H2_OK and p.get("dir") == "in" and conn in self.h2conns:
            hc = self.h2_in.get(conn) or self.h2_in.setdefault(conn, H2Conn())
            for msg in hc.feed(data):
                self._emit_h2_response(pid, conn, p.get("conn"), msg)

        else:
            # Not HTTP/1 — usually HTTP/2 binary frames (HPACK). We can't fully
            # parse them, but readable literal strings (hosts/paths) often leak,
            # so record a lightweight entry so h2 apps aren't silently empty.
            strings = re.findall(rb"[ -~]{5,}", data)
            hints = [s.decode("latin1") for s in strings]
            hostish = [s for s in hints if "." in s and " " not in s and len(s) < 100]
            is_h2 = data[:3] == b"PRI"
            if p.get("dir") == "out" and (is_h2 or hostish):
                rec = {
                    "ts": now_iso(), "pid": pid, "conn": p.get("conn"), "kind": "raw-out",
                    "proto": "http2-preface" if is_h2 else "tls-data",
                    "bytes": p.get("len"), "ascii_hints": hints[:30],
                }
                self.write(rec)
                print("[%s] >>> [raw %sB h2?] %s" % (pid, p.get("len"), " ".join(hostish[:4])))

    # ---- HTTP/2 message emit (headers + reassembled body) ----
    @staticmethod
    def _decode_body(body, hdrs):
        """Return (text_or_None, gzip_bool). Gunzips if content-encoding says so."""
        if not body:
            return None, False
        gzip = "gzip" in (hdrs.get("content-encoding", "") or "")
        raw = body
        if gzip:
            try:
                raw = zlib.decompress(body, 16 + zlib.MAX_WBITS)
            except Exception:
                return None, True
        return raw[:H2_BODY_CAP].decode("utf-8", "replace"), gzip

    def _emit_h2_request(self, pid, conn, conn_id, msg):
        hd = msg["headers"]
        method, path, auth = hd.get(":method"), hd.get(":path"), hd.get(":authority")
        if not method or not path:
            return
        host = auth or ""
        self.conn_host[conn] = host
        if not self.allow(host):
            return
        body_text, _ = self._decode_body(msg["body"], hd)
        rec = {"ts": now_iso(), "pid": pid, "conn": conn_id, "kind": "request",
               "method": method, "url": ("https://" + host + path) if host else path,
               "host": host, "path": path, "http_version": "HTTP/2", "headers": hd,
               "body_len": len(msg["body"]), "body_cut": msg["cut"], "body": body_text}
        self.write(rec)
        extra = "  [body %dB%s]" % (len(msg["body"]), "+" if msg["cut"] else "") if msg["body"] else ""
        print("[%s] >>> %-6s %s%s" % (pid, method, rec["url"], extra))

    def _emit_h2_response(self, pid, conn, conn_id, msg):
        hd = msg["headers"]
        status = hd.get(":status")
        if not status:
            return
        host = self.conn_host.get(conn, "")
        if not self.allow(host):
            return
        body_text, gzip = self._decode_body(msg["body"], hd)
        rec = {"ts": now_iso(), "pid": pid, "conn": conn_id, "kind": "response",
               "status": status, "host": host, "http_version": "HTTP/2", "headers": hd,
               "body_len": len(msg["body"]), "gzip": gzip, "body_cut": msg["cut"],
               "body_preview": (body_text[:2048] if body_text else None),
               # full decoded body (already capped at H2_BODY_CAP) so JSON API
               # responses can be parsed offline, not just previewed
               "body": body_text}
        self.write(rec)
        print("[%s] <<< %-16s %-28s %s" % (pid, status, host, hd.get("content-type", "")))

    def flush_h2(self):
        """At shutdown, drain streams that never saw END_STREAM so in-flight
        requests/responses (e.g. a long download) aren't dropped."""
        if not H2_OK:
            return
        for conn, hc in list(self.h2_out.items()):
            for msg in hc.flush():
                self._emit_h2_request(conn[0], conn, conn[1], msg)
        for conn, hc in list(self.h2_in.items()):
            for msg in hc.flush():
                self._emit_h2_response(conn[0], conn, conn[1], msg)

    def _dump_raw(self, conn, direction, data):
        fn = os.path.join(self.raw_dir, "%s_%s.%s.bin" % (conn[0], conn[1], direction))
        try:
            with open(fn, "ab") as f:
                f.write(data)
        except Exception:
            pass

    # ---- attaching ----
    def attach_pid(self, pid, label=""):
        if pid in self.sessions:
            return
        try:
            session = self.device.attach(pid)
        except Exception as e:
            return
        try:
            script = session.create_script(open(AGENT, "r", encoding="utf-8").read())
            script.on("message", lambda m, d, _pid=pid: self.on_message(_pid, m, d))
            script.load()
            cfg = {"mode": "send"}
            if self.offsets:
                cfg["offsets"] = self.offsets
            if self.patterns:
                cfg["patterns"] = self.patterns
            info = script.exports_sync.configure(cfg)
            self.sessions[pid] = session
            hk = ",".join((info.get("ssl") or []) + (info.get("conscrypt") or [])) or "(none yet)"
            extra = (info.get("offsets") or []) + (info.get("patterns") or [])
            if extra:
                hk += "  stripped=[" + ",".join(extra) + "]"
            print("  attached pid=%s %s  hooked=[%s]" % (pid, label, hk))
        except Exception as e:
            print("  attach pid=%s failed: %s" % (pid, e), file=sys.stderr)

    def resolve_device(self, dev_id):
        """Robust device pick: by id → USB → first non-local, with a short retry
        (frida's device list can lag an adb (re)connect)."""
        last = None
        for _ in range(6):
            try:
                if dev_id:
                    try:
                        return frida.get_device(dev_id, timeout=2)
                    except Exception as e:
                        last = e
                        # id may not be registered yet; try to match by substring
                        for d in frida.enumerate_devices():
                            if dev_id in (d.id or ""):
                                return d
                try:
                    return frida.get_usb_device(timeout=2)
                except Exception as e:
                    last = e
                for d in frida.enumerate_devices():
                    if d.type in ("usb", "remote") and d.id not in ("local", "socket", "barebone"):
                        return d
            except Exception as e:
                last = e
            time.sleep(1)
        raise SystemExit("no device found (%s). Is the emulator up + frida-server running? "
                         "Try: adb connect <ip:port>, then --device <that id>." % last)

    def run(self):
        a = self.args
        self.device = self.resolve_device(a.device)
        print("device:", self.device.id, "| out:", a.out)

        if a.follow:
            try:
                self.device.enable_spawn_gating()
                def on_spawn(spawn):
                    # resume FIRST so a slow/failed attach never freezes the system
                    name = spawn.identifier or ""
                    if is_app_proc(name):
                        self.attach_pid(spawn.pid, "(spawned %s)" % name)
                    try: self.device.resume(spawn.pid)
                    except Exception: pass
                self.device.on("spawn-added", on_spawn)
                print("spawn-gating ON (following new processes)")
            except Exception as e:
                print("spawn-gating unavailable:", e, file=sys.stderr)

        if a.spawn:
            pid = self.device.spawn([a.spawn])
            self.attach_pid(pid, "(%s)" % a.spawn)
            self.device.resume(pid)
        elif a.attach:
            try:
                pid = int(a.attach)
            except ValueError:
                pid = self.device.get_process(a.attach).pid
            self.attach_pid(pid, "(%s)" % a.attach)
        elif a.attach_all:
            procs = [p for p in self.device.enumerate_processes() if is_app_proc(p.name)]
            print("attaching to %d app processes (system procs skipped)" % len(procs))
            for proc in procs:
                self.attach_pid(proc.pid, "(%s)" % proc.name)
        else:
            print("pick one of --spawn / --attach / --attach-all", file=sys.stderr)
            return

        print("capturing%s — Ctrl-C to stop" % ((" %ds" % a.seconds) if a.seconds else ""))
        try:
            if a.seconds:
                time.sleep(a.seconds)
            else:
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            pass
        self.flush_h2()
        print("\n--- done: %d records -> %s ---" % (self.count, os.path.join(a.out, "requests.ndjson")))


def main():
    ap = argparse.ArgumentParser(description="Scale HTTP(S) capture via capture-http.js")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--spawn", metavar="PKG", help="spawn a package fresh")
    g.add_argument("--attach", metavar="NAME|PID", help="attach to a running process")
    g.add_argument("--attach-all", action="store_true", help="attach to every running process")
    ap.add_argument("--follow", action="store_true", help="follow newly spawned child processes")
    ap.add_argument("--device", help="frida device id (e.g. 127.0.0.1:5557); default USB/first")
    ap.add_argument("--out", default="fridacap-" + time.strftime("%Y%m%d-%H%M%S"), help="output dir")
    ap.add_argument("--seconds", type=int, default=0, help="capture duration (0 = until Ctrl-C)")
    ap.add_argument("--include", action="append", default=[], help="only hosts containing this (repeatable)")
    ap.add_argument("--exclude", action="append", default=[], help="drop hosts containing this (repeatable)")
    ap.add_argument("--raw", action="store_true", help="also dump raw per-connection byte streams")
    ap.add_argument("--offsets", metavar="FILE",
                    help="JSON {module:{SSL_read:{addr,absolute},SSL_write:{…}}} to hook stripped "
                         "BoringSSL (libcronet/libflutter) by base+offset found with REA — see README")
    ap.add_argument("--patterns", metavar="FILE",
                    help="JSON {module:{SSL_read:'<hex>',SSL_write:'<hex>'}} prologue byte-signatures "
                         "(fallback when you have no offsets; build/arch specific)")
    Capture(ap.parse_args()).run()


if __name__ == "__main__":
    main()
