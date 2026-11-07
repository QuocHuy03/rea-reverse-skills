/*
 * capture-http.js — dump raw plaintext HTTP(S) by hooking BoringSSL
 * SSL_write / SSL_read. You see requests BEFORE encryption and responses
 * AFTER decryption, so no proxy and no CA install are needed, and it works
 * even against certificate pinning (the bytes are read inside the process).
 * Pair with ssl-unpin.js only if the app refuses to connect at all.
 *
 * Two output modes:
 *  - 'console' (default): human-readable dump — use standalone for quick triage:
 *      frida -U -f <package> -l capture-http.js --no-pause
 *  - 'send': structured binary events for a host harness (fridacap.py) that
 *      reassembles/parses HTTP and writes NDJSON. Enabled via rpc configure.
 *      Use this to capture across MANY apps/sites at scale.
 *
 * Stripped/static BoringSSL (libcronet, libflutter) has no SSL_read/SSL_write
 * exports to scan, so the host can also pass OFFSETS (base+offset from REA/
 * Ghidra static analysis — most reliable) and/or PATTERNS (prologue byte-
 * signatures, Memory.scan'd) via rpc.configure to hook those by raw address.
 * See README for how to produce the offsets with REA + the UDP/443 block that
 * forces QUIC apps back onto capturable TLS-over-TCP.
 *
 * '>>>' = SSL_write (outgoing / request), '<<<' = SSL_read (incoming / response).
 */
'use strict';

var MAX = 256 * 1024;         // cap bytes per call (send mode ships full chunks)
var TEXT_ONLY = true;         // console mode: only print buffers that look like text
var MODE = 'console';         // 'console' | 'send' (set by host via rpc.configure)

/* Frida 17-safe module/export resolution (with legacy fallback) */
function _mod(name) { try { return Process.findModuleByName(name); } catch (_) { return null; } }
function modExport(name, sym) {
  var m = _mod(name);
  try { if (m && m.findExportByName) { var p = m.findExportByName(sym); if (p) return p; } } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(name, sym); } catch (_) {}
  return null;
}
function globalExport(sym) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym); } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(null, sym); } catch (_) {}
  return null;
}

function looksTextual(u8) {
  var n = Math.min(u8.length, 64), printable = 0;
  for (var i = 0; i < n; i++) {
    var c = u8[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  return n > 0 && printable / n > 0.85;
}

// dir: 'out' (SSL_write/request) | 'in' (SSL_read/response); conn = SSL* id
function emit(dir, conn, ptr_, len) {
  if (!ptr_ || ptr_.isNull() || len <= 0) return;
  try {
    var take = Math.min(len, MAX);
    var ab = ptr_.readByteArray(take);
    if (!ab) return;
    if (MODE === 'send') {
      // ship raw bytes + metadata; the host reassembles/parses/decodes.
      send({ t: 'tls', dir: dir, conn: conn, pid: Process.id, ts: Date.now(), len: len, cut: len > take }, ab);
      return;
    }
    // console mode: human-readable, text-only
    var u8 = new Uint8Array(ab);
    if (TEXT_ONLY && !looksTextual(u8)) return;   // skip TLS records / binary blobs
    var s = '';
    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    var label = dir === 'out' ? '>>> WRITE' : '<<< READ';
    console.log('\n==== ' + label + ' ' + len + ' bytes ====\n' + s +
                (len > take ? '\n…(+' + (len - take) + ' more)' : ''));
  } catch (e) { /* ignore unreadable buffers */ }
}

function modSymbols(name) {
  var m = _mod(name);
  try { if (m && m.enumerateSymbols) return m.enumerateSymbols(); } catch (_) {}
  try { if (Module.enumerateSymbols) return Module.enumerateSymbols(name); } catch (_) {}
  return [];
}

/* Conscrypt (Android's Java TLS behind HttpsURLConnection/OkHttp) does NOT call
 * the classic SSL_read/SSL_write — it uses ENGINE_SSL_{read,write}_direct, which
 * carry the PLAINTEXT. Hooking only SSL_read/SSL_write misses almost all Java
 * apps, so we also hook these (local JNI symbols, found via enumerateSymbols).
 * Sig: (JNIEnv*, jclass, jlong sslRef, jobject, jlong address, jint len, jobject)
 *   → conn=a[2], buffer=a[4], len=a[5] (write) / retval (read). */
function hookConscrypt(modName) {
  var n = 0;
  modSymbols(modName).forEach(function (s) {
    if (!s.address || s.address.isNull()) return;
    if (s.name.indexOf('ENGINE_SSL_write_direct') !== -1) {
      Interceptor.attach(s.address, {
        onEnter: function (a) { emit('out', a[2].toString(), a[4], a[5].toInt32()); },
      });
      n++;
    } else if (s.name.indexOf('ENGINE_SSL_read_direct') !== -1) {
      Interceptor.attach(s.address, {
        onEnter: function (a) { this.conn = a[2].toString(); this.buf = a[4]; },
        onLeave: function (ret) { emit('in', this.conn, this.buf, ret.toInt32()); },
      });
      n++;
    }
  });
  if (n) console.log('[+] Conscrypt ENGINE_SSL_*_direct hooked in ' + modName + ' (' + n + ')');
  return n;
}

/* The two BoringSSL plaintext hooks, factored out so the export path, the
 * offset path (OFFSETS) and the pattern path (PATTERNS) all install the SAME
 * interceptor. Sig: SSL_write(ssl, buf, num) → conn=a[0], buf=a[1], len=a[2];
 * SSL_read(ssl, buf, num) → conn=a[0], buf=a[1], len=retval. */
function attachWrite(addr) {
  Interceptor.attach(addr, { onEnter: function (a) { emit('out', a[0].toString(), a[1], a[2].toInt32()); } });
}
function attachRead(addr) {
  Interceptor.attach(addr, {
    onEnter: function (a) { this.conn = a[0].toString(); this.buf = a[1]; },
    onLeave: function (ret) { emit('in', this.conn, this.buf, ret.toInt32()); },
  });
}

var _sslDone = {};   // SSL_read/write hooked in module
var _conDone = {};   // Conscrypt ENGINE_SSL_*_direct hooked in module
function hookSSL(modName) {
  if (!_sslDone[modName]) {
    var w = modExport(modName, 'SSL_write');
    var r = modExport(modName, 'SSL_read');
    if (w) attachWrite(w);
    if (r) attachRead(r);
    if (w || r) { _sslDone[modName] = true; console.log('[+] SSL_read/SSL_write hooked in ' + modName); }
  }
  // Conscrypt symbols (.symtab) may not be enumerable at early spawn — retry via
  // the poll until they appear, so Java/OkHttp traffic isn't missed.
  if (!_conDone[modName] && hookConscrypt(modName) > 0) _conDone[modName] = true;
  return _sslDone[modName] || _conDone[modName];
}

/* ---- Stripped / statically-linked BoringSSL (libcronet, libflutter, …) ----
 * These libs ship BoringSSL with no SSL_read/SSL_write exports, so the scan
 * above finds nothing. Two ways to hook them by raw address:
 *   OFFSETS  — hardest/most reliable: base+offset found by STATIC analysis
 *              (REA/Ghidra/BoringSecretHunter on the pulled .so). friTap's
 *              `--offsets` mechanism; immune to the ASLR/anti-scan games.
 *   PATTERNS — fallback when you have no offsets: a byte-signature of the
 *              function prologue, Memory.scanSync'd over the module's r-x
 *              ranges (friTap's `--patterns`). Build/arch specific → rots.
 * NB: QUIC/HTTP3 plaintext does NOT pass through SSL_read/SSL_write at all
 * (it's QuicSpdyStream::Readv/WriteOrBufferBody), so pair this with a UDP/443
 * block to force cronet back onto TLS-over-TCP — see README.
 * Both are opt-in: set by the host via rpc.configure({offsets, patterns}). */
var OFFSETS = {};    // { "<module>": { SSL_read:{addr,absolute}, SSL_write:{…} } }
var PATTERNS = {};   // { "<module>": { SSL_read:"<hex>", SSL_write:"<hex>" } }
var _offDone = {};   // "<module>|SSL_read" → true once hooked by offset
var _patDone = {};   // "<module>|SSL_read" → true once hooked by pattern

function _normOff(v) {
  // accept "0x1234" (base-relative) or { addr, absolute }
  if (typeof v === 'string' || typeof v === 'number') return { addr: '' + v, absolute: false };
  return { addr: '' + (v.addr || v.address), absolute: !!v.absolute };
}
function _offsetAddr(m, spec) {
  try { return spec.absolute ? ptr(spec.addr) : m.base.add(ptr(spec.addr)); } catch (_) { return null; }
}

function hookByOffsets() {
  Object.keys(OFFSETS).forEach(function (modName) {
    var m = _mod(modName);
    if (!m) return;   // not loaded yet → retry on next poll / dlopen
    var spec = OFFSETS[modName] || {};
    ['SSL_write', 'SSL_read'].forEach(function (fn) {
      var key = modName + '|' + fn;
      if (_offDone[key] || !spec[fn]) return;
      var addr = _offsetAddr(m, _normOff(spec[fn]));
      if (!addr) return;
      (fn === 'SSL_write' ? attachWrite : attachRead)(addr);
      _offDone[key] = true;
      _sslDone[modName] = true;   // so the export scan stops re-probing it
      console.log('[+] ' + fn + ' hooked by OFFSET in ' + modName + ' @ ' + addr);
    });
  });
}

function hookByPatterns() {
  Object.keys(PATTERNS).forEach(function (modName) {
    var m = _mod(modName);
    if (!m) return;
    var spec = PATTERNS[modName] || {};
    ['SSL_write', 'SSL_read'].forEach(function (fn) {
      var key = modName + '|' + fn;
      if (_offDone[key] || _patDone[key] || !spec[fn]) return;
      var ranges;
      try { ranges = m.enumerateRanges('r-x'); } catch (_) { return; }
      for (var i = 0; i < ranges.length; i++) {
        var hits;
        try { hits = Memory.scanSync(ranges[i].base, ranges[i].size, spec[fn]); } catch (_) { continue; }
        if (hits && hits.length) {
          (fn === 'SSL_write' ? attachWrite : attachRead)(hits[0].address);
          _patDone[key] = true;
          _sslDone[modName] = true;
          console.log('[+] ' + fn + ' hooked by PATTERN in ' + modName + ' @ ' + hits[0].address +
                      (hits.length > 1 ? ' (' + hits.length + ' matches — used first)' : ''));
          break;
        }
      }
    });
  });
}

/* Universal discovery: instead of a fixed library list, probe EVERY loaded
 * module for exported SSL_read/SSL_write (also catches renamed/bundled BoringSSL:
 * TikTok libttboringssl, cronet, Flutter, Meta libcoldstart) AND Conscrypt's
 * ENGINE_SSL_*_direct. Non-crypto modules are probed once and skipped; crypto
 * libs are re-probed by the poll until their (late) symbols resolve. */
var tested = {};   // non-crypto modules already probed → skip forever
function scan() {
  var any = false, mods;
  hookByOffsets();    // stripped libs by static base+offset (REA) …
  hookByPatterns();   // … or by prologue byte-signature (fallback)
  try { mods = Process.enumerateModules(); } catch (_) { return false; }
  mods.forEach(function (m) {
    if (tested[m.name]) return;
    if (_sslDone[m.name] && _conDone[m.name]) return;   // fully hooked
    var before = _sslDone[m.name] || _conDone[m.name];
    if (hookSSL(m.name)) any = true;
    // if nothing found and the name isn't crypto-ish, stop re-probing it
    if (!before && !_sslDone[m.name] && !_conDone[m.name] && !/crypto|ssl|conscrypt|boring|tls|cronet|flutter|coldstart/i.test(m.name)) {
      tested[m.name] = true;
    }
  });
  return any;
}

scan();
// late-loaded TLS libs → a dlopen means new exports may now exist: rescan.
// IMPORTANT: a dlopen runs on the APP's own thread (often a fragile one — e.g.
// the RenderThread loading GLES). Running the heavy scan() (enumerateModules +
// enumerateSymbols) synchronously there can corrupt that thread and SIGSEGV the
// app (seen crashing YouTube's RenderThread). Defer to Frida's JS thread via
// setTimeout so the app thread returns from dlopen untouched; debounce so a
// burst of dlopens triggers a single scan.
var _rescanPending = false;
function deferScan() {
  if (_rescanPending) return;
  _rescanPending = true;
  setTimeout(function () { _rescanPending = false; scan(); }, 50);
}
['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
  var p = globalExport(fn);
  if (!p) return;
  Interceptor.attach(p, { onLeave: function () { deferScan(); } });
});
// backup poll for libs that load without us seeing the dlopen
var tries = 0;
var poll = setInterval(function () { if (++tries > 60) return clearInterval(poll); scan(); }, 1000);
console.log('[*] capture-http loaded — probing all modules for SSL_read/SSL_write');

/* Host harness (fridacap.py) flips us into structured 'send' mode and can
 * trigger an immediate rescan after attaching to a freshly-spawned process. */
rpc.exports = {
  configure: function (opts) {
    if (opts && opts.mode) MODE = opts.mode;
    if (opts && opts.max) MAX = opts.max;
    // stripped-lib hooking (libcronet/libflutter): static offsets (preferred)
    // and/or prologue byte-patterns. Merge so repeated configure() calls add.
    if (opts && opts.offsets) Object.keys(opts.offsets).forEach(function (k) { OFFSETS[k] = opts.offsets[k]; });
    if (opts && opts.patterns) Object.keys(opts.patterns).forEach(function (k) { PATTERNS[k] = opts.patterns[k]; });
    scan();
    return { pid: Process.id, mode: MODE, ssl: Object.keys(_sslDone), conscrypt: Object.keys(_conDone),
             offsets: Object.keys(_offDone), patterns: Object.keys(_patDone) };
  },
  rescan: function () { scan(); return { ssl: Object.keys(_sslDone), conscrypt: Object.keys(_conDone),
                                         offsets: Object.keys(_offDone), patterns: Object.keys(_patDone) }; },
};
