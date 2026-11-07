/*
 * anti-detect.js — blunt Frida anti-detection helper for Android analysis.
 * Load it BEFORE the app runs its checks (spawn mode is best):
 *   frida -U -f <package> -l anti-detect.js --no-pause
 * Stack it with ssl-unpin.js / capture-http.js (-l anti-detect.js -l ssl-unpin.js).
 *
 * It covers the cheap, high-coverage vectors most Android apps actually use
 * (see README "Anti-Frida detection"). It is NOT a magic cloak: a determined
 * app that reads /proc via raw syscalls, checks CRC/inline-hooks, or scans with
 * strcmp instead of strstr will slip past. The robust fix is always to find the
 * detector statically (REA) and NOP/patch the check — this script just buys you
 * the common cases and, via the open() logger, tells you WHICH vector fired.
 *
 * Three layers, each toggleable below:
 *  1) STRING_FILTER — libc strstr/strcasestr/memmem return "not found" when the
 *     needle is a Frida signature. Defeats the usual pattern: read /proc/self/maps
 *     | /proc/<pid>/fd | /proc/<pid>/task/<tid>/comm into a buffer, then strstr it
 *     for "frida" / "gum-js" / "frida-agent" / thread names. One hook, many vectors.
 *  2) PTRACE_GUARD — ptrace(PTRACE_TRACEME) returns 0 without tracing, so an app
 *     that self-ptraces at init to lock out debuggers can't, and late attach works.
 *  3) OPEN_LOGGER — behaviour-neutral: logs when the app opens a sensitive /proc
 *     path (maps, net/tcp, status, task) so you can confirm the detection vector.
 */
'use strict';

var STRING_FILTER = true;   // strstr/memmem signature filtering
var PTRACE_GUARD  = true;   // neutralize ptrace(PTRACE_TRACEME)
var OPEN_LOGGER   = true;   // log sensitive /proc opens (no behaviour change)

// Needles treated as Frida/instrumentation signatures (lower-cased contains).
// NB: 'gmain'/'gdbus' are generic glib thread names — filtering them can touch a
// legitimate glib app; acceptable in an analysis context. Trim if it destabilizes.
var SIGS = ['frida', 'gum-js', 'gum_js', 'gmain', 'gdbus', 'pool-frida', 'gadget',
            'linjector', 'frida-agent', 'frida-server', 'frida-helper', ':rpc',
            '27042', '27043'];

function _hit(s) {
  if (!s) return false;
  var l = s.toLowerCase();
  for (var i = 0; i < SIGS.length; i++) if (l.indexOf(SIGS[i]) !== -1) return true;
  return false;
}

/* Frida 17-safe global export resolution (same shape as the other scripts). */
function globalExport(sym) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym); } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(null, sym); } catch (_) {}
  return null;
}
function hook(sym, cbs) {
  var p = globalExport(sym);
  if (!p) return false;
  try { Interceptor.attach(p, cbs); return true; } catch (e) { console.log('[-] ' + sym + ': ' + e.message); return false; }
}

/* ---- 1) string-signature filtering ---- */
function installStringFilter() {
  var n = 0;
  // strstr(haystack, needle) / strcasestr — hide when the needle is a signature.
  ['strstr', 'strcasestr'].forEach(function (fn) {
    if (hook(fn, {
      onEnter: function (a) { try { this.hide = _hit(a[1].readCString()); } catch (_) { this.hide = false; } },
      onLeave: function (r) { if (this.hide && !r.isNull()) r.replace(ptr(0)); },
    })) n++;
  });
  // memmem(haystack, hlen, needle, nlen) — same, needle is arg2/len arg3.
  if (hook('memmem', {
    onEnter: function (a) {
      this.hide = false;
      try { var len = a[3].toInt32(); if (len > 0 && len < 256) this.hide = _hit(a[2].readUtf8String(len)); } catch (_) {}
    },
    onLeave: function (r) { if (this.hide && !r.isNull()) r.replace(ptr(0)); },
  })) n++;
  console.log(n ? '[+] string filter on ' + n + ' fn(s) (strstr/strcasestr/memmem)' : '[-] string filter: no symbols');
}

/* ---- 2) ptrace(PTRACE_TRACEME) guard ---- */
function installPtraceGuard() {
  var PTRACE_TRACEME = 0;
  var ok = hook('ptrace', {
    onEnter: function (a) { this.traceme = a[0].toInt32() === PTRACE_TRACEME; },
    onLeave: function (r) { if (this.traceme) { r.replace(ptr(0)); if (!this._logged) { console.log('[+] ptrace(PTRACE_TRACEME) neutralized'); this._logged = true; } } },
  });
  if (!ok) console.log('[-] ptrace guard: symbol not found');
}

/* ---- 3) sensitive /proc open logger (no behaviour change) ---- */
function installOpenLogger() {
  var SENS = /\/proc\/(self|\d+)\/(maps|status|task)|\/proc\/net\/(tcp|udp)/;
  function logPath(p) { try { var s = p.readCString(); if (s && SENS.test(s)) console.log('[*] open ' + s + '  (potential anti-frida probe)'); } catch (_) {} }
  // open(path, …) → arg0 ; openat(dirfd, path, …) → arg1
  hook('open',   { onEnter: function (a) { logPath(a[0]); } });
  hook('openat', { onEnter: function (a) { logPath(a[1]); } });
  console.log('[*] open logger armed (watching /proc maps|status|task|net)');
}

if (STRING_FILTER) installStringFilter();
if (PTRACE_GUARD)  installPtraceGuard();
if (OPEN_LOGGER)   installOpenLogger();
console.log('[*] anti-detect loaded — string-filter=' + STRING_FILTER + ' ptrace=' + PTRACE_GUARD + ' open-log=' + OPEN_LOGGER);
