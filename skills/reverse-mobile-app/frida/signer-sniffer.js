/*
 * signer-sniffer.js — SEE the exact string an app signs, without reading its code.
 *
 * The hard part of a signer is never the hash (HMAC-SHA256 is trivial to redo in
 * Python). The hard part is the CANONICAL STRING: which fields, in which order,
 * with which separators/salt, get fed into the hash. This script reconstructs it
 * for you — it accumulates every update()/DigestUpdate() call per hash instance
 * and prints the FULL pre-hash bytes at doFinal, plus the HMAC key and a stack
 * trace that points at the exact signing function in the app.
 *
 *   frida -U -f <package> -l frida/signer-sniffer.js --no-pause
 *   (stack with anti-detect.js if the app detects Frida)
 *
 * Workflow: trigger ONE signed request -> read the "canonical" line -> that IS
 * what you reimplement. Read the ">>> digest" line -> grep it in your capture to
 * learn which header it becomes. If the canonical line is garbage/empty, the app
 * builds the string in native/obfuscated code -> climb docs/signer-reverse-deepdive.md.
 *
 * Difference vs crypto-dump.js: crypto-dump shows each crypto call in isolation
 * (key, IV, one buffer); signer-sniffer JOINS the pieces into the signed string.
 * Pure Frida, no deps.
 */
'use strict';

var CAP = 8192;    // max bytes accumulated per hash instance
var acc = {};      // java instance id   -> [byte,...]
var nacc = {};     // native ctx pointer -> hex string

/* ---------- helpers ---------- */
function hexOf(a) { var s = ''; for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2); return s; }
function asciiOf(a) {
  var s = '', p = 0;
  for (var i = 0; i < a.length; i++) { var c = a[i] & 0xff; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) { s += String.fromCharCode(c); p++; } else s += '.'; }
  return (a.length && p / a.length > 0.6) ? s : null;   // only show if mostly text
}
function jbHex(b) { if (!b) return 'null'; var n = Math.min(b.length, 64), s = ''; for (var i = 0; i < n; i++) s += ('0' + (b[i] & 0xff).toString(16)).slice(-2); return s + (b.length > n ? '…(+' + (b.length - n) + ')' : ''); }
function nhex(p, len) { try { var ab = p.readByteArray(len); if (!ab) return ''; var u = new Uint8Array(ab), s = ''; for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2); return s; } catch (e) { return '<unreadable>'; } }

function append(id, b, off, len) {
  if (!acc[id]) acc[id] = [];
  var a = acc[id], start = off || 0, end = (len != null) ? start + len : b.length;
  for (var i = start; i < end && a.length < CAP; i++) a.push(b[i] & 0xff);
}
function javaStack() {
  try {
    var s = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
    return s.split('\n').filter(function (l) {
      return l.indexOf('javax.crypto') < 0 && l.indexOf('java.security') < 0 &&
             l.indexOf('android.util.Log') < 0 && l.indexOf('java.lang.Throwable') < 0;
    }).slice(0, 8).join('\n    ');
  } catch (e) { return '(stack unavailable)'; }
}
function dump(label, id, outHex, keyHint) {
  var a = acc[id] || [];
  console.log('\n[sign] ===== ' + label + ' =====');
  if (keyHint) console.log('[sign] key=' + keyHint);
  console.log('[sign] canonical (' + a.length + 'B) hex=' + hexOf(a).slice(0, 4096));
  var t = asciiOf(a); if (t) console.log('[sign] canonical TEXT="' + t.slice(0, 2048) + '"');
  if (outHex) console.log('[sign] >>> digest=' + outHex + '   (grep this in your NDJSON capture to find which header it becomes)');
  console.log('[sign] signed at:\n    ' + javaStack());
  delete acc[id];
}

/* ---------- Java: Mac (HMAC) + MessageDigest (hash) ---------- */
function hookJava() {
  Java.perform(function () {
    try {
      var Mac = Java.use('javax.crypto.Mac');
      // key: the secret enters via init(Key) -> getEncoded() gives the raw bytes
      ['java.security.Key', 'java.security.Key,java.security.spec.AlgorithmParameterSpec'].forEach(function (sig) {
        try {
          Mac.init.overload.apply(Mac.init, sig.split(',')).implementation = function () {
            try { var e = arguments[0].getEncoded(); if (e) console.log('[sign] HMAC key set algo=' + this.getAlgorithm() + ' key=' + jbHex(e)); } catch (_) {}
            return this.init.apply(this, arguments);
          };
        } catch (_) {}
      });
      Mac.update.overload('[B').implementation = function (b) { append(this.hashCode(), b); return this.update(b); };
      Mac.update.overload('[B', 'int', 'int').implementation = function (b, o, l) { append(this.hashCode(), b, o, l); return this.update(b, o, l); };
      Mac.doFinal.overload().implementation = function () { var id = this.hashCode(); var out = this.doFinal(); dump('HMAC ' + this.getAlgorithm(), id, jbHex(out)); return out; };
      Mac.doFinal.overload('[B').implementation = function (inp) { var id = this.hashCode(); if (inp) append(id, inp); var out = this.doFinal(inp); dump('HMAC ' + this.getAlgorithm(), id, jbHex(out)); return out; };
      console.log('[+] Mac (HMAC) hooked');
    } catch (e) {}

    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.update.overload('[B').implementation = function (b) { append(this.hashCode(), b); return this.update(b); };
      MD.update.overload('[B', 'int', 'int').implementation = function (b, o, l) { append(this.hashCode(), b, o, l); return this.update(b, o, l); };
      MD.digest.overload().implementation = function () { var id = this.hashCode(); var out = this.digest(); dump('DIGEST ' + this.getAlgorithm(), id, jbHex(out)); return out; };
      MD.digest.overload('[B').implementation = function (inp) { var id = this.hashCode(); if (inp) append(id, inp); var out = this.digest(inp); dump('DIGEST ' + this.getAlgorithm(), id, jbHex(out)); return out; };
      console.log('[+] MessageDigest hooked');
    } catch (e) {}
    console.log('[*] signer-sniffer: Java hash/hmac hooked — trigger one signed request');
  });
}

/* ---------- Native: OpenSSL/BoringSSL hash + HMAC ---------- */
function gexp(sym) { try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym); } catch (_) {} try { return Module.findExportByName(null, sym); } catch (_) {} return null; }
function napp(ctx, p, len) { var k = ctx.toString(); nacc[k] = (nacc[k] || '') + nhex(p, Math.min(len, 1024)); if (nacc[k].length > CAP * 2) nacc[k] = nacc[k].slice(0, CAP * 2); }

function hookNative() {
  // streaming digest: *_Update accumulates, *_Final flushes
  [['EVP_DigestUpdate', 'EVP_DigestFinal_ex'], ['EVP_DigestUpdate', 'EVP_DigestFinal'],
   ['SHA256_Update', 'SHA256_Final'], ['HMAC_Update', 'HMAC_Final']].forEach(function (pair) {
    var up = gexp(pair[0]), fin = gexp(pair[1]);
    if (up) {
      Interceptor.attach(up, { onEnter: function (a) { napp(a[0], a[1], a[2].toInt32()); } });
      console.log('[+] native ' + pair[0] + ' hooked');
    }
    if (fin) {
      Interceptor.attach(fin, {
        onEnter: function (a) { this.ctx = a[0].toString(); this.md = a[1]; },
        onLeave: function () {
          var c = this.ctx, canon = nacc[c] || '';
          console.log('\n[sign] ===== native ' + pair[1] + ' =====');
          console.log('[sign] canonical (' + (canon.length / 2) + 'B) hex=' + canon.slice(0, 4096));
          try { console.log('[sign] >>> digest=' + nhex(this.md, 32)); } catch (_) {}
          console.log('[sign] (native — use REA/ghidra on the caller to see how the string was built)');
          delete nacc[c];
        }
      });
      console.log('[+] native ' + pair[1] + ' hooked');
    }
  });
  // one-shot HMAC(evp, key, key_len, data, data_len, md, md_len)
  var hm = gexp('HMAC');
  if (hm) {
    Interceptor.attach(hm, { onEnter: function (a) {
      console.log('\n[sign] ===== native HMAC (one-shot) =====');
      console.log('[sign] key=' + nhex(a[1], Math.min(a[2].toInt32(), 128)));
      var dl = a[4].toInt32();
      console.log('[sign] canonical (' + dl + 'B) hex=' + nhex(a[3], Math.min(dl, 2048)));
    }});
    console.log('[+] native HMAC (one-shot) hooked');
  }
}

/* ---------- run ---------- */
function whenJavaReady(cb) {
  if (typeof Java !== 'undefined' && Java.available) { cb(); return; }
  var n = 0, t = setInterval(function () {
    if (typeof Java !== 'undefined' && Java.available) { clearInterval(t); cb(); }
    else if (++n > 200) clearInterval(t);
  }, 50);
}
whenJavaReady(hookJava);
setTimeout(hookNative, 400);
console.log('[*] signer-sniffer loaded — reconstructs the exact signed string + key + caller');
