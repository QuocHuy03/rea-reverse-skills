/*
 * crypto-dump.js — dump the app's crypto live: key / IV / mode / plaintext.
 * Hooks the whole Java crypto stack + common native OpenSSL/BoringSSL entry
 * points, so when you trigger a signed/encrypted request you SEE the HMAC key,
 * the AES key+IV+mode, and the exact pre-hash / plaintext bytes → reimplement in
 * Python (see docs/decryption-playbook.md §1). Bundled replacement for the
 * CryptoFucker role (no external dependency).
 *   frida -U -f <package> -l crypto-dump.js --no-pause
 * Stack with anti-detect.js if the app detects Frida.
 */
'use strict';

var MAX = 512;   // cap bytes printed per buffer

function jhex(b) {
  if (b === null || b === undefined) return 'null';
  try {
    var n = Math.min(b.length, MAX), s = '';
    for (var i = 0; i < n; i++) { var v = b[i] & 0xff; s += ('0' + v.toString(16)).slice(-2); }
    return s + (b.length > n ? ' …(+' + (b.length - n) + ')' : '');
  } catch (e) { return '<unreadable>'; }
}
function jtext(b) {
  try {
    var n = Math.min(b.length, MAX), s = '', printable = 0;
    for (var i = 0; i < n; i++) { var c = b[i] & 0xff; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) { s += String.fromCharCode(c); printable++; } else s += '.'; }
    return (n > 0 && printable / n > 0.7) ? s : null;   // only show if mostly text
  } catch (e) { return null; }
}
function show(tag, b) {
  var t = jtext(b);
  console.log('[crypto] ' + tag + ' hex=' + jhex(b) + (t ? '\n[crypto]   text="' + t + '"' : ''));
}

/* ---------- Java layer ---------- */
function hookJava() {
  Java.perform(function () {
    // key material
    try {
      var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
      SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
        console.log('[crypto] SecretKeySpec algo=' + algo + ' key=' + jhex(key));
        return this.$init(key, algo);
      };
    } catch (e) {}
    try {
      var IV = Java.use('javax.crypto.spec.IvParameterSpec');
      IV.$init.overload('[B').implementation = function (iv) {
        console.log('[crypto] IvParameterSpec iv=' + jhex(iv));
        return this.$init(iv);
      };
    } catch (e) {}
    // Cipher: transformation (algo/mode/padding) + in/out
    try {
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
        console.log('[crypto] Cipher.getInstance ' + t);
        return this.getInstance(t);
      };
      try {
        Cipher.doFinal.overload('[B').implementation = function (input) {
          show('Cipher.doFinal IN ', input);
          var out = this.doFinal(input);
          show('Cipher.doFinal OUT', out);
          return out;
        };
      } catch (_) {}
      try {
        Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, off, len) {
          show('Cipher.doFinal IN ', input);
          var out = this.doFinal(input, off, len);
          show('Cipher.doFinal OUT', out);
          return out;
        };
      } catch (_) {}
      console.log('[+] Cipher hooked');
    } catch (e) {}
    // Mac (HMAC) + MessageDigest (hash)
    try {
      var Mac = Java.use('javax.crypto.Mac');
      Mac.getInstance.overload('java.lang.String').implementation = function (a) { console.log('[crypto] Mac.getInstance ' + a); return this.getInstance(a); };
      Mac.doFinal.overload('[B').implementation = function (input) {
        show('Mac.doFinal IN ', input);
        var out = this.doFinal(input);
        console.log('[crypto] Mac.doFinal OUT hex=' + jhex(out));
        return out;
      };
    } catch (e) {}
    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.digest.overload('[B').implementation = function (input) {
        show('MessageDigest IN ', input);
        var out = this.digest(input);
        console.log('[crypto] MessageDigest OUT hex=' + jhex(out));
        return out;
      };
    } catch (e) {}
    console.log('[*] crypto-dump: Java stack hooked');
  });
}

/* ---------- Native layer (OpenSSL/BoringSSL) ---------- */
function globalExport(sym) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym); } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(null, sym); } catch (_) {}
  return null;
}
function nhex(p, len) {
  try { var ab = p.readByteArray(len); if (!ab) return ''; var u = new Uint8Array(ab), s = ''; for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2); return s; } catch (e) { return '<unreadable>'; }
}
function hookNative() {
  // EVP_{Encrypt,Decrypt}Init_ex(ctx, cipher, impl, key, iv): key=a[3], iv=a[4]
  ['EVP_EncryptInit_ex', 'EVP_DecryptInit_ex'].forEach(function (fn) {
    var p = globalExport(fn);
    if (!p) return;
    Interceptor.attach(p, { onEnter: function (a) {
      console.log('[crypto] ' + fn + ' key=' + nhex(a[3], 32) + ' iv=' + nhex(a[4], 16));
    }});
    console.log('[+] native ' + fn + ' hooked');
  });
  // AES_set_encrypt_key(userKey, bits, key): key bytes=a[0], bits=a[1]
  ['AES_set_encrypt_key', 'AES_set_decrypt_key'].forEach(function (fn) {
    var p = globalExport(fn);
    if (!p) return;
    Interceptor.attach(p, { onEnter: function (a) {
      var bits = a[1].toInt32(); console.log('[crypto] ' + fn + ' bits=' + bits + ' key=' + nhex(a[0], bits / 8));
    }});
    console.log('[+] native ' + fn + ' hooked');
  });
}

/* ---------- run ---------- */
function whenJavaReady(cb) {
  if (typeof Java !== 'undefined' && Java.available) { cb(); return; }
  var n = 0, t = setInterval(function () {
    if (typeof Java !== 'undefined' && Java.available) { clearInterval(t); cb(); }
    else if (++n > 200) { clearInterval(t); }
  }, 50);
}
whenJavaReady(hookJava);
setTimeout(hookNative, 300);
console.log('[*] crypto-dump loaded');
