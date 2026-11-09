/*
 * sign-sniffer.js — SEE the exact string a web app signs, in your own browser.
 * The web analogue of the mobile skill's frida/signer-sniffer.js.
 *
 * Paste this into DevTools Console on the page (your own authorized session),
 * then trigger one signed request. It hooks the common web crypto/sign paths and
 * prints the pre-hash CANONICAL STRING + key + output, plus a stack trace to the
 * caller — so you reimplement the signer instead of guessing field order.
 *
 * Hooks: CryptoJS (HmacSHA256, MD5, SHA family, AES), window.crypto.subtle
 * (sign/digest/importKey/encrypt/decrypt), and JSON.stringify of objects that
 * look like a sign payload. It reads values only; it does not change requests.
 *
 * If nothing prints, the signer runs in a Web Worker or WASM -> capture there
 * (Worker: paste in the worker context / use "sources > threads"), or read the
 * bundle with REA (export-web-scripts) per docs/web-anti-bot-ladder.md + SKILL.
 */
(() => {
  'use strict';
  const tag = (t, o) => console.log('%c[sign] ' + t, 'color:#0a0;font-weight:bold', o);
  const stack = () => { try { return (new Error().stack || '').split('\n').slice(3, 9).join('\n'); } catch (e) { return ''; } };
  const cut = (s, n) => (typeof s === 'string' ? (s.length > n ? s.slice(0, n) + '…(+' + (s.length - n) + ')' : s) : s);

  // ---- CryptoJS (the most common web signer lib) ----
  const CJS = window.CryptoJS;
  if (CJS) {
    ['HmacSHA256', 'HmacSHA1', 'HmacMD5', 'SHA256', 'SHA1', 'MD5', 'SHA512'].forEach(fn => {
      if (typeof CJS[fn] !== 'function') return;
      const orig = CJS[fn].bind(CJS);
      CJS[fn] = function (msg, key) {
        const out = orig(msg, key);
        try { tag(fn, { canonical: cut('' + msg, 2048), key: key != null ? cut('' + key, 256) : undefined, digest: '' + out }); console.log('[sign]   at\n' + stack()); } catch (e) {}
        return out;
      };
    });
    if (CJS.AES && CJS.AES.encrypt) {
      const oe = CJS.AES.encrypt.bind(CJS.AES), od = CJS.AES.decrypt.bind(CJS.AES);
      CJS.AES.encrypt = function (m, k, c) { const r = oe(m, k, c); try { tag('AES.encrypt', { plain: cut('' + m, 1024), key: cut('' + k, 128), cfg: c, out: cut('' + r, 120) }); } catch (e) {} return r; };
      CJS.AES.decrypt = function (ct, k, c) { const r = od(ct, k, c); try { tag('AES.decrypt', { ct: cut('' + ct, 120), key: cut('' + k, 128), out: cut(r.toString(CJS.enc.Utf8), 1024) }); } catch (e) {} return r; };
    }
    console.log('[sign] CryptoJS hooked');
  }

  // ---- WebCrypto (SubtleCrypto) ----
  try {
    const S = crypto.subtle, b64 = b => { try { return btoa(String.fromCharCode(...new Uint8Array(b.buffer ? b.buffer : b))); } catch (e) { return '<bin>'; } };
    const osign = S.sign.bind(S), odig = S.digest.bind(S), oimp = S.importKey.bind(S);
    S.importKey = async (f, k, a, e, u) => { try { tag('subtle.importKey', { fmt: f, algo: a, keyB64: cut(b64(k), 96) }); } catch (x) {} return oimp(f, k, a, e, u); };
    S.sign = async (a, k, d) => { const r = await osign(a, k, d); try { tag('subtle.sign', { alg: a.name || a, canonicalB64: cut(b64(d), 2048), sigB64: cut(b64(r), 96) }); console.log('[sign]   at\n' + stack()); } catch (x) {} return r; };
    S.digest = async (a, d) => { const r = await odig(a, d); try { tag('subtle.digest', { alg: a.name || a, canonical: cut(new TextDecoder().decode(d), 2048), digestB64: cut(b64(r), 96) }); } catch (x) {} return r; };
    console.log('[sign] WebCrypto hooked');
  } catch (e) {}

  console.log('%c[sign-sniffer] ready — trigger one signed request; the canonical string + key will print.', 'color:#06c;font-weight:bold');
})();
