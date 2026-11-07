/*
 * ssl-unpin.js — universal SSL pinning bypass (Java layer + native BoringSSL),
 * handles late-loaded .so (spawn mode) + scans for obfuscated classes.
 * Usage: frida -U -f <package> -l ssl-unpin.js --no-pause
 *
 * Technique (distilled from several community scripts):
 *  Java: TrustManager-all, HostnameVerifier-all, OkHttp CertificatePinner
 *        (standard name + check$okhttp + a scan for obfuscated classes), Conscrypt
 *        TrustManagerImpl, TrustKit, Cronet builder pins (addPublicKeyPins /
 *        enablePublicKeyPinningBypassForLocalTrustAnchors), WebView onReceivedSslError.
 *  Native: probe every crypto module for the full verify surface — BoringSSL
 *          set_custom_verify, cert_verify_callback, classic SSL[_CTX]_set_verify
 *          (forced SSL_VERIFY_NONE), and X509_verify_cert / SSL_get_verify_result
 *          return-overrides; covers forks like TikTok's libttboringssl. If the .so
 *          loads late, catch it via android_dlopen_ext/dlopen then retry (Flutter /
 *          app bundles with their own networking stack).
 *          + Proxygen path (Meta apps: FB/IG/Messenger) in libcoldstart.so,
 *            which bypasses BoringSSL's set_custom_verify entirely.
 * Does not touch the app's signature/HMAC/version-check crypto functions (to avoid breaking the app).
 * If still stuck, pair it with frida-multiple-unpinning / objection.
 */
'use strict';

/* ------------------------------ JAVA LAYER ------------------------------ */
function hookJava() {
  Java.perform(function () {
    // 1) TrustManager "accept everything"
    try {
      const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      const TrustAll = Java.registerClass({
        name: 'dev.rea.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; },
        },
      });
      const tms = [TrustAll.$new()];
      const init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
      init.implementation = function (km, _tm, sr) { init.call(this, km, tms, sr); };
      console.log('[+] TrustManager/SSLContext hooked');
    } catch (e) { console.log('[-] TrustManager:', e.message); }

    // 2) HostnameVerifier "accept any host" (default for HttpsURLConnection)
    try {
      const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
      const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      const VerifyAll = Java.registerClass({
        name: 'dev.rea.VerifyAll',
        implements: [HostnameVerifier],
        methods: { verify: function () { return true; } },
      });
      HttpsURLConnection.setDefaultHostnameVerifier(VerifyAll.$new());
      console.log('[+] HostnameVerifier hooked');
    } catch (e) { console.log('[-] HostnameVerifier:', e.message); }

    // 3) OkHttp CertificatePinner — standard name
    try {
      const CP = Java.use('okhttp3.CertificatePinner');
      CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      try { CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {}; } catch (_) {}
      // check$okhttp — the Kotlin-internal name on OkHttp 4/5 (what newer builds call).
      try { CP.check$okhttp.overloads.forEach(function (ov) { ov.implementation = function () {}; }); } catch (_) {}
      console.log('[+] OkHttp CertificatePinner hooked');
    } catch (e) { /* may be obfuscated → step 3b */ }

    // 3b) OkHttp obfuscated/bundled: scan loaded classes for a check(String, List) method
    try {
      Java.enumerateLoadedClasses({
        onMatch: function (name) {
          if (name.indexOf('CertificatePinner') === -1 && !/okhttp|okio/i.test(name)) return;
          try {
            const C = Java.use(name);
            if (!C.check) return;
            C.check.overloads.forEach(function (ov) {
              const sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
              if (sig.indexOf('java.lang.String') === 0) {
                ov.implementation = function () {};
                console.log('[+] obfuscated pinner neutralized: ' + name + '(' + sig + ')');
              }
            });
          } catch (_) {}
        },
        onComplete: function () {},
      });
    } catch (_) {}

    // 4) Conscrypt TrustManagerImpl (many apps pin here)
    try {
      const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TMI.checkTrustedRecursive.implementation = function () { return Java.use('java.util.ArrayList').$new(); };
      try { TMI.verifyChain.implementation = function (certs) { return certs; }; } catch (_) {}
      console.log('[+] Conscrypt TrustManagerImpl hooked');
    } catch (e) {}

    // 5) TrustKit (DataTheorem) — a common standalone pinning lib.
    try {
      const PTM = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
      PTM.checkServerTrusted.overloads.forEach(function (ov) { ov.implementation = function () {}; });
      try { PTM.checkClientTrusted.overloads.forEach(function (ov) { ov.implementation = function () {}; }); } catch (_) {}
      try { PTM.shouldEnforcePinning.implementation = function () { return false; }; } catch (_) {}
      console.log('[+] TrustKit PinningTrustManager hooked');
    } catch (_) {}

    // 6) Cronet (Chromium net) — kill pins at the Java builder (before the native
    //    stack spins up). enablePublicKeyPinningBypassForLocalTrustAnchors(true)
    //    makes cronet honor a user/MITM CA; addPublicKeyPins → no-op.
    ['org.chromium.net.CronetEngine$Builder',
     'org.chromium.net.ExperimentalCronetEngine$Builder',
     'org.chromium.net.impl.CronetEngineBuilderImpl'].forEach(function (cn) {
      try {
        const B = Java.use(cn);
        try { B.addPublicKeyPins.overloads.forEach(function (ov) { ov.implementation = function () { return this; }; }); } catch (_) {}
        try {
          B.enablePublicKeyPinningBypassForLocalTrustAnchors.overloads.forEach(function (ov) {
            ov.implementation = function () { try { return ov.call(this, true); } catch (_) { return this; } };
          });
        } catch (_) {}
        console.log('[+] Cronet Java pinning neutralized (' + cn + ')');
      } catch (_) {}
    });

    // 7) In-app WebView: proceed through SSL errors.
    try {
      const WVC = Java.use('android.webkit.WebViewClient');
      WVC.onReceivedSslError.implementation = function (view, handler, error) {
        try { handler.proceed(); } catch (_) {}
      };
      console.log('[+] WebViewClient.onReceivedSslError -> proceed()');
    } catch (_) {}
  });
}

/* ----------------------------- NATIVE LAYER ----------------------------- */
/* Frida 17 removed the static Module.findExportByName(name,…) /
 * Module.enumerateSymbols(name) forms — resolve per-module now, with a
 * fallback to the legacy API so the script still runs on Frida 16. */
function _mod(name) { try { return Process.findModuleByName(name); } catch (_) { return null; } }
function modExport(name, sym) {
  const m = _mod(name);
  try { if (m && m.findExportByName) { const p = m.findExportByName(sym); if (p) return p; } } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(name, sym); } catch (_) {}
  return null;
}
function globalExport(sym) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym); } catch (_) {}
  try { if (Module.findExportByName) return Module.findExportByName(null, sym); } catch (_) {}
  return null;
}
function modSymbols(name) {
  const m = _mod(name);
  try { if (m && m.enumerateSymbols) return m.enumerateSymbols(); } catch (_) {}
  try { if (Module.enumerateSymbols) return Module.enumerateSymbols(name); } catch (_) {}
  return [];
}

/* The verify symbols we try per crypto module. BoringSSL's modern path is
 * set_custom_verify; but many libs (incl. forks like Douyin/TikTok's
 * libttboringssl, older OpenSSL, some Flutter builds) still gate on the classic
 * API — cert_verify_callback, SSL[_CTX]_set_verify(mode,cb), X509_verify_cert,
 * SSL_get_verify_result. Covering all of them (technique breadth borrowed from
 * TikTok-oriented community scripts) catches apps custom_verify-only misses. */
const VERIFY_SYMS = ['SSL_CTX_set_custom_verify', 'SSL_set_custom_verify',
                     'SSL_CTX_set_cert_verify_callback', 'SSL_set_verify',
                     'SSL_CTX_set_verify', 'X509_verify_cert', 'SSL_get_verify_result'];

// Reuse ONE NativeCallback per return value instead of allocating inside onEnter.
// Frida pins every NativeCallback, so making a new one on each TLS handshake leaks
// over a long capture. The verify callback is stateless (always returns ok), so a
// single shared instance is correct. Created lazily on first hook.
let _cbOk0 = null, _cbOk1 = null;
function okVerifyCb(ret) {
  if (ret === 0) return _cbOk0 || (_cbOk0 = new NativeCallback(function () { return 0; /* ssl_verify_ok */ }, 'int', ['pointer', 'pointer']));
  return _cbOk1 || (_cbOk1 = new NativeCallback(function () { return 1; /* ok */ }, 'int', ['pointer', 'pointer']));
}

function neutralizeBoringSSL(modName) {
  let hooked = 0;
  try {
    // 1) BoringSSL custom_verify: replace the callback (arg[2]) → 0 = ssl_verify_ok.
    const setCustom = modExport(modName, 'SSL_CTX_set_custom_verify') ||
                      modExport(modName, 'SSL_set_custom_verify');
    if (setCustom) {
      Interceptor.attach(setCustom, { onEnter: function (args) { args[2] = okVerifyCb(0); } });
      console.log('[+] BoringSSL custom_verify neutralized (' + modName + ')'); hooked++;
    }
    // 2) OpenSSL/BoringSSL cert_verify_callback: replace callback (arg[1]) → 1 = ok.
    const certCb = modExport(modName, 'SSL_CTX_set_cert_verify_callback');
    if (certCb) {
      Interceptor.attach(certCb, { onEnter: function (args) { args[1] = okVerifyCb(1); } });
      console.log('[+] cert_verify_callback neutralized (' + modName + ')'); hooked++;
    }
    // 3) classic set_verify(obj, mode, cb): force mode (arg[1]) → SSL_VERIFY_NONE (0).
    ['SSL_set_verify', 'SSL_CTX_set_verify'].forEach(function (sym) {
      const p = modExport(modName, sym);
      if (p) {
        Interceptor.attach(p, { onEnter: function (args) { args[1] = ptr(0); } });
        console.log('[+] ' + sym + ' forced SSL_VERIFY_NONE (' + modName + ')'); hooked++;
      }
    });
    // 4) return-overrides: X509_verify_cert → 1, SSL_get_verify_result → 0 (X509_V_OK).
    const xv = modExport(modName, 'X509_verify_cert');
    if (xv) { Interceptor.attach(xv, { onLeave: function (r) { r.replace(ptr(1)); } });
      console.log('[+] X509_verify_cert forced OK (' + modName + ')'); hooked++; }
    const gvr = modExport(modName, 'SSL_get_verify_result');
    if (gvr) { Interceptor.attach(gvr, { onLeave: function (r) { r.replace(ptr(0)); } });
      console.log('[+] SSL_get_verify_result forced X509_V_OK (' + modName + ')'); hooked++; }

    if (!hooked) console.log('[-] ' + modName + ': verify symbols present but none hookable (stripped? → use offsets, see README)');
    return hooked > 0;
  } catch (e) { console.log('[-] native verify ' + modName + ':', e.message); return hooked > 0; }
}

/* Proxygen (Meta apps: Facebook/Instagram/Messenger) verify in their own C++
 * layer, NOT via BoringSSL's set_custom_verify — so neutralizeBoringSSL misses
 * them. The verifying functions live in libcoldstart.so with mangled C++ names;
 * we match by substring over enumerated symbols and force success.
 * Technique ref: danieldev23/frida-ssl-bypass (fb4a_bypass.js). */
function neutralizeProxygen(modName, verbose) {
  if (verbose === undefined) verbose = true;
  try {
    const syms = modSymbols(modName);
    // return-true targets (bool cert-check functions)
    const RET_TRUE = ['verifyWithMetrics', 'verifySSLCertificate'];
    // force-arg-false targets (setVerifyCertificates(bool) → disable verify)
    const ARG_FALSE = ['setVerifyCertificates'];
    let hit = 0;
    syms.forEach(function (s) {
      if (!s.address || s.address.isNull()) return;
      if (RET_TRUE.some(function (k) { return s.name.indexOf(k) !== -1; })) {
        Interceptor.attach(s.address, { onLeave: function (r) { r.replace(ptr(1)); } });
        console.log('[+] proxygen force-true: ' + s.name);
        hit++;
      } else if (ARG_FALSE.some(function (k) { return s.name.indexOf(k) !== -1; })) {
        Interceptor.attach(s.address, { onEnter: function (a) { a[1] = ptr(0); } });
        console.log('[+] proxygen force-noverify: ' + s.name);
        hit++;
      }
    });
    if (hit) { console.log('[+] Proxygen neutralized (' + modName + ', ' + hit + ' hooks)'); return true; }
    if (verbose) console.log('[-] ' + modName + ': no proxygen verify symbols (stripped? needs pattern scan)');
    return false;
  } catch (e) { console.log('[-] Proxygen ' + modName + ':', e.message); return false; }
}

/* Universal native scan — don't hard-code library names. Probe every loaded
 * module for BoringSSL's custom_verify export; for Proxygen (expensive symbol
 * enumeration) probe only app-private libs under /data or /mnt, which is where
 * Meta's libcoldstart and friends live. Each module is probed once. */
const _nbDone = {};   // BoringSSL-probed modules
const _pxDone = {};   // Proxygen-probed modules
function scanBoring() {
  let mods; try { mods = Process.enumerateModules(); } catch (_) { return; }
  mods.forEach(function (m) {
    if (_nbDone[m.name]) return;
    const has = VERIFY_SYMS.some(function (s) { return modExport(m.name, s); });
    if (has) { _nbDone[m.name] = true; neutralizeBoringSSL(m.name); }
  });
}
function scanProxygen() {
  let mods; try { mods = Process.enumerateModules(); } catch (_) { return; }
  mods.forEach(function (m) {
    if (_pxDone[m.name]) return;
    const appPrivate = m.path && (m.path.indexOf('/data/') !== -1 || m.path.indexOf('/mnt/') !== -1);
    if (!appPrivate) { _pxDone[m.name] = true; return; }   // skip system libs (too many symbols)
    _pxDone[m.name] = true;
    neutralizeProxygen(m.name, false);   // quiet: most app libs have no proxygen syms
  });
}

let _rescanPending = false;
function deferScan() {
  // A dlopen runs on the APP's own thread (sometimes a fragile one, e.g. the
  // RenderThread loading GLES). Running the heavy scans (enumerateModules +
  // enumerateSymbols) synchronously there can corrupt that thread and SIGSEGV
  // the app. Defer to Frida's JS thread; debounce bursts into one scan.
  if (_rescanPending) return;
  _rescanPending = true;
  setTimeout(function () { _rescanPending = false; scanBoring(); scanProxygen(); }, 50);
}
function hookNative() {
  scanBoring();
  scanProxygen();
  // a dlopen means new modules/exports may now exist → rescan both (deferred).
  ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
    const p = globalExport(fn);
    if (!p) return;
    Interceptor.attach(p, { onLeave: function () { deferScan(); } });
  });
  console.log('[*] native: probing all modules (BoringSSL custom_verify + Proxygen verify syms)…');
}

/* -------------------------------- RUN ---------------------------------- */
// On early spawn the Java (ART) bridge isn't injected yet, so referencing
// `Java` throws ReferenceError. Wait until it's actually available.
function whenJavaReady(cb) {
  if (typeof Java !== 'undefined' && Java.available) { cb(); return; }
  let n = 0;
  const t = setInterval(function () {
    if (typeof Java !== 'undefined' && Java.available) { clearInterval(t); cb(); }
    else if (++n > 200) { clearInterval(t); console.log('[-] Java runtime never became available'); }
  }, 50);
}
whenJavaReady(hookJava);
setTimeout(hookNative, 300);
// backup polling for stripped/late-loaded native
let tries = 0;
const poll = setInterval(function () {
  if (++tries > 60) return clearInterval(poll);
  scanBoring();
  scanProxygen();
}, 1000);
console.log('[*] ssl-unpin loaded');
