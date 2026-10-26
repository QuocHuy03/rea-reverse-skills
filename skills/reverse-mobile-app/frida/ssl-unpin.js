/*
 * ssl-unpin.js — universal SSL pinning bypass (Java layer + native BoringSSL),
 * handles late-loaded .so (spawn mode) + scans for obfuscated classes.
 * Usage: frida -U -f <package> -l ssl-unpin.js --no-pause
 *
 * Technique (distilled from several community scripts):
 *  Java: TrustManager-all, HostnameVerifier-all, OkHttp CertificatePinner
 *        (both the standard name and a scan for obfuscated classes), Conscrypt TrustManagerImpl.
 *  Native: hook ssl_verify in libssl.so; if the .so loads late, catch it via
 *          android_dlopen_ext/dlopen then retry (important for Flutter apps /
 *          app bundles with their own networking stack).
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
  });
}

/* ----------------------------- NATIVE LAYER ----------------------------- */
function neutralizeBoringSSL(modName) {
  try {
    const setCustom = Module.findExportByName(modName, 'SSL_CTX_set_custom_verify') ||
                      Module.findExportByName(modName, 'SSL_set_custom_verify');
    if (setCustom) {
      Interceptor.attach(setCustom, {
        onEnter: function (args) {
          this.cb = new NativeCallback(function () { return 0; /* ssl_verify_ok */ }, 'int', ['pointer', 'pointer']);
          args[2] = this.cb;
        },
      });
      console.log('[+] BoringSSL custom_verify neutralized (' + modName + ')');
      return true;
    }
    // Fallback: ssl_verify_peer_cert is stripped → needs a per-build pattern scan.
    console.log('[-] ' + modName + ': custom_verify symbol not found (may be stripped)');
    return false;
  } catch (e) { console.log('[-] BoringSSL ' + modName + ':', e.message); return false; }
}

function hookNative() {
  const candidates = ['libssl.so', 'libmonochrome.so', 'libflutter.so'];
  let done = false;
  candidates.forEach(function (n) {
    if (Process.findModuleByName(n)) done = neutralizeBoringSSL(n) || done;
  });
  if (done) return;

  // late-loaded .so → catch it via dlopen then retry (spawn mode timing)
  ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
    const p = Module.findExportByName(null, fn);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) { try { this.path = args[0].readCString(); } catch (_) {} },
      onLeave: function () {
        if (!this.path) return;
        candidates.forEach(function (n) {
          if (this.path.indexOf(n) !== -1 && Process.findModuleByName(n)) neutralizeBoringSSL(n);
        }, this);
      },
    });
  });
  console.log('[*] native: waiting for libssl to load via dlopen…');
}

/* -------------------------------- RUN ---------------------------------- */
hookJava();
setTimeout(hookNative, 300);
// backup polling for stripped/late-loaded native
let tries = 0;
const poll = setInterval(function () {
  if (++tries > 60) return clearInterval(poll);
  ['libssl.so', 'libmonochrome.so', 'libflutter.so'].forEach(function (n) {
    if (Process.findModuleByName(n)) neutralizeBoringSSL(n);
  });
}, 1000);
console.log('[*] ssl-unpin loaded');
