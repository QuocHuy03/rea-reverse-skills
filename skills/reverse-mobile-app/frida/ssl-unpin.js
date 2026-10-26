/*
 * ssl-unpin.js — universal SSL pinning bypass (Java layer + native BoringSSL),
 * có xử lý .so nạp muộn (spawn mode) + quét class obfuscate.
 * Dùng: frida -U -f <package> -l ssl-unpin.js --no-pause
 *
 * Kỹ thuật (đúc kết từ nhiều script cộng đồng):
 *  Java: TrustManager-all, HostnameVerifier-all, OkHttp CertificatePinner
 *        (cả tên chuẩn lẫn quét class obfuscate), Conscrypt TrustManagerImpl.
 *  Native: hook ssl_verify trong libssl.so; nếu .so nạp muộn thì bắt qua
 *          android_dlopen_ext/dlopen rồi retry (quan trọng cho app Flutter/
 *          app bundle networking stack riêng).
 * Không chạm hàm crypto signature/HMAC/version-check của app (tránh làm vỡ app).
 * Bí hơn nữa thì dùng kèm frida-multiple-unpinning / objection.
 */
'use strict';

/* ------------------------------ JAVA LAYER ------------------------------ */
function hookJava() {
  Java.perform(function () {
    // 1) TrustManager "chấp nhận tất cả"
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

    // 2) HostnameVerifier "chấp nhận mọi host" (default cho HttpsURLConnection)
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

    // 3) OkHttp CertificatePinner — tên chuẩn
    try {
      const CP = Java.use('okhttp3.CertificatePinner');
      CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      try { CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {}; } catch (_) {}
      console.log('[+] OkHttp CertificatePinner hooked');
    } catch (e) { /* có thể bị obfuscate → bước 3b */ }

    // 3b) OkHttp bị obfuscate/bundle: quét class loaded có method check(String, List)
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

    // 4) Conscrypt TrustManagerImpl (nhiều app pin ở đây)
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
    // Fallback: hàm ssl_verify_peer_cert bị strip → cần pattern scan riêng cho từng build.
    console.log('[-] ' + modName + ': không thấy symbol custom_verify (có thể strip)');
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

  // .so nạp muộn → bắt qua dlopen rồi thử lại (spawn mode timing)
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
  console.log('[*] native: chờ libssl nạp qua dlopen…');
}

/* -------------------------------- RUN ---------------------------------- */
hookJava();
setTimeout(hookNative, 300);
// backup polling cho native strip/nạp muộn
let tries = 0;
const poll = setInterval(function () {
  if (++tries > 60) return clearInterval(poll);
  ['libssl.so', 'libmonochrome.so', 'libflutter.so'].forEach(function (n) {
    if (Process.findModuleByName(n)) neutralizeBoringSSL(n);
  });
}, 1000);
console.log('[*] ssl-unpin loaded');
