/*
 * rpc-signer.js — FALLBACK: turn the live app into a signing oracle.
 * Use only when the signing algorithm lives in a native .so you can't
 * reimplement or emulate (unidbg). The device/app stays in the loop.
 *
 * Run:   frida -U -f <package> -l rpc-signer.js --no-pause
 * Then from Python (pip install frida):
 *
 *   import frida
 *   dev = frida.get_usb_device()
 *   pid = dev.spawn(["<package>"]); sess = dev.attach(pid)
 *   script = sess.create_script(open("rpc-signer.js").read())
 *   script.load(); dev.resume(pid)
 *   print(script.exports_sync.sign("the-string-to-sign"))
 *
 * Edit TARGET_CLASS/TARGET_METHOD to the signer you located with REA
 * (search-android-classes / trace-android-references) or jnitrace.
 */
'use strict';

const TARGET_CLASS = 'com.foo.security.Signer';   // <-- edit
const TARGET_METHOD = 'sign';                     // <-- edit

rpc.exports = {
  // Call the Java signer and return its result to the Python host.
  sign: function (input) {
    return new Promise(function (resolve, reject) {
      Java.perform(function () {
        try {
          const C = Java.use(TARGET_CLASS);
          // If several overloads exist, pick the String one explicitly.
          const r = C[TARGET_METHOD].overload('java.lang.String')
            ? C[TARGET_METHOD].overload('java.lang.String').call(C.$new(), input)
            : C[TARGET_METHOD](input);
          resolve(r != null ? r.toString() : null);
        } catch (e) {
          reject('' + e);
        }
      });
    });
  },

  // Some signers are static OR need an instance. If sign() above throws,
  // adapt here: get a live instance via a hooked constructor, Java.choose,
  // or call a static method directly.
  ping: function () { return 'ok'; },
};

console.log('[*] rpc-signer loaded — call script.exports_sync.sign(...) from Python');
