/*
 * rpc-signer.js — turn the LIVE app into a signing oracle (Frida-RPC).
 * Use when the signer is native/obfuscated/white-box/stateful and you can't (or
 * won't) reimplement it — see docs/hard-sign-types.md. The device + app stay in
 * the loop, so anti-tamper, white-box keys and TEE/keystore ops all "just work"
 * because the real code runs. For an OFFLINE oracle use unidbg instead.
 *
 * Run:   frida -U -f <package> -l rpc-signer.js --no-pause
 *        (stack with anti-detect.js if the app detects Frida)
 * Python (pip install frida):
 *   import frida
 *   dev = frida.get_usb_device(); pid = dev.spawn(["<package>"])
 *   s = dev.attach(pid); sc = s.create_script(open("rpc-signer.js").read())
 *   sc.load(); dev.resume(pid)
 *   sc.exports_sync.init()                      # once, for argus/ladon-class SDKs
 *   print(sc.exports_sync.sign(["https://api/x", "{\"a\":1}", "1730900000"]))
 *
 * Fill the CONFIG from what REA/jnitrace told you. Edit per case as noted.
 */
'use strict';

// ---- CONFIG: the Java signer (RegisterNatives natives are reached here too) ----
const SIGN_CLASS   = 'com.foo.security.Signer';  // <-- edit (dot form)
const SIGN_METHOD  = 'sign';                      // <-- edit
const SIGN_STATIC  = false;                        // static method? else an instance is used
const SIGN_OVERLOAD = null;                        // e.g. ['java.lang.String','java.lang.String'] if multiple overloads
// ---- CONFIG: one-time init/register some SDKs need before the first sign ----
const INIT_CLASS   = null;                          // e.g. 'com.foo.security.Ladon'  (null = skip)
const INIT_METHOD  = 'init';
const INIT_STATIC  = true;
const INIT_ARGS    = [];                            // literal args the init needs, if any

function callJava(cls, method, isStatic, overload, args) {
  return new Promise(function (resolve, reject) {
    Java.perform(function () {
      try {
        const C = Java.use(cls);
        const m = overload ? C[method].overload.apply(C[method], overload) : C[method];
        const invoke = function (recv) {
          const r = m.apply(recv, args || []);
          resolve(r != null ? r.toString() : null);
        };
        if (isStatic) { invoke(C); return; }
        // instance method: prefer a LIVE instance (keeps SDK state), else construct one
        let found = false;
        try {
          Java.choose(cls, {
            onMatch: function (inst) { if (!found) { found = true; invoke(inst); } return 'stop'; },
            onComplete: function () { if (!found) invoke(C.$new()); }
          });
        } catch (_) { invoke(C.$new()); }
      } catch (e) { reject('' + e); }
    });
  });
}

rpc.exports = {
  ping: function () { return 'ok'; },

  // Call the one-time init/register (argus/ladon-class SDKs seed device+counter here).
  init: function () {
    if (!INIT_CLASS) return Promise.resolve('no-init-configured');
    return callJava(INIT_CLASS, INIT_METHOD, INIT_STATIC, null, INIT_ARGS);
  },

  // Call the signer. Pass an array of args (strings/numbers) matching its signature,
  // or a single value. Returns the signature string.
  sign: function (args) {
    const a = Array.isArray(args) ? args : [args];
    return callJava(SIGN_CLASS, SIGN_METHOD, SIGN_STATIC, SIGN_OVERLOAD, a);
  },

  // Pure-C export (not a RegisterNatives method): char* f(const char*).
  // Adapt the NativeFunction ret/arg types + marshalling to the real prototype
  // (jnitrace/REA gives it). Returns the result as a UTF-8 string.
  signNative: function (moduleName, exportName, inputStr) {
    const addr = Module.findExportByName(moduleName, exportName);
    if (!addr) return 'export-not-found';
    const fn = new NativeFunction(addr, 'pointer', ['pointer']);   // <-- edit prototype
    const inp = Memory.allocUtf8String('' + inputStr);
    const res = fn(inp);
    try { return res.readUtf8String(); } catch (e) { return res.toString(); }
  },
};

console.log('[*] rpc-signer loaded — init() then sign([...]) / signNative(mod,exp,in) from Python');
