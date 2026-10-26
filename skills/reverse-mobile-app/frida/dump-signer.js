/*
 * dump-signer.js — TEMPLATE hook for the request-signing function to reveal the formula.
 * Edit <FQCN> + <method> to match the class you found with REA (search-android-classes /
 * trace-android-references), then: frida -U -f <package> -l dump-signer.js --no-pause
 *
 * Prints the INPUT string (before hash/HMAC) + the return value. Compare the printed
 * string against the fields of a real captured request → infer how the formula is assembled
 * (path + body + ts + nonce + secret …). This is the fastest and most reliable way.
 */
'use strict';

Java.perform(function () {
  const TARGET_CLASS = 'com.foo.security.Signer';   // <-- edit
  const TARGET_METHOD = 'sign';                     // <-- edit

  try {
    const C = Java.use(TARGET_CLASS);
    // hook every overload of the method
    C[TARGET_METHOD].overloads.forEach(function (ov) {
      ov.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        const r = ov.apply(this, args);
        console.log('\n[sign] ' + TARGET_CLASS + '.' + TARGET_METHOD +
          '\n  in : ' + args.map(String).join(' | ') +
          '\n  out: ' + r);
        return r;
      };
    });
    console.log('[+] hooked ' + TARGET_CLASS + '.' + TARGET_METHOD +
      ' (' + C[TARGET_METHOD].overloads.length + ' overload)');
  } catch (e) {
    console.log('[-] could not hook: ' + e.message);
  }

  // Bonus: catch common algorithms to trace the key/mode when the signing class is unknown.
  try {
    const MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (b) {
      console.log('[MessageDigest ' + this.getAlgorithm() + '] len=' + b.length);
      return this.digest(b);
    };
  } catch (_) {}
  try {
    const Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload('[B').implementation = function (b) {
      console.log('[Mac ' + this.getAlgorithm() + '] input bytes=' + b.length);
      return this.doFinal(b);
    };
  } catch (_) {}
  try {
    const Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (b) {
      console.log('[Cipher ' + this.getAlgorithm() + '] opmode set, input=' + b.length);
      return this.doFinal(b);
    };
  } catch (_) {}
});
