/*
 * dump-signer.js — TEMPLATE hook hàm ký request để lộ công thức.
 * Sửa <FQCN> + <method> theo class tìm được bằng REA (search-android-classes /
 * trace-android-references), rồi: frida -U -f <package> -l dump-signer.js --no-pause
 *
 * In ra chuỗi ĐẦU VÀO (trước khi hash/HMAC) + giá trị trả về. So chuỗi in được
 * với các field của request thật đã capture → suy ra công thức ghép
 * (path + body + ts + nonce + secret …). Đây là cách nhanh & chắc nhất.
 */
'use strict';

Java.perform(function () {
  const TARGET_CLASS = 'com.foo.security.Signer';   // <-- sửa
  const TARGET_METHOD = 'sign';                     // <-- sửa

  try {
    const C = Java.use(TARGET_CLASS);
    // hook mọi overload của method
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
    console.log('[-] không hook được: ' + e.message);
  }

  // Bonus: bắt thuật toán phổ biến để lần key/mode khi chưa biết class ký.
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
