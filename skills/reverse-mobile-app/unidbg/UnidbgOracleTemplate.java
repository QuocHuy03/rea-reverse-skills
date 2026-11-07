/*
 * UnidbgOracleTemplate.java — TEMPLATE: run an app's native encrypt/decrypt/sign
 * function as an OFFLINE ORACLE with unidbg (zhkl0228/unidbg). No device, no
 * Frida → the app's anti-frida/anti-debug/root checks never run. This is the
 * robust route for "mã hoá căng" (see docs/decryption-playbook.md §2c): you
 * don't extract the key, you just call the function the app itself uses.
 *
 * ADAPT the 6 placeholders marked  <<< EDIT >>>  to your target, then run it as
 * a JUnit test inside a unidbg checkout (see unidbg/README.md for setup).
 *
 * Idiom: build a 64-bit Android emulator → create a Dalvik VM → loadLibrary +
 * call JNI_OnLoad → invoke the native method through its owning DvmClass by JNI
 * signature. Feed a captured ciphertext byte[], read back the plaintext byte[].
 */
package com.rea.unidbg;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.util.Base64;

public class UnidbgOracleTemplate extends AbstractJni {

    // <<< EDIT 1 >>> the owning Java class of the native method, slash form.
    private static final String SIGN_CLASS = "com/target/app/security/NativeCrypto";
    // <<< EDIT 2 >>> paths to the pulled artifacts (adb pull from the device).
    private static final String APK_PATH = "unidbg-android/src/test/resources/target/base.apk";
    private static final String SO_PATH  = "unidbg-android/src/test/resources/target/lib/arm64-v8a/libnative.so";

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass cNativeCrypto;

    public UnidbgOracleTemplate() {
        // 64-bit ARM emulator. setProcessName to the real package (some libs read it).
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.target.app")                 // <<< EDIT 3 >>>
                .build();
        Memory memory = emulator.getMemory();
        // SDK level the lib expects (23 = Android 6; bump to 26/29 if JNI_OnLoad needs newer).
        memory.setLibraryResolver(new AndroidResolver(23));        // <<< EDIT 4 >>>

        // APK lets unidbg answer getPackageName()/signature()/etc. the lib may query.
        vm = emulator.createDalvikVM(new File(APK_PATH));
        vm.setJni(this);
        vm.setVerbose(true);   // prints every JNI call — invaluable while adapting; turn off later.

        DalvikModule dm = vm.loadLibrary(new File(SO_PATH), true);
        dm.callJNI_OnLoad(emulator);   // registers the native methods (RegisterNatives)
        module = dm.getModule();

        cNativeCrypto = vm.resolveClass(SIGN_CLASS);
    }

    /**
     * Call the native decrypt. <<< EDIT 5 >>> the method name + JNI signature +
     * static-vs-instance to match what jnitrace/REA told you. Example here:
     *   static byte[] decrypt(byte[] input)   →  "decrypt([B)[B"
     * For a String in/out use "(Ljava/lang/String;)Ljava/lang/String;" and
     * DvmObject/StringObject instead of ByteArray.
     */
    public byte[] decrypt(byte[] ciphertext) {
        ByteArray in = new ByteArray(vm, ciphertext);
        // static method:
        ByteArray out = (ByteArray) cNativeCrypto.callStaticJniMethodObject(
                emulator, "decrypt([B)[B", in);
        // instance method instead? create the object then:
        //   DvmObject<?> obj = cNativeCrypto.newObject(null);
        //   ByteArray out = (ByteArray) obj.callJniMethodObject(emulator, "decrypt([B)[B", in);
        return out.getValue();
    }

    // Alternative: call a plain C export by symbol/address (no JNI env needed),
    // when the function isn't a RegisterNatives method:
    //   Number n = module.callFunction(emulator, "exported_decrypt", arg0, arg1);
    //   (write inputs into emulator memory first and pass their pointers.)

    public void destroy() throws Exception { emulator.close(); }

    public static void main(String[] args) throws Exception {
        UnidbgOracleTemplate t = new UnidbgOracleTemplate();
        // <<< EDIT 6 >>> paste a REAL captured blob (base64 here) to prove the oracle.
        byte[] captured = Base64.getDecoder().decode("PASTE_CAPTURED_CIPHERTEXT_B64");
        byte[] plain = t.decrypt(captured);
        System.out.println("plaintext: " + new String(plain));   // expect valid JSON
        t.destroy();
    }

    /*
     * If the lib calls back into Java (SystemProperties, getPackageInfo, a Java
     * MD5/AES helper, currentTimeMillis…), unidbg routes it here. Override the
     * needed callbacks; vm.setVerbose(true) above prints the exact signature to
     * implement. Common ones:
     *
     * @Override
     * public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass,
     *         String signature, VarArg varArg) {
     *     switch (signature) {
     *         case "android/os/SystemProperties->get(Ljava/lang/String;)Ljava/lang/String;":
     *             return new StringObject(vm, "");   // return what the real device would
     *     }
     *     return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
     * }
     */
}
