# Frida scripts

- **ssl-unpin.js** — universal SSL pinning bypass. Java layer (TrustManager, HostnameVerifier, OkHttp `CertificatePinner` including obfuscated builds, Conscrypt) + native BoringSSL (`SSL_[CTX_]set_custom_verify`), with `android_dlopen_ext`/`dlopen` hooks to catch late-loaded `.so`s (spawn mode) and a fallback polling loop.
- **dump-signer.js** — TEMPLATE hook for the request-signing function to reveal the input string + output. Edit `TARGET_CLASS`/`TARGET_METHOD` to match the class you found with REA.

Further reference techniques:
- `dlopen` timing + scanning for obfuscated OkHttp classes: learned from [danieldev23/frida-ssl-bypass](https://github.com/danieldev23/frida-ssl-bypass).
- When stuck, pair it with stronger community builds: [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/), or `objection android sslpinning disable`.

These scripts are for lawful analysis (your own apps / authorized research / CTF). Comply with the law and software licenses.
