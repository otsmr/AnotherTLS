# AnotherTls
Yet another TLS implementation, but written in pure Rust - of course.

Goal: To use it in my websocket implementation,
[WebRocket](https://github.com/otsmr/webrocket). And to learn about common
mistakes when implementing crypto, especially when using elliptic curves.


## standards
- [TLSv1.3](https://datatracker.ietf.org/doc/html/rfc8446) (with [Modern compatibility](https://wiki.mozilla.org/Security/Server_Side_TLS))
### already implemented
- Hash: [SHA256](https://datatracker.ietf.org/doc/html/rfc6234)
- Cipher: [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [ECDSA]()
- TLS curves: [prime256v1]()
### work in progress
- Certificate type: ECDSA (P-256)
- Cipher suite: [TLS_AES_128_GCM_SHA256](https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf)
### Maybe
- Cipher suite: [TLS_AES_256_GCM_SHA384]()
- Hash: [SHA384](https://datatracker.ietf.org/doc/html/rfc6234)
- Cipher suite: [TLS_CHACHA20_POLY1305_SHA256]()
- [SHA384](https://datatracker.ietf.org/doc/html/rfc6234)
- TLS curves: [secp384r1]()
- TLS curves: [X25519]()
