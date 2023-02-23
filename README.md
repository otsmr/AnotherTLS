# AnotherTls
Yet another TLS implementation, but written in pure Rust - of course.

Goal: To use it in my websocket implementation,
[WebRocket](https://github.com/otsmr/webrocket). And to learn about common
mistakes when implementing crypto, especially when using elliptic curves.


## standards
### already implemented
- [SHA256](https://datatracker.ietf.org/doc/html/rfc6234)
- [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [ECDSA (P-256)]()
### work in progress
- [TLSv1.3](https://datatracker.ietf.org/doc/html/rfc8446) (with [Modern compatibility](https://wiki.mozilla.org/Security/Server_Side_TLS))
- Cipher suite: [TLS: AES_256_GCM]()
- Key exchange protocol: [TLS: X25519]()
### Maybe
- Cipher suite: [TLS: AES_128_GCM]()
- Cipher suite: [TLS: HACHA20_POLY1305]()
- [SHA384](https://datatracker.ietf.org/doc/html/rfc6234)
- TLS curves: [TLS: secp384r1]()
