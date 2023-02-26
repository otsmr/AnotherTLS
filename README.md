# AnotherTls
Yet another TLS implementation, but written **from scratch** (including the
crypto) in pure Rust - of course.


Goal: To use it in my websocket implementation,
[WebRocket](https://github.com/otsmr/webrocket). And to learn about common
mistakes when implementing crypto, especially when using elliptic curves.


It depends only on the following crates:
```bash
cargo tree
anothertls v0.1.0
├── ibig v0.3.6
│   ├── cfg-if v1.0.0
│   └── static_assertions v1.1.0
└── log v0.4.17
└── cfg-if v1.0.0
```

## standards
### already implemented
- Hash: [SHA256](https://datatracker.ietf.org/doc/html/rfc6234)
- Cipher: [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- Cipher suite: [TLS_AES_128_GCM_SHA256](https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf)
- TLS curves: [prime256v1]()
### work in progress
- [TLSv1.3](https://datatracker.ietf.org/doc/html/rfc8446) (with [Modern compatibility](https://wiki.mozilla.org/Security/Server_Side_TLS))
- Certificate type: ECDSA (P-256)
- Hash: [SHA384](https://datatracker.ietf.org/doc/html/rfc6234) (+TLS_AES_256_GCM_SHA384)
### Maybe
- Cipher suite: [TLS_CHACHA20_POLY1305_SHA256]()
- TLS curves: [secp384r1]()
- TLS curves: [X25519]()
