# AnotherTLS
Yet another TLS implementation, but written **from scratch** (including the
crypto) in **pure Rust** - of course. The focus of this implementation is the
simplicity and to use no dependencies. I started this project to deep dive into
Rust, cryptography and network protocols.

**If you are interested in hacking TLS, you should checkout my
[VulnTLS](https://github.com/otsmr/VulnTLS) project.**

## What makes AnotherTLS unique?
It depends only on the standard library and the `ibig` crate. So you will find
**the entire TLSv1.3 stack in a single repo** to play around with, as I do with
my VulnTLS implementation. Also, everything is `pub`, so you can use AnotherTLS
to easily simulate parts of TLS for example to write an exploit.

With the current version it is possible to connect via curl or the browser with
the AnotherTLS server. AnotherTLS can also be used as a client. Since the
parsing of certificates is still WIP, it is not yet possible to connect
(securely) to known websites (resp. certificates are not verified).


**handshake and application data**
```bash
$ cargo run --bin server_https
# other window
$ curl -iv --insecure https://localhost:4000/
```

**client certificate**
```bash
$ cargo run --bin server_client_auth
# other window
$ cd ./examples/src/bin/config/client_cert/
$ curl --cert client.signed.cert --key client.key -iv --insecure https://localhost:4000/
```

For more information about using AnotherTLS, see the `./examples` folder.


## depending standards
The TLSv1.3 stack consists of the following standards, which are also
implemented in this repository.

### implemented
- [SHA256](https://datatracker.ietf.org/doc/html/rfc6234)
- [SHA384](https://datatracker.ietf.org/doc/html/rfc6234)
- [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES_GCM](https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf)
- [prime256v1](https://github.com/starkbank/ecdsa-python/)
- [X25519](https://martin.kleppmann.com/papers/curve25519.pdf)
- [HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [X.509](https://www.rfc-editor.org/rfc/rfc5280#section-4.1)
- [CHACHA20_POLY1305](https://datatracker.ietf.org/doc/html/rfc8439)
- [CHACHA20_POLY1305_TLS](https://www.rfc-editor.org/rfc/rfc7905)

### open
- TLS curves: [secp384r1]()


## security
Currently, the focus of this implementation is to be TLS-complaint according to
the [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446), but when all
requirements are implemented, I will switch the focus to the security part,
because this is one of the main reasons I started this project.

**Todo**
- setup [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)
- setup [TLS-Attacker](https://github.com/tls-attacker/TLS-Attacker)

