# AnotherTLS™
Yet another TLS implementation, but written **from scratch** (including the
crypto) in **pure Rust** - of course. The focus of this implementation is the
simplicity and to use no dependencies. I started this project to deep dive into
Rust, cryptography and network protocols. So don't use it in production, just
**use [rustls](https://crates.io/crates/rustls)** as it is the better choice
and will be forever.

**If you are interested in hacking TLS, you should checkout my
[VulnTLS](https://github.com/otsmr/VulnTLS) project.**

## What makes AnotherTLS unique?
It depends only on the standard library and the ibig crate. So you will find
**the entire TLSv1.3 stack in a single repo** to play around with, as I do with
my VulnTLS implementation. Also, everything is public, so you can use
AnotherTLS to easily simulate parts of TLS for example to write an exploit :^).


With the current version it is possible to connect via curl or the browser with
the AnotherTLS server. AnotherTLS can also be used as a client. Since the
parsing of certificates is still WIP, it is not yet possible to connect
(securely) to known websites.


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

## security
Currently, the focus of this implementation is to be TLS-complaint according to
the [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446), but when all
requirements are implemented, I will switch the focus to the security part,
because this is one of the main reasons I started this project.


**Todo**
- setup [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)
- setup [TLS-Attacker](https://github.com/tls-attacker/TLS-Attacker)

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

### open
- TLS curves: [secp384r1]()

## status of [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446)
The Implementation is currently work in progress. The current state is
tracked in the following section.

```
4. Handshake Protocol
 4.1. Key Exchange Messages
  4.1.1. Cryptographic Negotiation ✓
  4.1.2. Client Hello ✓
  4.1.3. Server Hello ✓
  4.1.4. Hello Retry Request ×
 4.2. Extension
  4.2.1. Supported Versions ✓
  4.2.2. Cookie ×
  4.2.3. Signature Algorithms (✓)
  4.2.4. Certificate Authority
  4.2.5. OID Filter ×
  4.2.6. Post-Handshake Client Authentication ×
  4.2.7. Supported Groups ( ✓)
  4.2.8. Key Share  ✓
  4.2.9. Pre-Shared Key Exchange Mode ×
  4.2.10. Early Data Indication ×
  4.2.11. Pre-Shared Key Extension ×
 4.3. Server Parameters ✓
  4.3.1. Encrypted Extensions ✓
  4.3.2. Certificate Request ✓
 4.4. Authentication Messages ✓
  4.4.1. The Transcript Hash ✓
  4.4.2. Certificat ✓
  4.4.3. Certificate Verify ✓
  4.4.4. Finished ✓
 4.5. End of Early Data ×
 4.6. Post-Handshake Messages ×
  4.6.1. New Session Ticket Message MAY for server
  4.6.2. Post-Handshake Authentication MAY for server
  4.6.3. Key and Initialization Vector Update ×
5. Record Protocol
  5.1. Record Layer ✓
  5.2. Record Payload Protection ✓
  5.3. Per-Record Nonce ✓
  5.4. Record Padding ✓
  5.5. Limits on Key Usage ×
 6. Alert Protocol
  6.1. Closure Alerts ✓
  6.2. Error Alerts ✓
9.1.  Mandatory-to-Implement Cipher Suites (✓, no support for rsa)
 MUST
  cipher suite
   TLS_AES_128_GCM_SHA256 ✓
  digital signatures
   rsa_pkcs1_sha256 (for certificates)
   rsa_pss_rsae_sha256 (for CertificateVerify and certificates)
   ecdsa_secp256r1_sha256 ✓
  key exchange
   secp256r1 (NIST P-256) (✓, wip)
 SHOULD
  cipher suite
   TLS_AES_256_GCM_SHA384 ✓
   TLS_CHACHA20_POLY1305_SHA256 TODO: https://datatracker.ietf.org/doc/html/rfc8439
  key exchange
   X25519 ✓
```

