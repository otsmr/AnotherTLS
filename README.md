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
```

## status of RFC8446
- [TLSv1.3](https://datatracker.ietf.org/doc/html/rfc8446)
```
4. Handshake Protocol
 4.1. Key Exchange Messages
  4.1.1. Cryptographic Negotiation ✓
  4.1.2. Client Hello ✓
  4.1.3. Server Hello ✓
  4.1.4. Hello Retry Request
 4.2. Extension
  4.2.1. Supported Versions ✓
  4.2.2. Cookie
  4.2.3. Signature Algorithms (✓)
  4.2.4. Certificate Authoritie
  4.2.5. OID Filter
  4.2.6. Post-Handshake Client Authentication
  4.2.7. Supported Groups ( ✓)
  4.2.8. Key Share  ✓
  4.2.9. Pre-Shared Key Exchange Mode
  4.2.10. Early Data Indication
  4.2.11. Pre-Shared Key Extension
 4.3. Server Parameters ✓
  4.3.1. Encrypted Extensions ✓
  4.3.2. Certificate Request ✓
 4.4. Authentication Messages ✓
  4.4.1. The Transcript Hash ✓
  4.4.2. Certificat ✓
  4.4.3. Certificate Verify ✓
  4.4.4. Finished ✓
 4.5. End of Early Data
 4.6. Post-Handshake Messages
  4.6.1. New Session Ticket Message
  4.6.2. Post-Handshake Authentication
  4.6.3. Key and Initialization Vector Update
5. Record Protocol
  5.1. Record Layer ✓
  5.2. Record Payload Protection ✓
  5.3. Per-Record Nonce ✓
  5.4. Record Padding
  5.5. Limits on Key Usage
 6. Alert Protocol
  6.1. Closure Alerts
  6.2. Error Alerts
9.1.  Mandatory-to-Implement Cipher Suites
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
   TLS_CHACHA20_POLY1305_SHA256
  key exchange
   X25519 ✓
```
## depending standards
### implemented
- [SHA256](https://datatracker.ietf.org/doc/html/rfc6234)
- [SHA384](https://datatracker.ietf.org/doc/html/rfc6234)
- [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES_GCM](https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf)
- [prime256v1](https://github.com/starkbank/ecdsa-python/)
- [X25519](https://martin.kleppmann.com/papers/curve25519.pdf)
- [HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [HMAC](https://www.rfc-editor.org/rfc/rfc2104)
### work in progress
### maybe
- Cipher suite: [TLS_CHACHA20_POLY1305_SHA256]()
- TLS curves: [secp384r1]()


## Example
```bash
/opt/homebrew/opt/curl/bin/curl --tlsv1.3 -iv --insecure https://localhost:4000/
```
