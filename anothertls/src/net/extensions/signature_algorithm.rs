/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::Extension;
use crate::net::extensions::shared::ExtensionType;
use crate::utils::bytes;

#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    // rsa_pkcs1_sha256 = 0x0401,
    // rsa_pkcs1_sha384 = 0x0501,
    // rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    // rsa_pss_rsae_sha256 = 0x0804,
    // rsa_pss_rsae_sha384 = 0x0805,
    // rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    // ed25519 = 0x0807,
    // ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    // rsa_pss_pss_sha256 = 0x0809,
    // rsa_pss_pss_sha384 = 0x080a,
    // rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    // rsa_pkcs1_sha1 = 0x0201,
    // ecdsa_sha1 = 0x0203,
}

impl SignatureScheme {
    pub fn new(buf: u16) -> Result<SignatureScheme, TlsError> {
        Ok(match buf {
            0x0403 => SignatureScheme::ecdsa_secp256r1_sha256,
            0x0503 => SignatureScheme::ecdsa_secp384r1_sha384,
            0x0603 => SignatureScheme::ecdsa_secp521r1_sha512,
            _ => return Err(TlsError::DecodeError),
        })
    }
}
#[derive(Debug)]
pub struct SignatureAlgorithms(pub Vec<SignatureScheme>);

impl SignatureAlgorithms {
    pub fn new(scheme: SignatureScheme) -> Self {
        Self(vec![scheme])
    }
    pub fn supported() -> Self {
        // TODO: extend supported signature scheme
        Self(vec![SignatureScheme::ecdsa_secp256r1_sha256])
    }
    // pub fn push(&mut self, scheme: SignatureScheme) {
    //     self.0.push(scheme)
    // }
    // pub fn parse_without_size(buf: &[u8]) -> Result<SignatureAlgorithms, TlsError> {
    //     let mut out = vec![];
    //     if buf.len() >= 2 {
    //         let tes = bytes::to_u16(&buf[0..2]);
    //         out.push(SignatureScheme::new(tes)?);
    //     }
    //     Ok(SignatureAlgorithms(out))
    // }
}

impl Extension for SignatureAlgorithms {
    fn server_as_bytes(&self) -> Vec<u8> {
        let len = self.0.len() * 2;
        let mut out = vec![
            0x00,
            ExtensionType::SignatureAlgorithms as u8,
            (len >> 8) as u8,
            len as u8 + 2,
            (len >> 8) as u8,
            len as u8,
        ];
        for scheme in self.0.iter() {
            let v = *scheme as u16;
            out.push((v >> 8) as u8);
            out.push(v as u8);
        }
        out
    }

    fn server_parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let len = bytes::to_u16(buf) as usize;
        let mut out = vec![];
        if len % 2 == 0 {
            for i in (2..len).step_by(2) {
                let tes = bytes::to_u16(&buf[i..(i + 2)]);
                out.push(SignatureScheme::new(tes)?);
            }
        }
        Ok(SignatureAlgorithms(out))
    }
}
