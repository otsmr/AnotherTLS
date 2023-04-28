/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::aes::gcm::Gcm;
use crate::crypto::chacha20::Poly1305;
use crate::hash::{Sha256, Sha384, TranscriptHash};
use crate::net::alert::TlsError;


pub trait Cipher {
    // FIXME: How to use traits without self
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), TlsError>;

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError>;
    fn get_cipher_suite(&self) -> CipherSuite;
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
}

impl CipherSuite {
    pub fn new(x: u16) -> Result<CipherSuite, TlsError> {
        Ok(match x {
            0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
            0x1303 => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
            0x00ff => CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            _ => return Err(TlsError::InsufficientSecurity),
        })
    }
    pub fn as_u16(&self) -> u16 {
        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => 0x1302,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => 0x1303,
            CipherSuite::TLS_AES_128_GCM_SHA256 => 0x1301,
            CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
        }
    }
    pub fn get_tshash(&self) -> Result<Box<dyn TranscriptHash>, TlsError> {
        let tshash: Box<dyn TranscriptHash> = match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => Box::new(Sha384::new()),
            CipherSuite::TLS_AES_128_GCM_SHA256 => Box::new(Sha256::new()),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Box::new(Sha256::new()),
            _ => return Err(TlsError::InsufficientSecurity),
        };
        Ok(tshash)
    }
    pub fn get_key_and_iv_len(&self) -> (usize, usize) {
        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => (32, 12),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
            CipherSuite::TLS_AES_128_GCM_SHA256 => (16, 12),
            // FIMXE: Key size?
            CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => (32, 12),
        }
    }
    pub fn get_cipher(&self) -> Result<Box<dyn Cipher>, TlsError> {
        let cipher: Box<dyn Cipher> = match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 | CipherSuite::TLS_AES_128_GCM_SHA256 => Box::new(Gcm::new(*self)),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Box::<Poly1305>::default(),
            _ => return Err(TlsError::InsufficientSecurity),
        };
        Ok(cipher)
    }
}
