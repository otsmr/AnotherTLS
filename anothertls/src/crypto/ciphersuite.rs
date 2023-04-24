/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::aes::gcm::Gcm;
use crate::crypto::chacha20::Poly1305;
use crate::hash::{Sha256, Sha384, TranscriptHash};
use crate::net::alert::TlsError;


pub trait Cipher {
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, u128), String>;

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: u128,
    ) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 1303,
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
    pub fn get_cipher(&self) -> Result<Box<dyn Cipher>, TlsError> {
        let cipher: Box<dyn Cipher> = match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => Box::<Gcm>::default(),
            CipherSuite::TLS_AES_128_GCM_SHA256 => Box::<Gcm>::default(),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Box::<Poly1305>::default(),
            _ => return Err(TlsError::InsufficientSecurity),
        };
        Ok(cipher)
    }
}
