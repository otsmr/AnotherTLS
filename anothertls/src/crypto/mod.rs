/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_camel_case_types)]

pub mod aes;
pub mod ellipticcurve;
use crate::net::alert::TlsError;

#[derive(Debug, Clone, Copy)]
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
            _ => 0x0000,
        }
    }
}
