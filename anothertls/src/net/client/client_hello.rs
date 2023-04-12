/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */
#![allow(non_camel_case_types)]

use crate::{
    crypto::CipherSuite,
    net::{
        alert::TlsError,
        extensions::{self, shared::KeyShareEntry, ClientExtension},
    },
    utils::log,
};
use std::result::Result;

pub(crate) struct ClientHello<'a> {
    pub random: &'a [u8],
    pub cipher_suites: Vec<CipherSuite>,
    pub legacy_session_id_echo: Option<&'a [u8]>,
    pub extensions: Vec<ClientExtension>,
}

impl<'a> ClientHello<'a> {
    pub fn new(random: &'a [u8]) -> Result<ClientHello, TlsError> {
        Ok(ClientHello {
            random,
            cipher_suites: vec![CipherSuite::TLS_AES_256_GCM_SHA384, CipherSuite::TLS_AES_128_GCM_SHA256],
            legacy_session_id_echo: None,
            extensions: vec![],
        })
    }
    pub fn as_bytes(&self) -> Result<Vec<u8>, TlsError> {
        Ok(vec![])
    }
    pub fn from_raw(buf: &[u8]) -> Result<ClientHello, TlsError> {
        if buf.len() < 100 {
            // FIXME: make this dynamic -> extensions_len...
            return Err(TlsError::IllegalParameter);
        }

        let legacy_version = ((buf[0] as u16) << 8) | buf[1] as u16;
        if legacy_version != 0x0303 {
            return Err(TlsError::ProtocolVersion);
        }

        let random = buf[2..34].try_into().unwrap();
        let session_id_length = buf[35];
        let mut consumed = 35;
        let mut legacy_session_id_echo = None;

        if session_id_length != 0 {
            consumed += 32;
            legacy_session_id_echo = Some(&buf[35..(35 + 32)]);
        }

        // Cipher Suites
        let cipher_suites_len = ((buf[consumed] as u16) << 8) | (buf[consumed + 1] as u16);
        if cipher_suites_len % 2 != 0 || buf.len() < (consumed + cipher_suites_len as usize) {
            return Err(TlsError::IllegalParameter);
        }
        consumed += 2;
        let mut cipher_suites = vec![];
        log::debug!("Clients CipherSuites:");
        for i in (consumed..(consumed + cipher_suites_len as usize)).step_by(2) {
            let cs = CipherSuite::new(((buf[i] as u16) << 8) | (buf[i + 1] as u16));
            if let Ok(cs) = cs {
                log::debug!("  {cs:?}");
                cipher_suites.push(cs);
            }
        }

        consumed += cipher_suites_len as usize;

        // Compression Methode
        // TLS 1.3 no longer allows compression
        consumed += 2;

        let extensions_len = ((buf[consumed] as usize) << 8) | (buf[consumed + 1] as usize);
        consumed += 2;

        let extensions = extensions::ClientExtension::from_client_hello(
            &buf[consumed..(consumed + extensions_len)],
        )?;

        Ok(ClientHello {
            random,
            cipher_suites,
            legacy_session_id_echo,
            extensions,
        })
    }

    pub fn get_public_key_share(&self) -> Option<&KeyShareEntry> {
        for ext in self.extensions.iter() {
            if let ClientExtension::KeyShare(key_share) = ext {
                if !key_share.0.is_empty() {
                    return Some(&key_share.0[0]);
                }
            }
        }
        None
    }
}
