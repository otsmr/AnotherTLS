/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::ellipticcurve::{Curve, PrivateKey};
use crate::crypto::CipherSuite;
use crate::net::alert::TlsError;
use crate::net::client::ClientHello;
use crate::net::extensions::{
    server::ServerExtension, ClientExtension, KeyShare, KeyShareEntry, NamedGroup,
    ServerExtensions, SignatureScheme, SupportedVersions,
};
use crate::net::server::ServerConfig;
use crate::rand::RngCore;
use crate::utils::bytes::{self, ByteOrder};
use crate::utils::log;
use ibig::IBig;
use std::result::Result;

pub struct ServerHello<'a> {
    pub random: [u8; 32],
    pub legacy_session_id_echo: Option<&'a [u8]>,
    pub cipher_suite: CipherSuite,
    pub extensions: ServerExtensions,
}

impl<'a> ServerHello<'a> {
    pub fn from_raw(buf: &[u8]) -> Result<ServerHello, TlsError> {
        if buf.len() < 36 {
            return Err(TlsError::IllegalParameter);
        }

        let legacy_version = ((buf[0] as u16) << 8) | buf[1] as u16;
        if legacy_version != 0x0303 {
            println!("legacy_version={:#x}", legacy_version);
            return Err(TlsError::ProtocolVersion);
        }

        let random: [u8; 32] = buf[2..34].try_into().unwrap();
        let session_id_length = buf[34];
        let mut consumed = 35;
        // let mut legacy_session_id_echo = None;

        if session_id_length != 0 {
            consumed += 32;
            // legacy_session_id_echo = Some(&buf[35..(35 + 32)]);
        }

        let cipher_suite =
            CipherSuite::new(((buf[consumed] as u16) << 8) | (buf[consumed + 1] as u16))?;

        consumed += 3; // CipherSuite + Compression Method

        let extensions_len = ((buf[consumed] as usize) << 8) | (buf[consumed + 1] as usize);
        consumed += 2;

        let extensions =
            ServerExtensions::from_server_hello(&buf[consumed..(consumed + extensions_len)])?;

        let mut tls13_is_supported = false;
        for ext in extensions.as_vec().iter() {
            if let ServerExtension::SupportedVersions(ext) = ext {
                if ext.is_tls13_supported() {
                    tls13_is_supported = true;
                }
                break;
            }
        }

        if !tls13_is_supported {
            return Err(TlsError::ProtocolVersion);
        }

        Ok(ServerHello {
            random,
            legacy_session_id_echo: None,
            cipher_suite,
            extensions,
        })
    }
    pub fn from_client_hello(
        client_hello: &'a ClientHello,
        rng: &mut dyn RngCore<IBig>,
        config: &'a ServerConfig,
    ) -> Result<(ServerHello<'a>, PrivateKey), TlsError> {
        let mut extensions = ServerExtensions::new();
        let mut private_key = None;
        let mut named_group = None;

        let random: [u8; 32] = rng.bytes(32).try_into().unwrap();

        // Value is: DOWNGRD
        // Only needed if negotiating TLSv1.2
        // let downgrade_protection = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

        // for (i, b) in downgrade_protection.iter().enumerate() {
        //     random[(32 - 8) + i] = *b;
        // }

        for ext in client_hello.extensions.as_vec().iter() {
            match ext {
                ClientExtension::SupportedVersion(version) => {
                    if !version.is_tls13_supported() {
                        return Err(TlsError::InsufficientSecurity);
                    }
                }
                ClientExtension::KeyShare(key_share) => {
                    for key in key_share.0.iter() {
                        match key.group {
                            NamedGroup::X25519 => {
                                log::debug!("TLS key exchange using ECDHE with Curve25519");
                                let secret = rng.between(1, 32);
                                let pk = PrivateKey::new(Curve::curve25519(), secret);
                                let key_share_data = bytes::ibig_to_32bytes(
                                    pk.get_public_key().point.x,
                                    ByteOrder::Little,
                                );
                                private_key = Some(pk);
                                let kse =
                                    KeyShareEntry::new(NamedGroup::X25519, key_share_data.to_vec());
                                extensions.push(ServerExtension::KeyShare(KeyShare::new(kse)));
                                named_group = Some(NamedGroup::X25519);
                                break;
                            }
                            NamedGroup::Secp256r1 => {
                                todo!("Add support for secp256 key exchange");
                                // named_group = Some(NamedGroup::Secp256r1);
                            }
                            _ => {}
                        }
                    }
                }
                ClientExtension::ServerName(server_name) => {
                    if let Some(expected_server_name) = &config.server_name {
                        if expected_server_name != server_name.get() {
                            return Err(TlsError::UnrecognizedName);
                        }
                    }
                }
                ClientExtension::SignatureAlgorithms(sa) => {
                    let mut supported = false;
                    for sig_algo in sa.0.iter() {
                        if matches!(sig_algo, SignatureScheme::ecdsa_secp256r1_sha256) {
                            supported = true;
                            break;
                        }
                    }
                    if !supported {
                        return Err(TlsError::InsufficientSecurity);
                    }
                }
                ClientExtension::SupportedGroups(_sg) => (),
            }
        }

        if named_group.is_none() {
            log::error!("No supported group -> Hello Retry Request");
            return Err(TlsError::InsufficientSecurity);
        }

        extensions.push(ServerExtension::SupportedVersions(SupportedVersions::new(
            true,
        )));

        let mut cipher_suite_to_use = None;
        // let mut hash = None;
        for cs in client_hello.cipher_suites.iter() {
            match cs {
                CipherSuite::TLS_AES_256_GCM_SHA384 => {
                    cipher_suite_to_use = Some(CipherSuite::TLS_AES_256_GCM_SHA384);
                    // hash = Some(HashType::SHA384);
                    break; // Break because server best choice
                }
                CipherSuite::TLS_AES_128_GCM_SHA256 => {
                    // hash = Some(HashType::SHA256);
                    cipher_suite_to_use = Some(CipherSuite::TLS_AES_128_GCM_SHA256)
                }
                _ => (),
            }
        }

        let cipher_suite = match cipher_suite_to_use {
            Some(cs) => cs,
            None => return Err(TlsError::HandshakeFailure),
        };

        let private_key = match private_key {
            Some(pk) => pk,
            None => return Err(TlsError::HandshakeFailure),
        };

        log::debug!("TLS connection using {cipher_suite:?}");

        Ok((
            ServerHello {
                random,
                legacy_session_id_echo: client_hello.legacy_session_id_echo,
                cipher_suite,
                // hash: hash.unwrap(),
                extensions,
            },
            private_key,
        ))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x3, 0x3]; // Server Version
        out.extend_from_slice(&self.random);

        if let Some(session_id) = self.legacy_session_id_echo {
            out.push(session_id.len() as u8);
            out.extend_from_slice(session_id);
        } else {
            out.push(0);
        }

        let cs = self.cipher_suite as u16;
        out.push((cs >> 8) as u8);
        out.push(cs as u8);

        out.push(00); // Compression Method

        let server_extensions_raw = self.extensions.as_bytes();
        out.extend(server_extensions_raw);

        out
    }
    pub fn get_public_key_share(&self) -> Option<&KeyShareEntry> {
        for ext in self.extensions.as_vec().iter() {
            if let ServerExtension::KeyShare(key_share) = ext {
                if !key_share.0.is_empty() {
                    return Some(&key_share.0[0]);
                }
            }
        }
        None
    }
}
