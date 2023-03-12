/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use ibig::{ibig, IBig};
use std::result::Result;

use crate::{
    crypto::{
        ellipticcurve::{Curve, PrivateKey},
        CipherSuite,
    },
    hash::HashType,
    net::{
        extensions::{
            ClientExtension, KeyShare, KeyShareEntry, ServerExtension, ServerExtensions,
            SupportedVersions,
        },
        handshake::ClientHello,
        named_groups::NamedGroup,
        alert::TlsError,
        TlsContext,
    },
    utils::bytes::{self, ByteOrder},
};

pub struct ServerHello<'a> {
    pub random: [u8; 32],
    pub legacy_session_id_echo: Option<&'a [u8]>,
    pub cipher_suite: CipherSuite,
    pub hash: HashType,
    pub named_group: NamedGroup,
    pub private_key: PrivateKey,
    pub extensions: ServerExtensions,
}

impl<'a> ServerHello<'a> {
    pub fn from_client_hello(
        client_hello: &'a ClientHello,
        config: &mut TlsContext,
    ) -> Result<ServerHello<'a>, TlsError> {
        let mut extensions = ServerExtensions::new();
        let mut private_key = None;
        let mut named_group = NamedGroup::X25519;

        for ext in client_hello.extensions.iter() {
            match ext {
                ClientExtension::SupportedVersion(version) => {
                    if !version.tls13 {
                        return Err(TlsError::InsufficientSecurity);
                    }
                }
                ClientExtension::KeyShare(key_share) => {
                    for key in key_share.0.iter() {
                        match key.group {
                            NamedGroup::X25519 => {
                                let curve = Curve::curve25519();
                                // FIMXE: Remove hardcoded secret
                                let secret = ibig!(_909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf base 16);
                                let pk = PrivateKey::new(curve, secret);
                                private_key = Some(pk);
                                break;
                            }
                            NamedGroup::Secp256r1 => {
                                named_group = NamedGroup::Secp256r1;
                            }
                            _ => {}
                        }
                    }
                }
                _ => (),
            }
        }

        extensions.push(ServerExtension::SupportedVersion(SupportedVersions::new(
            true, false,
        )));

        let mut cipher_suite_to_use = None;
        let mut hash = None;
        for cs in client_hello.cipher_suites.iter() {
            match cs {
                CipherSuite::TLS_AES_256_GCM_SHA384 => {
                    cipher_suite_to_use = Some(CipherSuite::TLS_AES_256_GCM_SHA384);
                    hash = Some(HashType::SHA384);
                    break;
                }
                CipherSuite::TLS_AES_128_GCM_SHA256 => {
                    hash = Some(HashType::SHA256);
                    cipher_suite_to_use = Some(CipherSuite::TLS_AES_128_GCM_SHA256)
                }
                _ => (),
            }
        }

        let cipher_suite = match cipher_suite_to_use {
            Some(cs) => cs,
            None => return Err(TlsError::HandshakeFailure),
        };
        let hash = hash.unwrap();

        let random = config
            .rng
            .between(IBig::from(2).pow(255), IBig::from(2).pow(256));
        let mut random = bytes::ibig_to_32bytes(random, ByteOrder::Little);


        // Value is: DOWNGRD
        let downgrade_protection = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

        for (i, b) in downgrade_protection.iter().enumerate() {
            random[(32 - 8) + i] = *b;
        }

        // FIMXE: REMOVE hardcoded random
        let random = bytes::from_hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f").unwrap().try_into().unwrap();

        let private_key = match private_key {
            Some(pk) => pk,
            None => return Err(TlsError::HandshakeFailure),
        };

        Ok(ServerHello {
            random,
            legacy_session_id_echo: client_hello.legacy_session_id_echo,
            named_group,
            private_key,
            cipher_suite,
            hash,
            extensions,
        })
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = vec![0x3, 0x3];
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

        let key_share_data;
        let selected_key_share = match self.named_group {
            NamedGroup::X25519 => {
                key_share_data = bytes::ibig_to_32bytes(self.private_key.get_public_key().point.x, ByteOrder::Little);
                KeyShareEntry::new(NamedGroup::X25519, &key_share_data)
            }
            _ => todo!(),
        };
        let key_share = KeyShare::new(selected_key_share);
        let key_share_raw = key_share.to_raw();
        let supported_version_raw = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

        let extension_len = key_share_raw.len() + supported_version_raw.len();
        out.push((extension_len >> 8) as u8);
        out.push(extension_len as u8);

        out.extend_from_slice(&supported_version_raw);
        out.extend_from_slice(&key_share_raw);

        out
    }
}
