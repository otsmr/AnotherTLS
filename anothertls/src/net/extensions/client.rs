/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::{
    Extension, ExtensionType, ExtensionWrapper, Extensions, KeyShare, ServerName,
    SignatureAlgorithms, SupportedVersions,
};
use crate::utils::bytes;

pub(crate) type ClientExtensions = Extensions<ClientExtension>;

// #[derive(Debug)]
pub(crate) enum ClientExtension {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare),
    ServerName(ServerName),
    SignatureAlgorithms(SignatureAlgorithms),
}

impl ExtensionWrapper for ClientExtension {
    fn get_extension(&self) -> Box<&dyn Extension> {
        match self {
            ClientExtension::SupportedVersion(sv) => Box::new(sv),
            ClientExtension::KeyShare(ks) => Box::new(ks),
            ClientExtension::SignatureAlgorithms(sa) => Box::new(sa),
            ClientExtension::ServerName(sn) => Box::new(sn),
        }
    }
}
impl ClientExtension {
    pub fn from_client_hello(buf: &[u8]) -> Result<ClientExtensions, TlsError> {
        let mut consumed = 0;
        let mut extensions = ClientExtensions::new();

        while consumed < buf.len() {
            let extension_type = bytes::to_u16(&buf[consumed..consumed + 2]);
            let extension_type = ExtensionType::new(extension_type);
            let size = bytes::to_u16(&buf[consumed + 2..consumed + 4]) as usize;
            consumed += 4;
            if extension_type.is_none() {
                consumed += size;
                continue;
            }
            let extension_type = extension_type.unwrap();

            let extension = match extension_type {
                ExtensionType::ServerName => {
                    ClientExtension::ServerName(ServerName::parse(&buf[consumed..consumed + size])?)
                }
                ExtensionType::KeyShare => {
                    ClientExtension::KeyShare(KeyShare::parse(&buf[consumed..consumed + size])?)
                }
                ExtensionType::SupportedVersions => {
                    ClientExtension::SupportedVersion(SupportedVersions::parse(&buf[consumed..])?)
                }
                ExtensionType::SignatureAlgorithms => ClientExtension::SignatureAlgorithms(
                    SignatureAlgorithms::parse(&buf[consumed..])?,
                ), // ExtensionType::SupportedGroups => continue, // TODO
                   // ExtensionType::PSKKeyExchangeMode => continue, // TODO
            };
            consumed += size;
            extensions.push(extension);
        }
        Ok(extensions)
    }
}
