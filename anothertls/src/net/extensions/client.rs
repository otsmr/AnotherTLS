/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::{
    Extension, ExtensionType, ExtensionWrapper, Extensions, KeyShare, ServerName,
    SignatureAlgorithms, SupportedVersions, SupportedGroups
};
use crate::utils::bytes;

pub type ClientExtensions = Extensions<ClientExtension>;

// #[derive(Debug)]
pub enum ClientExtension {
    SupportedVersion(SupportedVersions),
    SupportedGroups(SupportedGroups),
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
            ClientExtension::SupportedGroups(sn) => Box::new(sn),
        }
    }
}
impl ClientExtension {
    pub fn from_client_hello(buf: &[u8]) -> Result<ClientExtensions, TlsError> {
        let mut consumed = 0;
        let mut extensions = ClientExtensions::new();

        while consumed < buf.len() {
            if buf.len() < consumed + 4 {
                return Err(TlsError::IllegalParameter);
            }
            let extension_type = bytes::to_u16(&buf[consumed..consumed + 2]);
            let extension_type = ExtensionType::new(extension_type);
            let size = bytes::to_u16(&buf[consumed + 2..consumed + 4]) as usize;
            consumed += 4;
            if extension_type.is_none() {
                consumed += size;
                continue;
            }
            if buf.len() < consumed + size {
                return Err(TlsError::IllegalParameter);
            }
            let extension_type = extension_type.unwrap();

            let extension = match extension_type {
                ExtensionType::ServerName => ClientExtension::ServerName(ServerName::server_parse(
                    &buf[consumed..consumed + size],
                )?),
                ExtensionType::KeyShare => ClientExtension::KeyShare(KeyShare::server_parse(
                    &buf[consumed..consumed + size],
                )?),
                ExtensionType::SupportedVersions => ClientExtension::SupportedVersion(
                    SupportedVersions::server_parse(&buf[consumed..])?,
                ),
                ExtensionType::SignatureAlgorithms => ClientExtension::SignatureAlgorithms(
                    SignatureAlgorithms::server_parse(&buf[consumed..])?,
                ),
                ExtensionType::SupportedGroups => continue
            };
            consumed += size;
            extensions.push(extension);
        }
        Ok(extensions)
    }
}
