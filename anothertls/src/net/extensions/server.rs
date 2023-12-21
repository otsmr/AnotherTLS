/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

// use crate::utils::x509::Extensions;
use crate::net::alert::TlsError;
use crate::net::extensions::{
    Extension, ExtensionType, ExtensionWrapper, Extensions, KeyShare, SignatureAlgorithms,
    SupportedVersions,
};
use crate::utils::bytes;

pub enum ServerExtension {
    SupportedVersions(SupportedVersions),
    KeyShare(KeyShare),
    SignatureAlgorithms(SignatureAlgorithms),
}

impl ExtensionWrapper for ServerExtension {
    fn get_extension(&self) -> Box<&dyn Extension> {
        match self {
            ServerExtension::SupportedVersions(sv) => Box::new(sv),
            ServerExtension::KeyShare(ks) => Box::new(ks),
            ServerExtension::SignatureAlgorithms(sa) => Box::new(sa),
        }
    }
}

pub type ServerExtensions = Extensions<ServerExtension>;

impl ServerExtensions {
    pub fn from_server_hello(buf: &[u8]) -> Result<ServerExtensions, TlsError> {
        let mut consumed = 0;
        let mut extensions = ServerExtensions::new();
        extensions.set_is_client();

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
                ExtensionType::KeyShare => ServerExtension::KeyShare(KeyShare::client_parse(
                    &buf[consumed..consumed + size],
                )?),
                ExtensionType::SupportedVersions => ServerExtension::SupportedVersions(
                    SupportedVersions::client_parse(&buf[consumed..])?,
                ),
                ExtensionType::SignatureAlgorithms => ServerExtension::SignatureAlgorithms(
                    SignatureAlgorithms::client_parse(&buf[consumed..])?,
                ), // ExtensionType::SupportedGroups => continue, // TODO
                _ => continue, // ExtensionType::PSKKeyExchangeMode => continue, // TODO
            };
            consumed += size;
            extensions.push(extension);
        }
        Ok(extensions)
    }
}
