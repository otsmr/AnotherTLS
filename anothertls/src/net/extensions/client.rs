/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::{Extension, ExtensionWrapper, Extensions, KeyShare};
use crate::net::extensions::{ExtensionType, SupportedVersions};
use crate::utils::bytes;

use super::shared::SignatureAlgorithms;

#[derive(Debug)]
pub struct ServerName(String);
impl ServerName {
    pub fn get(&self) -> &str {
        &self.0
    }
}
impl Extension for ServerName {
    fn parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let server_name_list_len = bytes::to_u16(buf);
        let mut consumed = 2;
        let mut server_name = String::new();
        if server_name_list_len > 0 {
            let name_type = buf[consumed];
            consumed += 1;
            if name_type != 0 {
                return Err(TlsError::DecodeError);
            }
            let server_name_len = bytes::to_u16(&buf[consumed..]) as usize;
            consumed += 2;
            server_name =
                match String::from_utf8(buf[consumed..server_name_len + consumed].to_vec()) {
                    Ok(a) => a,
                    Err(_) => return Err(TlsError::DecodeError),
                };
        }
        Ok(ServerName(server_name))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.get().as_bytes().to_vec()
    }
}

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
