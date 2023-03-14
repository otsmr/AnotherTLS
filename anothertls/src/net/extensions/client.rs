/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use crate::net::extensions::SupportedVersions;
use crate::net::extensions::ExtensionType;
use crate::utils::bytes;
use crate::net::{named_groups::NamedGroup, alert::TlsError};

#[derive(Debug)]
pub struct ServerName(String);
impl ServerName {
    pub fn get(&self) -> &str {
        &self.0
    }
    fn parse(buf: &[u8]) -> Result<Self, TlsError>  {
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
            server_name = match String::from_utf8(buf[consumed..server_name_len+consumed].to_vec()) {
                Ok(a) => a,
                Err(_) => return Err(TlsError::DecodeError)
            };
        }
        Ok(ServerName(server_name))
    }
}

#[derive(Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub opaque: Vec<u8>,
}
impl KeyShareEntry {
    pub fn new(group: NamedGroup, opaque: Vec<u8>) -> KeyShareEntry {
        KeyShareEntry { group, opaque }
    }
    fn parse(buf: &[u8]) -> Result<(usize, KeyShareEntry), TlsError> {
        let group = bytes::to_u16(buf);
        let group = match NamedGroup::new(group) {
            Some(x) => x,
            None => return Err(TlsError::IllegalParameter),
        };
        let public_key_len = bytes::to_u16(&buf[2..]);
        Ok((
            4 + public_key_len as usize,
            KeyShareEntry {
                group,
                opaque: (buf[4..(public_key_len + 4) as usize]).to_vec(),
            },
        ))
    }
    fn to_raw(&self) -> Vec<u8> {
        let mut out = vec![];
        match self.group {
            NamedGroup::X25519 => {
                out.append(&mut vec![0x00, 0x1d, 0x00, 0x20]);
                for i in 0..self.opaque.len() {
                    out.push(self.opaque[self.opaque.len() -1 - i]);
                }
            }
            _ => todo!(),
        }
        out
    }
}

#[derive(Debug)]
pub struct KeyShare(pub Vec<KeyShareEntry>);
impl KeyShare {
    pub fn new(kse: KeyShareEntry) -> KeyShare {
        KeyShare(vec![kse])
    }
    fn parse(buf: &[u8]) -> Result<KeyShare, TlsError> {
        let mut entries = vec![];
        let mut consumed = 2;
        let len = bytes::to_u16(buf) as usize;
        loop {
            let (used, entry) = KeyShareEntry::parse(&buf[consumed..])?;
            if used <= 7 {
                break;
            }
            entries.push(entry);
            consumed += used;
            if consumed >= len {
                break;
            }
        }
        Ok(KeyShare(entries))
    }
    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x33, 0, 0];
        let mut total_len = 0;
        for ext in self.0.iter() {
            let mut raw = ext.to_raw();
            total_len += raw.len();
            out.append(&mut raw);
        }
        out[2] = (total_len >> 8) as u8;
        out[3] = total_len as u8;
        out
    }
}


#[derive(Debug)]
pub(crate) enum ClientExtension {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare),
    ServerName(ServerName),
    // SignatureAlgorithms()
    // PreSharedKey(u16),
}

impl ClientExtension {
    pub fn from_client_hello(buf: &[u8]) -> Result<Vec<ClientExtension>, TlsError> {
        let mut consumed = 0;
        let mut extensions: Vec<ClientExtension> = vec![];

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
                    ClientExtension::SupportedVersion(SupportedVersions::parse(&buf[consumed..]))
                }
                // ExtensionType::SignatureAlgorithms => { }
                // ExtensionType::SupportedGroups => continue, // TODO
                // ExtensionType::PSKKeyExchangeMode => continue, // TODO
            };

            consumed += size;
            extensions.push(extension);
        }

        Ok(extensions)
    }
}
