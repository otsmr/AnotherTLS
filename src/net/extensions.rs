use crate::utils::bytes;

use super::{named_groups::NamedGroup, stream::TlsError};

#[derive(PartialEq, Debug)]
pub enum ExtensionType {
    ServerName = 0x00,
    ECPointFormats = 0x0b,
    SupportedGroups = 0x0a,
    SessionTicket = 0x23,
    EncryptThenMac = 0x16,
    ExtendedMasterSecret = 0x17,
    SignatureAlgorithms = 0x0d,
    SupportedVersions = 0x2b,
    PSKKeyExchangeMode = 0x2d,
    KeyShare = 0x33,
}

impl ExtensionType {
    pub fn new(val: u16) -> Option<ExtensionType> {
        Some(match val {
            0x00 => ExtensionType::ServerName,
            // 0x0b => ExtensionType::ECPointFormats,
            // 0x0a => ExtensionType::SupportedGroups,
            // 0x23 => ExtensionType::SessionTicket,
            // 0x16 => ExtensionType::EncryptThenMac,
            // 0x17 => ExtensionType::ExtendedMasterSecret,
            // 0x0d => ExtensionType::SignatureAlgorithms,
            0x2b => ExtensionType::SupportedVersions,
            // 0x2d => ExtensionType::PSKKeyExchangeMode,
            0x33 => ExtensionType::KeyShare,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub struct SupportedVersions {
    pub tls13: bool,
    pub tls12: bool,
}
impl SupportedVersions {
    pub fn new(tls13: bool, tls12: bool) -> SupportedVersions {
        SupportedVersions { tls13, tls12 }
    }
    fn parse(buf: &[u8]) -> SupportedVersions {
        let len = buf[0] as usize;
        println!("len={len}");
        if len % 2 == 1 {
            return SupportedVersions::new(false, false);
        }
        let mut tls13 = false;
        let mut tls12 = false;
        for i in (0..len).step_by(2) {
            match bytes::to_u16(&buf[(i + 1)..(i + 1 + 2)]) {
                0x0303 => tls12 = true,
                0x0304 => tls13 = true,
                _ => continue,
            }
        }
        SupportedVersions { tls13, tls12 }
    }
}
#[derive(Debug)]
pub struct ServerName {}
impl ServerName {
    fn parse(_buf: &[u8]) -> String {
        String::new()
    }
}
#[derive(Debug)]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup,
    pub opaque: &'a [u8],
}
impl<'a> KeyShareEntry<'a> {
    pub fn new(group: NamedGroup, opaque: &'a [u8]) -> KeyShareEntry {
        KeyShareEntry { group, opaque }
    }
    fn parse(buf: &'a [u8]) -> Result<(usize, KeyShareEntry), TlsError> {
        let group = bytes::to_u16(buf);
        let group = match NamedGroup::new(group) {
            Some(x) => x,
            None => return Err(TlsError::IllegalParameter),
        };
        let public_key_len = bytes::to_u16(&buf[2..]);
        Ok((
            6 + public_key_len as usize,
            KeyShareEntry {
                group,
                opaque: &buf[4..(public_key_len + 4) as usize],
            },
        ))
    }
    fn to_raw(&self) -> Vec<u8> {
        let mut out = vec![];
        match self.group {
            NamedGroup::X25519 => {
                out.append(&mut vec![0x00, 0x1d, 0x00, 0x20]);
                // TODO: Bad :/
                let mut t = self.opaque.to_vec();
                t.reverse();
                out.extend_from_slice(&t);
            }
            _ => todo!(),
        }
        out
    }
}
#[derive(Debug)]
/// https://www.rfc-editor.org/rfc/rfc8446#page-48
pub struct KeyShare<'a>(pub Vec<KeyShareEntry<'a>>);
impl<'a> KeyShare<'a> {
    pub fn new(kse: KeyShareEntry<'a>) -> KeyShare<'a> {
        KeyShare(vec![kse])
    }
    fn parse(buf: &'a [u8]) -> Result<KeyShare, TlsError> {
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
pub enum ServerExtension<'a> {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare<'a>),
}

pub struct ServerExtensions<'a>(Vec<ServerExtension<'a>>);

impl<'a> ServerExtensions<'a> {

    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn push(&mut self, ext: ServerExtension<'a>) {
        self.0.push(ext)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        if self.0.is_empty() {
            return vec![0x00, 0x00]; // Length of the extension list (0 bytes)
        }
        // Needed for EncryptedExtensions -> currently always empty
        todo!()
    }

}

impl<'a> Default for ServerExtensions<'a> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum ClientExtension<'a> {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare<'a>),
    ServerName(String),
    PreSharedKey(u16),
}

impl<'a> ClientExtension<'a> {
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
                    ClientExtension::ServerName(ServerName::parse(&buf[consumed..consumed + size]))
                }
                ExtensionType::KeyShare => {
                    ClientExtension::KeyShare(KeyShare::parse(&buf[consumed..consumed + size])?)
                }
                ExtensionType::SupportedVersions => {
                    ClientExtension::SupportedVersion(SupportedVersions::parse(&buf[consumed..]))
                }
                // ExtensionType::SupportedGroups => continue, // TODO
                // ExtensionType::PSKKeyExchangeMode => continue, // TODO
                _ => continue,
            };

            consumed += size;
            extensions.push(extension);
        }

        Ok(extensions)
    }
}
