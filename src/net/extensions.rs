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
    KeyShare = 0x33
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
    tls13: bool,
    tls12: bool
}
impl SupportedVersions {
    fn new(tls13: bool, tls12: bool) -> SupportedVersions {
        SupportedVersions { tls13, tls12 }
    }
    fn parse(buf: &[u8]) -> SupportedVersions {
        let len = buf[0] as usize;
        if len % 2 == 1 {
            return SupportedVersions::new(false, false);
        }
        let mut tls13 = false;
        let mut tls12 = false;
        for i in (0..len).step_by(2) {
            match bytes::to_u16(&buf[(i+1)..(i+1+2)]) {
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
    group: NamedGroup,
    opaque: &'a [u8],
}
impl<'a> KeyShareEntry<'a> {
    fn parse(buf: &'a [u8]) -> Result<KeyShareEntry, TlsError> {
        let len = bytes::to_u16(buf);
        let group = bytes::to_u16(&buf[2..]);
        let group = match NamedGroup::new(group) {
            Some(x) => x,
            None => return Err(TlsError::InvalidHandshake)
        };
        Ok(KeyShareEntry {
            group,
            opaque: &buf[4..len as usize]
        })
    }
}
#[derive(Debug)]
pub struct KeyShare<'a>(KeyShareEntry<'a>);
impl<'a> KeyShare<'a> {
    fn parse(buf: &'a [u8]) -> Result<KeyShare, TlsError> {
        Ok(KeyShare(KeyShareEntry::parse(buf)?))
    }
}

#[derive(Debug)]
pub enum ClientExtension<'a> {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare<'a>),
    ServerName(String),
    PreSharedKey(u16)
}

pub fn from_client_hello(buf: &[u8]) -> Result<Vec<ClientExtension>, TlsError> {
    let mut consumed = 0;
    let mut extensions: Vec<ClientExtension> = vec![];

    while consumed < buf.len() {
        let extension_type = bytes::to_u16(&buf[consumed..consumed+2]);
        let extension_type = ExtensionType::new(extension_type);
        let size = bytes::to_u16(&buf[consumed+2..consumed+4]) as usize;
        consumed += 4;
        if extension_type.is_none() {
            consumed += size;
            continue;
        }
        let extension_type = extension_type.unwrap();

        let extension = match extension_type {
            ExtensionType::ServerName => ClientExtension::ServerName(
                ServerName::parse(&buf[consumed..consumed+size])
            ),
            ExtensionType::KeyShare => ClientExtension::KeyShare(
                KeyShare::parse(&buf[consumed..consumed+size])?
            ),
            ExtensionType::SupportedVersions => ClientExtension::SupportedVersion(
                SupportedVersions::parse(&buf[consumed..])
            ),
            // ExtensionType::SupportedGroups => continue, // TODO
            // ExtensionType::PSKKeyExchangeMode => continue, // TODO
            _ => continue
        };

        consumed += size;
        extensions.push(extension);

    }

    Ok(extensions)

}

