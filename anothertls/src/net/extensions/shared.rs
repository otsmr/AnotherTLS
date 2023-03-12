/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use crate::utils::bytes;

#[derive(PartialEq, Debug)]
pub enum ExtensionType {
    ServerName = 0x00,
    // ECPointFormats = 0x0b,
    // SupportedGroups = 0x0a,
    // SessionTicket = 0x23,
    // EncryptThenMac = 0x16,
    // ExtendedMasterSecret = 0x17,
    // SignatureAlgorithms = 0x0d,
    SupportedVersions = 0x2b,
    // PSKKeyExchangeMode = 0x2d,
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
pub(crate) struct SupportedVersions(bool);
impl SupportedVersions {
    pub(crate) fn tls13_is_supported(&self) -> bool {
        self.0
    }
    pub(crate) fn new(tls13: bool) -> SupportedVersions {
        SupportedVersions(tls13)
    }
    pub(crate) fn parse(buf: &[u8]) -> SupportedVersions {
        let len = buf[0] as usize;
        if len % 2 == 1 {
            return SupportedVersions::new(false);
        }
        let mut tls13 = false;
        for i in (0..len).step_by(2) {
            match bytes::to_u16(&buf[(i + 1)..(i + 1 + 2)]) {
                // 0x0303 => tls12 = true,
                0x0304 => tls13 = true,
                _ => continue,
            }
        }
        SupportedVersions::new(tls13)
    }
    pub(crate) fn to_raw(&self) -> [u8; 6] {
        // TODO: do it dynamic
        [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    }
}
