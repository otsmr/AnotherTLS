/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;

pub trait Extension {
    fn parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized;
    fn server_as_bytes(&self) -> Vec<u8>;
    fn client_as_bytes(&self) -> Vec<u8> {
        self.server_as_bytes()
    }
}

pub trait ExtensionWrapper {
    #[allow(clippy::redundant_allocation)]
    // FIXME: How to avoid Box<&dyn> ?
    fn get_extension(&self) -> Box<&dyn Extension>;
}

pub(crate) struct Extensions<T: ExtensionWrapper>{
    extensions: Vec<T>,
    is_client: bool
}

impl<T: ExtensionWrapper> Extensions<T> {
    pub fn new() -> Self {
        Self { extensions: vec![], is_client: false }
    }
    pub fn as_vec(&self) -> &Vec<T> {
        &self.extensions
    }
    pub fn push(&mut self, ext: T) {
        self.extensions.push(ext)
    }
    pub fn set_is_client(&mut self) {
        self.is_client = true;
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x00];
        if self.extensions.is_empty() {
            return out; // Length of the extension list (0 bytes)
        }
        for ext in self.extensions.iter() {
            if self.is_client {
                out.extend_from_slice(&ext.get_extension().client_as_bytes());
            } else {
                out.extend_from_slice(&ext.get_extension().server_as_bytes());
            }
        }
        let extension_len = out.len() - 2;
        out[0] = (extension_len >> 8) as u8;
        out[1] = extension_len as u8;
        out
    }
}

#[derive(PartialEq, Debug)]
pub enum ExtensionType {
    ServerName = 0x00,
    // ECPointFormats = 0x0b,
    // SupportedGroups = 0x0a,
    // SessionTicket = 0x23,
    // EncryptThenMac = 0x16,
    // ExtendedMasterSecret = 0x17,
    SignatureAlgorithms = 0x0d,
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

