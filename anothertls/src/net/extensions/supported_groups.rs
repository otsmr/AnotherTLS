/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::Extension;
use crate::net::extensions::ExtensionType;

use super::NamedGroup;

#[derive(Debug)]
pub struct SupportedGroups(Vec<NamedGroup>);
impl SupportedGroups {
    pub fn supported() -> Self {
        SupportedGroups(vec![NamedGroup::Secp256r1, NamedGroup::X25519])
    }
}
impl Extension for SupportedGroups {
    fn server_as_bytes(&self) -> Vec<u8> {
        todo!("")
    }
    fn client_as_bytes(&self) -> Vec<u8> {
        let len = self.0.len() * 2;
        let mut out = vec![
            0x00,
            ExtensionType::SupportedGroups as u8,
            (len >> 8) as u8,
            len as u8 + 2,
            (len >> 8) as u8,
            len as u8,
        ];
        for group in self.0.iter() {
            let v = *group as u16;
            out.push((v >> 8) as u8);
            out.push(v as u8);
        }
        out
    }

    fn server_parse(_buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        todo!("parse supported groups");
    }
}
