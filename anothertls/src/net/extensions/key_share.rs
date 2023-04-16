/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::Extension;
use crate::net::extensions::NamedGroup;
use crate::utils::bytes;

use super::ExtensionType;

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
    fn as_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        match self.group {
            NamedGroup::X25519 => {
                out.append(&mut vec![0x00, 0x1d, 0x00, 0x20]);
                for i in 0..self.opaque.len() {
                    out.push(self.opaque[self.opaque.len() - 1 - i]);
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
    fn parse(buf: &[u8], is_client: bool) -> Result<Self, TlsError> {
        let mut entries = vec![];
        let mut len = 0;
        let mut consumed = 0;
        if !is_client {
            len = bytes::to_u16(buf) as usize;
            consumed += 2;
        }
        loop {
            let (used, entry) = KeyShareEntry::parse(&buf[consumed..])?;
            if used <= 7 {
                break;
            }
            entries.push(entry);
            consumed += used;
            // len is for server 0, so it should always break here
            if consumed >= len {
                break;
            }
        }
        Ok(KeyShare(entries))
    }
}
impl Extension for KeyShare {
    fn server_parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        KeyShare::parse(buf, false)
    }
    fn client_parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        KeyShare::parse(buf, true)
    }
    fn server_as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x00, ExtensionType::KeyShare as u8, 0x00, 0x00];
        if self.0.len() == 1 {
            out.append(&mut self.0[0].as_bytes());
        }
        let len = out.len() - 4;
        out[2] = (len >> 8) as u8;
        out[3] = len as u8;
        out
    }
    fn client_as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x00, ExtensionType::KeyShare as u8, 0x00, 0x00];
        for ext in self.0.iter() {
            let mut raw = ext.as_bytes();
            let len = raw.len();
            out.extend_from_slice(&[(len >> 8) as u8, len as u8]);
            out.append(&mut raw);
        }
        let len = out.len() - 4;
        out[2] = (len >> 8) as u8;
        out[3] = len as u8;
        out
    }
}
