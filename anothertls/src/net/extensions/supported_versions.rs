/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::Extension;
use crate::utils::bytes;

#[derive(Debug)]
pub struct SupportedVersions(bool);
impl SupportedVersions {
    pub fn is_tls13_supported(&self) -> bool {
        self.0
    }
    pub fn new(tls13: bool) -> SupportedVersions {
        SupportedVersions(tls13)
    }
}
impl Default for SupportedVersions {
    fn default() -> Self {
        Self(true)
    }
}
impl Extension for SupportedVersions {
    fn server_as_bytes(&self) -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    }
    fn client_as_bytes(&self) -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
    }

    fn server_parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let len = buf[0] as usize;
        if len % 2 == 0 {
            for i in (1..len + 1).step_by(2) {
                if bytes::to_u16(&buf[i..(i + 2)]) == 0x0304 {
                    return Ok(SupportedVersions::new(true));
                }
            }
        }
        Ok(SupportedVersions::new(false))
    }
    fn client_parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        if bytes::to_u16(&buf[0..2]) == 0x0304 {
            return Ok(SupportedVersions::new(true));
        }
        Ok(SupportedVersions::new(false))
    }
}
