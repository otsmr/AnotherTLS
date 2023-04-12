/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::shared::Extension;
use crate::utils::bytes;

#[derive(Debug)]
pub(crate) struct SupportedVersions(bool);
impl SupportedVersions {
    pub(crate) fn is_tls13_supported(&self) -> bool {
        self.0
    }
    pub(crate) fn new(tls13: bool) -> SupportedVersions {
        SupportedVersions(tls13)
    }
}
impl Extension for SupportedVersions {
    fn parse(buf: &[u8]) -> Result<SupportedVersions, TlsError> {
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
    fn server_as_bytes(&self) -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    }
    fn client_as_bytes(&self) -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
    }
}
