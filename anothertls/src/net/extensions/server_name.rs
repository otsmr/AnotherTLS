/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::{Extension, ExtensionType};
use crate::utils::bytes;

#[derive(Debug)]
pub struct ServerName(String);
impl ServerName {
    pub fn new(server_name: String) -> ServerName {
        ServerName(server_name)
    }
    pub fn get(&self) -> &str {
        &self.0
    }
}
impl Extension for ServerName {
    fn server_as_bytes(&self) -> Vec<u8> {
        let hostname_len = self.get().len();
        let list_entry_len = hostname_len + 3;
        let list_len = list_entry_len + 2;
        let mut out = vec![
            0x00,
            ExtensionType::ServerName as u8,
            (list_len >> 8) as u8,
            list_len as u8,
            (list_entry_len >> 8) as u8,
            list_entry_len as u8,
            0x00,
            (hostname_len >> 8) as u8,
            hostname_len as u8,
        ];
        out.extend_from_slice(self.get().as_bytes());
        out
    }

    fn server_parse(buf: &[u8]) -> Result<Self, TlsError>
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
}
