#![allow(non_camel_case_types)]
pub struct Extension {}

#[derive(Debug)]
pub enum CipherSuite {
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 1303,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
}

impl CipherSuite {
    pub fn new(x: u16) -> Option<CipherSuite> {
        Some(match x {
            0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
            0x1303 => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
            0x00ff => CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            _ => return None,
        })
    }
}

pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    // pub // legacy_session_id,
    pub cipher_suites: Vec<CipherSuite>,
    pub legacy_compression_methods: [u8; 32],
    pub extensions: Vec<Extension>,
}
impl ClientHello {

    pub fn from_raw(buf: &[u8]) -> Option<ClientHello> {

        if buf.len() < 100 {
            return None
        }

        let legacy_version = ((buf[0] as u16) << 8) | buf[1] as u16;
        let random = buf[2..34].try_into().unwrap();
        let session_id_length = buf[35];
        let mut consumed = 35;

        if session_id_length != 0 {
            consumed += 32;
            // let session_id: [u8; 32] = buf[36..68].try_into().unwrap();
        }

        let cipher_suites_len = ((buf[consumed] as u16) << 8) | (buf[consumed+1] as u16);
        if cipher_suites_len % 2 != 0 || buf.len() < (consumed + cipher_suites_len as usize) {
            return None;
        }
        consumed += 2;
        let mut cipher_suites = vec![];
        for i in (consumed..(consumed+cipher_suites_len as usize)).step_by(2) {
            cipher_suites.push(CipherSuite::new(((buf[i] as u16) << 8) | (buf[i+1] as u16))?)
        }

        consumed += cipher_suites_len as usize;
        let extensions = vec![];

        Some(ClientHello {
            legacy_version,
            random,
            cipher_suites,
            legacy_compression_methods: [0; 32],
            extensions
        })
    }
}
