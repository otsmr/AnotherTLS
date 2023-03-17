/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::named_groups::NamedGroup;
use crate::utils::bytes;

pub trait Extension {
    fn parse(buf: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized;
    fn to_raw(&self) -> Vec<u8>;
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
#[derive(Clone, Copy)]
pub enum SignatureScheme {
  /* RSASSA-PKCS1-v1_5 algorithms */
  // rsa_pkcs1_sha256 = 0x0401,
  // rsa_pkcs1_sha384 = 0x0501,
  // rsa_pkcs1_sha512 = 0x0601,

  /* ECDSA algorithms */
  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0503,
  ecdsa_secp521r1_sha512 = 0x0603,

  /* RSASSA-PSS algorithms with public key OID rsaEncryption */
  // rsa_pss_rsae_sha256 = 0x0804,
  // rsa_pss_rsae_sha384 = 0x0805,
  // rsa_pss_rsae_sha512 = 0x0806,

  /* EdDSA algorithms */
  // ed25519 = 0x0807,
  // ed448 = 0x0808,

  /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
  // rsa_pss_pss_sha256 = 0x0809,
  // rsa_pss_pss_sha384 = 0x080a,
  // rsa_pss_pss_sha512 = 0x080b,

  /* Legacy algorithms */
  // rsa_pkcs1_sha1 = 0x0201,
  // ecdsa_sha1 = 0x0203,
}

impl SignatureScheme {
    fn new(buf: u16) -> Result<SignatureScheme, TlsError> {
        Ok(match buf {
            0x0403 => SignatureScheme::ecdsa_secp256r1_sha256,
            0x0503 => SignatureScheme::ecdsa_secp384r1_sha384,
            0x0603 => SignatureScheme::ecdsa_secp521r1_sha512,
            _ => return Err(TlsError::DecodeError)
        })
    }

}
pub struct SignatureAlgorithms(pub Vec<SignatureScheme>);

impl SignatureAlgorithms {
    pub fn new(scheme: SignatureScheme) -> Self {
        Self(vec![scheme])
    }
    // pub fn push(&mut self, scheme: SignatureScheme) {
    //     self.0.push(scheme)
    // }
}

impl Extension for SignatureAlgorithms {
    fn parse(buf: &[u8]) -> Result<SignatureAlgorithms, TlsError> {
        let len = bytes::to_u16(buf) as usize;
        let mut out = vec![];
        if len % 2 == 0 {
            for i in (2..len).step_by(2) {
                let tes = bytes::to_u16(&buf[i..(i + 2)]);
                out.push(SignatureScheme::new(tes)?);
            }
        }
        Ok(SignatureAlgorithms(out))
    }
    fn to_raw(&self) -> Vec<u8> {
        let len = self.0.len() * 2;
        let mut out = vec![0x00, ExtensionType::SignatureAlgorithms as u8, (len >> 8) as u8, len as u8 +2, (len >> 8) as u8, len as u8];
        for scheme in self.0.iter() {
            let v = *scheme as u16;
            out.push((v >> 8) as u8);
            out.push(v as u8);
        }
        out
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
}
impl Extension for SupportedVersions {
    fn parse(buf: &[u8]) -> Result<SupportedVersions, TlsError> {
        let len = buf[0] as usize;
        if len % 2 == 0 {
            for i in (1..len+1).step_by(2) {
                if bytes::to_u16(&buf[i..(i + 2)]) == 0x0304 {
                    return Ok(SupportedVersions::new(true));
                }
            }
        }
        Ok(SupportedVersions::new(false))
    }
    fn to_raw(&self) -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    }
}

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
    fn to_raw(&self) -> Vec<u8> {
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
}
impl Extension for KeyShare {
    fn parse(buf: &[u8]) -> Result<Self, TlsError> {
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
    fn to_raw(&self) -> Vec<u8> {
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
