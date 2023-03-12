/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

mod client_hello;
mod server_hello;
mod certificate;
mod finished;

pub(crate) use client_hello::ClientHello;
pub(crate) use server_hello::ServerHello;
pub(crate) use certificate::Certificate;
pub(crate) use finished::get_finished_handshake;
pub(crate) use finished::get_verify_client_finished;

use super::alert::TlsError;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn new(byte: u8) -> Option<HandshakeType> {
        Some(match byte {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            _ => return None,
        })
    }
}

pub struct Handshake<'a> {
    pub handshake_type: HandshakeType,
    pub len: u32,
    pub fraqment: &'a [u8],
}

impl<'a> Handshake<'a> {
    pub fn from_raw(buf: &[u8]) -> Result<Handshake, TlsError> {
        if buf.len() < 4 {
            return Err(TlsError::DecodeError);
        }
        let handshake_type = match HandshakeType::new(buf[0]) {
            Some(a) => a,
            None => return Err(TlsError::DecodeError)

        };
        let len = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
        Ok(Handshake {
            handshake_type,
            len,
            fraqment: &buf[4..],
        })
    }
    pub fn to_raw(typ: HandshakeType, mut data: Vec<u8>) -> Vec<u8> {
        let len = data.len();
        let mut t = vec![typ as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        t.append(&mut data);
        t
    }
    // pub fn is_full(&self) -> bool {
    //     self.len == self.fraqment.len() as u32
    // }
}
