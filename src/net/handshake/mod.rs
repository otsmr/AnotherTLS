/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

mod client_hello;

pub use client_hello::ClientHello;

#[derive(PartialEq)]
pub enum HandshakeType {
    ClientHello = 1,
}

impl HandshakeType {
    pub fn new(byte: u8) -> Option<HandshakeType> {
        Some(match byte {
            1 => HandshakeType::ClientHello,
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
    pub fn from_raw(buf: &[u8]) -> Option<Handshake> {
        if buf.len() < 4 {
            return None;
        }

        let handshake_type = HandshakeType::new(buf[0])?;
        let len = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;

        Some(Handshake {
            handshake_type,
            len,
            fraqment: &buf[4..],
        })
    }

    pub fn is_full(&self) -> bool {
        self.len == self.fraqment.len() as u32
    }
}
