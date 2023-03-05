/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use super::TlsContext;
use super::handshake::{ClientHello, ServerHello};
use super::record::Record;
use crate::net::record::RecordType;
use crate::rand::URandomRng;
use crate::{
    net::handshake::{Handshake, HandshakeType},
    TlsConfig,
};
use std::io::Write;
use std::result::Result;
use std::{
    io::Read,
    net::{SocketAddr, TcpStream},
    process::exit,
};

#[derive(PartialEq)]
enum HandshakeState {
    WaitingForClientHello,
    WaitingForAuthTag,
    Finished,
}

#[derive(Debug, Copy, Clone)]
pub enum TlsError {
    UnexpectedMessage = 10,
    HandshakeFailure = 40,
    IllegalParameter = 47,
    DecryptError = 50,
    DecodeError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    MissingExtension = 109,
}


pub struct TlsSessionContext {

}

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig,

}

impl<'a> TlsStream<'a> {
    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self {
            stream,
            addr,
            config,
        }
    }

    pub fn do_handshake_block(&mut self) -> Result<(), TlsError> {
        let mut state = HandshakeState::WaitingForClientHello;

        let mut context = TlsContext {
            config: self.config,
            rng: Box::new(URandomRng::new()),
        };

        loop {
            let mut raw_buf: [u8; 4096] = [0; 4096];

            let n = match self.stream.read(&mut raw_buf) {
                Ok(n) => n,
                Err(_) => return Err(TlsError::InternalError)
            };

            let record = Record::from_raw(&raw_buf[..n]).unwrap();

            if record.content_type != RecordType::Handshake {
                return Err(TlsError::UnexpectedMessage);
            }

            let handshake = Handshake::from_raw(record.fraqment).unwrap();

            let mut write_buffer = vec![];

            match state {
                HandshakeState::WaitingForClientHello => {

                    if handshake.handshake_type != HandshakeType::ClientHello {
                        return Err(TlsError::UnexpectedMessage);
                    }

                    let client_hello = ClientHello::from_raw(handshake.fraqment)?;

                    println!("{:?}", client_hello.cipher_suites);
                    println!("{:?}", client_hello.extensions);

                    let mut server_hello = ServerHello::from_client_hello(&client_hello, &mut context)?;
                    let handshake_raw = Handshake::to_raw(HandshakeType::ServerHello, server_hello.to_raw());
                    let mut record_raw = Record::to_raw(RecordType::Handshake, handshake_raw);

                    write_buffer.append(&mut record_raw);

                    let mut server_change_cipher_spec = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

                    write_buffer.append(&mut server_change_cipher_spec);

                    state = HandshakeState::WaitingForAuthTag;

                }
                HandshakeState::WaitingForAuthTag => {

                }
                HandshakeState::Finished => break

            }

            if self.stream.write_all(write_buffer.as_slice()).is_err() {
                return Err(TlsError::InternalError)
            };

        }

        exit(0);

        // Ok(())
    }

    pub fn read<'b>(&'b mut self, _buf: &'b mut [u8]) -> std::io::Result<usize> {
        let mut raw_buf: [u8; 4096] = [0; 4096];

        let n = self.stream.read(&mut raw_buf)?;

        Ok(n)
    }

    pub fn write<'b>(&'b mut self, _src: &'b [u8]) {}
}
