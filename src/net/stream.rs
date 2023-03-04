/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use super::handshake::ClientHello;
use super::record::Record;
use crate::{
    net::{handshake::{Handshake, HandshakeType}, record::ContentType},
    TlsConfig,
};
use std::result::Result;
use std::{
    io::Read,
    net::{SocketAddr, TcpStream},
    process::exit,
};

#[derive(PartialEq)]
enum HandshakeState {
    WaitingForClientHello,
    SendServerHello,
    Finished,
}

#[derive(Debug, Copy, Clone)]
pub enum TlsError {
    InvalidHandshake
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

        loop {
            let mut raw_buf: [u8; 4096] = [0; 4096];

            let n = match self.stream.read(&mut raw_buf) {
                Ok(n) => n,
                Err(_) => return Err(TlsError::InvalidHandshake)
            };

            let record = Record::from_raw(&raw_buf[..n]).unwrap();

            if record.content_type != ContentType::Handshake {
                return Err(TlsError::InvalidHandshake);
            }

            let handshake = Handshake::from_raw(record.fraqment).unwrap();

            match state {
                HandshakeState::WaitingForClientHello => {

                    if handshake.handshake_type != HandshakeType::ClientHello {
                        return Err(TlsError::InvalidHandshake);
                    }

                    let client_hello = ClientHello::from_raw(handshake.fraqment).unwrap();

                    println!("{:?}", client_hello.cipher_suites);
                    println!("{:?}", client_hello.extensions);


                }
                HandshakeState::SendServerHello => {

                }
                HandshakeState::Finished => break

            }



            state = HandshakeState::Finished;
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
