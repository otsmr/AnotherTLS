/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use crate::{TlsConfig, net::{record::ContentType, handshake::Handshake}};
use std::{
    io::{Read, self, ErrorKind},
    net::{SocketAddr, TcpStream}, process::exit,
};
use std::io::{Result, Error};
use super::handshake::ClientHello;
use super::record::Record;


#[derive(PartialEq)]
enum HandshakeState {
    WaitingForClientHello,
    SendServerHello,
    Finished,
}

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig
}



impl<'a> TlsStream<'a> {

    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self { stream,  addr, config }
    }


    pub fn do_handshake_block(&mut self) -> Result<()> {

        let mut state = HandshakeState::WaitingForClientHello;

        while state != HandshakeState::Finished {

            let mut raw_buf: [u8; 4096] = [0; 4096];

            let n = self.stream.read(&mut raw_buf)?;

            println!("{:?}", &raw_buf[..n]);


            let record = Record::from_raw(&raw_buf[..n]).unwrap();

            if record.content_type != ContentType::Handshake {
                return Err(Error::new(ErrorKind::InvalidData, "should get an handshake record"));
            }

            let handshake_message = Handshake::from_raw(record.fraqment).unwrap();

            println!("{:?}", handshake_message.fraqment);

            let client_hello = ClientHello::from_raw(handshake_message.fraqment).unwrap();

            println!("{:?}", client_hello.cipher_suites);

            state = HandshakeState::Finished;


        }

        exit(0);

        // Ok(())


    }

    pub fn read<'b>(&'b mut self, _buf: &'b mut [u8]) -> Result<usize> {

        let mut raw_buf: [u8; 4096] = [0; 4096];

        let n = self.stream.read(&mut raw_buf)?;


        Ok(n)

    }

    pub fn write<'b>(&'b mut self, _src: &'b [u8]) {

    }

}
