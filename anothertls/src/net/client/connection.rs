/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::hash::TranscriptHash;
use crate::net::TlsStream;
use crate::rand::RngCore;
use crate::rand::URandomRng;
use crate::utils::keylog::KeyLog;
use crate::ClientConfig;
use crate::net::alert::TlsError;
use ibig::IBig;

use std::net::TcpStream;
use std::result::Result;


pub struct ClientConnection();

impl ClientConnection {

    pub fn connect(sock: TcpStream, config: &ClientConfig) -> Result<TlsStream, TlsError> {

        let mut stream = TlsStream::new(sock);

        let mut shs = ClientHandshake::new(&mut stream, config);
        shs.do_handshake_with_error()?;

        Ok(stream)

    }

}

#[derive(PartialEq, PartialOrd, Clone, Copy, Debug)]
#[repr(u8)]
enum ClientHsState {
    ServerHello,
    ServerCertificate = 0x10,
    ServerCertificateVerify,
    FinishWithError(TlsError),
    Finished,
    Ready,
}

pub struct ClientHandshake<'a> {
    stream: &'a mut TlsStream,
    config: &'a ClientConfig,
    state: ClientHsState,
    keylog: Option<KeyLog>,
    rng: Box<dyn RngCore<IBig>>,
    tshash: Option<Box<dyn TranscriptHash>>,
}

impl<'a> ClientHandshake<'a> {
    pub fn new(stream: &'a mut TlsStream, config: &'a ClientConfig) -> Self {
        ClientHandshake {
            stream,
            config,
            state: ClientHsState::ServerHello,
            keylog: None,
            rng: Box::new(URandomRng::new()),
            tshash: None,
        }
    }
    pub fn do_handshake_with_error(&mut self) -> Result<(), TlsError> {
        Ok(())
    }
}

