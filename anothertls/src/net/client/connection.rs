/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::hash::TranscriptHash;
use crate::net::alert::TlsError;
use crate::net::extensions::shared::SignatureAlgorithms;
use crate::net::extensions::ClientExtension;
use crate::net::extensions::ClientExtensions;
use crate::net::extensions::SupportedVersions;
use crate::net::record::Record;
use crate::net::TlsStream;
use crate::rand::RngCore;
use crate::rand::URandomRng;
use crate::utils::keylog::KeyLog;
use crate::ClientConfig;
use ibig::IBig;

use std::net::TcpStream;
use std::result::Result;

use super::ClientHello;

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
        if let Err(mut err) = self.do_handshake() {
            if err < TlsError::NotOfficial {
                self.stream.write_alert(err)?;
            }
            if let TlsError::GotAlert(err_code) = err {
                err = TlsError::new(err_code);
            }
            return Err(err);
        }
        Ok(())
    }

    fn do_handshake(&mut self) -> Result<(), TlsError> {
        self.send_client_hello()?;

        let mut rx_buf: [u8; 4096] = [0; 4096];

        while self.state != ClientHsState::Ready {
            let n = self.stream.tcp_read(&mut rx_buf)?;
            let mut consumed_total = 0;
            while consumed_total < n {
                let (consumed, record) = Record::from_raw(&rx_buf[consumed_total..n])?;
                consumed_total += consumed;
                self.handle_handshake_record(record)?;
            }
            // send server handshake records to the client
            self.stream.flush()?;
        }
        Ok(())
    }

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        // Create ClientHello and send it to the Server
        let random = self.rng.between_bytes(32);
        let mut client_hello = ClientHello::new(&random)?;
        // TODO: push ClientExtensions

        // Set version to TLSv1.3
        client_hello
            .extensions
            .push(ClientExtension::SupportedVersion(SupportedVersions::new(
                true,
            )));

        client_hello
            .extensions
            .push(ClientExtension::SignatureAlgorithms(
                SignatureAlgorithms::supported(),
            ));

        self.stream.tcp_write(&client_hello.as_bytes()?)?;
        Ok(())
    }

    fn handle_handshake_record(&mut self, record: Record) -> Result<(), TlsError> {
        println!("Got record from type: {:?}", record.content_type);
        // match record.content_type {
        //     // RecordType::ChangeCipherSpec => {
        // }
        Ok(())
    }
}
