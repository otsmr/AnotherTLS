/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::ellipticcurve::{Curve, PrivateKey};
use crate::hash::TranscriptHash;
use crate::net::alert::TlsError;
use crate::net::client::ClientHello;
use crate::net::extensions::{ClientExtension, ServerName, SignatureAlgorithms, SupportedVersions};
use crate::net::extensions::{KeyShare, KeyShareEntry, NamedGroup};
use crate::net::handshake::{Handshake, HandshakeType};
use crate::net::record::{Record, RecordType, Value};
use crate::net::TlsStream;
use crate::net::server::ServerHello;
use crate::rand::{RngCore, URandomRng};
use crate::utils::keylog::KeyLog;
use crate::utils::log;
use crate::utils::{bytes, bytes::ByteOrder};
use crate::ClientConfig;

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
    ServerCertificate,
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
    private_key: PrivateKey,
}

impl<'a> ClientHandshake<'a> {
    pub fn new(stream: &'a mut TlsStream, config: &'a ClientConfig) -> Self {
        let mut rng = Box::new(URandomRng::new());
        let secret = rng.between(1, 32);
        let private_key = PrivateKey::new(Curve::curve25519(), secret);

        ClientHandshake {
            stream,
            config,
            state: ClientHsState::ServerHello,
            keylog: None,
            rng,
            tshash: None,
            private_key,
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

        let key_share_data =
            bytes::ibig_to_32bytes(self.private_key.get_public_key().point.x, ByteOrder::Little);

        client_hello
            .extensions
            .push(ClientExtension::KeyShare(KeyShare::new(
                KeyShareEntry::new(NamedGroup::X25519, key_share_data.to_vec()),
            )));

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

        if let Some(server_name) = self.config.server_name.as_ref() {
            client_hello
                .extensions
                .push(ClientExtension::ServerName(ServerName::new(
                    server_name.clone(),
                )));
        }

        let handshake_raw =
            Handshake::as_bytes(HandshakeType::ClientHello, client_hello.as_bytes()?);
        let record = Record::new(RecordType::Handshake, Value::Owned(handshake_raw));

        self.stream.tcp_write(&record.as_bytes())?;
        Ok(())
    }

    fn handle_handshake_record(&mut self, record: Record) -> Result<(), TlsError> {
        match record.content_type {
            RecordType::ChangeCipherSpec => {
                log::debug!("--> ChangeCipherSpec");
                if self.state == ClientHsState::ServerHello {
                    return Err(TlsError::UnexpectedMessage);
                }
                return Ok(());
            }
            RecordType::Alert => {
                let alert_code = record.fraqment.as_ref()[1];
                let alert = TlsError::new(alert_code);
                log::debug!("--> Alert {alert:?}");
                if self.state != ClientHsState::Ready {
                    log::error!("Handshake aborted by client");
                }
                return Err(TlsError::GotAlert(alert_code));
            }
            _ => match self.state {
                ClientHsState::ServerHello => {
                    if record.content_type != RecordType::Handshake {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    self.handle_server_hello(record)?;
                }
                ClientHsState::ServerCertificate
                | ClientHsState::ServerCertificateVerify
                | ClientHsState::FinishWithError(_)
                | ClientHsState::Finished => {
                    self.handle_handshake_encrypted_record(record)?;
                }
                ClientHsState::Ready => {}
            },
        }
        Ok(())
    }
    pub fn handle_server_hello(&mut self, record: Record) -> Result<(), TlsError> {

        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::ServerHello {
            return Err(TlsError::UnexpectedMessage);
        }

        log::debug!("--> ServerHello");
        let server_hello = ServerHello::from_raw(record.fraqment.as_ref());


        self.state = ClientHsState::ServerCertificate;
        Ok(())
    }
    fn handle_handshake_encrypted_record(&mut self, record: Record) -> Result<(), TlsError> {
        log::debug!("==> Encrypted handshake record");
        Ok(())
    }
}
