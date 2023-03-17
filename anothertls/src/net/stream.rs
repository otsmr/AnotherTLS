/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use crate::{
    crypto::CipherSuite,
    hash::{sha256::Sha256, sha384::Sha384, TranscriptHash},
    net::{
        alert::{AlertLevel, TlsError},
        extensions::ServerExtensions,
        handshake::{
            get_finished_handshake, get_verify_client_finished, ClientHello, Handshake,
            HandshakeType, ServerHello,
        },
        key_schedule::KeySchedule,
        record::{Record, RecordPayloadProtection, RecordType, Value},
    },
    rand::{RngCore, URandomRng},
    utils::keylog::KeyLog,
    utils::log,
    TlsConfig,
};
use ibig::IBig;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    result::Result,
};

#[derive(PartialEq)]
enum HandshakeState {
    ClientHello,
    ChangeCipherSpec,
    ClientCertificate,
    Finished,
    Ready,
}

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig,
    protection: Option<RecordPayloadProtection>,
    state: HandshakeState,
    key_log: Option<KeyLog>,
    rng: Box<dyn RngCore<IBig>>,
    tshash: Option<Box<dyn TranscriptHash>>,
}

impl<'a> TlsStream<'a> {
    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self {
            stream,
            addr,
            config,
            state: HandshakeState::ClientHello,
            key_log: None,
            protection: None,
            rng: Box::new(URandomRng::new()),
            tshash: None,
        }
    }
    pub fn read_to_end(&mut self) -> Result<(), TlsError> {
        // TODO: Read to end xD
        self.write_alert(TlsError::CloseNotify)
    }
    pub fn write_alert(&mut self, err: TlsError) -> Result<(), TlsError> {
        let data = vec![AlertLevel::get_from_error(err) as u8, err as u8];

        let record = Record::new(RecordType::Alert, Value::Owned(data));

        let record_raw = if let Some(protect) = self.protection.as_mut() {
            protect.encrypt(record)?
        } else {
            record.as_bytes()
        };

        if self.stream.write_all(&record_raw).is_err() {
            return Err(TlsError::BrokenPipe);
        };

        Ok(())
    }

    pub fn do_handshake_block(&mut self) -> Result<(), TlsError> {
        if let Err(err) = self.do_handshake() {
            self.write_alert(err)?;
            return Err(err);
        }

        Ok(())
    }

    fn handle_client_hello(
        &mut self,
        record: Record,
        tx_buf: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        if record.content_type != RecordType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }

        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::ClientHello {
            return Err(TlsError::UnexpectedMessage);
        }

        let client_hello = ClientHello::from_raw(handshake.fraqment)?;

        // -- Server Hello --
        let server_hello =
            ServerHello::from_client_hello(&client_hello, &mut *self.rng, self.config)?;
        let handshake_raw = Handshake::to_raw(HandshakeType::ServerHello, server_hello.to_raw());

        let mut tshash: Box<dyn TranscriptHash> = match server_hello.cipher_suite {
            CipherSuite::TLS_AES_256_GCM_SHA384 => Box::new(Sha384::new()),
            CipherSuite::TLS_AES_128_GCM_SHA256 => Box::new(Sha256::new()),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => todo!(),
            _ => return Err(TlsError::InsufficientSecurity),
        };

        // Add ClientHello
        tshash.update(record.fraqment.as_ref());
        tshash.update(&handshake_raw);

        let mut record_raw = Record::to_raw(RecordType::Handshake, &handshake_raw);
        tx_buf.append(&mut record_raw);

        // -- Change Cipher Spec --
        let mut server_change_cipher_spec = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        tx_buf.append(&mut server_change_cipher_spec);

        // -- Handshake Keys Calc --
        let key_schedule =
            KeySchedule::from_handshake(tshash.as_ref(), &client_hello, &server_hello)?;

        if let Some(filepath) = &self.config.keylog {
            let key_log = KeyLog::new(filepath.to_owned(), client_hello.random);
            key_log.append_handshake_traffic_secrets(
                &key_schedule
                    .server_handshake_traffic_secret
                    .pseudo_random_key,
                &key_schedule
                    .client_handshake_traffic_secret
                    .pseudo_random_key,
            );
            self.key_log = Some(key_log);
        }

        self.protection = RecordPayloadProtection::new(key_schedule);

        if self.protection.is_none() {
            return Err(TlsError::InternalError);
        }

        let protect = self.protection.as_mut().unwrap();

        // -- ServerParameters --

        // > EncryptedExtensions
        let encrypted_extensions = ServerExtensions::new();
        let encrypted_extensions_raw = encrypted_extensions.to_raw();
        let handshake_raw =
            Handshake::to_raw(HandshakeType::EncryptedExtensions, encrypted_extensions_raw);
        tshash.update(&handshake_raw);
        let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
        let mut encrypted_record_raw = protect.encrypt(record)?;
        log::debug!("<-- EncryptedExtensions");
        tx_buf.append(&mut encrypted_record_raw);

        // > Certificate Request

        if let Some(client_cert_ca) = &self.config.client_cert_ca {
            let random = self.rng.between_bytes(32);
            let certificate_request = client_cert_ca.get_certificate_request(&random);

            let handshake_raw =
                Handshake::to_raw(HandshakeType::CertificateRequest, certificate_request);

            tshash.update(&handshake_raw);
            let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));

            let mut encrypted_record_raw = protect.encrypt(record)?;
            log::debug!("<-- CertificateRequest");
            tx_buf.append(&mut encrypted_record_raw);
        }

        // -- Server Certificate --

        let certificate_raw = self.config.cert.get_certificate_for_handshake();

        let handshake_raw = Handshake::to_raw(HandshakeType::Certificate, certificate_raw);

        tshash.update(&handshake_raw);
        let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
        let mut encrypted_record_raw = protect.encrypt(record)?;
        log::debug!("<-- Certificate");
        tx_buf.append(&mut encrypted_record_raw);

        // -- Server Certificate Verify --

        let certificate_verify_raw = self
            .config
            .cert
            .get_certificate_verify_for_handshake(&self.config.privkey, tshash.as_ref())?;

        let handshake_raw =
            Handshake::to_raw(HandshakeType::CertificateVerify, certificate_verify_raw);

        tshash.update(&handshake_raw);
        let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
        let mut encrypted_record_raw = protect.encrypt(record)?;
        log::debug!("<-- CertificateVerify");
        tx_buf.append(&mut encrypted_record_raw);

        // -- FINISHED --
        let handshake_raw = get_finished_handshake(
            server_hello.hash,
            &protect.key_schedule.server_handshake_traffic_secret,
            tshash.as_ref(),
        )?;

        tshash.update(&handshake_raw);
        let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
        let mut encrypted_record_raw = protect.encrypt(record)?;
        tx_buf.append(&mut encrypted_record_raw);

        self.state = HandshakeState::ChangeCipherSpec;
        self.tshash = Some(tshash);
        Ok(())
    }

    fn handle_handshake_record(&mut self, record: Record) -> Result<Vec<u8>, TlsError> {
        let mut tx_buf = Vec::with_capacity(4096);

        match self.state {
            HandshakeState::Ready => {}
            HandshakeState::ClientHello => {
                self.handle_client_hello(record, &mut tx_buf)?;
            }
            HandshakeState::ChangeCipherSpec => {
                if record.content_type != RecordType::ChangeCipherSpec {
                    return Err(TlsError::UnexpectedMessage);
                }
                log::debug!("--> ChangeCipherSpec");
                if self.config.client_cert_ca.is_some() {
                    self.state = HandshakeState::ClientCertificate;
                } else {
                    self.state = HandshakeState::Finished;
                }
            }
            HandshakeState::ClientCertificate => {
                log::debug!("--> ClientCertificate");
                todo!("Handle ClientCertificate")
            }
            HandshakeState::Finished => {
                if record.content_type != RecordType::ApplicationData {
                    return Err(TlsError::UnexpectedMessage);
                }
                if self.protection.is_none() || self.tshash.is_none() {
                    return Err(TlsError::InternalError);
                }

                log::debug!("--> Finished");

                let protect = self.protection.as_mut().unwrap();
                let tshash = self.tshash.as_ref().unwrap();

                let verify_data = get_verify_client_finished(
                    &protect.key_schedule.client_handshake_traffic_secret,
                    tshash.as_ref(),
                )?;

                let record = protect.decrypt(record)?;

                if record.content_type != RecordType::Handshake {
                    return Err(TlsError::UnexpectedMessage);
                }

                let handshake = Handshake::from_raw(record.fraqment.as_ref())?;
                if handshake.fraqment != verify_data {
                    return Err(TlsError::DecryptError);
                }

                protect.generate_application_keys(tshash.as_ref())?;

                if let Some(k) = &self.key_log {
                    k.append_application_traffic_secrets(
                        &protect
                            .application_keys
                            .as_ref()
                            .unwrap()
                            .server
                            .traffic_secret,
                        &protect
                            .application_keys
                            .as_ref()
                            .unwrap()
                            .client
                            .traffic_secret,
                    );
                }
                self.state = HandshakeState::Ready;
            }
        }
        Ok(tx_buf)
    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut rx_buf: [u8; 4096] = [0; 4096];

        while self.state != HandshakeState::Ready {
            let n = match self.stream.read(&mut rx_buf) {
                Ok(n) => n,
                Err(_) => return Err(TlsError::DecodeError),
            };
            let mut consumed_total = 0;

            while consumed_total < n {
                let (consumed, record) = Record::from_raw(&rx_buf[consumed_total..n])?;
                consumed_total += consumed;

                let tx_buf = self.handle_handshake_record(record)?;

                // Send buffer
                if !tx_buf.is_empty() && self.stream.write_all(tx_buf.as_slice()).is_err() {
                    return Err(TlsError::BrokenPipe);
                }
            }
            rx_buf.fill(0);
        }

        Ok(())
    }

    pub fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> Result<usize, TlsError> {
        let mut rx_buf: [u8; 4096] = [0; 4096];

        let n = match self.stream.read(&mut rx_buf) {
            Ok(n) => n,
            Err(_) => return Err(TlsError::BrokenPipe),
        };

        let (_consumed, record) = Record::from_raw(&rx_buf[..n])?;

        if record.len as usize != record.fraqment.len() {
            return Err(TlsError::DecodeError);
        }

        let record = self.protection.as_mut().unwrap().decrypt(record)?;

        if record.content_type != RecordType::ApplicationData {
            todo!();
        }
        if record.fraqment.len() > buf.len() {
            todo!();
        }
        for (i, b) in record.fraqment.as_ref().iter().enumerate() {
            buf[i] = *b;
        }
        Ok(record.fraqment.len())
    }

    pub fn write_all<'b>(&'b mut self, src: &'b [u8]) -> Result<(), TlsError> {
        let record = Record::new(RecordType::ApplicationData, Value::Ref(src));

        let record = self.protection.as_mut().unwrap().encrypt(record)?;

        if self.stream.write_all(&record).is_err() {
            return Err(TlsError::BrokenPipe);
        };

        Ok(())
    }
}
