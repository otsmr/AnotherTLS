/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use crate::hash::TranscriptHash;
use crate::{
    net::{
        handshake::{ClientHello, Handshake, HandshakeType, ServerHello},
        key_schedule::KeySchedule,
        record::{Record, RecordPayloadProtection, RecordType},
        TlsContext,
        extensions::ServerExtensions,
    },
    crypto::CipherSuite,
    hash::sha384::Sha384,
    rand::URandomRng,
    TlsConfig,
};

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::exit,
    result::Result,
};


#[derive(PartialEq)]
enum HandshakeState {
    KeyExchange,
    ServerParameters,
    Authentication,
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

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig,
    record_payload_protection: Option<RecordPayloadProtection>,
}

impl<'a> TlsStream<'a> {
    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self {
            stream,
            addr,
            config,
            record_payload_protection: None,
        }
    }

    pub fn do_handshake_block(&mut self) -> Result<(), TlsError> {
        let state = HandshakeState::KeyExchange;

        let mut context = TlsContext {
            config: self.config,
            rng: Box::new(URandomRng::new()),
            ts_hash: None
        };
        let mut rx_buf: [u8; 4096] = [0; 4096];
        let mut tx_buf = Vec::with_capacity(4096);

        loop {
            let n = match self.stream.read(&mut rx_buf) {
                Ok(n) => n,
                Err(_) => return Err(TlsError::InternalError),
            };

            let record = Record::from_raw(&rx_buf[..n]).unwrap();

            if record.content_type != RecordType::Handshake {
                return Err(TlsError::UnexpectedMessage);
            }

            let handshake = Handshake::from_raw(record.fraqment.as_ref()).unwrap();

            match state {
                HandshakeState::KeyExchange => {
                    if handshake.handshake_type != HandshakeType::ClientHello {
                        return Err(TlsError::UnexpectedMessage);
                    }

                    let client_hello = ClientHello::from_raw(handshake.fraqment)?;

                    // -- Server Hello --
                    let server_hello =
                        ServerHello::from_client_hello(&client_hello, &mut context)?;
                    let handshake_raw =
                        Handshake::to_raw(HandshakeType::ServerHello, server_hello.to_raw());

                    let mut ts_hash = match server_hello.cipher_suite {
                        CipherSuite::TLS_AES_256_GCM_SHA384 => Sha384::new(),
                        CipherSuite::TLS_AES_128_GCM_SHA256 => todo!(),
                        CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => todo!(),
                        _ => return Err(TlsError::InsufficientSecurity)
                    };

                    // Add ClientHello
                    ts_hash.update(record.fraqment.as_ref());
                    ts_hash.update(&handshake_raw);

                    let mut record_raw = Record::to_raw(RecordType::Handshake, &handshake_raw);
                    tx_buf.append(&mut record_raw);

                    // -- Change Cipher Spec --
                    let mut server_change_cipher_spec = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                    tx_buf.append(&mut server_change_cipher_spec);

                    // -- Handshake Keys Calc --
                    let key_schedule =
                        KeySchedule::from_handshake(&ts_hash, &client_hello, &server_hello)?;

                    self.record_payload_protection = RecordPayloadProtection::new(key_schedule);

                    if self.record_payload_protection.is_none() {
                        return Err(TlsError::InternalError);
                    }

                    let protect = self.record_payload_protection.as_mut().unwrap();

                    // -- ServerParameters --

                    let encrypted_extensions = ServerExtensions::new();
                    let encrypted_extensions_raw = encrypted_extensions.as_bytes();
                    let handshake_raw = Handshake::to_raw(
                        HandshakeType::EncryptedExtensions,
                        encrypted_extensions_raw,
                    );
                    ts_hash.update(&handshake_raw);
                    let record = Record::new(RecordType::Handshake, &handshake_raw);
                    let mut encrypted_record_raw = protect.encrypt(record)?;
                    // ts_hash.update(&encrypted_record_raw[5..]);
                    tx_buf.append(&mut encrypted_record_raw);

                    // -- Server Certificate --

                    let certificate_raw = self.config.cert.get_certificate_for_handshake();

                    let handshake_raw = Handshake::to_raw(HandshakeType::Certificate, certificate_raw);
                    ts_hash.update(&handshake_raw);
                    let record = Record::new(RecordType::Handshake, &handshake_raw);
                    let mut encrypted_record_raw = protect.encrypt(record)?;
                    // ts_hash.update(&encrypted_record_raw[5..]);
                    tx_buf.append(&mut encrypted_record_raw);

                    // -- Server Certificate Verify --

                    let certificate_verify_raw = self.config.cert.get_certificate_verify_for_handshake(server_hello.hash, &self.config.privkey, &ts_hash)?;

                    let handshake_raw = Handshake::to_raw(HandshakeType::CertificateVerify, certificate_verify_raw);
                    ts_hash.update(&handshake_raw);
                    let record = Record::new(RecordType::Handshake, &handshake_raw);
                    let mut encrypted_record_raw = protect.encrypt(record)?;
                    // tx_buf.append(&mut encrypted_record_raw);

                }
                HandshakeState::ServerParameters => {}
                HandshakeState::Authentication => break,
                HandshakeState::Finished => break,
            }

            if self.stream.write_all(tx_buf.as_slice()).is_err() {
                return Err(TlsError::InternalError);
            };

            rx_buf.fill(0);
            tx_buf.clear();
            exit(0);
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
