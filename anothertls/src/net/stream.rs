/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(dead_code)]

use crate::{
    crypto::CipherSuite,
    hash::{sha384::Sha384, TranscriptHash},
    net::{
        alert::{AlertLevel, TlsError},
        extensions::ServerExtensions,
        handshake::{
            get_finished_handshake, get_verify_client_finished, ClientHello, Handshake,
            HandshakeType, ServerHello,
        },
        key_schedule::KeySchedule,
        record::{Record, RecordPayloadProtection, RecordType, Value},
        TlsContext,
    },
    rand::URandomRng,
    utils::keylog::KeyLog,
    TlsConfig,
};

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    result::Result,
};

#[derive(PartialEq)]
enum HandshakeState {
    ClientHello,
    Finished,
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
    pub fn read_to_end(&mut self) -> Result<(), TlsError> {
        // TODO: Read to end xD
        self.write_alert(TlsError::CloseNotify)
    }
    pub fn write_alert(&mut self, err: TlsError) -> Result<(), TlsError> {
        let data = vec![AlertLevel::get_from_error(err) as u8, err as u8];

        let record = Record::new(RecordType::Alert, Value::Owned(data));

        let record_raw = if let Some(protect) = self.record_payload_protection.as_mut() {
            protect.encrypt(record)?
        } else {
            record.as_bytes()
        };

        if self.stream.write_all(&record_raw).is_err() {
            return Err(TlsError::InternalError);
        };

        Ok(())
    }

    pub fn do_handshake_block (&mut self) -> Result<(), TlsError> {

        if let Err(err) = self.do_handshake() {
            self.write_alert(err)?;
            return Err(err);
        }

        Ok(())

    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut state = HandshakeState::ClientHello;

        let mut context = TlsContext {
            config: self.config,
            rng: Box::new(URandomRng::new()),
            ts_hash: None,
        };
        let mut rx_buf: [u8; 4096] = [0; 4096];
        let mut tx_buf = Vec::with_capacity(4096);
        let mut ts_hash_handshake = None;
        let mut key_log = None;

        loop {
            let n = match self.stream.read(&mut rx_buf) {
                Ok(n) => n,
                Err(_) => return Err(TlsError::DecodeError),
            };

            if let HandshakeState::ClientHello = state {
                let record = match Record::from_raw(&rx_buf[..n]) {
                    Some(r) => r,
                    None => return Err(TlsError::DecodeError),
                };

                if record.content_type != RecordType::Handshake {
                    return Err(TlsError::UnexpectedMessage);
                }

                let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

                if handshake.handshake_type != HandshakeType::ClientHello {
                    return Err(TlsError::UnexpectedMessage);
                }

                let client_hello = ClientHello::from_raw(handshake.fraqment)?;

                // -- Server Hello --
                let server_hello = ServerHello::from_client_hello(&client_hello, &mut context)?;
                let handshake_raw =
                    Handshake::to_raw(HandshakeType::ServerHello, server_hello.to_raw());

                let mut ts_hash = match server_hello.cipher_suite {
                    CipherSuite::TLS_AES_256_GCM_SHA384 => Sha384::new(),
                    CipherSuite::TLS_AES_128_GCM_SHA256 => todo!(),
                    CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => todo!(),
                    _ => return Err(TlsError::InsufficientSecurity),
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

                if let Some(filepath) = &self.config.keylog {
                    key_log = Some(KeyLog::new(filepath.to_owned(), client_hello.random));
                    key_log.as_ref().unwrap().append_handshake_traffic_secrets(
                        &key_schedule
                            .server_handshake_traffic_secret
                            .pseudo_random_key,
                        &key_schedule
                            .client_handshake_traffic_secret
                            .pseudo_random_key,
                    )
                }

                self.record_payload_protection = RecordPayloadProtection::new(key_schedule);

                if self.record_payload_protection.is_none() {
                    return Err(TlsError::InternalError);
                }

                let protect = self.record_payload_protection.as_mut().unwrap();

                // -- ServerParameters --

                let encrypted_extensions = ServerExtensions::new();
                let encrypted_extensions_raw = encrypted_extensions.as_bytes();
                let handshake_raw =
                    Handshake::to_raw(HandshakeType::EncryptedExtensions, encrypted_extensions_raw);
                ts_hash.update(&handshake_raw);
                let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
                let mut encrypted_record_raw = protect.encrypt(record)?;
                tx_buf.append(&mut encrypted_record_raw);

                // -- Server Certificate --

                let certificate_raw = self.config.cert.get_certificate_for_handshake();

                let handshake_raw = Handshake::to_raw(HandshakeType::Certificate, certificate_raw);

                ts_hash.update(&handshake_raw);
                let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
                let mut encrypted_record_raw = protect.encrypt(record)?;
                tx_buf.append(&mut encrypted_record_raw);

                // -- Server Certificate Verify --

                let certificate_verify_raw = self
                    .config
                    .cert
                    .get_certificate_verify_for_handshake(&self.config.privkey, &ts_hash)?;

                let handshake_raw =
                    Handshake::to_raw(HandshakeType::CertificateVerify, certificate_verify_raw);

                ts_hash.update(&handshake_raw);
                let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
                let mut encrypted_record_raw = protect.encrypt(record)?;
                tx_buf.append(&mut encrypted_record_raw);

                // -- FINISHED --

                let handshake_raw = get_finished_handshake(
                    server_hello.hash,
                    &protect.key_schedule.server_handshake_traffic_secret,
                    &ts_hash,
                )?;

                ts_hash.update(&handshake_raw);
                let record = Record::new(RecordType::Handshake, Value::Ref(&handshake_raw));
                let mut encrypted_record_raw = protect.encrypt(record)?;
                tx_buf.append(&mut encrypted_record_raw);

                state = HandshakeState::Finished;
                ts_hash_handshake = Some(ts_hash);
            } else if state == HandshakeState::Finished {
                let change_cipher_spec = match Record::from_raw(&rx_buf[..n]) {
                    Some(e) => e,
                    None => return Err(TlsError::DecodeError),
                };

                let finished_start = 5 + change_cipher_spec.len as usize;

                let finished = match Record::from_raw(&rx_buf[finished_start..n]) {
                    Some(e) => e,
                    None => return Err(TlsError::DecodeError),
                };

                if finished.content_type != RecordType::ApplicationData {
                    return Err(TlsError::UnexpectedMessage);
                }

                if let Some(protect) = &mut self.record_payload_protection {
                    let ts_hash = ts_hash_handshake.as_ref().unwrap();
                    let verify_data = get_verify_client_finished(
                        &protect.key_schedule.client_handshake_traffic_secret,
                        ts_hash,
                    )?;
                    let record = protect.decrypt(finished).unwrap();

                    if record.content_type != RecordType::Handshake {
                        return Err(TlsError::UnexpectedMessage);
                    }

                    let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

                    if handshake.fraqment != verify_data {
                        return Err(TlsError::DecryptError);
                    }
                    protect.generate_application_keys(ts_hash)?;
                    if let Some(k) = key_log {
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
                    break;
                }

                return Err(TlsError::InternalError);
            }

            // Send buffer
            if self.stream.write_all(tx_buf.as_slice()).is_err() {
                return Err(TlsError::InternalError);
            };

            rx_buf.fill(0);
            tx_buf.clear();
        }

        Ok(())
    }

    pub fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> Result<usize, TlsError> {
        let mut rx_buf: [u8; 4096] = [0; 4096];

        let n = match self.stream.read(&mut rx_buf) {
            Ok(n) => n,
            Err(_) => return Err(TlsError::InternalError),
        };

        let record = match Record::from_raw(&rx_buf[..n]) {
            Some(e) => e,
            None => return Err(TlsError::DecodeError),
        };

        if record.len as usize != record.fraqment.len() {
            todo!();
        }

        let record = self
            .record_payload_protection
            .as_mut()
            .unwrap()
            .decrypt(record)?;

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

        let record = self
            .record_payload_protection
            .as_mut()
            .unwrap()
            .encrypt(record)?;

        if self.stream.write_all(&record).is_err() {
            return Err(TlsError::InternalError);
        };

        Ok(())
    }
}
