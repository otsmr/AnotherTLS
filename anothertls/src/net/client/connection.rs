/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::ellipticcurve::{Curve, PrivateKey, Signature};
use crate::hash::TranscriptHash;
use crate::net::alert::TlsError;
use crate::net::client::ClientHello;
use crate::net::extensions::{
    ClientExtension, KeyShare, KeyShareEntry, NamedGroup, ServerName, SignatureAlgorithms,
    SignatureScheme, SupportedGroups, SupportedVersions,
};
use crate::net::handshake::{
    get_finished_handshake, get_verify_data_for_finished, Certificate, Handshake, HandshakeType,
};
use crate::net::record::{Record, RecordPayloadProtection, RecordType, Value};
use crate::net::server::ServerHello;
use crate::net::{KeySchedule, TlsStream};
use crate::rand::{RngCore, URandomRng};
use crate::utils::keylog::KeyLog;
use crate::utils::{bytes, bytes::ByteOrder, log};
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
    EncryptedExtensions,
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
    server_cert: Option<Certificate>,
    client_hello_bytes: Option<Vec<u8>>,
    client_hello_random: Option<Vec<u8>>,
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
            server_cert: None,
            private_key,
            client_hello_bytes: None,
            client_hello_random: None,
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
        log::debug!("<-- ClientHello");

        let mut defragmented = Vec::with_capacity(2048);
        let mut rxbuf = [0; 2048];

        while self.state != ClientHsState::Ready {
            let n = self.stream.tcp_read(&mut rxbuf)?;

            if n == 0 {
                log::error!("Got empty tcp");
                return Err(TlsError::BrokenPipe);
            }

            println!("Got {n} bytes.");

            // if !defragmented.is_empty() {
            //     defragmented.extend_from_slice(&rxbuf[..n]);
            // }

            let mut offset = 0;

            if !defragmented.is_empty() {
                defragmented.extend_from_slice(&rxbuf[..n]);
            }

            while offset < n || !defragmented.is_empty() {
                println!("Starting @ {offset}");

                // let mut last_offset = 0;

                let record_buf = if defragmented.is_empty() {
                    &rxbuf[offset..n]
                } else {
                    //     last_offset = defragmented.len();
                    &defragmented[offset..]
                };

                println!("Record_start = {:?}", &record_buf[..5]);
                if let Ok((consumed, record)) = Record::from_raw(record_buf) {
                    self.handle_handshake_record(record)?;
                    println!("This consumed = {consumed}");
                    offset += consumed;
                    if offset == defragmented.len() {
                        defragmented.clear();
                        break;
                    }
                } else {
                    println!("Got Error");
                    if defragmented.is_empty() {
                        defragmented.extend_from_slice(&rxbuf[offset..n]);
                    }
                    break;
                }
            }
            println!(
                "Consumed {offset} bytes. defragmented={}",
                defragmented.len()
            );

            if !defragmented.is_empty() {
                // defragmented = defragmented[offset..].to_vec();
            }
            // send server handshake records to the client
            self.stream.flush()?;
        }
        Ok(())
    }

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        // Create ClientHello and send it to the Server
        let random = self.rng.between_bytes(32);
        let session_id = self.rng.between_bytes(32);

        let mut client_hello = ClientHello::new(&random, Some(&session_id))?;
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

        client_hello
            .extensions
            .push(ClientExtension::SupportedGroups(
                SupportedGroups::supported(),
            ));

        if let Some(server_name) = self.config.server_name.as_ref() {
            client_hello
                .extensions
                .push(ClientExtension::ServerName(ServerName::new(
                    server_name.clone(),
                )));
        }

        let handshake_raw =
            Handshake::to_bytes(HandshakeType::ClientHello, client_hello.as_bytes()?);

        self.client_hello_random = Some(random);
        self.client_hello_bytes = Some(handshake_raw);

        let record = Record::new(
            RecordType::Handshake,
            Value::Ref(self.client_hello_bytes.as_ref().unwrap()),
        );

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
                ClientHsState::EncryptedExtensions
                | ClientHsState::ServerCertificate
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

        let server_hello = ServerHello::from_raw(handshake.fraqment)?;

        let mut tshash = server_hello.cipher_suite.get_tshash()?;

        tshash.update(self.client_hello_bytes.as_ref().unwrap());
        tshash.update(record.fraqment.as_ref());

        let key_share_entry = match server_hello.get_public_key_share() {
            Some(kse) => kse,
            None => return Err(TlsError::HandshakeFailure),
        };
        let key_schedule =
            KeySchedule::from_handshake(tshash.as_ref(), &self.private_key, key_share_entry)?;

        let protection = RecordPayloadProtection::new(key_schedule, true);

        if let Some(filepath) = &self.config.keylog {
            if protection.is_some() {
                let protection = protection.as_ref().unwrap();
                let keylog = KeyLog::new(
                    filepath.to_owned(),
                    self.client_hello_random.as_ref().unwrap(),
                );
                keylog.append_handshake_traffic_secrets(
                    &protection.handshake_keys.server.traffic_secret,
                    &protection.handshake_keys.client.traffic_secret,
                );
                self.keylog = Some(keylog);
            }
        }

        self.stream.set_protection(protection);
        self.tshash = Some(tshash);

        self.state = ClientHsState::EncryptedExtensions;

        Ok(())
    }

    fn handle_handshake_encrypted_record(&mut self, record: Record) -> Result<(), TlsError> {
        log::debug!("=> Encrypted");
        let (content_type, content) = self.stream.protection.as_mut().unwrap().decrypt(record)?;

        println!("content_type={content_type:?}");

        let record = Record::new(content_type, crate::net::record::Value::Owned(content));

        println!("record={}", record.fraqment.len());

        if record.content_type != RecordType::Handshake {
            if record.content_type == RecordType::Alert {
                return Err(TlsError::GotAlert(record.fraqment.as_ref()[1]));
            }
            return Err(TlsError::UnexpectedMessage);
        }

        let mut consumed = 0;

        while consumed < record.fraqment.len() {
            let handshake = Handshake::from_raw(&record.fraqment.as_ref()[consumed..])?;
            consumed += handshake.as_bytes().len();

            match self.state {
                ClientHsState::EncryptedExtensions => self.handle_encrypted_extension(handshake)?,
                ClientHsState::ServerCertificate => self.handle_server_certificate(handshake)?,
                ClientHsState::ServerCertificateVerify => {
                    self.handle_server_certificate_verify(handshake)?
                }
                ClientHsState::Finished | ClientHsState::FinishWithError(_) => {
                    self.handle_server_finish(handshake)?
                }
                _ => (),
            }
        }
        Ok(())
    }
    pub fn handle_encrypted_extension(&mut self, handshake: Handshake) -> Result<(), TlsError> {

        if handshake.handshake_type != HandshakeType::EncryptedExtensions {
            return Err(TlsError::UnexpectedMessage);
        }
        log::debug!("--> EncryptedExtensions");

        self.tshash.as_mut().unwrap().update(handshake.as_bytes());

        self.state = ClientHsState::ServerCertificate;
        Ok(())
    }
    pub fn handle_server_certificate(&mut self, handshake: Handshake) -> Result<(), TlsError> {
        if handshake.handshake_type != HandshakeType::Certificate {
            return Err(TlsError::UnexpectedMessage);
        }

        self.tshash.as_mut().unwrap().update(handshake.as_bytes());

        log::debug!("--> ServerCertificate");

        let mut certs = match Certificate::from_hello(handshake.fraqment) {
            Ok(e) => e,
            Err(e) => {
                self.state = ClientHsState::FinishWithError(e);
                return Ok(());
            }
        };

        println!("Got {} server certificates", certs.len());

        let cert = certs.pop().unwrap();

        // Validate client cert against the CA
        log::error!("Validate server certificate with system!!!");
        // if self
        //     .config
        //     .client_cert_ca
        //     .as_ref()
        //     .unwrap()
        //     .has_signed(&cert)
        //     .is_err()
        // {
        //     self.state = ServerHsState::FinishWithError(TlsError::UnknownCa)
        // }
        //
        self.server_cert = Some(cert);
        self.state = ClientHsState::ServerCertificateVerify;

        Ok(())
    }
    pub fn handle_server_certificate_verify(
        &mut self,
        handshake: Handshake,
    ) -> Result<(), TlsError> {
        if handshake.handshake_type != HandshakeType::CertificateVerify
            || self.server_cert.is_none()
        {
            return Err(TlsError::UnexpectedMessage);
        }

        log::debug!("--> ClientCertificateVerify");

        let algo = SignatureScheme::new(bytes::to_u16(&handshake.fraqment[0..2]))?;

        let mut consumed = 4; // algo and len

        match algo {
            SignatureScheme::ecdsa_secp256r1_sha256 => {
                let (signature, size) = match Signature::from_der(&handshake.fraqment[consumed..]) {
                    Ok(e) => e,
                    Err(e) => {
                        self.state = ClientHsState::FinishWithError(e);
                        return Ok(());
                    }
                };

                consumed += size;

                if !self.server_cert.as_ref().unwrap().is_certificate_valid(
                    signature,
                    self.tshash.as_ref().unwrap().as_ref(),
                    b"server",
                ) {
                    println!("HALLO");
                    self.state = ClientHsState::FinishWithError(TlsError::BadCertificate);
                    return Ok(());
                }
            }
            e => todo!("SignatureScheme {e:?} for client cert not implemented yet"),
        }

        let sign_len = bytes::to_u16(&handshake.fraqment[2..4]) as usize;
        if sign_len != consumed - 4 {
            self.state = ClientHsState::FinishWithError(TlsError::BadCertificate);
            return Ok(());
        }

        self.tshash.as_mut().unwrap().update(handshake.as_bytes());

        self.state = ClientHsState::Finished;
        Ok(())
    }
    pub fn handle_server_finish(&mut self, handshake: Handshake) -> Result<(), TlsError> {
        if handshake.handshake_type != HandshakeType::Finished {
            if let ClientHsState::FinishWithError(_) = self.state {
                // When error in Certificate, then CertificateVerify will follow
                return Ok(());
            }
            return Err(TlsError::UnexpectedMessage);
        }

        let protection = self.stream.protection.as_mut().unwrap();
        log::debug!("--> ServerFinished");

        let fraqment = handshake.fraqment.to_owned();

        let verify_data = Some(get_verify_data_for_finished(
            &protection.key_schedule.server_handshake_traffic_secret,
            self.tshash.as_mut().unwrap().as_ref(),
        )?);

        if fraqment != verify_data.unwrap() {
            return Err(TlsError::DecryptError);
        }

        if let ClientHsState::FinishWithError(err) = self.state {
            log::error!("Abort connection: {err:?}");
            return Err(err);
        }

        self.tshash.as_mut().unwrap().update(handshake.as_bytes());

        let finished = get_finished_handshake(
            &protection.key_schedule.client_handshake_traffic_secret,
            self.tshash.as_mut().unwrap().as_ref(),
        )?;

        log::debug!("<-- ClientFinished");

        self.stream.write_record(RecordType::Handshake, &finished)?;
        self.stream.flush()?;

        // Derive-Secret: ClientHello..server Finished
        let protection = self.stream.protection.as_mut().unwrap();
        protection.generate_application_keys(self.tshash.as_ref().unwrap().as_ref())?;

        if let Some(k) = &self.keylog {
            k.append_from_record_payload_protection(protection);
        }

        self.state = ClientHsState::Ready;
        Ok(())
    }
}
