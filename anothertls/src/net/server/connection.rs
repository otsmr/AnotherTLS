/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::server::ServerHello;
use crate::net::TlsStream;
use crate::rand::URandomRng;
use crate::ServerConfig;
use crate::{
    crypto::{ellipticcurve::Signature, CipherSuite},
    hash::{sha256::Sha256, sha384::Sha384, TranscriptHash},
    net::{
        alert::TlsError,
        client::ClientHello,
        extensions::{SignatureScheme, ServerExtensions},
        handshake::{
            get_finished_handshake, get_verify_client_finished, Certificate, Handshake,
            HandshakeType,
        },
        key_schedule::KeySchedule,
        record::{Record, RecordPayloadProtection, RecordType},
    },
    rand::RngCore,
    utils::{bytes, keylog::KeyLog, log},
};
use ibig::IBig;
use std::net::SocketAddr;
use std::net::TcpListener;

use std::result::Result;

pub struct ServerConnection {
    server: TcpListener,
    config: ServerConfig,
}

impl ServerConnection {
    pub fn new(server: TcpListener, config: ServerConfig) -> Self {
        Self { server, config }
    }

    pub fn accept(&self) -> std::result::Result<(TlsStream, SocketAddr), TlsError> {
        let (sock, _addr) = match self.server.accept() {
            Ok(e) => e,
            Err(e) => {
                log::error!("TCP accept error: {e:?}");
                return Err(TlsError::BrokenPipe);
            }
        };

        let mut stream = TlsStream::new(sock);

        let mut shs = ServerHandshake::new(&mut stream, &self.config);
        shs.do_handshake_with_error()?;

        Ok((stream, _addr))
    }
}

#[derive(PartialEq, PartialOrd, Clone, Copy, Debug)]
#[repr(u8)]
enum ServerHsState {
    ClientHello,
    ClientCertificate = 0x10,
    ClientCertificateVerify,
    ClientFinished,
    FinishWithError(TlsError),
    Ready,
}

struct ServerHandshake<'a> {
    stream: &'a mut TlsStream,
    config: &'a ServerConfig,
    state: ServerHsState,
    keylog: Option<KeyLog>,
    client_cert: Option<Certificate>,
    certificate_request_context: Option<Vec<u8>>,
    rng: Box<dyn RngCore<IBig>>,
    tshash: Option<Box<dyn TranscriptHash>>,
    tshash_clienthello_serverfinished: Option<Box<dyn TranscriptHash>>,
}

impl<'a> ServerHandshake<'a> {
    pub fn new(stream: &'a mut TlsStream, config: &'a ServerConfig) -> Self {
        Self {
            stream,
            config,
            state: ServerHsState::ClientHello,
            keylog: None,
            client_cert: None,
            certificate_request_context: None,
            rng: Box::new(URandomRng::new()),
            tshash: None,
            tshash_clienthello_serverfinished: None,
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
        let mut rx_buf: [u8; 4096] = [0; 4096];

        while self.state != ServerHsState::Ready {
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

    fn handle_handshake_record(&mut self, record: Record) -> Result<(), TlsError> {
        match record.content_type {
            RecordType::ChangeCipherSpec => {
                log::debug!("--> ChangeCipherSpec");
                if self.state == ServerHsState::ClientHello {
                    return Err(TlsError::UnexpectedMessage);
                }
                return Ok(());
            }
            RecordType::Alert => {
                let alert_code = record.fraqment.as_ref()[1];
                let alert = TlsError::new(alert_code);
                log::debug!("--> Alert {alert:?}");
                if self.state != ServerHsState::Ready {
                    log::error!("Handshake aborted by client");
                }
                return Err(TlsError::GotAlert(alert_code));
            }
            _ => match self.state {
                ServerHsState::ClientHello => {
                    if record.content_type != RecordType::Handshake {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    self.handle_client_hello(record)?;
                }
                ServerHsState::ClientCertificate
                | ServerHsState::ClientCertificateVerify
                | ServerHsState::FinishWithError(_)
                | ServerHsState::ClientFinished => {
                    self.handle_handshake_encrypted_record(record)?;
                }
                ServerHsState::Ready => {}
            },
        }
        Ok(())
    }
    fn handle_client_hello(&mut self, record: Record) -> Result<(), TlsError> {
        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::ClientHello {
            return Err(TlsError::UnexpectedMessage);
        }

        log::debug!("--> ClientHello");
        let client_hello = ClientHello::from_raw(handshake.fraqment)?;

        let server_hello =
            ServerHello::from_client_hello(&client_hello, &mut *self.rng, self.config)?;

        let mut tshash: Box<dyn TranscriptHash> = match server_hello.cipher_suite {
            CipherSuite::TLS_AES_256_GCM_SHA384 => Box::new(Sha384::new()),
            CipherSuite::TLS_AES_128_GCM_SHA256 => Box::new(Sha256::new()),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => todo!(),
            _ => return Err(TlsError::InsufficientSecurity),
        };

        // Add ClientHello
        tshash.update(record.fraqment.as_ref());

        // -- ServerHello --
        let handshake_raw = Handshake::as_bytes(HandshakeType::ServerHello, server_hello.as_bytes());
        tshash.update(&handshake_raw);
        self.stream
            .write_record(RecordType::Handshake, &handshake_raw)?;

        // -- Change Cipher Spec --
        // Either side can send change_cipher_spec at any time during the handshake, as they
        // must be ignored by the peer, but if the client sends a non-empty session ID, the
        // server MUST send the change_cipher_spec as described in this appendix.
        if client_hello.legacy_session_id_echo.is_some() {
            self.stream
                .write_record(RecordType::ChangeCipherSpec, &[0x01])?;
        }

        // -- Handshake Keys Calc --
        let key_schedule =
            KeySchedule::from_handshake(tshash.as_ref(), &client_hello, &server_hello)?;

        let protection = RecordPayloadProtection::new(key_schedule);

        if let Some(filepath) = &self.config.keylog {
            if protection.is_some() {
                let protection = protection.as_ref().unwrap();
                let keylog = KeyLog::new(filepath.to_owned(), client_hello.random);
                keylog.append_handshake_traffic_secrets(
                    &protection.handshake_keys.server.traffic_secret,
                    &protection.handshake_keys.client.traffic_secret,
                );
                self.keylog = Some(keylog);
            }
        }

        self.stream.set_protection(protection);

        // -- EncryptedExtensions --
        let encrypted_extensions_raw = ServerExtensions::new().as_bytes();
        let handshake_raw =
            Handshake::as_bytes(HandshakeType::EncryptedExtensions, encrypted_extensions_raw);

        log::debug!("<-- EncryptedExtensions");
        self.stream
            .write_record(RecordType::Handshake, &handshake_raw)?;
        tshash.update(&handshake_raw);

        // -- Certificate Request --
        if let Some(client_cert_ca) = &self.config.client_cert_ca {
            // prevent an attacker who has temporary access to the client's
            // private key from pre-computing valid CertificateVerify messages
            self.certificate_request_context = Some(self.rng.between_bytes(32));
            let certificate_request = client_cert_ca
                .get_certificate_request(self.certificate_request_context.as_ref().unwrap());

            let handshake_raw =
                Handshake::as_bytes(HandshakeType::CertificateRequest, certificate_request);

            log::debug!("<-- CertificateRequest");
            self.stream
                .write_record(RecordType::Handshake, &handshake_raw)?;
            tshash.update(&handshake_raw);
        }

        // -- Server Certificate --
        let handshake_raw = Handshake::as_bytes(
            HandshakeType::Certificate,
            self.config.cert.get_certificate_for_handshake(),
        );

        log::debug!("<-- Certificate");
        self.stream
            .write_record(RecordType::Handshake, &handshake_raw)?;
        tshash.update(&handshake_raw);

        // -- Server Certificate Verify --
        let certificate_verify_raw = self
            .config
            .cert
            .get_certificate_verify_for_handshake(&self.config.privkey, tshash.as_ref())?;

        let handshake_raw =
            Handshake::as_bytes(HandshakeType::CertificateVerify, certificate_verify_raw);

        tshash.update(&handshake_raw);
        self.stream
            .write_record(RecordType::Handshake, &handshake_raw)?;
        log::debug!("<-- CertificateVerify");

        // -- FINISHED --
        let handshake_raw = get_finished_handshake(
            server_hello.hash,
            &self
                .stream
                .protection
                .as_ref()
                .unwrap()
                .key_schedule
                .server_handshake_traffic_secret,
            tshash.as_ref(),
        )?;

        tshash.update(&handshake_raw);
        self.stream
            .write_record(RecordType::Handshake, &handshake_raw)?;
        log::debug!("<-- ServerFinished");

        self.state = if self.config.client_cert_ca.is_some() {
            ServerHsState::ClientCertificate
        } else {
            ServerHsState::ClientFinished
        };

        self.tshash = Some(tshash);
        Ok(())
    }

    fn handle_handshake_encrypted_record(&mut self, record: Record) -> Result<(), TlsError> {
        log::debug!("==> Encrypted handshake record");

        let (content_type, content) = self.stream.protection.as_mut().unwrap().decrypt(record)?;

        let record = Record::new(content_type, crate::net::record::Value::Owned(content));

        if record.content_type != RecordType::Handshake
            || (self.config.client_cert_ca.is_some() && self.certificate_request_context.is_none())
        {
            if record.content_type == RecordType::Alert {
                return Err(TlsError::GotAlert(record.fraqment.as_ref()[1]));
            }
            return Err(TlsError::UnexpectedMessage);
        }

        match self.state {
            ServerHsState::ClientCertificate => self.handle_client_certificate(record)?,
            ServerHsState::ClientCertificateVerify => {
                self.handle_client_certificate_verify(record)?
            }
            ServerHsState::ClientFinished | ServerHsState::FinishWithError(_) => {
                self.handle_client_finish(record)?
            }
            _ => (),
        }
        Ok(())
    }

    pub fn handle_client_finish(&mut self, record: Record) -> Result<(), TlsError> {
        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::Finished {
            return Err(TlsError::UnexpectedMessage);
        }

        let protection = self.stream.protection.as_mut().unwrap();
        log::debug!("--> Finished");
        let fraqment = handshake.fraqment.to_owned();
        let verify_data = Some(get_verify_client_finished(
            &protection.key_schedule.client_handshake_traffic_secret,
            self.tshash.as_mut().unwrap().as_ref(),
        )?);

        if fraqment != verify_data.unwrap() {
            return Err(TlsError::DecryptError);
        }

        // Derive-Secret: ClientHello..server Finished
        let tshash = if self.tshash_clienthello_serverfinished.is_some() {
            self.tshash_clienthello_serverfinished.as_mut().unwrap()
        } else {
            self.tshash.as_mut().unwrap()
        };

        protection.generate_application_keys(tshash.as_ref())?;

        if let Some(k) = &self.keylog {
            let protect = self.stream.protection.as_ref().unwrap();
            k.append_from_record_payload_protection(protect);
        }

        if let ServerHsState::FinishWithError(err) = self.state {
            return Err(err);
        }

        self.state = ServerHsState::Ready;
        Ok(())
    }
    pub fn handle_client_certificate(&mut self, record: Record) -> Result<(), TlsError> {
        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::Certificate {
            return Err(TlsError::UnexpectedMessage);
        }

        self.tshash_clienthello_serverfinished = Some((*self.tshash.as_ref().unwrap()).clone());

        self.tshash
            .as_mut()
            .unwrap()
            .update(record.fraqment.as_ref());
        log::debug!("--> ClientCertificate");

        let mut consumed = 1;
        let cert_request_context_len = handshake.fraqment[0] as usize;
        let cert_request_context = &handshake.fraqment[1..cert_request_context_len + 1];

        if cert_request_context != self.certificate_request_context.as_ref().unwrap() {
            return Err(TlsError::HandshakeFailure);
        }

        consumed += cert_request_context_len;

        let certs_len =
            bytes::to_u128_le_fill(&handshake.fraqment[consumed..consumed + 3]) as usize;
        consumed += 3;

        if certs_len == 0 {
            log::debug!("Client send no certificate!");
            self.state = ServerHsState::FinishWithError(TlsError::CertificateRequired);
            return Ok(());
        }

        let cert_len = bytes::to_u128_le_fill(&handshake.fraqment[consumed..consumed + 3]) as usize;
        consumed += 3;

        if certs_len != cert_len + 5 {
            todo!("Add support for multiple certs");
        }

        let cert =
            Certificate::from_raw_x509(handshake.fraqment[consumed..consumed + cert_len].to_vec())?;

        if !cert
            .x509
            .as_ref()
            .unwrap()
            .tbs_certificate
            .validity
            .is_valid()
        {
            log::debug!("Certificate is not valid");
            self.state = ServerHsState::FinishWithError(TlsError::CertificateExpired);
            return Ok(());
        }

        log::debug!("Client certificate:");
        // TODO: only in debug
        let issuer = &cert.x509.as_ref().unwrap().tbs_certificate.issuer;
        let subject = &cert.x509.as_ref().unwrap().tbs_certificate.subject;

        log::debug!("   subject: {subject}");
        log::debug!("   issuer: {issuer}");

        if let Some(f) = self.config.client_cert_custom_verify_fn.as_ref() {
            if !f(cert.x509.as_ref().unwrap()) {
                log::debug!("Certificate denied by custom verify function");
                self.state = ServerHsState::FinishWithError(TlsError::AccessDenied);
                return Ok(());
            }
        }

        self.client_cert = Some(cert);
        self.state = ServerHsState::ClientCertificateVerify;

        Ok(())
    }

    pub fn handle_client_certificate_verify(&mut self, record: Record) -> Result<(), TlsError> {
        let handshake = Handshake::from_raw(record.fraqment.as_ref())?;

        if handshake.handshake_type != HandshakeType::CertificateVerify {
            return Err(TlsError::UnexpectedMessage);
        }

        log::debug!("--> ClientCertificateVerify");

        if self.client_cert.is_none() {
            return Err(TlsError::UnexpectedMessage);
        }

        let algo = SignatureScheme::new(bytes::to_u16(&handshake.fraqment[0..2]))?;

        let mut consumed = 4; // algo and len

        match algo {
            SignatureScheme::ecdsa_secp256r1_sha256 => {
                let (signature, size) = match Signature::from_der(&handshake.fraqment[consumed..]) {
                    Ok(e) => e,
                    Err(e) => {
                        self.state = ServerHsState::FinishWithError(e);
                        return Ok(());
                    }
                };

                consumed += size;

                if self
                    .client_cert
                    .as_ref()
                    .unwrap()
                    .verify_client_certificate(signature, self.tshash.as_ref().unwrap().as_ref())
                    .is_err()
                {
                    self.state = ServerHsState::FinishWithError(TlsError::BadCertificate);
                    return Ok(());
                }
            }
            e => todo!("SignatureScheme {e:?} for client cert not implemented yet"),
        }

        let sign_len = bytes::to_u16(&handshake.fraqment[2..4]) as usize;
        if sign_len != consumed - 4 || self.client_cert.is_none() {
            self.state = ServerHsState::FinishWithError(TlsError::BadCertificate);
            return Ok(());
        }

        // TODO: Check the validity of the client cert

        // Validate client cert against the CA
        if self
            .config
            .client_cert_ca
            .as_ref()
            .unwrap()
            .has_signed(self.client_cert.as_ref().unwrap())
            .is_err()
        {
            self.state = ServerHsState::FinishWithError(TlsError::UnknownCa)
        }

        self.tshash
            .as_mut()
            .unwrap()
            .update(record.fraqment.as_ref());

        self.state = ServerHsState::ClientFinished;
        Ok(())
    }
}
