/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::{
    crypto::ellipticcurve::{Ecdsa, PrivateKey, Signature},
    hash::{sha256, TranscriptHash},
    net::{
        alert::TlsError,
        extensions::{
            server::ServerExtension,
            shared::{SignatureAlgorithms, SignatureScheme},
            ServerExtensions,
        },
    },
    utils::{log, pem::get_pem_content_from_file, x509::X509},
};

pub struct Certificate {
    pub raw: Vec<u8>,
    pub x509: Option<X509>,
}

impl Certificate {
    pub fn from_raw_x509(raw: Vec<u8>) -> Result<Self, TlsError> {
        Ok(Certificate {
            x509: Some(match X509::from_raw(&raw) {
                Ok(a) => a,
                Err(e) => {
                    log::error!("Error parsing: {e:?}");
                    return Err(TlsError::DecodeError);
                }
            }),
            raw,
        })
    }
    pub fn from_pem_x509(filepath: String) -> Option<Self> {
        let raw = get_pem_content_from_file(filepath)?;
        // TODO: check if cert using the available algos
        Some(
            Certificate::from_raw_x509(raw.get("CERTIFICATE")?.to_vec())
                .expect("Provided client certificate is not a valid x509 certificate."),
        )
    }

    pub fn from_pem(filepath: String) -> Option<Self> {
        let raw = get_pem_content_from_file(filepath)?;
        // TODO: check if cert using the available algos
        Some(Certificate {
            raw: raw.get("CERTIFICATE")?.to_vec(),
            x509: None,
        })
    }

    pub fn get_certificate_request(&self, random: &[u8]) -> Vec<u8> {
        let mut extensions = ServerExtensions::new();
        let algs = SignatureAlgorithms::new(SignatureScheme::ecdsa_secp256r1_sha256);
        extensions.push(ServerExtension::SignatureAlgorithms(algs));
        let mut out = vec![random.len() as u8];
        out.extend_from_slice(random);
        out.extend(extensions.to_raw());
        out
    }

    pub fn get_certificate_for_handshake(&self) -> Vec<u8> {
        let len = self.raw.len();
        let lens = len + 5;
        let mut certificate_raw = vec![
            0x00,
            // CertificateS Length + Extensions
            (lens >> 16) as u8,
            (lens >> 8) as u8,
            (lens as u8),
            // Certificate Length
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len as u8),
        ];
        certificate_raw.extend_from_slice(&self.raw);
        // Certificate Extensions
        certificate_raw.push(0x00);
        certificate_raw.push(0x00);
        certificate_raw
    }

    pub fn get_certificate_verify_for_handshake(
        &self,
        privkey: &PrivateKey,
        tshash: &dyn TranscriptHash,
    ) -> std::result::Result<Vec<u8>, TlsError> {
        // 4.4.3.  Certificate Verify

        let mut content = Vec::with_capacity(150);
        content.resize(64, 0x20);
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend(tshash.clone().finalize());

        let hash = sha256(&content);

        let mut ecdsa = Ecdsa::urandom();
        let signature = match ecdsa.sign(privkey, &hash) {
            Ok(a) => a,
            Err(_) => return Err(TlsError::InternalError),
        };
        let der = signature.to_der();
        let mut res = vec![0x04, 0x03, (der.len() >> 8) as u8, der.len() as u8]; // ecdsa_secp256r1_sha256 + Length
        res.extend(der);
        Ok(res)
    }

    /// Checks if the other certificate is signed from self as CA.
    pub fn has_signed(&self, other: &Certificate) -> Result<(), TlsError> {
        if self.x509.is_none() || other.x509.is_none() {
            return Err(TlsError::InternalError);
        }

        let ca_public_key = self
            .x509
            .as_ref()
            .unwrap()
            .get_public_key()
            .expect("CA for client certificate has no public key");

        let other_x509 = other.x509.as_ref().unwrap();
        let signature = match &other_x509.signature {
            Some(e) => e,
            None => return Err(TlsError::DecryptError),
        };

        let context = &other.raw[4..4 + other_x509.tbs_certificate_size];

        let hash = sha256(context);

        if Ecdsa::verify(ca_public_key, signature, &hash) {
            return Ok(());
        }
        log::error!("Client Certificate not valid.");

        Err(TlsError::DecryptError)
    }

    pub fn verify_client_certificate(
        &self,
        signature: Signature,
        tshash: &dyn TranscriptHash,
    ) -> Result<(), TlsError> {
        // 4.4.3.  Certificate Verify

        let mut content = Vec::with_capacity(150);
        content.resize(64, 0x20);
        content.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        content.push(0x00);
        content.extend(tshash.clone().finalize());

        let hash = sha256(&content);

        if let Some(pubkey) = self.x509.as_ref().unwrap().get_public_key() {
            if Ecdsa::verify(pubkey, &signature, &hash) {
                return Ok(());
            }
        }

        Err(TlsError::DecryptError)
    }
}
