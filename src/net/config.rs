/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use crate::hash::TranscriptHash;
use super::handshake::Certificate;
use ibig::IBig;

use crate::{rand::RngCore, crypto::ellipticcurve::PrivateKey};

pub struct TlsConfig {
    // pub server_name: Option<String>,
    // ca: Option<Certificate<'a>>, // Client Cert ?

    // openssl ecparam -out pk_server.pem -name prime256v1 -genkey
    // openssl req -new -key ec_key.pem -x509 -nodes -days 365 -out cert.pem
    pub(crate) cert: Certificate,
    pub(crate) privkey: PrivateKey,
    pub(crate) keylog: Option<String>
}

pub struct TlsConfigBuilder {
    cert: Option<Certificate>,
    privkey: Option<PrivateKey>,
    keylog: Option<String>

}
impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {

    pub fn new () -> Self {
        TlsConfigBuilder {
            cert: None,
            privkey: None,
            keylog: None
        }
    }
    pub fn add_cert_pem(mut self, filepath: String) -> Self {
        self.cert = Certificate::from_pem(filepath);
        if self.cert.is_none() {
            panic!("Error reading or parsing certificate");
        }
        self
    }
    pub fn add_privkey_pem(mut self, filepath: String) -> Self {
        self.privkey = PrivateKey::from_pem(filepath);
        // TODO: Validate priv key against the cert
        if self.privkey.is_none() {
            panic!("Error reading or parsing private key");
        }
        self
    }
    pub fn set_keylog_path(mut self, filepath: String) -> Self {
        self.keylog = Some(filepath);
        self
    }
    pub fn enable_keylog(mut self) -> Self {
        self.keylog = Some("keylog.txt".to_string());
        self
    }
    pub fn build (self) -> std::result::Result<TlsConfig, String> {
        if self.cert.is_none() {
            return Err("No cert provided".to_string());
        }
        if self.privkey.is_none() {
            return Err("No privkey for cert provided".to_string());
        }
        Ok(TlsConfig { cert: self.cert.unwrap(), privkey: self.privkey.unwrap(), keylog: self.keylog })
    }
}

pub struct TlsContext<'a> {
    pub config: &'a TlsConfig,
    pub rng: Box<dyn RngCore<IBig>>,
    pub ts_hash: Option<Box<dyn TranscriptHash>>
}
