/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use super::handshake::Certificate;
use ibig::IBig;

use crate::{rand::RngCore, crypto::ellipticcurve::PrivateKey};

pub struct TlsConfig {
    // pub server_name: Option<String>,
    // ca: Option<Certificate<'a>>, // Client Cert ?

    // openssl ecparam -out pk_server.pem -name prime256v1 -genkey
    // openssl req -new -key ec_key.pem -x509 -nodes -days 365 -out cert.pem
    pub(crate) cert: Option<Certificate>,
    pub(crate) privkey: Option<PrivateKey>,
}

pub struct TlsConfigBuilder {
    config: TlsConfig

}
impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {

    pub fn new () -> Self {
        TlsConfigBuilder {
            config: TlsConfig {
                cert: None,
                privkey: None
            }
        }
    }
    pub fn add_cert_pem(mut self, filepath: String) -> Self {
        self.config.cert = Certificate::from_pem(filepath);
        if self.config.cert.is_none() {
            panic!("Error reading or parsing certificate");
        }
        self
    }
    pub fn add_privkey_pem(mut self, filepath: String) -> Self {
        self.config.privkey = PrivateKey::from_pem(filepath);
        if self.config.privkey.is_none() {
            panic!("Error reading or parsing private key");
        }
        self
    }
    pub fn build (self) -> TlsConfig {
        self.config
    }
}

pub struct TlsContext<'a> {
    pub config: &'a TlsConfig,
    pub rng: Box<dyn RngCore<IBig>>
}
