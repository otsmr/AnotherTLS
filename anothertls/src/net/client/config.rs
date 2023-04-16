/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

// TODO: Validate server certificate against os trusted CA
// $ security verify-cert

use crate::{crypto::ellipticcurve::PrivateKey, log, net::handshake::Certificate};

pub struct ClientConfig {
    pub(crate) server_name: Option<String>,
    pub(crate) client_cert: Option<Certificate>,
    pub(crate) client_key: Option<PrivateKey>,
    // #[allow(unused)]
    pub(crate) keylog: Option<String>,
}

pub struct ClientConfigBuilder {
    keylog: Option<String>,
    server_name: Option<String>,
    client_cert: Option<Certificate>,
    client_key: Option<PrivateKey>,
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientConfigBuilder {
    pub fn new() -> Self {
        ClientConfigBuilder {
            keylog: None,
            server_name: None,
            client_key: None,
            client_cert: None,
        }
    }
    pub fn add_client_cert_pem(mut self, filepath: String) -> Self {
        self.client_cert = Certificate::from_pem_x509(filepath);
        if self.client_cert.is_none() {
            panic!("Error reading or parsing client certificate ca");
        }
        self
    }
    pub fn add_client_key_pem(mut self, filepath: String) -> Self {
        self.client_key = PrivateKey::from_pem(filepath);
        log::fixme!("TODO: Validate priv key against the cert");
        if self.client_key.is_none() {
            panic!("Error reading or parsing private key");
        }
        self
    }
    pub fn set_server_name(mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
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
    pub fn build(self) -> std::result::Result<ClientConfig, String> {
        if self.client_cert.is_some() && self.client_key.is_none() {
            panic!("No private key was set for the client certificate.")
        }
        Ok(ClientConfig {
            keylog: self.keylog,
            server_name: self.server_name,
            client_cert: self.client_cert,
            client_key: self.client_key,
        })
    }
}
