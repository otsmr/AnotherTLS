/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::handshake::Certificate;
use crate::crypto::ellipticcurve::PrivateKey;

pub struct TlsConfig {

    // Required
    // (1) openssl ecparam -out server.key -name prime256v1 -genkey
    pub(crate) privkey: PrivateKey,
    // (2) openssl req -new -key server.key -x509 -nodes -days 365 -out server.cert
    pub(crate) cert: Certificate,

    // Optional
    // pub server_name: Option<String>,
    // -- Client Certificate --
    // https://stackoverflow.com/questions/21297139/how-do-you-sign-a-certificate-signing-request-with-your-certification-authority
    // (1) Create CA
    //      (a) openssl ecparam -out ca.key -name prime256v1 -genkey
    //      (b) openssl req -new -key ca.key -x509 -nodes -days 365 -out ca.cert
    // (2) Create Client
    //      (a) openssl ecparam -out client.key -name prime256v1 -genkey
    //      (b) openssl req -new -key client.key -out client.cert
    // (3) Sign client cert
    //      (a) openssl x509 -req -in client.cert -days 365 -CA ca.cert -CAkey ca.key -CAcreateserial -out client.signed.cert
    pub(crate) client_cert_ca: Option<Certificate>,
    pub(crate) keylog: Option<String>,
    pub(crate) server_name: Option<String>,
}

pub struct TlsConfigBuilder {
    cert: Option<Certificate>,
    privkey: Option<PrivateKey>,
    keylog: Option<String>,
    server_name: Option<String>,
    client_cert_ca: Option<Certificate>
}
impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        TlsConfigBuilder {
            cert: None,
            privkey: None,
            keylog: None,
            server_name: None,
            client_cert_ca: None
        }
    }
    pub fn add_cert_pem(mut self, filepath: String) -> Self {
        self.cert = Certificate::from_pem(filepath);
        if self.cert.is_none() {
            panic!("Error reading or parsing certificate");
        }
        self
    }
    pub fn add_client_cert_ca(mut self, filepath: String) -> Self {
        self.client_cert_ca = Certificate::from_pem_x509(filepath);
        if self.client_cert_ca.is_none() {
            panic!("Error reading or parsing client certificate ca");
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
    pub fn set_server_name(mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
        self
    }
    pub fn build(self) -> std::result::Result<TlsConfig, String> {
        if self.cert.is_none() {
            return Err("No cert provided".to_string());
        }
        if self.privkey.is_none() {
            return Err("No privkey for cert provided".to_string());
        }
        Ok(TlsConfig {
            client_cert_ca: self.client_cert_ca,
            cert: self.cert.unwrap(),
            privkey: self.privkey.unwrap(),
            keylog: self.keylog,
            server_name: self.server_name
        })
    }
}

