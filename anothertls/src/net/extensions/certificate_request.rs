/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::alert::TlsError;
use crate::net::extensions::{
    Extension, ExtensionType, ExtensionWrapper, Extensions, SignatureAlgorithms,
};
use crate::utils::bytes;

pub enum CertificateRequestExtension {
    SignatureAlgorithms(SignatureAlgorithms),
}

impl ExtensionWrapper for CertificateRequestExtension {
    fn get_extension(&self) -> Box<&dyn Extension> {
        match self {
            CertificateRequestExtension::SignatureAlgorithms(sa) => Box::new(sa),
        }
    }
}
pub type CertificateRequestExtensions = Extensions<CertificateRequestExtension>;

impl CertificateRequestExtensions {
    pub fn from_request(buf: &[u8]) -> Result<CertificateRequestExtensions, TlsError> {
        let mut consumed = 0;
        let mut extensions = Self::new();
        extensions.set_is_client();

        while consumed < buf.len() {
            let extension_type = bytes::to_u16(&buf[consumed..consumed + 2]);
            let extension_type = ExtensionType::new(extension_type);
            let size = bytes::to_u16(&buf[consumed + 2..consumed + 4]) as usize;
            consumed += 4;
            if extension_type.is_none() {
                consumed += size;
                continue;
            }
            let extension_type = extension_type.unwrap();

            let extension = match extension_type {
                ExtensionType::SignatureAlgorithms => {
                    CertificateRequestExtension::SignatureAlgorithms(
                        SignatureAlgorithms::client_parse(&buf[consumed..])?,
                    )
                }
                _ => continue,
            };
            consumed += size;
            extensions.push(extension);
        }
        Ok(extensions)
    }
}
