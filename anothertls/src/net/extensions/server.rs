/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::extensions::shared::Extensions;
// use crate::utils::x509::Extensions;
use super::shared::{Extension, KeyShare, SignatureAlgorithms, SupportedVersions, ExtensionWrapper};

pub(crate) enum ServerExtension {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare),
    SignatureAlgorithms(SignatureAlgorithms),
}

impl ExtensionWrapper for ServerExtension {
    fn get_extension(&self) -> Box<&dyn Extension> {
        match self {
            ServerExtension::SupportedVersion(sv) => Box::new(sv),
            ServerExtension::KeyShare(ks) => Box::new(ks),
            ServerExtension::SignatureAlgorithms(sa) => Box::new(sa)
        }
    }
}

pub(crate) type ServerExtensions = Extensions<ServerExtension>;
