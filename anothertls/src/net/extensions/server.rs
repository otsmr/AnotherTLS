/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::shared::{Extension, KeyShare, SignatureAlgorithms, SupportedVersions};

pub(crate) enum ServerExtension {
    SupportedVersion(SupportedVersions),
    KeyShare(KeyShare),
    SignatureAlgorithms(SignatureAlgorithms),
}

pub(crate) struct ServerExtensions(Vec<ServerExtension>);

impl ServerExtensions {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn push(&mut self, ext: ServerExtension) {
        self.0.push(ext)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x00];
        if self.0.is_empty() {
            return out; // Length of the extension list (0 bytes)
        }
        for ext in self.0.iter() {
            match ext {
                ServerExtension::SupportedVersion(sv) => out.extend(sv.as_bytes()),
                ServerExtension::KeyShare(ks) => out.extend(ks.as_bytes()),
                ServerExtension::SignatureAlgorithms(sa) => out.extend(sa.as_bytes()),
            }
        }
        let extension_len = out.len() - 2;
        out[0] = (extension_len >> 8) as u8;
        out[1] = extension_len as u8;
        out
    }
}
