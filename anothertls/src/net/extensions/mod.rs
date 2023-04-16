/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub(crate) mod certificate_request;
pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod shared;

pub(crate) use certificate_request::CertificateRequestExtensions;
pub(crate) use client::{ClientExtension, ClientExtensions};
pub(crate) use server::{ServerExtension, ServerExtensions};
pub(crate) use shared::{Extension, ExtensionWrapper, Extensions};

// Extensions
pub(crate) mod key_share;
pub(crate) mod named_groups;
pub(crate) mod server_name;
pub(crate) mod signature_algorithm;
pub(crate) mod supported_groups;
pub(crate) mod supported_versions;

pub(crate) use key_share::{KeyShare, KeyShareEntry};
pub(crate) use server_name::ServerName;
pub(crate) use shared::ExtensionType;
pub(crate) use signature_algorithm::{SignatureAlgorithms, SignatureScheme};
pub(crate) use supported_groups::SupportedGroups;
pub(crate) use supported_versions::SupportedVersions;

pub(crate) use named_groups::NamedGroup;
