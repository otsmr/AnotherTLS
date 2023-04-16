/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod shared;

pub(crate) use client::{ClientExtension, ClientExtensions};
pub(crate) use server::{ServerExtensions, ServerExtension};
pub(crate) use shared::{Extension, Extensions, ExtensionWrapper};

// Extensions
pub(crate) mod named_groups;
pub(crate) mod signature_algorithm;
pub(crate) mod key_share;
pub(crate) mod server_name;
pub(crate) mod supported_versions;
pub(crate) mod supported_groups;


pub(crate) use server_name::ServerName;
pub(crate) use shared::ExtensionType;
pub(crate) use supported_versions::SupportedVersions;
pub(crate) use supported_groups::SupportedGroups;
pub(crate) use signature_algorithm::{SignatureAlgorithms, SignatureScheme};
pub(crate) use key_share::{KeyShare, KeyShareEntry};

pub(crate) use named_groups::NamedGroup;
