/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

//! # AnotherTLS
//!
//! Yet another TLS implementation, but written from scratch (including the crypto) in pure Rust -
//! of course. The focus of this implementation is the simplicity and to use no dependencies. I
//! started this project to deep dive into Rust, cryptography and network protocols.
//!
//! Currently AnotherTLS depends only on the following crates:
//! ```ignore
//! anothertls v0.1.0
//! └── ibig v0.3.6
//!     ├── cfg-if v1.0.0
//!     └── static_assertions v1.1.0
//! ```
//!
//! ## Features
//! * TLSv1.3
//! * ECDSA client authentication by server.
//! * Forward secrecy using ECDHE; with curve25519
//! * AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
//! * Client authentication by servers.
//!
//! ## Getting started
//!
//! See [`examples`](https://github.com/otsmr/anothertls/tree/main/examples).

// TODO: Write documentation


pub(crate) mod crypto;
pub(crate) mod net;
pub(crate) mod utils;
pub(crate) mod rand;
pub(crate) mod hash;

pub use net::server::ServerConfig;
pub use net::server::ServerConfigBuilder;
pub use net::server::ServerConnection;
pub use net::TlsStream;
