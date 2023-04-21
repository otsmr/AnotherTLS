/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

//! # AnotherTLS
//!
//! Yet another TLS implementation, but written **from scratch** (including the
//! crypto) in **pure Rust** - of course. The focus of this implementation is the
//! simplicity and to use no dependencies. I started this project to deep dive into
//! Rust, cryptography and network protocols. So don't use it in production, just
//! **use [rustls](https://crates.io/crates/rustls)** as it is the better choice
//! and will be forever.
//!
//! **If you are interested in hacking TLS, you should checkout my
//! [VulnTLS](https://github.com/otsmr/VulnTLS) project.**
//!
//! ## What makes AnotherTLS unique?
//! It depends only on the standard library and the ibig crate. So you will find
//! **the entire TLSv1.3 stack in a single repo** to play around with, as I do with
//! my VulnTLS implementation. Also, everything is public, so you can use
//! AnotherTLS to easily simulate parts of TLS for example to write an exploit :^).
//!
//!
//! With the current version it is possible to connect via curl or the browser with
//! the AnotherTLS server. AnotherTLS can also be used as a client. Since the
//! parsing of certificates is still WIP, it is not yet possible to connect
//! (securely) to known websites.
//!
//!
//! **handshake and application data**
//! ```bash
//! $ cargo run --bin server_https
//! # other window
//! $ curl -iv --insecure https://localhost:4000/
//! ```
//!
//! **client certificate**
//! ```bash
//! $ cargo run --bin server_client_auth
//! # other window
//! $ cd ./examples/src/bin/config/client_cert/
//! $ curl --cert client.signed.cert --key client.key -iv --insecure https://localhost:4000/
//! ```
//!
//! For more information about using AnotherTLS, see the `./examples` folder.


pub mod crypto;
pub mod net;
pub mod utils;
pub mod rand;
pub mod hash;

// pub use net::server::ServerConfig;
pub use net::server::ServerConfigBuilder;
pub use net::server::ServerConnection;

pub use net::client::ClientConfig;
pub use net::client::ClientConfigBuilder;
pub use net::client::ClientConnection;

pub use utils::log;
