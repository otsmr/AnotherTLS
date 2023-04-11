/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod stream;

pub mod server {
    mod config;
    mod connection;
    mod server_hello;
    pub(crate) use server_hello::ServerHello;
    pub use config::{ServerConfig, ServerConfigBuilder};
    pub use connection::ServerConnection;
}

pub mod client {
    mod connection;
    mod config;
    mod client_hello;
    pub(crate) use client_hello::ClientHello;
    pub use config::{ClientConfig, ClientConfigBuilder};
    pub use connection::ClientConnection;
}

pub use stream::TlsStream;

pub(crate) mod alert;
pub(crate) mod handshake;
pub(crate) mod extensions;
pub(crate) mod record;
pub(crate) mod key_schedule;

