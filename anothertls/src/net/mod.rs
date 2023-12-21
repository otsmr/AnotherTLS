/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod stream;

pub mod server {
    pub mod config;
    pub mod connection;
    pub mod server_hello;
    pub use config::{ServerConfig, ServerConfigBuilder};
    pub use connection::ServerConnection;
    pub use server_hello::ServerHello;
}

pub mod client {
    pub mod client_hello;
    pub mod config;
    pub mod connection;
    pub use client_hello::ClientHello;
    pub use config::{ClientConfig, ClientConfigBuilder};
    pub use connection::ClientConnection;
}

pub use stream::TlsStream;

pub mod alert;
pub mod extensions;
pub mod handshake;
pub mod key_schedule;
pub mod record;

pub use key_schedule::KeySchedule;
