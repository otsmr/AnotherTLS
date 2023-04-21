/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod stream;

pub mod server {
    pub mod config;
    pub mod connection;
    pub mod server_hello;
    pub use server_hello::ServerHello;
    pub use config::{ServerConfig, ServerConfigBuilder};
    pub use connection::ServerConnection;
}

pub mod client {
    pub mod connection;
    pub mod config;
    pub mod client_hello;
    pub use client_hello::ClientHello;
    pub use config::{ClientConfig, ClientConfigBuilder};
    pub use connection::ClientConnection;
}

pub use stream::TlsStream;

pub mod alert;
pub mod handshake;
pub mod extensions;
pub mod record;
pub mod key_schedule;

pub use key_schedule::KeySchedule;
