/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod hkdf;
pub mod hmac;


pub use sha1::sha1;
pub use sha256::sha256;
pub use sha384::sha384;


#[derive(Debug, Clone, Copy)]
pub enum HashType {
    SHA1 = 20,
    SHA256 = 32,
    SHA384 = 48
}
