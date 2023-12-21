/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod hkdf;
pub mod hmac;
pub mod sha256;
pub mod sha384;

pub use hkdf::Hkdf;
pub use hmac::Hmac;
pub use sha256::sha256;
pub use sha256::Sha256;
pub use sha384::sha384;
pub use sha384::Sha384;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    SHA256 = 32,
    SHA384 = 48,
}

pub trait TranscriptHash {
    fn new() -> Self
    where
        Self: Sized;
    fn update(&mut self, buf: &[u8]);
    // finalize is not mutable and creates an copy of it self
    // the benefit is, that other functions doesn't have to clone
    // it before finalizing it
    fn finalize(&self) -> Vec<u8>;
    fn get_type(&self) -> HashType;
    fn clone(&self) -> Box<dyn TranscriptHash>;
}

pub fn sha_x(typ: HashType, data: &[u8]) -> Vec<u8> {
    match typ {
        HashType::SHA256 => sha256(data).to_vec(),
        HashType::SHA384 => sha384(data).to_vec(),
    }
}
