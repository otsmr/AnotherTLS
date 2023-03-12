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


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    SHA1 = 20,
    SHA256 = 32,
    SHA384 = 48
}

pub trait TranscriptHash {
    fn new() -> Self where Self: Sized;
    fn update(&mut self, buf: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn get_type(&self) -> HashType;
    fn clone(&self) -> Box<dyn TranscriptHash>;
}


pub fn sha_x(typ: HashType, data: &[u8]) -> Vec<u8> {
    match typ {
        HashType::SHA1 => sha1(data).to_vec(),
        HashType::SHA256 => sha256(data).to_vec(),
        HashType::SHA384 => sha384(data).to_vec()
    }
}
