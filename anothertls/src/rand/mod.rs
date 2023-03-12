/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod simplerng;
pub mod urandom;

pub use simplerng::SimpleRng;
pub use urandom::URandomRng;

pub trait RngCore<T> {
    fn next(&mut self) -> T;
    fn between(&mut self, min: usize, max: usize) -> T;
    // fn between_ibig(&mut self, min: usize, max: usize) -> Vec<u8>;
    fn between_bytes(&mut self, size: usize) -> Vec<u8>;
}

pub trait SeedableRng<T> {
    fn from_seed(seed: T) -> Self;
}
