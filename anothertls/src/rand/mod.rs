/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod simplerng;
pub mod urandom;
pub mod triple_ec;

pub use simplerng::SimpleRng;
pub use urandom::URandomRng;
pub use triple_ec::TripleEc;

pub trait RngCore<T> {
    fn next(&mut self) -> T;
    fn between(&mut self, min: usize, max: usize) -> T;
    fn between_bytes(&mut self, size: usize) -> Vec<u8>;
}

pub trait SeedableRng<T> {
    fn from_seed(seed: T) -> Self;
}
