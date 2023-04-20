/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub mod simplerng;
pub mod urandom;

pub use simplerng::SimpleRng;
pub use urandom::URandomRng;

#[derive(PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum PRNG {
    Simple,
    URandom,
}

pub trait RngCore<T> {
    fn between(&mut self, min: usize, max: usize) -> T;
    fn bytes(&mut self, size: usize) -> Vec<u8>;
}

pub trait SeedableRng<T> {
    fn from_seed(seed: T) -> Self;
}
