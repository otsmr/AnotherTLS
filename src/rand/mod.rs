pub mod simplerng;
pub mod urandom;

pub use simplerng::SimpleRng;
pub use urandom::URandomRng;

pub trait RngCore<T> {
    fn next(&mut self) -> T;
    fn between(&mut self, min: T, max: T) -> T;
}

pub trait SeedableRng<T> {
    fn from_seed(seed: T) -> Self;
}
