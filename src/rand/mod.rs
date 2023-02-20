use std::io::{BufReader, Read};
use std::fs::File;

use ibig::{IBig, ibig};

use crate::bytes;

pub trait RngCore<T> {
    fn next(&mut self) -> T;
    fn between(&mut self, min: T, max: T) -> T;
}

pub trait SeedableRng<T> {
    fn from_seed(seed: T) -> Self;
}


pub struct CryptoRng();

impl CryptoRng {

    pub fn new () -> Self {Self{}}

    fn read_from_urandom(&self) -> [u8; 100] {

        let mut buffer: [u8; 100] = [0; 100];
        let file = File::open("/dev/urandom").expect("/dev/urandom not found");
        let mut reader = BufReader::with_capacity(100, file);
        reader.read_exact(&mut buffer).expect("Reading from /dev/urandom");
        buffer

    }

}

impl RngCore<IBig> for CryptoRng {

    fn next(&mut self) -> IBig {
        let rand_bytes = self.read_from_urandom();
        let size = bytes::to_u64_le(&rand_bytes[..8]) as usize;

        bytes::to_ibig_le(&rand_bytes[8..size])
    }

    fn between(&mut self, min: IBig, max: IBig) -> IBig {
        self.next() % (max - min.clone()) + min
    }

}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleRng<T>(T);


impl<T> SeedableRng<T> for SimpleRng<T> {

    fn from_seed(seed: T) -> Self {
        Self(seed)
    }

}

impl RngCore<u32> for SimpleRng<u32>
{
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(1);
        let a = self.0.wrapping_mul(15485863);
        (a.wrapping_pow(3)) % u32::MAX
    }
    fn between(&mut self, min: u32, max: u32) -> u32 {
        self.next() % (max - min) + min
    }

}

impl RngCore<IBig> for SimpleRng<IBig>
{
    fn next(&mut self) -> IBig {
        let mut a = SimpleRng::<u32>::from_seed(self.0.to_f32() as u32);
        self.0 = self.0.clone() + ibig!(10);
        let mut b = ibig!(1);
        for _ in 0..10 {
            b *= IBig::from(a.next());
        }
        b

    }
    fn between(&mut self, min: IBig, max: IBig) -> IBig {
        self.next() % (max-min.clone()) + min
    }

}

#[cfg(test)]
mod tests {

    use crate::rand::SeedableRng;
    use super::{SimpleRng, RngCore};

    #[test]
    fn test_rand() {

        let mut rng = SimpleRng::<u32>::from_seed(10);
        assert_eq!(rng.next(), 3782026229);
        assert_eq!(rng.next(), 1899426624);

    }
}
