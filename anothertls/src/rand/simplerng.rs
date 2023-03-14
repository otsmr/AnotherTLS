/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::rand::RngCore;
use crate::rand::SeedableRng;
use crate::utils::bytes;
use ibig::{ibig, IBig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleRng<T>(T);

impl<T> SeedableRng<T> for SimpleRng<T> {
    fn from_seed(seed: T) -> Self {
        Self(seed)
    }
}

impl RngCore<u32> for SimpleRng<u32> {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(1);
        let a = self.0.wrapping_mul(15485863);
        (a.wrapping_pow(3)) % u32::MAX
    }
    fn between(&mut self, min: usize, max: usize) -> u32 {
        let min = min as u32;
        let max = max as u32;
        self.next() % (max - min) + min
    }
    fn between_bytes(&mut self, size: usize) -> Vec<u8> {
        let mut res = vec![];
        while res.len() >= size {
            res.push(self.next() as u8)
        }
        res
    }
}

impl RngCore<IBig> for SimpleRng<IBig> {
    fn next(&mut self) -> IBig {
        let mut a = SimpleRng::<u32>::from_seed(bytes::to_u128_le(&bytes::ibig_to_32bytes(
            self.0.clone(),
            bytes::ByteOrder::Little,
        )) as u32);
        self.0 = self.0.clone() + ibig!(10);
        let mut b = ibig!(1);
        for _ in 0..10 {
            b *= IBig::from(a.next());
        }
        b
    }
    fn between(&mut self, min: usize, max: usize) -> IBig {
        let min = ibig!(2).pow(min * 8);
        let max = ibig!(2).pow(max * 8);
        println!("min={min}");
        println!("max={max}");
        self.next() % (max - min.clone()) + min
    }
    fn between_bytes(&mut self, size: usize) -> Vec<u8> {
        let mut res = vec![];
        while res.len() >= size {
            res.extend_from_slice(&bytes::ibig_to_32bytes(
                self.next(),
                bytes::ByteOrder::Little,
            ));
        }
        res
    }
}

#[cfg(test)]
mod tests {

    use super::{RngCore, SeedableRng, SimpleRng};

    #[test]
    fn test_rand() {
        let mut rng = SimpleRng::<u32>::from_seed(10);
        assert_eq!(rng.next(), 3782026229);
        assert_eq!(rng.next(), 1899426624);
    }
}
