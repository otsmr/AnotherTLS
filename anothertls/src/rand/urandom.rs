/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use std::fs::File;
use std::io::{BufReader, Read};

use ibig::{IBig, ibig};

use crate::rand::RngCore;
use crate::utils::bytes;

pub struct URandomRng();

impl URandomRng {
    pub fn new() -> Self {
        Self {}
    }

    fn read_from_urandom(&self) -> [u8; 100] {
        let mut buffer: [u8; 100] = [0; 100];
        let file = File::open("/dev/urandom").expect("/dev/urandom not found");
        let mut reader = BufReader::with_capacity(100, file);
        reader
            .read_exact(&mut buffer)
            .expect("Reading from /dev/urandom");
        buffer
    }
}

impl Default for URandomRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore<IBig> for URandomRng {
    fn next(&mut self) -> IBig {
        let rand_bytes = self.read_from_urandom();
        let size = bytes::to_u64_le(&rand_bytes[..8]) as usize;
        let size = size % 50 + 50;
        bytes::to_ibig_le(&rand_bytes[8..size])
    }

    fn between(&mut self, min: usize, max: usize) -> IBig {
        // IDEA: remove *8 to get leading zeros
        let min = ibig!(2).pow(min*8);
        let max = ibig!(2).pow(max*8);

        self.next() % (max - min.clone()) + min
    }
    fn between_bytes(&mut self, size: usize) -> Vec<u8> {
        let rand_bytes = self.read_from_urandom();
        rand_bytes[..size].to_owned()
    }
}