/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_snake_case)]
use std::fs::File;
use std::io::{BufReader, Read};

use ibig::{ibig, IBig};

use crate::crypto::ellipticcurve::{math, Curve, Point};
use crate::rand::RngCore;
use crate::utils::bytes;

/// Changed point Q, to stop the NSA using there backdoor
pub struct DualECRng {
    s: IBig,
    curve: Curve,
    Q: Point,
}

impl DualECRng {
    pub fn new() -> Self {
        // Generate initial seed
        let random = Self::read_from_urandom();
        let secret = bytes::to_ibig_le(&random[0..32]);
        let curve = Curve::secp256r1();
        let s = math::multiply(&curve.g, secret, &curve).x;
        let Q = Point::new(
          ibig!(_fbfbce7a8c184ca69d3431ab45ab81f67c787ccb695f53a6dfd52c9a31a615ff base 16),
          ibig!(_7e35599b872f0a69d1d54631b2d4077bf7543baa4a4bd4a2f28edc768eb891a5 base 16),
        );
        Self { s, curve, Q }
    }
    fn read_from_urandom() -> [u8; 100] {
        let mut buffer: [u8; 100] = [0; 100];
        let file = File::open("/dev/urandom").expect("/dev/urandom not found");
        let mut reader = BufReader::with_capacity(100, file);
        reader
            .read_exact(&mut buffer)
            .expect("Reading from /dev/urandom");
        buffer
    }
    fn next(&mut self) -> IBig {
        self.s = math::multiply(&self.Q, self.s.clone(), &self.curve).x;
        math::multiply(&self.curve.g, self.s.clone(), &self.curve).x
    }
}

impl Default for DualECRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore<IBig> for DualECRng {
    fn between(&mut self, _min: usize, _max: usize) -> IBig {
        self.next()
    }
    fn bytes(&mut self, _size: usize) -> Vec<u8> {
        bytes::ibig_to_vec(self.next(), bytes::ByteOrder::Big)
    }
}
