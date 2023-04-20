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

/// Based on Dual_EC, but improved to use three multiplications, to prevent NSA using this as an
/// backdoor.
pub struct TripleEc {
    s: IBig,
    curve: Curve,
    D: Point,
    Q: Point
}

impl TripleEc {
    pub fn new() -> Self {
        // Generate initial seed
        let random = Self::read_from_urandom();
        let secret = bytes::to_ibig_le(&random[0..32]);
        let curve = Curve::secp256r1();
        let s = math::multiply(&curve.g, secret, &curve).x;
        let D = Point::new(ibig!(0), ibig!(0));
        let Q = Point::new(ibig!(0), ibig!(0));
        Self { s, curve, D, Q }
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
}

impl Default for TripleEc {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore<IBig> for TripleEc {
    fn next(&mut self) -> IBig {
        let r = math::multiply(&self.Q, self.s.clone(), &self.curve).x;
        self.s = math::multiply(&self.D, r.clone(), &self.curve).x;
        math::multiply(&self.Q, r, &self.curve).x
    }
    fn between(&mut self, min: usize, max: usize) -> IBig {
        todo!()
    }
    fn between_bytes(&mut self, size: usize) -> Vec<u8> {
        todo!()
    }
}
