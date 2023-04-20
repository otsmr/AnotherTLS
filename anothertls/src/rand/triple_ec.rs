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
    Q: Point,
}

impl TripleEc {
    pub fn new() -> Self {
        // Generate initial seed
        let random = Self::read_from_urandom();
        let secret = bytes::to_ibig_le(&random[0..32]);
        let curve = Curve::secp256r1();
        let s = math::multiply(&curve.g, secret, &curve).x;
        let D = Point::new(
            ibig!(_89cfbf8401e39ec991ad1e313c28c95c87c0e2013af5cd0107cfc925c14b96ad base 16),
            ibig!(_f1e7e06a2a7f3ba02c7bf8f7da2823088e39a94f6ccfce11a820ecda0ca7532a base 16),
        );
        let Q = Point::new(
            ibig!(_2eb8c6abf83456f93e08eb1417e01e3e587ca6d7a8ac20ccd4ea35e592ffa48f base 16),
            ibig!(_5db2de5d37257b34249eeb386bcc5ca199bb8e4fa355aae9f3c4e162ed7492c8 base 16),
        );
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
    fn next(&mut self) -> IBig {
        let r = math::multiply(&self.Q, self.s.clone(), &self.curve).x;
        self.s = math::multiply(&self.Q, r.clone(), &self.curve).x;
        math::multiply(&self.D, r, &self.curve).x
    }
}

impl Default for TripleEc {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore<IBig> for TripleEc {
    fn between(&mut self, _min: usize, _max: usize) -> IBig {
        self.next()
    }
    fn bytes(&mut self, _size: usize) -> Vec<u8> {
        bytes::ibig_to_vec(self.next(), bytes::ByteOrder::Big)
    }
}
