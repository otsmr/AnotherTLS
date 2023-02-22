/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use ibig::{IBig, ibig};

pub fn to_ibig_le(bytes: &[u8]) -> IBig {
    let mut res = ibig!(0);

    for (i, byte) in bytes.iter().enumerate() {
        res += IBig::from(*byte) << (((bytes.len() - 1) * 8) - i * 8);
    }

    res
}
pub fn to_u64_le(bytes: &[u8]) -> u64 {
    let mut res: u64 = 0;
    for (i, byte) in bytes[..8].iter().enumerate() {
        res += (*byte as u64) << ((7 * 8) - i * 8);
    }
    res
}

#[allow(dead_code)]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}
