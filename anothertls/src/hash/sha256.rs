/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_snake_case)]

use crate::hash::TranscriptHash;

fn rotr(n: u32, w: u32) -> u32 {
    (w >> n) | (w << ((32 - n) & 31))
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)
}
fn bsig1(x: u32) -> u32 {
    rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)
}
fn ssig0(x: u32) -> u32 {
    rotr(7, x) ^ rotr(18, x) ^ (x >> 3)
}
fn ssig1(x: u32) -> u32 {
    rotr(17, x) ^ rotr(19, x) ^ (x >> 10)
}

fn add(x: u32, y: u32) -> u32 {
    let (z, _) = x.overflowing_add(y);
    z
}

pub struct Sha256 {
    input: [u8; 64],
    input_len: usize,
    state: [u32; 8],
    length: u128,
}

impl Sha256 {
    fn padd_input(&mut self) {
        let input_len = self.length;
        let mut padding_length = 64 - (input_len % 64) as usize;
        let mut padding: [u8; 64] = [0; 64];

        if padding_length > 0 {
            padding[0] = 0x80;
            if padding_length < 9 {
                // Padding: "1" + 0's
                self.update(&padding[..padding_length]);
                padding_length = 64;
                padding[0] = 0;
            }
            for i in 1..8 {
                padding[padding_length - i] = ((input_len * 8) >> ((i - 1) * 8)) as u8;
            }

            self.update(&padding[..padding_length])
        }
    }
    fn calc_round(&mut self) {
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut w: [u32; 80] = [0; 80];
        let mut pos = 0;

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in 0..=63 {
            if t <= 15 {
                let mut wcount = 24;
                while wcount >= 0 {
                    w[t] += (self.input[pos] as u32) << wcount;
                    pos += 1;
                    wcount -= 8;
                }
            } else {
                w[t] = add(
                    ssig1(w[t - 2]),
                    add(w[t - 7], add(ssig0(w[t - 15]), w[t - 16])),
                );
            }

            let t1 = add(h, add(bsig1(e), add(ch(e, f, g), add(k[t], w[t]))));
            let t2 = add(bsig0(a), maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = add(d, t1);
            d = c;
            c = b;
            b = a;
            a = add(t1, t2);
        }

        self.state[0] = add(self.state[0], a);
        self.state[1] = add(self.state[1], b);
        self.state[2] = add(self.state[2], c);
        self.state[3] = add(self.state[3], d);
        self.state[4] = add(self.state[4], e);
        self.state[5] = add(self.state[5], f);
        self.state[6] = add(self.state[6], g);
        self.state[7] = add(self.state[7], h);
        self.input_len = 0;
    }
}
impl TranscriptHash for Sha256 {
    fn new() -> Self {
        Self {
            input: [0; 64],
            input_len: 0,
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length: 0,
        }
    }
    fn update(&mut self, buf: &[u8]) {
        self.length += buf.len() as u128;

        for b in buf.iter() {
            self.input[self.input_len] = *b;
            self.input_len += 1;

            if self.input_len == 64 {
                self.calc_round();
            }
        }
    }

    fn finalize(&self) -> Vec<u8> {
        let mut copy = Self {
            input: self.input,
            input_len: self.input_len,
            state: self.state,
            length: self.length,
        };

        copy.padd_input();
        let mut out: [u8; 32] = [0; 32];

        for i in 0u8..32u8 {
            out[i as usize] =
                (copy.state[(i >> 2) as usize] >> (8 * (3 - (i & 0x03))) as u32) as u8;
        }

        out.to_vec()
    }

    fn clone(&self) -> Box<dyn TranscriptHash> {
        Box::new(Self {
            input: self.input,
            input_len: self.input_len,
            state: self.state,
            length: self.length,
        })
    }

    fn get_type(&self) -> super::HashType {
        super::HashType::SHA256
    }
}
pub fn sha256(message: &[u8]) -> Vec<u8> {
    let mut sha = Sha256::new();
    sha.update(message);
    sha.finalize()
}

#[cfg(test)]
mod tests {
    use crate::hash::sha256;
    use core::fmt::Write;

    fn test_sha256_do(message: String, hash_expect: String) {
        let message = message.as_bytes().to_vec();
        let hash = sha256(&message).iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        assert_eq!(hash, hash_expect);
    }

    #[test]
    fn test_sha256() {
        test_sha256_do(
            "".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        test_sha256_do(
            "The quick brown fox jumps over the lazy dog".to_string(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_string(),
        );
        test_sha256_do(
            "The quick brown fox jumps over the lazy cog".to_string(),
            "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be".to_string(),
        );
    }
}
