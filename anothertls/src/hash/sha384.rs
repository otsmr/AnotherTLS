/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_snake_case)]

use crate::hash::TranscriptHash;

fn rotr(n: u64, w: u64) -> u64 {
    (w >> n) | (w << ((64 - n) & 63))
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u64) -> u64 {
    rotr(28, x) ^ rotr(34, x) ^ rotr(39, x)
}
fn bsig1(x: u64) -> u64 {
    rotr(14, x) ^ rotr(18, x) ^ rotr(41, x)
}
fn ssig0(x: u64) -> u64 {
    rotr(1, x) ^ rotr(8, x) ^ (x >> 7)
}
fn ssig1(x: u64) -> u64 {
    rotr(19, x) ^ rotr(61, x) ^ (x >> 6)
}

fn add(x: u64, y: u64) -> u64 {
    let (z, _) = x.overflowing_add(y);
    z
}

pub struct Sha384 {
    input: [u8; 128],
    input_len: usize,
    state: [u64; 8],
    length: u128,
}

impl Sha384 {
    fn padd_input(&mut self) {
        let input_len = self.length;
        let mut padding_length = 128 - (input_len % 128) as usize;
        let mut padding: [u8; 128] = [0; 128];

        if padding_length > 0 {
            padding[0] = 0x80;
            if padding_length < 17 {
                // Padding: "1" + 0's
                self.update(&padding[..padding_length]);
                padding_length = 128;
                padding[0] = 0;
            }
            for i in 1..16 {
                padding[padding_length - i] = ((input_len * 8) >> ((i - 1) * 8)) as u8;
            }
            self.update(&padding[..padding_length])
        }
    }
    fn calc_round(&mut self) {
        let k: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        ];

        let mut w: [u64; 80] = [0; 80];
        let mut pos = 0;

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in 0..=79 {
            if t <= 15 {
                let mut wcount = 56;
                while wcount >= 0 {
                    w[t] += (self.input[pos] as u64) << wcount;
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

impl TranscriptHash for Sha384 {
    fn new() -> Self {
        Self {
            input: [0; 128],
            input_len: 0,
            state: [
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            ],
            length: 0,
        }
    }
    fn update(&mut self, buf: &[u8]) {
        self.length += buf.len() as u128;

        for b in buf.iter() {
            self.input[self.input_len] = *b;
            self.input_len += 1;

            if self.input_len == 128 {
                self.calc_round();
            }
        }
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.padd_input();
        let mut out: [u8; 48] = [0; 48];
        for i in 0u8..48u8 {
            out[i as usize] = (self.state[(i >> 3) as usize] >> (8 * (7 - (i & 7))) as u64) as u8;
        }
        out.to_vec()
    }

    fn clone(&self) -> Box<dyn TranscriptHash> {
        Box::new(Self {
            input: self.input,
            input_len: self.input_len,
            state: self.state,
            length: self.length
        })
    }

    fn get_type(&self) -> super::HashType {
        super::HashType::SHA384
    }

}

pub fn sha384(message: &[u8]) -> Vec<u8> {
    let mut sha = Sha384::new();
    sha.update(message);
    sha.finalize()
}

#[cfg(test)]
mod tests {
    use crate::hash::sha384;

    fn test_sha384_do(message: String, hash_expect: String) {
        println!("{message}");
        let message = message.as_bytes().to_vec();
        let hash = sha384(&message)
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        assert_eq!(hash, hash_expect);
    }

    // struct TestCase<'a> {
    //     input: &'a str,
    //     expect: &'a str,
    // }

    #[test]
    fn test_sha384() {
        test_sha384_do("".to_string(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".to_string());
        test_sha384_do("The quick brown fox jumps over the lazy dog".to_string(), "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1".to_string());
        test_sha384_do("The quick brown fox jumps over the lazy cog".to_string(), "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b".to_string());

        // import hashlib
        // out = ("let test_cases = vec![")
        // for i in range(400, 1000, 3):
        //     string = b"\x00"*i
        //     hash = hashlib.sha384()
        //     hash.update(b"\x00"*i)
        //     out += ("TestCase {")
        //     out += (f" input: \"{string.hex()}\",")
        //     out += (f" expect: \"{hash.digest().hex()}\"")
        //     out += ("},")
        // out += ("];")
        // with open("test.txt", "w") as f:
        //     f.write(out)
        // for test_case in test_cases {
        //     let message = crate::utils::bytes::from_hex(test_case.input).unwrap();
        //     let hash = sha384(&message)
        //         .iter()
        //         .map(|x| format!("{:02x}", x))
        //         .collect::<String>();
        //     assert_eq!(hash, test_case.expect);
        // }
    }
}
