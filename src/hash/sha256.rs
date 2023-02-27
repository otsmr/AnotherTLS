/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_snake_case)]


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

pub fn sha256(message: Vec<u8>) -> [u8; 32] {

    let mut padding_length = 64 - (message.len() % 64);
    let mut padding: [u8; (64 + 5)] = [0; 69];

    // Message Padding
    if padding_length > 0 {
        if padding_length < 5 {
            // Padding: "1" + 0's + length (4*8 bits)
            padding_length += 64;
        }

        padding[0] = 0x80;

        for i in 1..5 {
            padding[padding_length - i] = ((message.len() * 8) >> ((i - 1) * 8)) as u8;
        } // 4-word representation of l
    }

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

    let mut H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut pos = 0;

    while pos < (message.len() + padding_length) {
        let mut w: [u32; 80] = [0; 80];

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        for t in 0..=63 {
            if t <= 15 {
                let mut wcount = 24;
                while wcount >= 0 {
                    if pos < message.len() {
                        w[t] += (message[pos] as u32) << wcount;
                    } else {
                        w[t] += (padding[pos - message.len()] as u32) << wcount;
                    }
                    pos += 1;
                    wcount -= 8;
                }
            } else {
                w[t] = add(ssig1(w[t - 2]), add(w[t - 7], add(ssig0(w[t - 15]), w[t - 16])));
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

        H[0] = add(H[0], a);
        H[1] = add(H[1], b);
        H[2] = add(H[2], c);
        H[3] = add(H[3], d);
        H[4] = add(H[4], e);
        H[5] = add(H[5], f);
        H[6] = add(H[6], g);
        H[7] = add(H[7], h);
    }

    let mut out: [u8; 32] = [0; 32];

    for i in 0u8..32u8 {
        out[i as usize] = (H[(i >> 2) as usize] >> (8 * (3 - (i & 0x03))) as u32) as u8;
    }

    out
}


#[cfg(test)]
mod tests {
    use crate::hash::sha256;

    fn test_sha256_do(message: String, hash_expect: String)  {
        let message = message.as_bytes().to_vec();
        let hash = sha256(message).iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(hash, hash_expect);
    }

    #[test]
    fn test_sha256() {
        test_sha256_do("".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
        test_sha256_do("The quick brown fox jumps over the lazy dog".to_string(), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_string());
        test_sha256_do("The quick brown fox jumps over the lazy cog".to_string(), "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be".to_string());
    }
}
