/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(non_snake_case)]


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

pub fn sha384(message: Vec<u8>) -> [u8; 48] {

    let mut padding_length = 128 - (message.len() % 128);
    let mut padding: [u8; (128 + 9)] = [0; 128 + 9];

    // Message Padding
    if padding_length > 0 {
        if padding_length < 9 {
            // Padding: "1" + 0's + length (4*8 bits)
            padding_length += 128;
        }

        padding[0] = 0x80;

        for i in 1..9 {
            padding[padding_length - i] = ((message.len() * 8) >> ((i - 1) * 8)) as u8;
        } // 8-word representation of l
    }

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
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];

    let mut H: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4
    ];

    let mut pos = 0;

    while pos < (message.len() + padding_length) {
        let mut w: [u64; 80] = [0; 80];

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        for t in 0..=79 {
            if t <= 15 {
                let mut wcount = 56;
                while wcount >= 0 {
                    if pos < message.len() {
                        w[t] += (message[pos] as u64) << wcount;
                    } else {
                        w[t] += (padding[pos - message.len()] as u64) << wcount;
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

    let mut out: [u8; 48] = [0; 48];

    for i in 0u8..48u8 {
        out[i as usize] = (H[(i >> 3) as usize] >> (8 * (7 - (i & 7))) as u64) as u8;
    }

    out
}


#[cfg(test)]
mod tests {
    use crate::hash::sha384;

    fn test_sha384_do(message: String, hash_expect: String)  {
        let message = message.as_bytes().to_vec();
        let hash = sha384(message).iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(hash, hash_expect);
    }

    #[test]
    fn test_sha384() {
        test_sha384_do("".to_string(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".to_string());
        test_sha384_do("The quick brown fox jumps over the lazy dog".to_string(), "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1".to_string());
        test_sha384_do("The quick brown fox jumps over the lazy cog".to_string(), "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b".to_string());
    }
}
