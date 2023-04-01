/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Specs: https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
 *
 */

#![allow(non_snake_case)]

use super::{Blocksize, AES};
use crate::utils::bytes;

pub struct Gcm {}

impl Gcm {

    fn gmult(mut a: u128, mut b: u128) -> u128 {
        a = a.reverse_bits();
        b = b.reverse_bits();

        let mut p: u128 = 0;
        let mut hi_bit_set;
        for _ in 0..128 {
            if b & 1 != 0 {
                p ^= a;
            }
            hi_bit_set = (a & 0x80000000000000000000000000000000) != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x0000000000000000000000000000000087;
            }
            b >>= 1;
        }

        p.reverse_bits()
    }


    fn gcm(key: &[u8], iv: &[u8], data: &[u8], additional_data: &[u8], encrypt: bool) -> Result<(Vec<u8>, u128), String> {

        let blocksize = Blocksize::new(key.len() * 8)?;

        let mut output = Vec::new();
        let mut aes = AES::init(key, blocksize)?;
        let mut counter = 1u128;
        let mut X = 0u128; // for i == 0

        let H = bytes::to_u128_le(&aes.encrypt([0; 16]));

        let iv_len = iv.len();
        let Yi = if iv_len * 8 != 96 {
            let mut N = 0;
            for i in (0..iv_len).step_by(16) {
                let add = if iv_len > i + 16 {
                    &iv[i..i + 16]
                } else {
                    &iv[i..]
                };
                N = Gcm::gmult(N ^ bytes::to_u128_le(add), H);
            }
            let len = (iv.len() * 8) as u128;
            Gcm::gmult(N ^ len, H)
        } else {
            bytes::to_u128_le(iv) | 1
        };

        let mut auth_tag = bytes::to_u128_le(&aes.encrypt(bytes::to_bytes(Yi)));

        let m = additional_data.len();
        for i in (0..m).step_by(16) {
            let add = if m > i + 16 {
                &additional_data[i..i + 16]
            } else {
                &additional_data[i..]
            };
            X = Gcm::gmult(X ^ bytes::to_u128_le(add), H);
        }

        let n = data.len();
        for i in (0..n).step_by(16) {

            counter = (counter + 1) % 0x100000000; // 2^32

            let Yi = if (iv.len() * 8) != 96 {
                Yi + counter
            } else {
                (Yi & !0xFFFFFFFF) | counter
            };

            let Ek_Y = aes.encrypt(bytes::to_bytes(Yi));

            let data_slice = if n > i + 16 {
                &data[i..i + 16]
            } else {
                &data[i..]
            };

            let data_u128 = bytes::to_u128_le(data_slice);
            let overflow = (16 - data_slice.len()) * 8;
            let out_i = (data_u128 ^ bytes::to_u128_le(&Ek_Y)) >> overflow;

            let out_i_bytes = &bytes::to_bytes(out_i)[16-data_slice.len()..];

            output.append(&mut out_i_bytes.to_vec());

            X = if encrypt {
                Gcm::gmult(X ^ (out_i << overflow), H)
            } else {
                Gcm::gmult(X ^ (data_u128), H)
            }
        }

        let len = ((m as u128 * 8) << 64) | (n as u128 * 8);

        auth_tag ^= Gcm::gmult(X ^ len, H);

        Ok((output, auth_tag))

    }

    pub fn encrypt(
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, u128), String> {
        Gcm::gcm(key, iv, plaintext, additional_data, true)
    }

    pub fn decrypt(
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: u128,
    ) -> Result<Vec<u8>, String> {

        let (P, T) = Gcm::gcm(key, iv, ciphertext, additional_data, false)?;

        if T != auth_tag {
            return Err("auth_tag is not correct".to_string());
        }

        Ok(P)

    }
}

#[cfg(test)]
mod tests {
    use crate::utils::bytes::from_hex;

    use super::Gcm;

    #[test]
    fn test_decrypt() {

        let K = from_hex("feffe9928665731c6d6a8f9467308308").unwrap();
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();
        let IV = from_hex("cafebabefacedbaddecaf888").unwrap();
        let A = from_hex("").unwrap();
        let (C, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x4d5c2af327cd64a62cf35abd2ba6fab4);

        let P1 = Gcm::decrypt(&K, &IV, &C, &A, T).unwrap();
        assert_eq!(P, P1);
    }

    #[test]
    fn test_encrypt() {
        // Test Case 1
        let K = from_hex("00000000000000000000000000000000").unwrap();
        let P = from_hex("").unwrap();
        let IV = from_hex("000000000000000000000000").unwrap();
        let A = from_hex("").unwrap();

        let (C, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(C, vec![]);
        assert_eq!(T, 0x58e2fccefa7e3061367f1d57a4e7455a);

        // Test Case 2
        let P = from_hex("00000000000000000000000000000000").unwrap();
        println!("len(P)={}", P.len());
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0xAB6E47D42CEC13BDF53A67B21257BDDF);

        // Test Case 3
        let K = from_hex("feffe9928665731c6d6a8f9467308308").unwrap();
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();
        let IV = from_hex("cafebabefacedbaddecaf888").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x4d5c2af327cd64a62cf35abd2ba6fab4);

        // Test Case 4
        let K = from_hex("feffe9928665731c6d6a8f9467308308").unwrap();
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let IV = from_hex("cafebabefacedbaddecaf888").unwrap();
        let A = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x5bc94fbc3221a5db94fae95ae7121a47);

        // Test Case 5
        let IV = from_hex("cafebabefacedbad").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x3612d2e79e3b0785561be14aaca2fccb);

        // Test Case 6
        let IV = from_hex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x619cc5aefffe0bfa462af43c1699d050);

        // Test Case 7
        let K = from_hex("000000000000000000000000000000000000000000000000").unwrap();
        let IV = from_hex("000000000000000000000000").unwrap();
        let P = from_hex("").unwrap();
        let A = from_hex("").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0xcd33b28ac773f74ba00ed1f312572435);

        // Test Case 8
        let P = from_hex("00000000000000000000000000000000").unwrap();
        let (_, T) = Gcm::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x2ff58d80033927ab8ef4d4587514f0fb);

        // Test Case 9
        // TODO: ADD the other test cases
    }
}
