/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Specs: https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
 *
 */

#![allow(non_snake_case)]

use ibig::{UBig, ubig};

use crate::utils::bytes;
use super::{AES, Blocksize};


pub struct GCM {

}


impl GCM {


    fn gmult(mut a: u128, mut b: u128) -> u128 {
    // Reverse the bit order of the input values
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

    // Reverse the bit order of the output value
    p.reverse_bits()
}


    // fn gmult(mut a: u128, mut b: u128) -> u128 {
    //     let mut p: u128 = 0;
    //     let mut hbs: u128;

    //     for _ in 0..128 {
    //         if b & 1 != 0 {
    //             p ^= a;
    //         }
    //         hbs = a & 0x80000000000000000000000000000000;
    //         a <<= 1;
    //         if hbs != 0 {
    //             a ^= 0xE1000000000000000000000000000000;
    //         }
    //         b >>= 1;
    //     }
    //     p
    // }


    pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<(Vec<u8>, u128), String> {

        let blocksize = Blocksize::new(key.len()*8)?;

        let mut ciphertext = Vec::new();

        // let counter;
        let mut aes = AES::init(key, blocksize)?;

        let H = bytes::to_u128_le(&aes.encrypt([0; 16]));
        println!("H={H:#01x}");

        if (iv.len()*8) < 96 {
            // TODO: GHASH(H, {}, IV )
            return Err("IV is to small".to_string());
        }

        let Y0 = bytes::to_bytes(bytes::to_u128_le(iv) | 1);
        let mut auth_tag = bytes::to_u128_le(&aes.encrypt(Y0));
        println!("E(K, Y0)={auth_tag:#x}");

        let iv = bytes::to_u128_le(iv);

        let mut counter = 1u128;

        let mut X = 0u128; // for i == 0
        let m = additional_data.len();

        for i in (0..m).step_by(16) {
            let add = if m > i+16 {
                &additional_data[i..i+16]
            } else {
                &additional_data[i..m]
            };
            X = GCM::gmult(X ^ bytes::to_u128_le(add), H);
            println!("X{i}={X:#X}");
        }

        let n = plaintext.len();
        for i in (0..n).step_by(16) {
            counter = (counter + 1) % 0x100000000; // 2^32
            let ci_1 = aes.encrypt(bytes::to_bytes(iv | counter));
            // println!("E(K, Y{i})={:#x}", bytes::to_u128_le(&ci_1));
            let plain = if n > i+16 {
                &plaintext[i..i+16]
            } else {
                &plaintext[i..n]
            };
            let pi = bytes::to_u128_le(plain);
            let ci = (pi ^ bytes::to_u128_le(&ci_1)) >> ((16 - plain.len()) * 8);
            ciphertext.append(&mut bytes::to_bytes(ci).to_vec());
            X = GCM::gmult(X ^ ci, H);
            println!("X{i}={X:#X}");
        }

        // println!("LEN={:#X}", ((n * 8)));
        // println!("LEN={:#X}", ((m * 8)<<32));
        X = GCM::gmult(X ^ (((m as u128 * 8) << 32) | (n as u128 * 8)), H);
        println!("GHASH(H, A, C)={X:#01X}");

        auth_tag ^= X;

        Ok((ciphertext, auth_tag))
    }

    pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], additional_data: &[u8], auth_tag: &[u8]) -> Result<Vec<u8>, ()> {

        let plaintext = Vec::new();


        Ok(plaintext)
    }

}

#[cfg(test)]
mod tests {
    use crate::utils::bytes::{from_hex, self};

    use super::GCM;


    #[test]
    fn test_encrypt() {

        // Test Case 1
        let K  = from_hex("00000000000000000000000000000000").unwrap();
        let P  = from_hex("").unwrap();
        let IV = from_hex("000000000000000000000000").unwrap();
        let A = from_hex("").unwrap();

        let (C, T) = GCM::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(C, vec![]);
        assert_eq!(T, 0x58e2fccefa7e3061367f1d57a4e7455a);

        // Test Case 2
        let P  = from_hex("00000000000000000000000000000000").unwrap();
        println!("len(P)={}", P.len());
        let (_, T) = GCM::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0xAB6E47D42CEC13BDF53A67B21257BDDF);



        // Test Case 3
        let K  = from_hex("feffe9928665731c6d6a8f9467308308").unwrap();
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();
        let IV = from_hex("cafebabefacedbaddecaf888").unwrap();
        let (_, T) = GCM::encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, 0x4d5c2af327cd64a62cf35abd2ba6fab4);


        // Test Case 4
        println!("CASE 4");

        let K  = from_hex("feffe9928665731c6d6a8f9467308308").unwrap();
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let IV = from_hex("cafebabefacedbaddecaf888").unwrap();
        let A = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let (C, T) = GCM::encrypt(&K, &IV, &P, &A).unwrap();
        println!("C=0x{}", bytes::to_hex(C));
        println!("T={T:#01X}");
        panic!("OK");
    }

}

