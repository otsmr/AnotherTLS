/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Specs: https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
 *
 */

#![allow(non_snake_case)]

use crate::net::alert::TlsError;
use super::{Blocksize, AES};
use crate::crypto::{Cipher, CipherSuite};
use crate::utils::bytes;

pub struct Gcm(CipherSuite);


impl Gcm {
    pub fn new(cs: CipherSuite) -> Self {
        Self(cs)
    }
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

    fn gcm(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: &[u8],
        encrypt: bool,
    ) -> Result<(Vec<u8>, [u8; 16]), TlsError> {
        let blocksize = Blocksize::new(key.len() * 8).unwrap();

        let mut output = Vec::default();
        let mut aes = AES::init(key, blocksize);
        let mut counter = 0u128;
        let mut X = 0u128; // for i == 0

        let H = bytes::to_u128_be(&aes.encrypt([0; 16]));

        let iv_len = iv.len();
        let Yi = if iv_len * 8 != 96 {
            let mut N = 0;
            for i in (0..iv_len).step_by(16) {
                let add = if iv_len > i + 16 {
                    &iv[i..i + 16]
                } else {
                    &iv[i..]
                };
                N = Gcm::gmult(N ^ bytes::to_u128_be(add), H);
            }
            let len = (iv.len() * 8) as u128;
            Gcm::gmult(N ^ len, H)
        } else {
            counter = 1;
            bytes::to_u128_be(iv) | 1
        };

        let mut auth_tag = bytes::to_u128_be(&aes.encrypt(bytes::u128_to_bytes_be(Yi)));

        let m = additional_data.len();
        for i in (0..m).step_by(16) {
            let add = if m > i + 16 {
                &additional_data[i..i + 16]
            } else {
                &additional_data[i..]
            };
            X = Gcm::gmult(X ^ bytes::to_u128_be(add), H);
        }

        let n = data.len();
        for i in (0..n).step_by(16) {
            counter = (counter + 1) % 0x100000000; // 2^32

            let Yi = if (iv.len() * 8) != 96 {
                Yi + counter
            } else {
                (Yi & !0xFFFFFFFF) | counter
            };

            let Ek_Y = aes.encrypt(bytes::u128_to_bytes_be(Yi));

            let data_slice = if n > i + 16 {
                &data[i..i + 16]
            } else {
                &data[i..]
            };

            let data_u128 = bytes::to_u128_be(data_slice);
            let overflow = (16 - data_slice.len()) * 8;
            let out_i = (data_u128 ^ bytes::to_u128_be(&Ek_Y)) >> overflow;

            let out_i_bytes = &bytes::u128_to_bytes_be(out_i)[16 - data_slice.len()..];

            output.append(&mut out_i_bytes.to_vec());

            X = if encrypt {
                Gcm::gmult(X ^ (out_i << overflow), H)
            } else {
                Gcm::gmult(X ^ (data_u128), H)
            }
        }

        let len = ((m as u128 * 8) << 64) | (n as u128 * 8);

        auth_tag ^= Gcm::gmult(X ^ len, H);

        let auth_tag = bytes::u128_to_bytes_be(auth_tag);

        Ok((output, auth_tag))
    }
}

impl Cipher for Gcm {
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), TlsError> {
        Gcm::gcm(key, iv, plaintext, additional_data, true)
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        let (P, T) = Gcm::gcm(key, iv, ciphertext, additional_data, false)?;

        if T != auth_tag {
            return Err(TlsError::BadRecordMac);
        }

        Ok(P)
    }

    fn get_cipher_suite(&self) -> crate::crypto::CipherSuite {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Gcm;
    use crate::crypto::CipherSuite;
    use crate::crypto::ciphersuite::Cipher;
    use crate::utils::bytes::from_hex;

    #[test]
    fn test_decrypt() {
        let K = from_hex("feffe9928665731c6d6a8f9467308308");
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let IV = from_hex("cafebabefacedbaddecaf888");
        let A = from_hex("");
        let cipher = Gcm::new(CipherSuite::TLS_AES_128_GCM_SHA256);
        let (C, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(&T, from_hex("4d5c2af327cd64a62cf35abd2ba6fab4").as_slice());

        let P1 = cipher.decrypt(&K, &IV, &C, &A, &T).unwrap();
        assert_eq!(P, P1);
    }

    #[test]
    fn test_encrypt() {
        // Test Case 1
        let K = from_hex("00000000000000000000000000000000");
        let P = from_hex("");
        let IV = from_hex("000000000000000000000000");
        let A = from_hex("");

        let cipher = Gcm::new(CipherSuite::TLS_AES_128_GCM_SHA256);
        let (C, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(C, vec![]);
        assert_eq!(T, from_hex("58e2fccefa7e3061367f1d57a4e7455a").as_slice());

        // Test Case 2
        let P = from_hex("00000000000000000000000000000000");
        println!("len(P)={}", P.len());
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("AB6E47D42CEC13BDF53A67B21257BDDF").as_slice());

        // Test Case 3
        let K = from_hex("feffe9928665731c6d6a8f9467308308");
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let IV = from_hex("cafebabefacedbaddecaf888");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("4d5c2af327cd64a62cf35abd2ba6fab4").as_slice());

        // Test Case 4
        let K = from_hex("feffe9928665731c6d6a8f9467308308");
        let P  = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let IV = from_hex("cafebabefacedbaddecaf888");
        let A = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("5bc94fbc3221a5db94fae95ae7121a47").as_slice());

        // Test Case 5
        let IV = from_hex("cafebabefacedbad");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("3612d2e79e3b0785561be14aaca2fccb").as_slice());

        // Test Case 6
        let IV = from_hex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("619cc5aefffe0bfa462af43c1699d050").as_slice());

        // Test Case 7
        let K = from_hex("000000000000000000000000000000000000000000000000");
        let IV = from_hex("000000000000000000000000");
        let P = from_hex("");
        let A = from_hex("");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("cd33b28ac773f74ba00ed1f312572435").as_slice());

        // Test Case 8
        let P = from_hex("00000000000000000000000000000000");
        let (_, T) = cipher.encrypt(&K, &IV, &P, &A).unwrap();
        assert_eq!(T, from_hex("2ff58d80033927ab8ef4d4587514f0fb").as_slice());

        // Test Case 9
        // TODO: ADD the other test cases
    }
}
