/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * https://www.rfc-editor.org/rfc/rfc5869
 */

use crate::utils::bytes;

use super::{hmac::HMAC, HashType};

pub struct HKDF {
    hash: HashType,
    pseudo_random_key: Vec<u8>,
}

impl HKDF {
    // 2.2 Step 1: Extract
    pub fn extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> HKDF {
        let mut hmac = HMAC::new(hash, salt);
        hmac.update(ikm);
        let pseudo_random_key = hmac.result();

        println!("pseudo_random_key={:?}", bytes::to_hex(&pseudo_random_key));

        Self {
            hash,
            pseudo_random_key,
        }
    }

    // 2.3 Step 2: Expand
    pub fn expand_label(&self, info: &[u8], out_len: usize) -> Option<Vec<u8>> {
        let hash_len = self.hash as usize;

        if out_len > (hash_len * 255) {
            return None;
        }

        let mut okm: Vec<u8> = Vec::with_capacity(out_len);
        let mut last = vec![];

        let mut i = 1;
        while okm.len() < out_len {
            let mut hmac = HMAC::new(self.hash, &self.pseudo_random_key);

            // T(i) = HMAC-Hash(PRK, T(i-1), info, i);

            hmac.update(&last);
            hmac.update(info);
            hmac.update(&[i]);

            last = hmac.result();

            let needed = std::cmp::min(out_len, okm.len() + hash_len) - okm.len();

            okm.extend(&last[..needed]);
            i += 1;
        }

        Some(okm)
    }
}

#[cfg(test)]
mod tests {

    use crate::hash::hkdf::HKDF;
    use crate::hash::HashType;
    use crate::utils::bytes;

    struct TestCase<'a> {
        hash: HashType,
        ikm: &'a str,
        salt: &'a str,
        info: &'a str,
        okm: &'a str,
    }

    #[test]
    fn test_case_1() {
        let test_cases = vec![
            TestCase {
                hash: HashType::SHA256,
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                info: "f0f1f2f3f4f5f6f7f8f9",
                okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            },
            TestCase { // Test Case 2
                hash: HashType::SHA256,
                ikm:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                okm:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
             },
             TestCase {
                 hash: HashType::SHA256,
                 ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 salt: "",
                 info: "",
                 okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
             },
             TestCase {
                 hash: HashType::SHA1,
                 ikm: "0b0b0b0b0b0b0b0b0b0b0b",
                 salt: "000102030405060708090a0b0c",
                 info: "f0f1f2f3f4f5f6f7f8f9",
                 okm: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
             },
        ];

        for (i, test_case) in test_cases.iter().enumerate() {
            println!("Trying TestCase {}", i+1);
            let ikm = bytes::from_hex(test_case.ikm).unwrap();
            let salt = bytes::from_hex(test_case.salt).unwrap();
            let info = bytes::from_hex(test_case.info).unwrap();
            let okm_expected = bytes::from_hex(test_case.okm).unwrap();

            let hkdf = HKDF::extract(test_case.hash, &salt, &ikm);

            let okm = hkdf.expand_label(&info, test_case.okm.len()/2).unwrap();
            assert_eq!(okm_expected, okm);
        }
    }
}
