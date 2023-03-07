/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc2104
 *
 */

use crate::utils::bytes;
use super::{HashType, sha1, sha256, sha384};

pub struct HMAC<'a> {
    hash: HashType,
    key: &'a [u8],
    input: Vec<u8>
}

impl<'a> HMAC<'a> {
    pub fn new(hash: HashType, key: &'a [u8]) -> Self {
        HMAC { hash, key, input: vec![] }
    }
    pub fn update(&mut self, buf: &[u8]) {
        self.input.extend_from_slice(buf);
    }
    pub fn result(&self) -> Vec<u8> {


        // FIMXE: This is realy bad code
        let mut k_ipad = vec![];
        let mut k_opad = vec![];
        let mut padded_key = vec![];

        if self.hash == HashType::SHA384 {
            k_opad.resize(128, 0);
            k_ipad.resize(128, 0);
            padded_key.resize(128, 0)
        } else {
            k_opad.resize(64, 0);
            k_ipad.resize(64, 0);
            padded_key.resize(64, 0)
        }
        let hashed_key;

        let key = if self.key.len() > 64 {
            hashed_key = match self.hash {
                HashType::SHA1 => sha1(self.key).to_vec(),
                HashType::SHA256 => sha256(self.key).to_vec(),
                HashType::SHA384 => sha384(self.key).to_vec()
            };
            &hashed_key
        } else {
            self.key
        };

        for (i, k) in key.iter().enumerate() {
            padded_key[i] = *k;
        }

        for (i, k) in padded_key.iter().enumerate() {
            k_opad[i] = k ^ 0x5C;
            k_ipad[i] = k ^ 0x36;
        }


        let mut input: Vec<u8> = Vec::with_capacity(256);
        input.extend_from_slice(&k_opad);

        let mut k_ipad_text = Vec::with_capacity(self.input.len() + 64);
        k_ipad_text.extend_from_slice(&k_ipad);
        k_ipad_text.extend_from_slice(&self.input);

        match self.hash {
            HashType::SHA1 => {
                input.extend_from_slice(&sha1(&k_ipad_text));
                sha1(&input).to_vec()
            }
            HashType::SHA256 => {
                input.extend_from_slice(&sha256(&k_ipad_text));
                sha256(&input).to_vec()
            }
            HashType::SHA384 => {
                input.extend_from_slice(&sha384(&k_ipad_text));
                sha384(&input).to_vec()
            }
        }

    }
}


// Test Cases from: https://www.rfc-editor.org/rfc/rfc2202

#[cfg(test)]
mod tests {

    use crate::hash::hmac::HMAC;
    use crate::hash::HashType;
    use crate::utils::bytes;

    enum TestResult<'a> {
        SHA256(&'a str),
        SHA384(&'a str)
    }
    struct TestCase<'a> {
        key: &'a str,
        data: &'a str,
        result: Vec<TestResult<'a>>
    }

    #[test]
    fn test_cases() {
        let test_cases = vec![
            TestCase {
                key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                data: "4869205468657265",
                result: vec![
                    TestResult::SHA256("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                    TestResult::SHA384("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
                ]
            },
            TestCase {
                key: "4a656665",
                data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                result: vec![
                    TestResult::SHA256("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                    TestResult::SHA384("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
                ]
            }

        ];

        for (i, test_case) in test_cases.iter().enumerate() {
            let key = bytes::from_hex(test_case.key).unwrap();
            let data = bytes::from_hex(test_case.data).unwrap();

            println!("Test Case {i}");
            for res in test_case.result.iter() {

                match res {
                    TestResult::SHA256(digest) => {
                        println!("SHA256");
                        let mut hmac = HMAC::new(HashType::SHA256, &key);
                        hmac.update(&data);
                        assert_eq!(digest.to_string(), bytes::to_hex(&hmac.result()));
                    },
                    TestResult::SHA384(digest) => {
                        println!("SHA384");
                        let mut hmac = HMAC::new(HashType::SHA384, &key);
                        hmac.update(&data);
                        assert_eq!(digest.to_string(), bytes::to_hex(&hmac.result()));
                    }
                }
            }
        }

    }
    #[test]
    fn test_case_1() {
        let key = bytes::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let digest_expected = bytes::from_hex("b617318655057264e28bc0b6fb378c8ef146be00").unwrap();
        let mut hmac = HMAC::new(HashType::SHA1, &key);
        hmac.update(data);
        assert_eq!(digest_expected, hmac.result());
    }

    #[test]
    fn test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let digest_expected = bytes::from_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap();
        let mut hmac = HMAC::new(HashType::SHA1, key);
        hmac.update(data);
        assert_eq!(digest_expected, hmac.result());
    }
    #[test]
    fn test_case_3() {
        let key = bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = bytes::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let digest_expected = bytes::from_hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap();
        let mut hmac = HMAC::new(HashType::SHA1, &key);
        hmac.update(&data);
        assert_eq!(digest_expected, hmac.result());
    }
    #[test]
    fn test_case_7() {
        let key = bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let digest_expected = bytes::from_hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91").unwrap();
        let mut hmac = HMAC::new(HashType::SHA1, &key);
        hmac.update(data);
        assert_eq!(digest_expected, hmac.result());
    }
}
