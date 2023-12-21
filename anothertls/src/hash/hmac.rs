/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc2104
 *
 */

use crate::hash::{sha256, sha384, HashType};

pub struct Hmac<'a> {
    hash: HashType,
    key: &'a [u8],
    pub input: Vec<u8>,
}

impl<'a> Hmac<'a> {
    pub fn new(hash: HashType, key: &'a [u8]) -> Self {
        Hmac {
            hash,
            key,
            input: vec![],
        }
    }

    pub fn update(&mut self, buf: &[u8]) {
        self.input.extend_from_slice(buf);
    }

    pub fn result(&self) -> Vec<u8> {
        let mut k_ipad = [0; 128];
        let mut k_opad = [0; 128];
        let mut padded_key = [0; 128];
        let mut size = 64;

        if self.hash == HashType::SHA384 {
            size = 128;
        }

        let hashed_key;

        let key = if self.key.len() > 64 {
            hashed_key = match self.hash {
                HashType::SHA256 => sha256(self.key),
                HashType::SHA384 => sha384(self.key),
            };
            &hashed_key
        } else {
            self.key
        };

        for (i, k) in key.iter().enumerate() {
            padded_key[i] = *k;
        }

        for i in 0..size {
            k_opad[i] = padded_key[i] ^ 0x5C;
            k_ipad[i] = padded_key[i] ^ 0x36;
        }

        let mut input: Vec<u8> = Vec::with_capacity(256);
        input.extend_from_slice(&k_opad[0..size]);

        let mut k_ipad_text = Vec::with_capacity(self.input.len() + 64);
        k_ipad_text.extend_from_slice(&k_ipad[0..size]);
        k_ipad_text.extend_from_slice(&self.input);

        match self.hash {
            HashType::SHA256 => {
                input.extend_from_slice(&sha256(&k_ipad_text));
                sha256(&input)
            }
            HashType::SHA384 => {
                input.extend_from_slice(&sha384(&k_ipad_text));
                sha384(&input)
            }
        }
    }
}

// Test Cases from: https://www.rfc-editor.org/rfc/rfc2202

#[cfg(test)]
mod tests {

    use crate::hash::hmac::Hmac;
    use crate::hash::HashType;
    use crate::utils::bytes;

    enum TestResult<'a> {
        SHA256(&'a str),
        SHA384(&'a str),
    }
    struct TestCase<'a> {
        key: &'a str,
        data: &'a str,
        result: Vec<TestResult<'a>>,
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
            let key = bytes::from_hex(test_case.key);
            let data = bytes::from_hex(test_case.data);

            println!("Test Case {i}");
            for res in test_case.result.iter() {
                match res {
                    TestResult::SHA256(digest) => {
                        println!("SHA256");
                        let mut hmac = Hmac::new(HashType::SHA256, &key);
                        hmac.update(&data);
                        assert_eq!(digest.to_string(), bytes::to_hex(&hmac.result()));
                    }
                    TestResult::SHA384(digest) => {
                        println!("SHA384");
                        let mut hmac = Hmac::new(HashType::SHA384, &key);
                        hmac.update(&data);
                        assert_eq!(digest.to_string(), bytes::to_hex(&hmac.result()));
                    }
                }
            }
        }
    }
}
