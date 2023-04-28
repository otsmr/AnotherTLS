/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8439
 *
 */

use crate::crypto::chacha20::ChaCha20;
use crate::net::alert::TlsError;
use crate::{crypto::Cipher, utils::bytes};
use ibig::ibig;

use super::cipher::ChaCha20Block;

#[derive(Default)]
pub struct Poly1305();

impl Poly1305 {
    pub fn key_gen(key: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut chacha20_block = ChaCha20Block::init(key, iv, 0).unwrap();
        chacha20_block.get_block()[..32].to_vec()
    }

    pub fn mac(key: &[u8], msg: &[u8]) -> [u8; 16] {
        let mut r = bytes::to_ibig_le(&key[..16]);
        r &= ibig!(_0ffffffc0ffffffc0ffffffc0fffffff base 16);
        let s = bytes::to_ibig_le(&key[16..32]);

        let mut a = ibig!(0);
        let p = ibig!(_3fffffffffffffffffffffffffffffffb base 16);

        for i in 1..=(msg.len() as f32 / 16.0).ceil() as usize {
            let n = if i * 16 > msg.len() {
                let mut buf = vec![];
                buf.extend_from_slice(&msg[(i - 1) * 16..]);
                buf.push(0x01);
                bytes::to_ibig_le(&buf)
            } else {
                let mut n = bytes::to_ibig_le(&msg[(i - 1) * 16..i * 16]);
                n += ibig!(_100000000000000000000000000000000 base 16);
                n
            };
            a += n;
            a = (r.clone() * a) % p.clone();
        }
        a += s;
        let mut ret = bytes::ibig_to_vec(a, bytes::ByteOrder::Little);
        // convert to u128
        ret.resize(16, 0);
        ret.try_into().unwrap()
    }
    pub fn pad16(input: &mut Vec<u8>, x: usize) {
        if x % 16 != 0 {
            input.resize(input.len() + (16 - (x % 16)), 0)
        }
    }
    pub fn get_mac_data(ciphertext: &[u8], additional_data: &[u8]) -> Vec<u8> {
        let mut mac_data = additional_data.to_vec();
        Poly1305::pad16(&mut mac_data, additional_data.len());
        mac_data.extend_from_slice(ciphertext);
        Poly1305::pad16(&mut mac_data, ciphertext.len());

        mac_data.extend_from_slice(&bytes::u64_to_bytes_le(additional_data.len() as u64));
        mac_data.extend_from_slice(&bytes::u64_to_bytes_le(ciphertext.len() as u64));
        mac_data
    }
}

impl Cipher for Poly1305 {
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), TlsError> {
        let ciphertext = ChaCha20::encrypt(plaintext, key, iv, 1).unwrap();
        let otk = Poly1305::key_gen(key, iv);
        let tag = Poly1305::mac(&otk, &Poly1305::get_mac_data(&ciphertext, additional_data));
        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        let otk = Poly1305::key_gen(key, iv);
        let tag = Poly1305::mac(&otk, &Poly1305::get_mac_data(ciphertext, additional_data));
        if tag == auth_tag {
            if let Some(plaintext) = ChaCha20::decrypt(ciphertext, key, iv, 1) {
                return Ok(plaintext);
            }
        }
        Err(TlsError::BadRecordMac)
    }

    fn get_cipher_suite(&self) -> crate::crypto::CipherSuite {
        crate::crypto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    }
}

#[cfg(test)]
mod tests {
    use super::Poly1305;
    use crate::crypto::ciphersuite::Cipher;
    use crate::utils::bytes;

    #[test]
    fn test_poly1305_mac() {
        let key =
            bytes::from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg =
            bytes::from_hex("43727970746f6772617068696320466f72756d2052657365617263682047726f7570");

        let expected = bytes::from_hex("a8061dc1305136c6c22b8baf0c0127a9");

        assert_eq!(expected, Poly1305::mac(&key, &msg));
    }

    #[test]
    fn test_poly1305_key_gen() {
        let key =
            bytes::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = bytes::from_hex("000000000001020304050607");
        let expected =
            bytes::from_hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646");

        assert_eq!(expected, Poly1305::key_gen(&key, &nonce));
    }
    #[test]
    fn test_poly1305_aead_de_encrypt() {
        let plaintext = bytes::from_hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let aad = bytes::from_hex("50515253c0c1c2c3c4c5c6c7");
        let key =
            bytes::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let iv = bytes::from_hex("070000004041424344454647");
        let ciphertext = bytes::from_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        let tag = bytes::from_hex("1ae10b594f09e26a7e902ecbd0600691");

        let encrypted = Poly1305::default()
            .encrypt(&key, &iv, &plaintext, &aad)
            .unwrap();

        assert_eq!(encrypted.0, ciphertext);
        assert_eq!(&encrypted.1, &tag.as_slice());

        let decrypted = Poly1305::default()
            .decrypt(&key, &iv, &ciphertext, &aad, &tag)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_poly1305_aead_decrypt() {
        let ciphertext = bytes::from_hex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b");

        let key =
            bytes::from_hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        let aad = bytes::from_hex("f33388860000000000004e91");
        let tag = bytes::from_hex("eead9d67890cbb22392336fea1851f38");
        let iv = bytes::from_hex("000000000102030405060708");
        let plaintext = bytes::from_hex("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d");

        let decrypted = Poly1305::default()
            .decrypt(&key, &iv, &ciphertext, &aad, &tag)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
