/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8439
 *
 */

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

    pub fn mac(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        if key.len() < 32 {
            return None;
        }
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
        Some(ret)
    }
}

impl Cipher for Poly1305 {
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, u128), String> {
        //     chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
        // nonce = constant | iv
        // otk = poly1305_key_gen(key, nonce)
        // ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
        // mac_data = aad | pad16(aad)
        // mac_data |= ciphertext | pad16(ciphertext)
        // mac_data |= num_to_8_le_bytes(aad.length)
        // mac_data |= num_to_8_le_bytes(ciphertext.length)
        // tag = poly1305_mac(mac_data, otk)
        // return (ciphertext, tag)
        todo!()
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        auth_tag: u128,
    ) -> Result<Vec<u8>, String> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::ciphersuite::Cipher;
    use super::Poly1305;
    use crate::utils::bytes;

    #[test]
    fn test_poly1305_mac() {
        let key =
            bytes::from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg =
            bytes::from_hex("43727970746f6772617068696320466f72756d2052657365617263682047726f7570");
        let expected = bytes::from_hex("a8061dc1305136c6c22b8baf0c0127a9");

        assert_eq!(expected, Poly1305::mac(&key, &msg).unwrap());
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
    fn test_poly1305_aead_encrypt() {
        let plaintext = bytes::from_hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let aad = bytes::from_hex("50515253c0c1c2c3c4c5c6c7");
        let key = bytes::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let iv = bytes::from_hex("4041424344454647");
        let ciphertext = bytes::from_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        let aead_construction = bytes::from_hex("50515253c0c1c2c3c4c5c6c700000000d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b611600000000000000000000000000000c000000000000007200000000000000");

        let encrypted = Poly1305::default().encrypt(&key, &iv, &plaintext, &aad);

        assert_eq!(encrypted.unwrap().0, aead_construction);
    }
}



