/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8439
 *
 */

use crate::crypto::Cipher;

use super::cipher::ChaCha20Block;

#[derive(Default)]
pub struct Poly1305();

impl Poly1305 {
    pub fn key_gen(key: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut chacha20_block = ChaCha20Block::init(key, iv, 0).unwrap();
        chacha20_block.get_block()[..31].to_vec()
    }

    pub fn mac(key: u128, mac_data: &[u8]) -> u128 {
        // clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        // poly1305_mac(msg, key):
        //     r = le_bytes_to_num(key[0..15])
        //     clamp(r)
        //     s = le_bytes_to_num(key[16..31])
        //     a = 0  /* a is the accumulator */
        //     p = (1<<130)-5
        //     for i=1 upto ceil(msg length in bytes / 16)
        //     n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
        //     a += n
        //     a = (r * a) % p
        //     end
        //     a += s
        //     return num_to_16_le_bytes(a)
        //     end
        0
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
