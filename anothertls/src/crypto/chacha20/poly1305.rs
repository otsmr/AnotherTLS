/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8439
 *
 */

use crate::crypto::Cipher;

#[derive(Default)]
pub struct Poly1305();

impl Cipher for Poly1305 {
    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, u128), String> {
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
