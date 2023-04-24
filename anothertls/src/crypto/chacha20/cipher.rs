/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8439
 *
 */

fn u8_to_u32_le(b: &[u8]) -> u32 {
    b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16 | (b[3] as u32) << 24
}

#[derive(Clone)]
pub struct ChaCha20Block {
    pub state: [u32; 16],
}

impl ChaCha20Block {
    pub fn init(key: &[u8], iv: &[u8], counter: u32) -> Option<Self> {
        if key.len() != 32 || iv.len() != 12 {
            return None;
        }

        let mut state = [0; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[i + 4] = u8_to_u32_le(&key[i * 4..]);
        }
        state[12] = counter;
        for i in 0..3 {
            state[i + 13] = u8_to_u32_le(&iv[i * 4..]);
        }

        Some(Self { state })
    }

    pub fn set_counter(&mut self, counter: u32) {
        self.state[12] = counter;
    }

    pub fn qround(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let x = &mut self.state;
        x[a] = x[a].overflowing_add(x[b]).0;
        x[d] = (x[d] ^ x[a]).rotate_left(16);
        x[c] = x[c].overflowing_add(x[d]).0;
        x[b] = (x[b] ^ x[c]).rotate_left(12);

        x[a] = x[a].overflowing_add(x[b]).0;
        x[d] = (x[d] ^ x[a]).rotate_left(8);
        x[c] = x[c].overflowing_add(x[d]).0;
        x[b] = (x[b] ^ x[c]).rotate_left(7);
    }

    pub fn get_block(&mut self) -> [u8; 64] {
        let initial_state = self.state;

        for _ in 0..10 {
            self.qround(0, 4, 8, 12);
            self.qround(1, 5, 9, 13);
            self.qround(2, 6, 10, 14);
            self.qround(3, 7, 11, 15);
            self.qround(0, 5, 10, 15);
            self.qround(1, 6, 11, 12);
            self.qround(2, 7, 8, 13);
            self.qround(3, 4, 9, 14);
        }

        for (i, s) in self.state.iter_mut().enumerate() {
            *s = s.overflowing_add(initial_state[i]).0;
        }

        let mut out = [0; 64];

        for (mut i, s) in self.state.iter().enumerate() {
            i *= 4;
            out[i] = *s as u8;
            out[i + 1] = (*s >> 8) as u8;
            out[i + 2] = (*s >> 16) as u8;
            out[i + 3] = (*s >> 24) as u8;
        }

        out
    }
}
pub struct ChaCha20();

impl ChaCha20 {
    pub fn encrypt(mut input: Vec<u8>, key: &[u8], iv: &[u8], counter: usize) -> Option<Vec<u8>> {
        let chacha20 = ChaCha20Block::init(key, iv, 0);
        let blocks_len = (input.len() as f32 / 64.0).ceil() as usize;
        for j in 0..blocks_len {
            let mut current_block = chacha20.clone()?;
            current_block.set_counter((counter + j) as u32);
            let key_stream = current_block.get_block();
            let mut count = key_stream.len();
            if (j * 64) + 64 >= input.len() {
                count = input.len() % 64;
            }
            for i in 0..count {
                input[j * 64 + i] ^= key_stream[i];
            }
        }
        Some(input)
    }
    pub fn decrypt(input: Vec<u8>, key: &[u8], iv: &[u8], counter: usize) -> Option<Vec<u8>> {
        Self::encrypt(input, key, iv, counter)
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::chacha20::cipher::ChaCha20, utils::bytes};

    #[test]
    fn test_chacha20() {
        let key =
            bytes::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let iv = bytes::from_hex("000000000000004a00000000").unwrap();

        let plaintext = bytes::from_hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();

        let encrypted = ChaCha20::encrypt(plaintext.clone(), &key, &iv, 1).unwrap();

        let expected = bytes::from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d").unwrap();

        assert_eq!(&encrypted, &expected);

        let decrypted = ChaCha20::decrypt(encrypted, &key, &iv, 1).unwrap();

        assert_eq!(&decrypted, &plaintext);

    }
}
