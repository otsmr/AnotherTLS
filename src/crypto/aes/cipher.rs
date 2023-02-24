#![allow(dead_code)]
/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

static SBOX: [[u8; 16]; 16] = [
    [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, ],
    [ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, ],
    [ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, ],
    [ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, ],
    [ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, ],
    [ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, ],
    [ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, ],
    [ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, ],
    [ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, ],
    [ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, ],
    [ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, ],
    [ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, ],
    [ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, ],
    [ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, ],
    [ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, ],
    [ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, ],
];
static INV_SBOX: [[u8; 16]; 16] = [
    [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, ],
    [ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, ],
    [ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, ],
    [ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, ],
    [ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, ],
    [ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, ],
    [ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, ],
    [ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, ],
    [ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, ],
    [ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, ],
    [ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, ],
    [ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, ],
    [ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, ],
    [ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, ],
    [ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, ],
    [ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, ],
];

#[repr(usize)]
#[derive(Debug, Clone, Copy)]
pub enum Blocksize {
    B128 = 128,
    B192 = 192,
    B256 = 256,
}

impl Blocksize {
    pub fn new (u: usize) -> Result<Blocksize, String> {
        Ok(match u {
            128 => Blocksize::B128,
            192 => Blocksize::B192,
            256 => Blocksize::B256,
            _ => return Err("Wrong blocksize".to_string())
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
pub struct AES {
    blocksize: Blocksize,
    expanded_key: [[u8; 4]; 60],
    state: [u8; 16],
}

impl AES {

    pub fn init(key: &[u8], blocksize: Blocksize) -> Result<AES, String> {
        Ok(AES {
            blocksize,
            state: [0; 16],
            expanded_key: AES::get_expanded_key(key, blocksize)?,
        })
    }

    pub fn encrypt(&mut self, input: [u8; 16]) -> [u8; 16] {
        self.state = input;

        let rounds = self.blocksize as usize / 32 + 6;

        self.add_round_key(0);

        for round in 1..=rounds {
            self.sub_bytes();
            self.shift_rows();
            if round < rounds {
                self.mix_columns(false);
            }
            self.add_round_key(round);
        }

        let out = self.state;
        self.state = [0; 16];
        out
    }

    pub fn decrypt(&mut self, input: [u8; 16]) -> [u8; 16] {
        self.state = input;

        let rounds = self.blocksize as usize / 32 + 6;

        self.add_round_key(rounds);

        for round in (0..rounds).rev() {
            self.inv_shift_rows();
            self.inv_sub_bytes();
            self.add_round_key(round);
            if round >= 1 {
                self.mix_columns(true);
            }
        }

        let out = self.state;
        self.state = [0; 16];
        out
    }
    fn get_expanded_key(key: &[u8], blocksize: Blocksize) -> Result<[[u8; 4]; 60], String> {
        if key.len() * 8 != blocksize as usize {
            return Err("Key has not the right size".to_string());
        }

        let mut temp: [u8; 4];

        let nk = blocksize as usize / 32; // (Key-Length in words (4 Bytes))
        let nr = blocksize as usize / 32 + 6;

        let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

        let mut expanded_key: [[u8; 4]; 60] = [[0; 4]; 60];

        for i in 0..nk {
            for j in 0..4 {
                expanded_key[i][j] = key[(i*4) + j].to_owned();
            }
        }

        for i in nk..(4 * (nr + 1)) {
            temp = expanded_key[i - 1];

            if i % nk == 0 {
                AES::rot_word(&mut temp);
                AES::sub_word(&mut temp);

                temp[0] ^= rcon[i / nk - 1];
            } else if nk > 6 && (i % nk) == 4 {
                AES::sub_word(&mut temp);
            }
            for (j, tmp) in temp.iter().enumerate() {
                expanded_key[i][j] = expanded_key[i - nk][j] ^ tmp;
            }
        }

        Ok(expanded_key)
    }

    fn gmult(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        let mut hbs: u8;

        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            hbs = a & 0x80;
            a <<= 1;
            if hbs != 0 {
                a ^= 0x1b; // 0000 0001 0001 1011
            }
            b >>= 1;
        }
        p
    }

    fn sub_word(word: &mut [u8; 4]) {
        for i in 0..4 {
            word[i] = SBOX[((word[i] >> 4) & 0xf) as usize][((word[i]) & 0xf) as usize];
        }
    }

    fn rot_word(word: &mut [u8; 4]) {
        let tmp: u8 = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = tmp;
    }

    fn sub_bytes(&mut self) {
        for i in 0..16 {
            self.state[i] =
                SBOX[((self.state[i] >> 4) & 0xf) as usize][((self.state[i]) & 0xf) as usize];
        }
    }

    fn inv_sub_bytes(&mut self) {
        for i in 0..16 {
            self.state[i] =
                INV_SBOX[((self.state[i] >> 4) & 0xf) as usize][((self.state[i]) & 0xf) as usize];
        }
    }

    fn shift_rows(&mut self) {
        // 1 5 9 13
        // 5 9 13 1
        let mut tmp = self.state[1];
        self.state[1] = self.state[5];
        self.state[5] = self.state[9];
        self.state[9] = self.state[13];
        self.state[13] = tmp;

        // 2 6 10 14
        // 10 14 2 6
        tmp = self.state[2];
        self.state[2] = self.state[10];
        self.state[10] = tmp;

        tmp = self.state[6];
        self.state[6] = self.state[14];
        self.state[14] = tmp;

        // 3 7 11 15
        // 15 3 7 11
        tmp = self.state[11];
        self.state[11] = self.state[7];
        self.state[7] = self.state[3];
        self.state[3] = self.state[15];
        self.state[15] = tmp;
    }

    fn inv_shift_rows(&mut self) {
        //  1 5 9 13
        // 13 1 5 9
        let mut tmp = self.state[9];
        self.state[9] = self.state[5];
        self.state[5] = self.state[1];
        self.state[1] = self.state[13];
        self.state[13] = tmp;

        // 2 6 10 14
        // 10 14 2 6
        tmp = self.state[2];
        self.state[2] = self.state[10];
        self.state[10] = tmp;

        tmp = self.state[6];
        self.state[6] = self.state[14];
        self.state[14] = tmp;

        // 3 7 11 15
        // 7 11 15 3
        tmp = self.state[3];
        self.state[3] = self.state[7];
        self.state[7] = self.state[11];
        self.state[11] = self.state[15];
        self.state[15] = tmp;
    }

    fn mix_columns(&mut self, inverse: bool) {
        let matrix: [u8; 16] = if inverse {
            [ 0xE, 0xB, 0xD, 0x9, 0x9, 0xE, 0xB, 0xD, 0xD, 0x9, 0xE, 0xB, 0xB, 0xD, 0x9, 0xE, ]
        } else {
            [ 0x2, 0x3, 0x1, 0x1, 0x1, 0x2, 0x3, 0x1, 0x1, 0x1, 0x2, 0x3, 0x3, 0x1, 0x1, 0x2, ]
        };

        let mut tmp_matrix: [u8; 16] = [0; 16];

        for column in 0..4 {
            for row in 0..4 {
                for matrix_column in 0..4 {
                    tmp_matrix[row + (4 * column)] ^= AES::gmult(
                        matrix[(row * 4) + matrix_column],
                        self.state[matrix_column + (4 * column)],
                    );
                }
            }
        }

        self.state = tmp_matrix;
    }

    fn add_round_key(&mut self, round: usize) {
        for x in 0..4 {
            for y in 0..4 {
                self.state[(x * 4) + y] ^= self.expanded_key[(round * 4) + x][y];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Blocksize, AES};

    fn test_aes(blocksize: Blocksize, input: [u8; 16], key: &[u8], expected: [u8; 16]) {


        let mut aes = AES::init(key, blocksize).unwrap();

        let out_encrypted = aes.encrypt(input);

        if out_encrypted != expected {
            println!("out_encrypted={out_encrypted:?}");
            println!("expected={expected:?}");
            panic!("encrypted data is wrong (blocksize={})!", blocksize as usize);
        }

        let out_decrypted = aes.decrypt(out_encrypted);

        if out_decrypted != input {
            println!("out_decrypted={out_decrypted:?}");
            println!("input={input:?}");
            panic!("decrypted data is wrong (blocksize={})!", blocksize as usize);
        }

    }

    #[test]
    fn test_aes_128() {

        let plaintext: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let key128: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let cypher128: [u8; 16] = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
        test_aes(Blocksize::B128, plaintext, &key128, cypher128);

        let key192: [u8; 24] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let cypher192: [u8; 16]= [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91];
        test_aes(Blocksize::B192, plaintext, &key192, cypher192);

        let key256: [u8; 32] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let cypher256: [u8; 16] = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
        test_aes(Blocksize::B256, plaintext, &key256, cypher256);

    }
}
