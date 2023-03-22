/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::utils::bytes;
use ibig::IBig;

// pub struct RecoveryId(u8);

#[derive(Debug)]
pub struct Signature {
    pub s: IBig,
    pub r: IBig,
    // recovery_id: RecoveryId,
}

impl Signature {
    pub fn new(s: IBig, r: IBig) -> Self {
        Self { s, r }
    }

    pub fn to_der(&self) -> Vec<u8> {
        // https://www.rfc-editor.org/rfc/rfc3279#page-7
        let s = bytes::ibig_to_32bytes(self.s.clone(), bytes::ByteOrder::Big);
        let r = bytes::ibig_to_32bytes(self.r.clone(), bytes::ByteOrder::Big);

        let integer_type = 0x02;
        let sequence_type = 0x30;

        let mut der: Vec<u8> = vec![sequence_type, 0];

        der.push(integer_type);
        der.push(r.len() as u8);
        if r[0] >> 7 == 1 {
            *der.last_mut().unwrap() += 1;
            der.push(00);
        }
        der.extend_from_slice(&r);

        der.push(integer_type);
        der.push(s.len() as u8);
        if s[0] >> 7 == 1 {
            *der.last_mut().unwrap() += 1;
            der.push(00);
        }
        der.extend_from_slice(&s);
        let len = der.len() - 2;
        der[1] = len as u8;
        der
    }

    // pub fn from_der() -> Signature {
    //     Signature {

    //     }
    // }

    // fn from_string(str: String) -> Signature {

    // }

    // fn to_string() -> String {

    // }
}