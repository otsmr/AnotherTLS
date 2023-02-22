/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use ibig::IBig;


// pub struct RecoveryId(u8);

#[derive(Debug)]
pub struct Signature {
    pub s: IBig,
    pub r: IBig,
    // recovery_id: RecoveryId,
}


impl Signature {

    pub fn new (s: IBig, r: IBig) -> Self {
        Self { s, r }
    }

    // pub fn to_der() {

    // }

    // pub fn from_der() -> Signature {
    //     Signature {

    //     }
    // }

    // fn from_string(str: String) -> Signature {

    // }

    // fn to_string() -> String {

    // }
}
