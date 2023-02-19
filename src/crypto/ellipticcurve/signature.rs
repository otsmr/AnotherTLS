
use ibig::IBig;


// pub struct RecoveryId(u8);

pub struct Signature {
    s: IBig,
    r: IBig,
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
