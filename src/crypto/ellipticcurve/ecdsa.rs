use ibig::{IBig, ibig};
use crate::rand::{SimpleRng, SeedableRng, RngCore };

use super::{privatekey::PrivateKey, signature::Signature, math};


fn bytes_to_ibig_le (bytes: &[u8]) -> IBig {

    let mut res = ibig!(0);

    for (i, byte) in bytes.iter().enumerate() {
        res += byte << (i * 8);
    }

    res

}

pub fn sign(privkey: &PrivateKey, message: &[u8]) -> Result<Signature, String> {

    let msg: IBig = bytes_to_ibig_le(message);

    let curve = privkey.curve.clone();
    let d = privkey.secret.clone();

    let mut r;
    let mut s;
    let mut rng = SimpleRng::<IBig>::from_seed(ibig!(10));

    loop {

        // 1. Select a cryptographically secure random integer
        let k = rng.between(ibig!(1), curve.p.clone()-1);

        // 2. k * G
        let p = math::multiply(&curve.g, k.clone(), &curve);

        // 3. r = p.x mod n, if r == 0, again
        r = math::rem_euclid(&p.x, &curve.n);
        if r == ibig!(0) {
            continue;
        }

        // 4. s = ( (msg + r * d) * inv(k) ) mod n
        s = ( msg.clone() + r.clone() * d.clone() ) * math::inv(&k, &curve.n);
        s = math::rem_euclid(&s, &curve.n);
        if s == ibig!(0) {
            continue;
        }

        break;

    }

    Ok(Signature::new(s, r))

}

// pub fn verify(pub_key: PublicKey, sign: Signature) -> bool {




// }
