/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::utils::bytes;
use ibig::{ibig, IBig};

use crate::rand::{RngCore, SeedableRng, SimpleRng, URandomRng};

use super::{math, Point, PrivateKey, PublicKey, Signature};

pub struct Ecdsa {
    rng: Box<dyn RngCore<IBig>>,
}
impl Ecdsa {
    /// Panics if /dev/urandom can't be read correctly
    pub fn urandom() -> Self {
        Self {
            rng: Box::new(URandomRng::new()),
        }
    }

    #[allow(dead_code)]
    pub fn unsecure() -> Self {
        Self {
            rng: Box::new(SimpleRng::<IBig>::from_seed(ibig!(10))),
        }
    }

    pub fn sign(
        &mut self,
        privkey: &PrivateKey,
        hashed_message: &[u8],
    ) -> Result<Signature, String> {
        let msg = bytes::to_ibig_le(hashed_message);
        let curve = privkey.curve.clone();
        let d = privkey.secret.clone();

        let mut r;
        let mut s;

        loop {
            // 1. Select a cryptographically secure pseudorandom number
            let k = self.rng.between(1, 32);

            // 2. k * G
            let p = math::multiply(&curve.g, k.clone(), &curve);

            // 3. r = p.x mod n, if r == 0, again
            r = math::rem_euclid(&p.x, &curve.n);
            if r == ibig!(0) {
                continue;
            }

            // 4. s = ( (msg + r * d) * inv(k) ) mod n
            s = (msg.clone() + r.clone() * d.clone()) * math::inv(&k, &curve.n);
            s = math::rem_euclid(&s, &curve.n);
            if s == ibig!(0) {
                continue;
            }

            break;
        }

        Ok(Signature::new(s, r))
    }

    pub fn verify(pub_key: PublicKey, sign: &Signature, hashed_message: &[u8]) -> bool {
        // Check Public Key
        // 1.
        if pub_key.point.x == ibig!(0) && pub_key.point.y == ibig!(0) {
            return false;
        }
        // TODO: Check if necessary
        if pub_key.point.x == pub_key.curve.n && pub_key.point.y == pub_key.curve.n {
            return false;
        }
        // 2.
        if !pub_key.curve.contains(&pub_key.point) {
            println!("not containes");
            return false;
        }
        // 3. n * pub_key.point == 0
        // ??

        // Check Signature
        if sign.s <= ibig!(0) {
            return false;
        }

        let z = bytes::to_ibig_le(hashed_message);
        let curve = pub_key.curve;

        let s_inv = math::inv(&sign.s, &curve.n);

        let u1 = math::rem_euclid(&(z * s_inv.clone()), &curve.n);
        let u2 = math::rem_euclid(&(sign.r.clone() * s_inv), &curve.n);

        let u = Point::new(u1, u2);

        let res1 = math::multiply(&curve.g, u.x.clone(), &curve);
        let res2 = math::multiply(&pub_key.point, u.y, &curve);
        let res = math::add(res1, res2, &curve);
        let x = math::rem_euclid(&res.x, &curve.n);

        if x != sign.r {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {

    use crate::utils::bytes;
    use ibig::ibig;

    use crate::crypto::ellipticcurve::{Curve, Ecdsa, PrivateKey};

    #[test]
    fn test_sign_and_verify() {
        let curve = Curve::secp256r1();
        let priv_key = PrivateKey::new(
            curve,
            ibig!(_4d5ecf8ab34b18233241976eb09b14b2507ba2f60ed6c0330b7c2230c806f208 base 16),
        );

        let hashed_message: Vec<u8> =
            bytes::from_hex("a582e8c28249fe7d7990bfa0afebd2da9185a9f831d4215b4efec74f355b301a")
                .unwrap();

        let mut ecdsa = Ecdsa::unsecure();

        let sign = ecdsa.sign(&priv_key, &hashed_message).unwrap();

        assert!(Ecdsa::verify(
            priv_key.get_public_key(),
            &sign,
            &hashed_message
        ));
    }
}
