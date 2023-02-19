use super::{curve::Curve, math, publickey::PublicKey};
use ibig::IBig;

pub struct PrivateKey {
    pub curve: Curve,
    pub secret: IBig,
}

impl PrivateKey {
    pub fn new(curve: Curve, secret: IBig) -> PrivateKey {
        PrivateKey { curve, secret }
    }

    pub fn get_public_key(&self) -> PublicKey {
        let point = math::multiply(&self.curve.g, self.secret.clone(), &self.curve);
        PublicKey::new(point, self.curve.clone())
    }
}
