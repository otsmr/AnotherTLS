/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::{curve::Curve, math, publickey::PublicKey};
use crate::utils::{bytes, pem::get_pem_content_from_file};
use ibig::IBig;

pub struct PrivateKey {
    pub curve: Curve,
    pub secret: IBig,
}

impl PrivateKey {
    pub fn new(curve: Curve, secret: IBig) -> PrivateKey {
        PrivateKey { curve, secret }
    }
    pub fn from_pem(filepath: String) -> Option<PrivateKey> {
        let raw = get_pem_content_from_file(filepath)?;
        let secret = raw.get("EC PRIVATE KEY")?;
        let secret = bytes::to_ibig_be(&secret[7..39]);
        // FIXME: PARSE ASN1 OID
        Some(PrivateKey {
            curve: Curve::secp256r1(),
            secret,
        })
    }
    pub fn get_public_key(&self) -> PublicKey {
        let point = math::multiply(&self.curve.g, self.secret.clone(), &self.curve);
        PublicKey::new(point, self.curve.clone())
    }
}
