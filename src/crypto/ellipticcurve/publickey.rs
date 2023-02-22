use super::{Point, Curve};


pub struct PublicKey {
    pub point: Point,
    pub curve: Curve
}

impl PublicKey {
    pub fn new (point: Point, curve: Curve) -> Self {
        Self {point, curve }
    }
}
