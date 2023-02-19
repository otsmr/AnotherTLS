use super::{Point, curve::Curve};


pub struct PublicKey {
    point: Point,
    curve: Curve
}

impl PublicKey {
    pub fn new (point: Point, curve: Curve) -> Self {
        Self {point, curve }
    }
}
