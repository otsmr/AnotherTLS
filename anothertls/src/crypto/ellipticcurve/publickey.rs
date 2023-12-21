/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::{Curve, Point};

pub struct PublicKey {
    pub point: Point,
    pub curve: Curve,
}

impl PublicKey {
    pub fn new(point: Point, curve: Curve) -> Self {
        Self { point, curve }
    }
}
