/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use ibig::{IBig, ibig};

use super::math;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: IBig,
    pub y: IBig,
}

impl Point {
    pub fn new(x: IBig, y: IBig) -> Point {
        Self { x, y }
    }
    pub fn u32(x: u32, y: u32) -> Point {
        Self {
            x: IBig::from(x),
            y: IBig::from(y),
        }
    }
}

#[derive(Clone, Debug)]
pub struct JacobianPoint {
    pub x: IBig,
    pub y: IBig,
    pub z: IBig,
}

impl JacobianPoint {
    pub fn new(x: i32, y: i32, z: i32) -> Self {
        Self {
            x: IBig::from(x),
            y: IBig::from(y),
            z: IBig::from(z),
        }
    }
    pub fn from_point(p: Point) -> Self {
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: ibig!(1),
        }
    }

    pub fn to_point(&self, p: &IBig) -> Point {

        let z = math::inv(&self.z, p);
        let x = self.x.clone() * z.pow(2) % p.clone();
        let y = self.y.clone() * z.pow(3) % p;

        Point { x, y }
    }
}
