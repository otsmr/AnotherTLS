use num_traits::One;
use num_bigint::{BigInt, ToBigInt};

use super::math;

#[derive(Clone)]
pub struct Point {
    pub x: BigInt,
    pub y: BigInt,
}

impl Point {
    pub fn u32(x: u32, y: u32) -> Option<Point> {
        Some(Self {
            x: match x.to_bigint() {
                Some(x) => x,
                None => return None,
            },
            y: match y.to_bigint() {
                Some(y) => y,
                None => return None,
            },
        })
    }
    pub fn u32u(x: u32, y: u32) -> Point {
        Self {
            x: x.to_bigint().unwrap(),
            y: y.to_bigint().unwrap(),
        }
    }
}

pub struct JacobianPoint {
    pub x: BigInt,
    pub y: BigInt,
    pub z: BigInt,
}

impl JacobianPoint {
    pub fn from_point(p: Point) -> Self {
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: One::one(),
        }
    }

    pub fn to_point(&self, p: BigInt) -> Point {

        let z = math::inv(&self.z, &p);
        let x = self.x.clone() * z.pow(2) % p.clone();
        let y = self.y.clone() * z.pow(3) % p;

        Point { x, y }
    }
}
