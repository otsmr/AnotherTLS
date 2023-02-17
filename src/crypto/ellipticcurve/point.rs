use num_traits::One;
use ibig::{ibig, IBig};

use super::math;

#[derive(Clone, Debug)]
pub struct Point {
    pub x: IBig,
    pub y: IBig,
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

#[derive(Clone, Debug)]
pub struct JacobianPoint {
    pub x: IBig,
    pub y: IBig,
    pub z: IBig,
}

impl JacobianPoint {
    pub fn new(x: i32, y: i32, z: i32) -> Self {
        Self {
            x: x.to_bigint().unwrap(),
            y: y.to_bigint().unwrap(),
            z: z.to_bigint().unwrap(),
        }
    }
    pub fn from_point(p: Point) -> Self {
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: One::one(),
        }
    }

    pub fn to_point(&self, p: &IBig) -> Point {

        let z = math::inv(&self.z, p);
        let x = self.x.clone() * z.pow(2) % p.clone();
        let y = self.y.clone() * z.pow(3) % p;

        Point { x, y }
    }
}
