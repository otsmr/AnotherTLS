/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::Point;
use ibig::{ibig, IBig};

#[derive(Clone, Debug)]
pub enum Equation {
    ShortWeierstrass,
    Montgomery,
    // Edwards
}

#[derive(Clone, Debug)]
pub struct Curve {
    pub name: String,
    pub equation: Equation,
    pub p: IBig,  // finite field
    pub a: IBig,  // used in equation
    pub b: IBig,  // used in equation
    pub n: IBig,  // prime order
    pub g: Point, // base point of prime order
}

impl Curve {
    pub fn secp256r1() -> Self {
        Curve {
            name: "secp256r1 (also known as NIST P-265)".to_string(),
            equation: Equation::ShortWeierstrass,
            p: ibig!(_ffffffff00000001000000000000000000000000ffffffffffffffffffffffff base 16),
            a: ibig!(_ffffffff00000001000000000000000000000000fffffffffffffffffffffffc base 16),
            b: ibig!(_5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b base 16),
            n: ibig!(_ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 base 16),
            g: Point {
                x: ibig!(_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 base 16),
                y: ibig!(_4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 base 16),
            },
        }
    }

    pub fn curve25519() -> Self {
        Curve {
            name: "Curve25519".to_string(),
            equation: Equation::Montgomery,
            p: ibig!(_7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed base 16),
            a: ibig!(486662),
            b: ibig!(1),
            n: ibig!(_1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed base 16),
            g: Point {
                x: ibig!(9),
                y: ibig!(_20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9 base 16),
            },
        }
    }

    /// Verify if the point p is on the curve.
    ///
    /// ```ignore
    /// # use anothertls::crypto::ellipticcurve::curve::Curve;
    /// # use anothertls::crypto::ellipticcurve::Point;
    /// let curve = Curve::secp256r1();
    /// assert_eq!(curve.contains(&Point::u32(10, 10)), false);
    /// assert_eq!(curve.contains(&curve.g), true);
    /// ```
    /// ```ignore
    /// # use anothertls::crypto::ellipticcurve::curve::Curve;
    /// # use anothertls::crypto::ellipticcurve::Point;
    /// let curve = Curve::curve25519();
    /// assert_eq!(curve.contains(&Point::u32(10, 10)), false);
    /// assert_eq!(curve.contains(&curve.g), true);
    /// ```
    pub fn contains(&self, p: &Point) -> bool {
        if p.x >= self.p || p.y >= self.p {
            return false;
        }
        let a = self.a.clone();
        let b = self.b.clone();
        let x = p.x.clone();
        let mut left = p.y.pow(2);
        let mut right = match self.equation {
            Equation::ShortWeierstrass => p.x.pow(3) + a * x + b,
            Equation::Montgomery => {
                left *= b;
                p.x.pow(3) + a * p.x.pow(2) + x
            }
        };
        left %= self.p.clone();
        right %= self.p.clone();
        left == right
    }
}
