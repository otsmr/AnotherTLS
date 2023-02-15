use num_bigint::{BigInt, ToBigInt};
use super::Point;

pub struct Curve {
    pub name: String,
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
    pub n: BigInt,
    pub g: Point,

}


impl Curve {

    /// Returns the curve secp256r1 (NIST P-265)

    pub fn secp256r1() -> Self {
        Curve {
            name: "secp256r1".to_string(),
            p: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap(),
            a: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap(),
            b: BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap(),
            n: BigInt::parse_bytes(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16).unwrap(),
            g: Point {
                x: BigInt::parse_bytes(b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16).unwrap(),
                y: BigInt::parse_bytes(b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16).unwrap()
            }
        }
    }



    /// Verify if the point p is on the curve.
    ///
    /// ```
    /// # use anothertls::crypto::ellipticcurve::curve::Curve;
    /// # use anothertls::crypto::ellipticcurve::Point;
    /// let curve = Curve::secp256r1();
    /// assert_eq!(curve.contains(&Point::u32u(10, 10)), false);
    /// assert_eq!(curve.contains(&curve.g), true);
    /// ```
    pub fn contains(&self, p: &Point) -> bool {

        if p.x >= self.p || p.y >= self.p {
            return false;
        }

        let a = self.a.clone();
        let b = self.b.clone();

        let y_2 = p.y.modpow(&2i32.to_bigint().unwrap(), &self.p);
        let x = (p.x.pow(3) + a * p.x.clone() + b) % self.p.clone();

        if y_2 != x  {
            return false;
        }

        true

    }

}
