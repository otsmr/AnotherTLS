/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

mod curve25519;
mod jacobian;

use ibig::{ibig, IBig};
use jacobian::{jacobian_add, jacobian_multiply};

use crate::utils::bytes;

use super::curve::Curve;
use super::curve::Equation;
use super::point::JacobianPoint;
use super::Point;

/// Calculates the modular inverse of `x` with respect to `n` using the Extended Euclidean Algorithm.
///
/// ```ignore
/// # use ibig::{ibig, IBig};
/// # use anothertls::crypto::ellipticcurve::math::inv;
/// let x = ibig!(5);
/// let n = ibig!(11);
///
/// assert_eq!(inv(&x, &n), ibig!(9));
/// ```
pub fn inv(x: &IBig, n: &IBig) -> IBig {
    if x.eq(&ibig!(0)) {
        return ibig!(0);
    }

    let mut lm = ibig!(1);
    let mut hm = ibig!(0);
    let mut low = x % n;
    let mut high = n.clone();

    while low > ibig!(1) {
        let r = &high / &low;
        let nm = &hm - &lm * &r;
        let nw = &high - &low * &r;
        high = low;
        hm = lm;
        low = nw;
        lm = nm;
    }

    rem_euclid(&lm, n)
}

/// Calculates the modules
///
/// ```ignore
/// # use ibig::{ibig, IBig};
/// # use anothertls::crypto::ellipticcurve::math::rem_euclid;
/// let x = ibig!(12);
/// let n = ibig!(11);
///
/// assert_eq!(rem_euclid(&x, &n), ibig!(1));
/// ```
pub fn rem_euclid(x: &IBig, v: &IBig) -> IBig {
    let r = x % v;
    if r < ibig!(0) {
        if *v < ibig!(0) {
            r - v
        } else {
            r + v
        }
    } else {
        r
    }
}

// pub fn double(p: Point, curve: &Curve) -> Point {
//     match curve.equation {
//         Equation::ShortWeierstrass => {
//             jacobian_double(&JacobianPoint::from_point(p), curve).to_point(&curve.p)
//         }
//         Equation::Montgomery => {
//             todo!()
//         }
//     }
// }

pub fn add(p: Point, q: Point, curve: &Curve) -> Point {
    match curve.equation {
        Equation::ShortWeierstrass => jacobian_add(
            &JacobianPoint::from_point(p),
            &JacobianPoint::from_point(q),
            curve,
        )
        .to_point(&curve.p),
        Equation::Montgomery => todo!(),
    }
}

pub fn multiply(p: &Point, n: IBig, curve: &Curve) -> Point {
    match curve.equation {
        Equation::Montgomery => {
            let a = bytes::ibig_to_32bytes(n, bytes::ByteOrder::Big);
            let x = bytes::ibig_to_32bytes(p.x.clone(), bytes::ByteOrder::Big);
            let res = curve25519::scalarmult(x, &a);
            Point {
                x: bytes::to_ibig_be(&res),
                y: ibig!(0),
            }
        }
        Equation::ShortWeierstrass => {
            jacobian_multiply(&JacobianPoint::from_point(p.clone()), n, curve).to_point(&curve.p)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::ellipticcurve::{math, Curve, Point};
    use ibig::ibig;

    #[test]
    fn test_curve25519() {
        // openssl genpkey -algorithm x25519 -out x25519-priv.pem
        // openssl pkey -noout -text < x25519-priv.pem
        let curve = Curve::curve25519();
        let p = &curve.g;
        let test_cases = [
            [
                ibig!(_583909765fa12b89f9e986f2beb10e8684fd058b1ddb79dbb4bd48e6ba7be65c base 16),
                ibig!(_771f6d3336a02e79c8c3758fccd6c14971ef40998133fe710fb23474f02d0664 base 16),
            ],
            [
                ibig!(_909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf base 16),
                ibig!(_9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615 base 16),
            ],
        ];
        for test_case in test_cases {
            let scalar = test_case[0].clone();
            let result = math::multiply(p, scalar, &curve);
            let expected = Point {
                x: test_case[1].clone(),
                y: ibig!(0),
            };
            assert!(result == expected);
        }
    }

    // #[test]
    // fn test_weierstrass_double() {
    //     let curve = Curve::secp256r1();
    //     let point = Point {
    //         x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
    //         y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16),
    //     };
    //     let result = math::double(point, &curve);
    //     assert!(result
    //         .x
    //         .eq(&ibig!(_aefb289843cfeba8dd1d1db86cb85f306384994c5a57c109ee018d8ef70b5582 base 16)));
    //     assert!(result
    //         .y
    //         .eq(&ibig!(_8b1babf616e2094b38d4b97c5e83182d3478734247a5a8523828430f99668ebf base 16)));
    // }

    #[test]
    fn test_weierstrass_add() {
        let curve = Curve::secp256r1();
        let p = Point {
            x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
            y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16),
        };
        let q = Point {
            x: ibig!(_7ce1ff2021e6deefb316d445735415e917f1f60c1617e4d21f7671168a1a97f0 base 16),
            y: ibig!(_af3f69d7f46758f99b027372b28c20bc8661422698f91de196695f1415a17c8d base 16),
        };
        let result = math::add(p, q, &curve);
        assert!(result
            .x
            .eq(&ibig!(_aba09341535abbb6e7d8a93d6dd69c3251ab4eb0b62e5b6d5af96bf0c4c9950e base 16)));
        assert!(result
            .y
            .eq(&ibig!(_91da9e032e4165b8b7115c58251ce1620ebefd8dd221b73bd93ca14c3650e62c base 16)));
    }

    #[test]
    fn test_weierstrass_multiply() {
        let curve = Curve::secp256r1();
        let point = Point {
            x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
            y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16),
        };
        let result = math::multiply(&point, ibig!(10), &curve);
        assert!(result
            .x
            .eq(&ibig!(_38bfb2c88dd3dcfc1513aaef707fd37211b8f664625ed52edd1b365b534cfb55 base 16)));
        assert!(result
            .y
            .eq(&ibig!(_5d1e3367bfc361ca6c7af6f46bd23e7ac8809d8364344558920b2f475278da52 base 16)));
    }
}
