use ibig::{ibig, IBig};

use super::curve::Curve;
use super::point::JacobianPoint;
use super::Point;

/// Calculates the modular inverse of `x` with respect to `n` using the Extended Euclidean Algorithm.
///
/// # Arguments
///
/// * `x` - Divisor
/// * `n` - Mod for division
///
/// # Returns
///
/// A value representing the division of `1/x` modulo `n`.
///
/// # Examples
///
/// ```
/// # use ibig::{ibig, IBig};
/// # use anothertls::crypto::ellipticcurve::math::inv;
/// let x = ibig!(7);
/// let n = ibig!(11);
///
/// assert_eq!(inv(&x, &n), ibig!(8));
/// ```
///
/// ```
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
/// ````
/// # use ibig::{ibig, IBig};
/// # use anothertls::crypto::ellipticcurve::math::rem_euclid;
/// let x = ibig!(12);
/// let n = ibig!(11);
///
/// assert_eq!(rem_euclid(&x, &n), ibig!(1));
/// ````
/// ````
/// # use ibig::{ibig, IBig};
/// # use anothertls::crypto::ellipticcurve::math::rem_euclid;
/// let x = ibig!(-5);
/// let n = ibig!(11);
///
/// assert_eq!(rem_euclid(&x, &n), ibig!(6));
/// ````
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

pub fn double(p: Point, curve: &Curve) -> Point {
    jacobian_double(&JacobianPoint::from_point(p), curve).to_point(&curve.p)
}
/// Double a point in elliptic curves
/// p: JacobianPoint you want to double
/// P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
/// A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
fn jacobian_double(p: &JacobianPoint, curve: &Curve) -> JacobianPoint {
    let a = curve.a.clone();
    let prime = &curve.p;

    if p.y == ibig!(0) {
        return JacobianPoint {
            x: ibig!(0),
            y: ibig!(0),
            z: ibig!(0),
        };
    }

    let ysq = p.y.pow(2);
    let s = rem_euclid(&(p.x.clone() * &ibig!(4) * ysq.clone()), prime);
    let m = rem_euclid(
        &(p.x.clone().pow(2) * &ibig!(3) + a * p.z.clone().pow(4)),
        prime,
    );
    let nx = rem_euclid(&(m.pow(2) - &ibig!(2) * s.clone()), prime);
    let ny = rem_euclid(
        &(m * (s - nx.clone()) - &ibig!(8) * ysq.pow(2)),
        prime,
    );
    let nz = rem_euclid(&(p.y.clone() * p.z.clone() * &ibig!(2)), prime);

    JacobianPoint {
        x: nx,
        y: ny,
        z: nz,
    }
}

pub fn add(p: Point, q: Point, curve: &Curve) -> Point {
    jacobian_add(
        &JacobianPoint::from_point(p),
        &JacobianPoint::from_point(q),
        curve,
    )
    .to_point(&curve.p)
}

fn jacobian_add(p: &JacobianPoint, q: &JacobianPoint, curve: &Curve) -> JacobianPoint {
    if p.y == ibig!(0) {
        return q.clone();
    }
    if q.y == ibig!(0) {
        return p.clone();
    }

    let u1 = rem_euclid(&(p.x.clone() * q.z.pow(2)), &curve.p);
    let u2 = rem_euclid(&(q.x.clone() * p.z.pow(2)), &curve.p);
    let s1 = rem_euclid(&(p.y.clone() * q.z.pow(3)), &curve.p);
    let s2 = rem_euclid(&(q.y.clone() * p.z.pow(3)), &curve.p);

    if u1 == u2 {
        if s1 != s2 {
            return JacobianPoint::new(0, 0, 1);
        }
        return jacobian_double(p, curve);
    }

    let h = rem_euclid(&(u2 - u1.clone()), &curve.p);
    let r = rem_euclid(&(s2 - s1.clone()), &curve.p);
    let h2 = rem_euclid(&(h.clone() * h.clone()), &curve.p);
    let h3 = rem_euclid(&(h.clone() * h2.clone()), &curve.p);
    let u1_h2 = rem_euclid(&(u1 * h2), &curve.p);
    let x = rem_euclid(&(r.pow(2) - h3.clone() - IBig::from(2) * u1_h2.clone()), &curve.p);
    let y = rem_euclid(&(r * (u1_h2 - &x) - s1 * h3), &curve.p);
    let z = rem_euclid(&(h * p.z.clone() * q.z.clone()), &curve.p);

    JacobianPoint {x, y, z}
}


pub fn multiply(p: &Point, n: IBig, curve: &Curve) -> Point {
    jacobian_multiply(
        &JacobianPoint::from_point(p.clone()),
        n,
        curve,
    )
    .to_point(&curve.p)
}

pub fn jacobian_multiply(p: &JacobianPoint, n: IBig, curve: &Curve) -> JacobianPoint {

    if p.y == ibig!(0) || n == ibig!(0) {
        return JacobianPoint::new(0, 0, 1);
    }

    if n == ibig!(1) {
        return p.clone();
    }

    if n < ibig!(0) || n >= curve.n {
        return jacobian_multiply(p, rem_euclid(&n, &curve.n), curve);
    }

    let q = jacobian_double(
        &jacobian_multiply(p, n.clone()/2, curve),
        curve
    );

    if rem_euclid(&n, &ibig!(2)) == ibig!(0) {
        return q;
    }

    jacobian_add(&q, p, curve)

}

#[cfg(test)]
mod tests {
    use crate::crypto::ellipticcurve::curve::Curve;
    use crate::crypto::ellipticcurve::point::JacobianPoint;
    use crate::crypto::ellipticcurve::{math, Point};
    use ibig::ibig;

    #[test]
    fn test_jacobian_double() {
        let curve = Curve::secp256r1();
        let point = JacobianPoint::from_point(Point {
            x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
            y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16)
        });
        let result = math::jacobian_double(&point, &curve);

        let point = result.to_point(&curve.p);
        assert!(point.x.eq(&ibig!(_aefb289843cfeba8dd1d1db86cb85f306384994c5a57c109ee018d8ef70b5582 base 16)));
        assert!(point.y.eq(&ibig!(_8b1babf616e2094b38d4b97c5e83182d3478734247a5a8523828430f99668ebf base 16)));
    }

    #[test]
    fn test_jacobian_add() {
        let curve = Curve::secp256r1();
        let p = JacobianPoint::from_point(Point {
            x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
            y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16)
        });
        let q = JacobianPoint::from_point(Point {
            x: ibig!(_7ce1ff2021e6deefb316d445735415e917f1f60c1617e4d21f7671168a1a97f0 base 16),
            y: ibig!(_af3f69d7f46758f99b027372b28c20bc8661422698f91de196695f1415a17c8d base 16)
        });

        let result = math::jacobian_add(&p, &q, &curve);

        let point = result.to_point(&curve.p);
        assert!(point.x.eq(&ibig!(_aba09341535abbb6e7d8a93d6dd69c3251ab4eb0b62e5b6d5af96bf0c4c9950e base 16)));
        assert!(point.y.eq(&ibig!(_91da9e032e4165b8b7115c58251ce1620ebefd8dd221b73bd93ca14c3650e62c base 16)));
    }

    #[test]
    fn test_jacobian_multiply() {
        let curve = Curve::secp256r1();
        let point = JacobianPoint::from_point(Point {
            x: ibig!(_440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61 base 16),
            y: ibig!(_c5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3 base 16)
        });
        let result = math::jacobian_multiply(&point, ibig!(10), &curve);

        let point = result.to_point(&curve.p);
        assert!(point.x.eq(&ibig!(_38bfb2c88dd3dcfc1513aaef707fd37211b8f664625ed52edd1b365b534cfb55 base 16)));
        assert!(point.y.eq(&ibig!(_5d1e3367bfc361ca6c7af6f46bd23e7ac8809d8364344558920b2f475278da52 base 16)));
    }
}
