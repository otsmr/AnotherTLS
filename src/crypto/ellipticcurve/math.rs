use num_bigint::BigInt;
use num_bigint::ToBigInt;
use num_traits::Zero;

use super::curve::Curve;
use super::point::JacobianPoint;

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
/// # use num_bigint::{BigInt, ToBigInt};
/// # use anothertls::crypto::ellipticcurve::math::inv;
/// let x = 7u32.to_bigint().unwrap();
/// let n = 11u32.to_bigint().unwrap();
///
/// assert_eq!(inv(&x, &n), 8u32.to_bigint().unwrap());
/// ```
///
/// ```
/// # use num_bigint::{BigInt, ToBigInt};
/// # use anothertls::crypto::ellipticcurve::math::inv;
/// let x = 5i32.to_bigint().unwrap();
/// let n = 11i32.to_bigint().unwrap();
///
/// assert_eq!(inv(&x, &n), 9i32.to_bigint().unwrap());
/// ```
pub fn inv(x: &BigInt, n: &BigInt) -> BigInt {
    if x.is_zero() {
        return 0u32.to_bigint().unwrap();
    }

    let mut lm = 1u32.to_bigint().unwrap();
    let mut hm = 0u32.to_bigint().unwrap();
    let mut low = x % n;
    let mut high = n.clone();

    while low > 1u32.to_bigint().unwrap() {
        let r = &high / &low;
        let nm = &hm - &lm * &r;
        let nw = &high - &low * &r;
        high = low;
        hm = lm;
        low = nw;
        lm = nm;
    }

    if lm.lt(&Zero::zero()) {
        lm += n;
    }
    lm
}
/// Double a point in elliptic curves
/// p: JacobianPoint you want to double
/// P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
/// A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
fn jacobian_double(p: &JacobianPoint, curve: &Curve) -> JacobianPoint {

    let a = curve.a.clone();
    let prime = &curve.p;

    if p.y == BigInt::zero() {
        return JacobianPoint {
            x: BigInt::zero(),
            y: BigInt::zero(),
            z: BigInt::zero(),
        };
    }

    let ysq = p.y.modpow(&BigInt::from(2u32), prime);
    let s = (p.x.clone() * &BigInt::from(4u32) * ysq.clone()) % prime;
    let m = (p.x.clone().pow(2u32) * &BigInt::from(3u32) + a * p.z.clone().pow(4u32)) % prime;
    let nx = (m.pow(2u32) - &BigInt::from(2u32) * s.clone()) % prime;
    let ny = (m * (s - nx.clone()) - &BigInt::from(8u32) * ysq.pow(2u32))
        % prime;
    let nz = (p.y.clone() * p.z.clone() * &BigInt::from(2u32)) % prime;

    JacobianPoint {
        x: nx,
        y: ny,
        z: nz,
    }
}


#[cfg(test)]
mod tests {
    use crate::crypto::ellipticcurve::curve::Curve;
    use crate::crypto::ellipticcurve::point::JacobianPoint;
    use crate::crypto::ellipticcurve::math;
    use num_bigint::ToBigInt;

    #[test]
    fn test_jacobian_double() {
        let curve = Curve::secp256r1();
        let point = JacobianPoint::from_point(curve.g.clone());
        let result = math::jacobian_double(&point, &curve);

        let point = result.to_point(curve.p);
        assert_eq!(point.x, 4.to_bigint().unwrap());
        assert_eq!(point.y, 5.to_bigint().unwrap());

    }
}
