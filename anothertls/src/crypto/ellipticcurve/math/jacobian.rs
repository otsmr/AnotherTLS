
use super::rem_euclid;
use crate::crypto::ellipticcurve::math::IBig;
use crate::crypto::ellipticcurve::Curve;
use crate::crypto::ellipticcurve::JacobianPoint;
use ibig::ibig;

pub(crate) fn jacobian_double(p: &JacobianPoint, curve: &Curve) -> JacobianPoint {
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
    let ny = rem_euclid(&(m * (s - nx.clone()) - &ibig!(8) * ysq.pow(2)), prime);
    let nz = rem_euclid(&(p.y.clone() * p.z.clone() * &ibig!(2)), prime);

    JacobianPoint {
        x: nx,
        y: ny,
        z: nz,
    }
}

pub(crate) fn jacobian_add(p: &JacobianPoint, q: &JacobianPoint, curve: &Curve) -> JacobianPoint {
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
    let x = rem_euclid(
        &(r.pow(2) - h3.clone() - IBig::from(2) * u1_h2.clone()),
        &curve.p,
    );
    let y = rem_euclid(&(r * (u1_h2 - &x) - s1 * h3), &curve.p);
    let z = rem_euclid(&(h * p.z.clone() * q.z.clone()), &curve.p);

    JacobianPoint { x, y, z }
}

fn get_nbits(n: IBig) -> usize {
    for i in (0..256).rev() {
        if n.clone() >> i & 1 == ibig!(1) {
            return i + 1;
        }
    }
    1
}

pub fn jacobian_multiply(p: &JacobianPoint, n: IBig, curve: &Curve) -> JacobianPoint {

    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder

    let mut r0 = JacobianPoint::new(0, 0, 1);
    let mut r1 = p.clone();
    let nbits = get_nbits(n.clone());

    for i in (0..nbits).rev() {
        if n.clone() >> i & 1 == ibig!(1) {
            r0 = jacobian_add(&r0, &r1, curve);
            r1 = jacobian_double(&r1, curve);
        } else {
            r1 = jacobian_add(&r0, &r1, curve);
            r0 = jacobian_double(&r0, curve);
        }
    }
    r0
}
// pub fn jacobian_multiply(p: &JacobianPoint, n: IBig, curve: &Curve) -> JacobianPoint {
//     if p.y == ibig!(0) || n == ibig!(0) {
//         return JacobianPoint::new(0, 0, 1);
//     }

//     if n == ibig!(1) {
//         return p.clone();
//     }

//     if n < ibig!(0) || n >= curve.n {
//         return jacobian_multiply(p, rem_euclid(&n, &curve.n), curve);
//     }

//     let q = jacobian_double(&jacobian_multiply(p, n.clone() / 2, curve), curve);

//     if rem_euclid(&n, &ibig!(2)) == ibig!(0) {
//         return q;
//     }

//     jacobian_add(&q, p, curve)
// }
