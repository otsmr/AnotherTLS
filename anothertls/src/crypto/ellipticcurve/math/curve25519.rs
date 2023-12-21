/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * Code based (almost completely) on https://martin.kleppmann.com/papers/curve25519.pdf
 */

type FieldElem = [i64; 16];

fn unpack25519(input: [u8; 32]) -> FieldElem {
    let mut out = [0; 16];
    for i in 0..16 {
        out[i] = input[2 * i] as i64 + ((input[2 * i + 1] as i64) << 8);
    }
    out[15] &= 0x7fff;
    out
}

fn carry25519(elem: &mut FieldElem) {
    for i in 0..16 {
        let carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if i < 15 {
            elem[i + 1] += carry;
        } else {
            elem[0] += 38 * carry
        };
    }
}

fn fadd(a: &FieldElem, b: &FieldElem) -> FieldElem /* out = a + b */
{
    let mut out: FieldElem = [0; 16];
    for i in 0..16 {
        out[i] = a[i] + b[i];
    }
    out
}

fn fsub(a: &FieldElem, b: &FieldElem) -> FieldElem /* out = a + b */
{
    let mut out: FieldElem = [0; 16];
    for i in 0..16 {
        out[i] = a[i] - b[i];
    }
    out
}

fn fmul(a: &FieldElem, b: &FieldElem) -> FieldElem /* out = a * b */ {
    let mut out: FieldElem = [0; 16];
    let mut product: [i64; 31] = [0; 31];
    for i in 0..16 {
        for j in 0..16 {
            product[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        product[i] += 38 * product[i + 16]
    }
    out.copy_from_slice(&product[..16]);
    carry25519(&mut out);
    carry25519(&mut out);
    out
}

fn finverse(input: &FieldElem) -> FieldElem {
    let mut c: FieldElem = *input;
    for i in (0..=253).rev() {
        c = fmul(&c, &c);
        if i != 2 && i != 4 {
            c = fmul(&c, input);
        }
    }
    c
}

fn swap25519(p: &mut FieldElem, q: &mut FieldElem, bit: i64) {
    let c = !(bit - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(input: &FieldElem) -> [u8; 32] {
    let mut t = *input;
    let mut m: FieldElem = [0; 16];
    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(&mut t, &mut m, 1 - carry);
    }
    let mut out = [0; 32];
    for i in 0..16 {
        out[2 * i] = t[i] as u8;
        out[2 * i + 1] = (t[i] >> 8) as u8;
    }
    out
}

pub fn scalarmult(point_x: [u8; 32], scalar: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;
    // unpack25519(x, point);
    let mut a: FieldElem = [0; 16];
    let mut b: FieldElem = [0; 16];
    let mut c: FieldElem = [0; 16];
    let mut d: FieldElem = [0; 16];
    let mut e: FieldElem;
    let mut f: FieldElem;

    let x = unpack25519(point_x);
    for i in 0..16 {
        b[i] = x[i];
        d[i] = 0;
        a[i] = 0;
        c[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;
    let mut constant = [0; 16];
    constant[0] = 121665;
    for i in (0..=254).rev() {
        let bit = ((clamped[i >> 3] >> (i & 7)) & 1) as i64;
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        c = fadd(&b, &d);
        b = fsub(&b, &d);
        d = fmul(&e, &e);
        f = fmul(&a, &a);
        a = fmul(&c, &a);
        c = fmul(&b, &e);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        b = fmul(&a, &a);
        c = fsub(&d, &f);
        a = fmul(&c, &constant);
        a = fadd(&a, &d);
        c = fmul(&c, &a);
        a = fmul(&d, &f);
        d = fmul(&b, &x);
        b = fmul(&e, &e);
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    }
    c = finverse(&c);
    a = fmul(&a, &c);
    pack25519(&a)
}
