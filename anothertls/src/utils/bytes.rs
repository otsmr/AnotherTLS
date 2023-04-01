/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use ibig::{ibig, IBig};

// pub fn to_ibig_be(bytes: &[u8]) -> IBig {
//     let mut res = ibig!(0);
//     for (i, byte) in bytes.iter().enumerate() {
//         res += IBig::from(*byte) << (i * 8);
//     }
//     res
// }
pub fn to_ibig_le(bytes: &[u8]) -> IBig {
    let mut res = ibig!(0);
    for (i, byte) in bytes.iter().enumerate() {
        res += IBig::from(*byte) << (((bytes.len() - 1) * 8) - i * 8);
    }
    res
}
#[derive(PartialEq)]
pub enum ByteOrder {
    Little,
    Big
}
pub fn ibig_to_32bytes(num: IBig, order: ByteOrder) -> [u8; 32] {
    let b = <ibig::UBig as std::convert::TryFrom<IBig>>::try_from(num).unwrap();
    let b = if order == ByteOrder::Big {
        b.to_be_bytes()
    } else {
        b.to_le_bytes()
    };
    let mut c = [0; 32];
    for (i, d) in b.iter().enumerate() {
        if i >= 32 {
            break;
        }
        c[i] = *d;
    }
    c
}
pub fn to_bytes(num: u128) -> [u8; 16] {
    let mut res = [0u8; 16];
    for (i, r) in res.iter_mut().enumerate() {
        *r = (num >> ((15 * 8) - i * 8)) as u8;
    }
    res
}

pub fn str_to_u8(s: &str) -> u8 {
    match &s[..1] {
        "1" => 1,
        "2" => 2,
        "3" => 3,
        "4" => 4,
        "5" => 5,
        "6" => 6,
        "7" => 7,
        "8" => 8,
        "9" => 9,
        _ => 0
    }

}
pub fn str_to_u16(s: &str) -> u16 {
    ((str_to_u8(&s[..1]) as u16)*10) + str_to_u8(&s[1..2]) as u16
}
// pub fn to_u32(buf: &[u8]) -> u32 {
//     if buf.is_empty() {
//         return 0;
//     }
//     let mut res = buf[0] as u32;
//     if buf.len() > 1 {
//         res += (res << 8) | buf[1] as u32;
//     }
//     if buf.len() > 2 {
//         res += (res << 8) | buf[2] as u32;
//     }
//     if buf.len() > 3 {
//         res += (res << 8) | buf[3] as u32;
//     }
//     res
// }
pub fn to_u16(buf: &[u8]) -> u16 {
    if buf.is_empty() {
        return 0;
    }
    if buf.len() < 2 {
        return buf[0] as u16;
    }
    ((buf[0] as u16) << 8) | buf[1] as u16
}
pub fn to_u128_le_fill(bytes: &[u8]) -> u128 {
    let mut new = [0; 16];
    let bytes: &[u8] = match bytes.len() {
        a if a < 16 => {
            for (i, b) in bytes.iter().enumerate() {
                new[(16 - bytes.len()) + i] = *b;
            }
            &new
        },
        a if a > 16 => &bytes[..16],
        _ => bytes
    };
    to_u128_le(bytes)
}
pub fn to_u128_le(bytes: &[u8]) -> u128 {
    // if bytes.len() < 128/8 filling 0 at the END
    let mut res: u128 = 0;
    let bytes: &[u8] = match bytes.len() {
        a if a > 16 => &bytes[..16],
        _ => bytes
    };
    for (i, byte) in bytes.iter().enumerate() {
        res += (*byte as u128) << ((15 * 8) - i * 8);
    }
    res
}
pub fn to_u64_le(bytes: &[u8]) -> u64 {
    let mut res: u64 = 0;
    for (i, byte) in bytes[..8].iter().enumerate() {
        res += (*byte as u64) << ((7 * 8) - i * 8);
    }
    res
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

#[allow(dead_code)]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}
