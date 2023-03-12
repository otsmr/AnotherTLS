/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub enum NamedGroup {
    // Elliptic Curve Groups (ECDHE)
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    // Finite Field Groups (DHE)
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}

impl NamedGroup {
    pub fn new(num: u16) -> Option<NamedGroup> {
        Some(match num {
            0x0017 => Self::Secp256r1,
            0x0018 => Self::Secp384r1,
            0x0019 => Self::Secp521r1,
            0x001D => Self::X25519,
            0x001E => Self::X448,
            0x0100 => Self::Ffdhe2048,
            0x0101 => Self::Ffdhe3072,
            0x0102 => Self::Ffdhe4096,
            0x0103 => Self::Ffdhe6144,
            0x0104 => Self::Ffdhe8192,
            _ => return None,
        })
    }
}
