/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::hash::{sha_x, HashType};
use crate::{
    crypto::ellipticcurve::{math, Point},
    hash::hkdf::HKDF,
    net::{named_groups::NamedGroup, stream::TlsError},
    utils::bytes,
};
use ibig::ibig;

use super::handshake::{ClientHello, ServerHello};
use std::result::Result;

pub fn get_hkdf_expand_label(label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![(len >> 8) as u8, len as u8, b't', b'l', b's', b'1', b'3', b' '];
    out.extend_from_slice(label);
    out.extend_from_slice(context);
    out
}

pub struct Key {
    pub key: [u8; 32],
    pub iv: [u8; 12],
    sequence_number: u64
}

impl Key {
    pub fn from_hkdf(hkdf: &HKDF) -> Option<Key> {
        let empty_hash = sha_x(hkdf.hash, b"");
        let (key_len, iv_len) = match hkdf.hash {
            HashType::SHA256 => (16, 12),
            HashType::SHA384 => (32, 12),
            HashType::SHA1 => return None
        };
        let key = hkdf.expand(
            &get_hkdf_expand_label(b"key", &empty_hash, key_len),
            key_len,
        )?;
        let key = key.try_into().unwrap();
        let iv = hkdf.expand(&get_hkdf_expand_label(b"iv", &empty_hash, iv_len), iv_len)?;
        println!("iv_={}", bytes::to_hex(&iv));
        let iv = iv.try_into().unwrap();
        Some(Key { key, iv, sequence_number: 0 })
    }
    pub fn get_per_record_nonce(&mut self) -> Vec<u8> {
        // 5.3.  Per-Record Nonce
        let mut out = self.iv.to_vec();

        for i in 0..8 {
            out[(self.iv.len() - 1) - (7-i)] ^= (self.sequence_number << i) as u8;
        }

        // FIXME: Because the size of sequence numbers is 64-bit, they should not wrap. If a TLS
        // implementation would need to wrap a sequence number, it MUST either rekey (Section
        // 4.6.3) or terminate the connection.
        self.sequence_number += 1;
        out
    }
}

pub struct WriteKeys {
    pub server: Key,
    pub client: Key,
}

impl WriteKeys {
    pub fn handshake_keys(key_schedule: &KeySchedule) -> Option<Self> {
        println!("Get Sever");
        let server = Key::from_hkdf(&key_schedule.server_handshake_traffic_secret)?;
        println!("Get Client");
        let client = Key::from_hkdf(&key_schedule.client_handshake_traffic_secret)?;
        Some(Self { server, client })
    }
    pub fn application_keys(key_schedule: &KeySchedule) -> Option<Self> {
        todo!();
    }
}

// 7.3 Traffic Key Calculation
pub struct KeySchedule {
    // Early Secret
    hkdf_early_secret: HKDF,
    // Handshake Secret
    client_handshake_traffic_secret: HKDF,
    server_handshake_traffic_secret: HKDF,
    // Master Secret
    hkdf_master_secret: HKDF,
}

impl KeySchedule {
    pub fn from_handshake(
        hello_raw: &[u8],
        client_hello: &ClientHello,
        server_hello: &ServerHello,
    ) -> Result<KeySchedule, TlsError> {
        let key_share_entry = match client_hello.get_public_key_share() {
            Some(kse) => kse,
            None => return Err(TlsError::HandshakeFailure),
        };

        if key_share_entry.group != NamedGroup::X25519 {
            // TODO: add support for other curves
            return Err(TlsError::HandshakeFailure);
        }

        let client_public_key = bytes::to_ibig_le(key_share_entry.opaque);
        let client_public_key = Point::new(client_public_key, ibig!(0));

        let server_private_key = server_hello.private_key.secret.clone();
        let curve = &server_hello.private_key.curve;

        let shared_secret = math::multiply(&client_public_key, server_private_key, curve);
        let shared_secret = bytes::ibig_to_32bytes(shared_secret.x, bytes::ByteOrder::Big);

        let hello_hash = sha_x(server_hello.hash, hello_raw);

        match Self::do_key_schedule(server_hello.hash, &hello_hash, &shared_secret) {
            Some(keys) => Ok(keys),
            None => Err(TlsError::HandshakeFailure),
        }
    }

    pub fn _get_early_keys() {

        // TODO: ext binder
        // let binder_key = HKDF::from_prk(hash, hkdf_early_secret.expand(
        //     &get_hkdf_expand_label(b"res binder", client_hello_hash, hash_len),
        //     hash_len,
        // )?);
        // let client_early_traffic_secret = HKDF::from_prk(hash, hkdf_early_secret.expand(
        //     &get_hkdf_expand_label(b"c e traffic", client_hello_hash, hash_len),
        //     hash_len,
        // )?);
        // let early_exporter_master_secret = HKDF::from_prk(hash, hkdf_early_secret.expand(
        //     &get_hkdf_expand_label(b"e exp master", client_hello_hash, hash_len),
        //     hash_len,
        // )?);
    }

    pub fn do_key_schedule(
        hash: HashType,
        hello_hash: &[u8],
        shared_secret: &[u8],
    ) -> Option<KeySchedule> {

        // 7.1 Key Schedule

        let psk = &[];
        let empty_hash = sha_x(hash, b"");
        let hash_len = hash as usize;

        // Early Secret
        let hkdf_early_secret = HKDF::extract(hash, &vec![0_u8; hash_len], psk);

        let derived_secret = hkdf_early_secret.expand(
            &get_hkdf_expand_label(b"derived", &empty_hash, hash_len),
            hash_len,
        )?;

        // Handshake Secret
        let hkdf_handshake_secret = HKDF::extract(hash, &derived_secret, shared_secret);
        let client_handshake_traffic_secret = HKDF::from_prk(
            hash,
            hkdf_handshake_secret.expand(
                &get_hkdf_expand_label(b"c hs traffic", hello_hash, hash_len),
                hash_len,
            )?,
        );
        let server_handshake_traffic_secret = HKDF::from_prk(
            hash,
            hkdf_handshake_secret.expand(
                &get_hkdf_expand_label(b"s hs traffic", hello_hash, hash_len),
                hash_len,
            )?,
        );

        let derived_secret = hkdf_handshake_secret.expand(
            &get_hkdf_expand_label(b"derived", &empty_hash, hash_len),
            hash_len,
        )?;

        // Master Secret
        let hkdf_master_secret = HKDF::extract(hash, &derived_secret, &vec![0_u8; hash_len]);

        Some(KeySchedule {
            hkdf_early_secret,
            // Handshake Secret
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            // Master Secret
            hkdf_master_secret,
        })
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_key_schedule() {
        // TODO: add tests
        // todo!();
    }
}