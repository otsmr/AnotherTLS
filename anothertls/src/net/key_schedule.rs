/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::crypto::ellipticcurve::PrivateKey;
use crate::crypto::CipherSuite;
use crate::hash::{sha_x, HashType, TranscriptHash};
use crate::{
    crypto::ellipticcurve::{math, Point},
    hash::hkdf::Hkdf,
    net::{alert::TlsError, extensions::NamedGroup},
    utils::bytes,
};
use ibig::ibig;

use super::extensions::KeyShareEntry;
use core::result::Result;

pub fn get_hkdf_expand_label(label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    // 3.4.  Vectors (variable-length vector) <3
    let mut res = vec![(out_len >> 8) as u8, out_len as u8];
    res.push((6 + label.len()) as u8);
    res.extend_from_slice(b"tls13 ");
    res.extend_from_slice(label);
    res.push((context.len()) as u8);
    res.extend_from_slice(context);
    res
}

#[derive(Debug)]
pub struct Key {
    pub traffic_secret: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    sequence_number: u64,
}

impl Key {
    pub fn from_hkdf(hkdf: &Hkdf, key_len: usize, iv_len: usize) -> Option<Key> {
        let key = hkdf.expand(&get_hkdf_expand_label(b"key", b"", key_len), key_len)?;
        let iv = hkdf.expand(&get_hkdf_expand_label(b"iv", b"", iv_len), iv_len)?;
        let iv: [u8; 12] = iv.try_into().unwrap();
        Some(Key {
            traffic_secret: hkdf.pseudo_random_key.to_owned(),
            key,
            iv,
            sequence_number: 0,
        })
    }
    pub fn get_per_record_nonce(&mut self) -> Vec<u8> {
        // 5.3.  Per-Record Nonce
        let mut out = self.iv.to_vec();

        for i in 0..8 {
            out[(12 - 1) - i] ^= (self.sequence_number >> (i * 8)) as u8;
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
    pub fn handshake_keys(key_schedule: &KeySchedule, cs: CipherSuite) -> Option<Self> {
        let (key_len, iv_len) = cs.get_key_and_iv_len();
        let server = Key::from_hkdf(
            &key_schedule.server_handshake_traffic_secret,
            key_len,
            iv_len,
        )?;
        let client = Key::from_hkdf(
            &key_schedule.client_handshake_traffic_secret,
            key_len,
            iv_len,
        )?;
        Some(Self { server, client })
    }
    pub fn application_keys_from_master_secret(
        hkdf_master_secret: &Hkdf,
        handshake_hash: &[u8],
        cs: CipherSuite,
    ) -> Option<Self> {
        let hash = hkdf_master_secret.hash;
        let hash_len = hash as usize;

        let client_application_traffic_secret_0 = Hkdf::from_prk(
            hash,
            hkdf_master_secret.expand(
                &get_hkdf_expand_label(b"c ap traffic", handshake_hash, hash_len),
                hash_len,
            )?,
        );
        let (key_len, iv_len) = cs.get_key_and_iv_len();
        let client = Key::from_hkdf(&client_application_traffic_secret_0, key_len, iv_len)?;
        let server_application_traffic_secret_0 = Hkdf::from_prk(
            hash,
            hkdf_master_secret.expand(
                &get_hkdf_expand_label(b"s ap traffic", handshake_hash, hash_len),
                hash_len,
            )?,
        );
        let server = Key::from_hkdf(&server_application_traffic_secret_0, key_len, iv_len)?;
        Some(Self { server, client })
    }
}

// 7.3 Traffic Key Calculation
pub struct KeySchedule {
    // Early Secret
    // hkdf_early_secret: Hkdf,
    // Handshake Secret
    pub client_handshake_traffic_secret: Hkdf,
    pub server_handshake_traffic_secret: Hkdf,
    // Master Secret
    pub hkdf_master_secret: Hkdf,
}

impl KeySchedule {
    pub fn from_handshake(
        tshash: &dyn TranscriptHash,
        private_key: &PrivateKey,
        key_share_entry: &KeyShareEntry,
    ) -> Result<KeySchedule, TlsError> {
        if key_share_entry.group != NamedGroup::X25519 {
            // TODO: add support for other curves
            return Err(TlsError::HandshakeFailure);
        }

        let client_public_key = bytes::to_ibig_be(&key_share_entry.opaque);
        let client_public_key = Point::new(client_public_key, ibig!(0));

        let server_private_key = private_key.secret.clone();
        let curve = &private_key.curve;

        let shared_secret = math::multiply(&client_public_key, server_private_key, curve);
        let shared_secret = bytes::ibig_to_32bytes(shared_secret.x, bytes::ByteOrder::Big);

        match Self::do_key_schedule(tshash.get_type(), &tshash.finalize(), &shared_secret) {
            Some(keys) => Ok(keys),
            None => Err(TlsError::HandshakeFailure),
        }
    }

    pub fn _get_early_keys() {

        // TODO: ext binder
        // let binder_key = Hkdf::from_prk(hash, hkdf_early_secret.expand(
        //     &get_hkdf_expand_label(b"res binder", client_hello_hash, hash_len),
        //     hash_len,
        // )?);
        // let client_early_traffic_secret = Hkdf::from_prk(hash, hkdf_early_secret.expand(
        //     &get_hkdf_expand_label(b"c e traffic", client_hello_hash, hash_len),
        //     hash_len,
        // )?);
        // let early_exporter_master_secret = Hkdf::from_prk(hash, hkdf_early_secret.expand(
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

        let hash_len = hash as usize;
        let empty_slice = &vec![0_u8; hash_len];
        let empty_hash = sha_x(hash, b"");

        // Early Secret
        let hkdf_early_secret = Hkdf::extract(hash, empty_slice, empty_slice);

        let derived_secret = hkdf_early_secret.expand(
            &get_hkdf_expand_label(b"derived", &empty_hash, hash_len),
            hash_len,
        )?;

        // Handshake Secret
        let hkdf_handshake_secret = Hkdf::extract(hash, &derived_secret, shared_secret);
        let client_handshake_traffic_secret = Hkdf::from_prk(
            hash,
            hkdf_handshake_secret.expand(
                &get_hkdf_expand_label(b"c hs traffic", hello_hash, hash_len),
                hash_len,
            )?,
        );
        let server_handshake_traffic_secret = Hkdf::from_prk(
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
        let hkdf_master_secret = Hkdf::extract(hash, &derived_secret, &vec![0_u8; hash_len]);

        Some(KeySchedule {
            // hkdf_early_secret,
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
