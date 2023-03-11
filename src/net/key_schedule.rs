/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use std::io::Write;
use crate::hash::{sha_x, HashType, TranscriptHash};
use crate::{
    crypto::ellipticcurve::{math, Point},
    hash::hkdf::HKDF,
    net::{named_groups::NamedGroup, stream::TlsError},
    utils::bytes,
};
use ibig::ibig;

use super::handshake::{ClientHello, ServerHello};
use std::fs::OpenOptions;
use std::result::Result;


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
    pub key: [u8; 32],
    pub iv: [u8; 12],
    sequence_number: u64,
}

impl Key {
    pub fn from_hkdf(hkdf: &HKDF) -> Option<Key> {
        let (key_len, iv_len) = match hkdf.hash {
            HashType::SHA256 => (16, 12),
            HashType::SHA384 => (32, 12),
            HashType::SHA1 => return None,
        };
        let key = hkdf.expand(&get_hkdf_expand_label(b"key", b"", key_len), key_len)?;
        let key = key.try_into().unwrap();
        let iv = hkdf.expand(&get_hkdf_expand_label(b"iv", b"", iv_len), iv_len)?;
        let iv: [u8; 12] = iv.try_into().unwrap();
        Some(Key {
            key,
            iv,
            sequence_number: 0,
        })
    }
    pub fn get_per_record_nonce(&mut self) -> Vec<u8> {
        // 5.3.  Per-Record Nonce
        let mut out = self.iv.to_vec();

        for i in 0..8 {
            out[(self.iv.len() - 1) - i] ^= (self.sequence_number << (i * 8)) as u8;
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
        let server = Key::from_hkdf(&key_schedule.server_handshake_traffic_secret)?;
        let client = Key::from_hkdf(&key_schedule.client_handshake_traffic_secret)?;
        Some(Self { server, client })
    }
    pub fn application_keys_from_master_secret(hkdf_master_secret: &HKDF, handshake_hash: &[u8]) -> Option<Self> {
        let hash = hkdf_master_secret.hash;
        let hash_len = hash as usize;

        let client_application_traffic_secret_0 = HKDF::from_prk(
            hash,
            hkdf_master_secret.expand(
                &get_hkdf_expand_label(b"c ap traffic", handshake_hash, hash_len),
                hash_len,
            )?,
        );
        let client = Key::from_hkdf(&client_application_traffic_secret_0)?;
        let server_application_traffic_secret_0 = HKDF::from_prk(
            hash,
            hkdf_master_secret.expand(
                &get_hkdf_expand_label(b"s ap traffic", handshake_hash, hash_len),
                hash_len,
            )?,
        );
        let server = Key::from_hkdf(&server_application_traffic_secret_0)?;
        Some(Self { server, client })
    }
}

// 7.3 Traffic Key Calculation
pub struct KeySchedule {
    // Early Secret
    // hkdf_early_secret: HKDF,
    // Handshake Secret
    pub(crate) client_handshake_traffic_secret: HKDF,
    pub(crate) server_handshake_traffic_secret: HKDF,
    // Master Secret
    pub(crate) hkdf_master_secret: HKDF,
}

impl KeySchedule {
    pub fn from_handshake(
        ts_hash: &dyn TranscriptHash,
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

        let hello_hash = ts_hash.clone().finalize();

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

        let hash_len = hash as usize;
        let empty_slice = &vec![0_u8; hash_len];
        let empty_hash = sha_x(hash, b"");

        // Early Secret
        let hkdf_early_secret = HKDF::extract(hash, empty_slice, empty_slice);

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
            // hkdf_early_secret,
            // Handshake Secret
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            // Master Secret
            hkdf_master_secret,
        })
    }
    pub fn create_keylog_file(&self, filepath: &str, client_random: &[u8]) {
        let mut content = String::new();

        let client_random = bytes::to_hex(client_random);

        content += "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
        content += &client_random;
        content += " ";
        content += &bytes::to_hex(&self.server_handshake_traffic_secret.pseudo_random_key);
        content += "\n";

        content += "CLIENT_HANDSHAKE_TRAFFIC_SECRET ";
        content += &client_random;
        content += " ";
        content += &bytes::to_hex(&self.client_handshake_traffic_secret.pseudo_random_key);
        // content += "\n";

        // content += "EXPORTER_SECRET ";
        // content += &client_random;
        // content += " ";
        // content += &bytes::to_hex(&self.hkdf_early_secret.pseudo_random_key);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(filepath)
            .unwrap_or_else(|_| panic!("Couldn't open or create file {}", filepath));

        if let Err(e) = writeln!(file, "{}", content) {
            eprintln!("Couldn't write to file: {}", e);
        }
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
