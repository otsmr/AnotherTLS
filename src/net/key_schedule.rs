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
    let mut out = vec![(len >> 8) as u8, len as u8, b't', b'l', b's', b'1', b'3'];
    out.extend_from_slice(label);
    out.extend_from_slice(context);
    out
}

pub struct Key {
    key: [u8; 32],
    iv: [u8; 12],
}

impl Key {
    pub fn from_hkdf(hkdf: HKDF) -> Option<Key> {
        let empty_hash = sha_x(hkdf.hash, b"");
        let key_len = 32;
        let iv_len = 12;
        let key = hkdf.expand(
            &get_hkdf_expand_label(b"key", &empty_hash, key_len),
            key_len,
        )?;
        let key = key.try_into().unwrap();
        let iv = hkdf.expand(&get_hkdf_expand_label(b"iv", &empty_hash, iv_len), iv_len)?;
        let iv = iv.try_into().unwrap();
        Some(Key { key, iv })
    }
}

pub struct HandshakeKeys {
    server: Key,
    client: Key,
}

impl HandshakeKeys {
    pub fn new(key_schedule: KeySchedule) -> Option<HandshakeKeys> {
        let server = Key::from_hkdf(key_schedule.server_handshake_traffic_secret)?;
        let client = Key::from_hkdf(key_schedule.client_handshake_traffic_secret)?;
        Some(HandshakeKeys { server, client })
    }
}

// 7.3 Traffic Key Calculation
pub struct KeySchedule {
    // binder_key: HKDF,
    // client_early_traffic_secret: HKDF,
    // early_exporter_master_secret: HKDF,
    client_handshake_traffic_secret: HKDF,
    server_handshake_traffic_secret: HKDF,
    // client_application_traffic_secret_0: HKDF,
    // client_application_traffic_secret_0: HKDF,
    // exporter_master_secret: HKDF,
    // resumption_master_secret: HKDF
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

        let client_public_key = key_share_entry.opaque;
        let client_public_key = bytes::to_ibig_le(client_public_key);

        let client_public_key = Point::new(client_public_key, ibig!(0));

        let server_private_key = server_hello.private_key.secret.clone();
        let curve = &server_hello.private_key.curve;

        let shared_secret = math::multiply(&client_public_key, server_private_key, curve);
        let shared_secret = shared_secret.x;
        let shared_secret = bytes::ibig_to_bytes(shared_secret);

        let hello_hash = sha_x(server_hello.hash, hello_raw);

        match Self::do_key_schedule(server_hello.hash, &hello_hash, &shared_secret) {
            Some(keys) => Ok(keys),
            None => Err(TlsError::HandshakeFailure),
        }
    }

    pub fn do_key_schedule(
        hash: HashType,
        hello_hash: &[u8],
        shared_secret: &[u8],
    ) -> Option<KeySchedule> {
        let hash_len = hash as usize;
        // 7.1 Key Schedule

        let psk = &[];

        let empty_hash = sha_x(hash, b"");
        // Early Secret
        let hkdf_early_secret = HKDF::extract(hash, &vec![0_u8; hash_len], psk);

        let derived_secret = hkdf_early_secret.expand(
            &get_hkdf_expand_label(b"derived", &empty_hash, hash_len),
            hash_len,
        )?;

        // Handshake Secret
        let hkdf_handshake_secret = HKDF::extract(hash, &derived_secret, shared_secret);

        let client_handshake_traffic_secret = hkdf_handshake_secret.expand(
            &get_hkdf_expand_label(b"c hs traffic", hello_hash, hash_len),
            hash_len,
        )?;
        let client_handshake_traffic_secret = HKDF::from_prk(hash, client_handshake_traffic_secret);

        let server_handshake_traffic_secret = hkdf_handshake_secret.expand(
            &get_hkdf_expand_label(b"s hs traffic", hello_hash, hash_len),
            hash_len,
        )?;
        let server_handshake_traffic_secret = HKDF::from_prk(hash, server_handshake_traffic_secret);

        Some(KeySchedule {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
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
