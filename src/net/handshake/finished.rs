use crate::{hash::{TranscriptHash, hmac::HMAC, HashType, hkdf::HKDF}, net::stream::TlsError};
use super::Handshake;
use crate::net::key_schedule::get_hkdf_expand_label;

pub fn get_finished_handshake (hash: HashType, server_secret: &HKDF, ts_hash: &dyn TranscriptHash) -> std::result::Result<Vec<u8>, TlsError> {

    let finished_hash = ts_hash.clone().finalize();

    let finished_key = match server_secret.expand(&get_hkdf_expand_label(b"finished", b"", 48), 48) {
        Some(a) => a,
        None => return Err(TlsError::InternalError)
    };

    let mut verify_data = HMAC::new(hash, &finished_key);
    verify_data.update(&finished_hash);

    Ok(Handshake::to_raw(super::HandshakeType::Finished, verify_data.result()))

}
