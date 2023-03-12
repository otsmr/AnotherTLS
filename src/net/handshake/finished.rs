/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use super::Handshake;
use crate::net::key_schedule::get_hkdf_expand_label;
use crate::{
    hash::{hkdf::HKDF, hmac::HMAC, HashType, TranscriptHash},
    net::stream::TlsError,
};
use std::result::Result;

pub fn get_finished_handshake(
    hash: HashType,
    server_secret: &HKDF,
    ts_hash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {
    let finished_hash = ts_hash.clone().finalize();

    let finished_key = match server_secret.expand(&get_hkdf_expand_label(b"finished", b"", 48), 48)
    {
        Some(a) => a,
        None => return Err(TlsError::InternalError),
    };

    let mut verify_data = HMAC::new(hash, &finished_key);
    verify_data.update(&finished_hash);

    Ok(Handshake::to_raw(
        super::HandshakeType::Finished,
        verify_data.result(),
    ))
}

pub fn get_verify_client_finished(
    client_secret: &HKDF,
    ts_hash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {
    let finished_hash = ts_hash.clone().finalize();

    let finished_key = match client_secret.expand(&get_hkdf_expand_label(b"finished", b"", 48), 48)
    {
        Some(a) => a,
        None => return Err(TlsError::InternalError),
    };

    let mut verify_data = HMAC::new(ts_hash.get_type(), &finished_key);
    verify_data.update(&finished_hash);

    Ok(verify_data.result())
}
