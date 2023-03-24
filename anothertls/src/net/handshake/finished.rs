/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::{
    hash::{hkdf::Hkdf, hmac::Hmac, HashType, TranscriptHash},
    net::{alert::TlsError, handshake::Handshake, key_schedule::get_hkdf_expand_label},
};
use std::result::Result;

pub fn get_finished_handshake(
    hash: HashType,
    server_secret: &Hkdf,
    ts_hash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {
    let finished_hash = ts_hash.clone().finalize();

    let finished_key = match server_secret.expand(&get_hkdf_expand_label(b"finished", b"", 48), 48)
    {
        Some(a) => a,
        None => return Err(TlsError::InternalError),
    };

    let mut verify_data = Hmac::new(hash, &finished_key);
    verify_data.update(&finished_hash);

    Ok(Handshake::to_raw(
        super::HandshakeType::Finished,
        verify_data.result(),
    ))
}

pub fn get_verify_client_finished(
    client_secret: &Hkdf,
    ts_hash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {
    let finished_hash = ts_hash.clone().finalize();

    let finished_key = match client_secret.expand(&get_hkdf_expand_label(b"finished", b"", 48), 48)
    {
        Some(a) => a,
        None => return Err(TlsError::InternalError),
    };

    let mut verify_data = Hmac::new(ts_hash.get_type(), &finished_key);
    verify_data.update(&finished_hash);

    Ok(verify_data.result())
}
