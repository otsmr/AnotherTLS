/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::{
    hash::{hkdf::Hkdf, hmac::Hmac, TranscriptHash},
    net::{alert::TlsError, handshake::Handshake, key_schedule::get_hkdf_expand_label},
};
use std::result::Result;

pub fn get_finished_handshake(
    secret: &Hkdf,
    tshash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {

    let verify_data = get_verify_data_for_finished(secret, tshash)?;

    Ok(Handshake::to_bytes(
        super::HandshakeType::Finished,
        verify_data,
    ))
}

pub fn get_verify_data_for_finished(
    secret: &Hkdf,
    tshash: &dyn TranscriptHash,
) -> Result<Vec<u8>, TlsError> {
    let finished_hash = tshash.finalize();

    let hash_size = tshash.get_type() as usize;
    let finished_key = match secret.expand(&get_hkdf_expand_label(b"finished", b"", hash_size), hash_size)
    {
        Some(a) => a,
        None => return Err(TlsError::InternalError),
    };

    let mut verify_data = Hmac::new(tshash.get_type(), &finished_key);
    verify_data.update(&finished_hash);

    Ok(verify_data.result())
}
