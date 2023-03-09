/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc8446#section-5.1
 */

use crate::{net::key_schedule::KeySchedule, crypto::aes::gcm::GCM, utils::bytes};

use super::{key_schedule::WriteKeys, stream::TlsError};
#[derive(PartialEq, Clone, Copy)]
pub enum RecordType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl RecordType {
    pub fn new(byte: u8) -> Option<RecordType> {
        Some(match byte {
            0 => RecordType::Invalid,
            20 => RecordType::ChangeCipherSpec,
            21 => RecordType::Alert,
            22 => RecordType::Handshake,
            23 => RecordType::ApplicationData,
            _ => return None,
        })
    }
}

pub enum Value<'a> {
    Ref(&'a [u8]),
    Owned(Vec<u8>)
}

impl<'a> AsRef<[u8]> for Value<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Value::Ref(a) => a,
            Value::Owned(a) => a
        }
    }
}

impl<'a> Value<'a> {

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        match self {
            Value::Ref(a) => a.len(),
            Value::Owned(a) => a.len()
        }
    }

}

pub struct Record<'a> {
    pub content_type: RecordType,
    pub version: u16,
    pub len: u16,
    pub fraqment: Value<'a>,
}

impl<'a> Record<'a> {
    pub fn new (content_type: RecordType, fraqment: &'a [u8]) -> Record {
        Record { content_type, version: 0x0303, len: 0, fraqment: Value::Ref(fraqment)}
    }

    pub fn from_raw(buf: &[u8]) -> Option<Record> {
        if buf.len() < 5 {
            return None;
        }

        let content_type = RecordType::new(buf[0])?;
        let version = ((buf[1] as u16) << 8) | buf[2] as u16;
        let len = ((buf[3] as u16) << 8) | buf[4] as u16;

        Some(Record {
            content_type,
            version,
            len,
            fraqment: Value::Ref(&buf[5..]),
        })
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        Record::to_raw(self.content_type, self.fraqment.as_ref())
    }
    pub fn to_raw(typ: RecordType, data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let mut t = vec![typ as u8, 0x3, 0x3, (len >> 8) as u8, len as u8];
        t.extend_from_slice(data);
        t
    }
    pub fn is_full(&self) -> bool {
        self.len == self.fraqment.len() as u16
    }
}


pub struct RecordPayloadProtection {
    key_schedule: KeySchedule,
    handshake_keys: WriteKeys,
    // application_keys: WriteKeys
}

impl RecordPayloadProtection {

    pub fn new (key_schedule: KeySchedule) -> Option<Self> {
        Some(Self {
            handshake_keys: WriteKeys::handshake_keys(&key_schedule)?,
            // FIMXE: use application_keys
            // application_keys: WriteKeys::handshake_keys(&key_schedule)?,
            key_schedule,
        })
    }

    pub fn encrypt(&mut self, record: Record) -> Result<Vec<u8>, TlsError>  {

        let keys = if let RecordType::Handshake = record.content_type {
            &mut self.handshake_keys
        } else {
            todo!();
            // &mut self.application_keys
        };

        let mut inner_plaintext = record.fraqment.as_ref().to_vec();
        inner_plaintext.push(record.content_type as u8);

        let len = inner_plaintext.len() + 16; // 1 = Inner ContentType
        let mut tls_cipher_text = vec![RecordType::ApplicationData as u8, 0x03, 0x03, (len >> 8) as u8, len as u8];

        let nonce = keys.server.get_per_record_nonce();

        let (encrypted_record, ahead) = match GCM::encrypt(&keys.server.key, &nonce, &inner_plaintext, &tls_cipher_text) {
            Ok(e) => e,
            Err(_) => return Err(TlsError::InternalError)
        };

        tls_cipher_text.extend(encrypted_record);
        tls_cipher_text.extend(bytes::to_bytes(ahead));

        Ok(tls_cipher_text)

    }

    pub fn decrypt(&self, record: Record) -> Record {
        todo!()
    }

}
