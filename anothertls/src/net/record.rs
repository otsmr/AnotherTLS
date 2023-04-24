/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc8446#section-5.1
 */

use crate::crypto::Cipher;
use crate::hash::TranscriptHash;
use crate::net::key_schedule::KeySchedule;
use crate::net::{alert::TlsError, key_schedule::WriteKeys};
use crate::utils::bytes;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum RecordType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl RecordType {
    pub fn new(byte: u8) -> Result<RecordType, TlsError> {
        Ok(match byte {
            0 => RecordType::Invalid,
            20 => RecordType::ChangeCipherSpec,
            21 => RecordType::Alert,
            22 => RecordType::Handshake,
            23 => RecordType::ApplicationData,
            _ => return Err(TlsError::DecodeError),
        })
    }
}

pub enum Value<'a> {
    Ref(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> AsRef<[u8]> for Value<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Value::Ref(a) => a,
            Value::Owned(a) => a,
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
            Value::Owned(a) => a.len(),
        }
    }
}

pub struct Record<'a> {
    pub content_type: RecordType,
    pub version: u16,
    pub len: usize,
    pub header: [u8; 5],
    pub fraqment: Value<'a>,
}

impl<'a> Record<'a> {
    pub fn new(content_type: RecordType, fraqment: Value) -> Record {
        Record {
            content_type,
            version: 0x0303,
            header: [content_type as u8, 0x03, 0x03, 0, 0],
            len: fraqment.as_ref().len(),
            fraqment,
        }
    }

    pub fn from_raw(buf: &[u8]) -> Result<(usize, Record), TlsError> {
        if buf.len() < 5 {
            return Err(TlsError::DecodeError);
        }
        let content_type = RecordType::new(buf[0])?;
        let version = ((buf[1] as u16) << 8) | buf[2] as u16;
        let len = (((buf[3] as u16) << 8) | buf[4] as u16) as usize;
        if buf.len() < (2 + len) {
            return Err(TlsError::DecodeError);
        }
        let consumed = 5 + len;
        Ok((
            consumed,
            Record {
                content_type,
                version,
                header: buf[..5].try_into().unwrap(),
                len,
                fraqment: Value::Ref(&buf[5..consumed]),
            },
        ))
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let len = self.fraqment.len();
        let mut t = vec![
            self.content_type as u8,
            0x3,
            0x3,
            (len >> 8) as u8,
            len as u8,
        ];
        t.extend_from_slice(self.fraqment.as_ref());
        t
    }
}

pub struct RecordPayloadProtection {
    pub key_schedule: KeySchedule,
    pub cipher: Box<dyn Cipher>,
    pub handshake_keys: WriteKeys,
    pub is_client: bool,
    pub application_keys: Option<WriteKeys>,
}

impl RecordPayloadProtection {
    pub fn new(key_schedule: KeySchedule, cipher: Box<dyn Cipher>, is_client: bool) -> Option<Self> {
        Some(Self {
            handshake_keys: WriteKeys::handshake_keys(&key_schedule)?,
            // FIMXE: use application_keys
            application_keys: None,
            cipher,
            // application_keys: WriteKeys::handshake_keys(&key_schedule)?,
            key_schedule,
            is_client,
        })
    }

    pub fn generate_application_keys(
        &mut self,
        tshash: &dyn TranscriptHash,
    ) -> Result<(), TlsError> {
        self.application_keys = WriteKeys::application_keys_from_master_secret(
            &self.key_schedule.hkdf_master_secret,
            &tshash.finalize(),
        );
        if self.application_keys.is_none() {
            return Err(TlsError::InternalError);
        }
        Ok(())
    }

    pub fn encrypt_handshake(&mut self, buf: &[u8]) -> Result<Vec<u8>, TlsError> {
        let record = Record::new(RecordType::Handshake, Value::Ref(buf));
        self.encrypt(record)
    }

    pub fn encrypt(&mut self, record: Record) -> Result<Vec<u8>, TlsError> {
        let keys = if self.application_keys.is_none() {
            &mut self.handshake_keys
        } else {
            match &mut self.application_keys {
                Some(e) => e,
                None => return Err(TlsError::InternalError),
            }
        };

        let mut inner_plaintext = record.fraqment.as_ref().to_vec();
        inner_plaintext.push(record.content_type as u8);

        let len_ahead = 16;
        let len = inner_plaintext.len() + len_ahead; // 1 = Inner ContentType
        let mut tls_cipher_text = vec![
            RecordType::ApplicationData as u8,
            0x03,
            0x03,
            (len >> 8) as u8,
            len as u8,
        ];

        let nonce = if self.is_client {
            keys.client.get_per_record_nonce()
        } else {
            keys.server.get_per_record_nonce()
        };

        let key = if self.is_client {
            keys.client.key
        } else {
            keys.server.key
        };

        let (encrypted_record, ahead) =
            match self.cipher.encrypt(&key, &nonce, &inner_plaintext, &tls_cipher_text) {
                Ok(e) => e,
                Err(_) => return Err(TlsError::InternalError),
            };

        tls_cipher_text.extend(encrypted_record);
        tls_cipher_text.extend(bytes::to_bytes(ahead));

        Ok(tls_cipher_text)
    }

    /// Returns Vec instead of a Record because of the borrow checker <3
    pub fn decrypt(&mut self, record: Record) -> Result<(RecordType, Vec<u8>), TlsError> {
        let keys = if self.application_keys.is_some() {
            self.application_keys.as_mut().unwrap()
        } else {
            &mut self.handshake_keys
        };

        let ciphertext = &record.fraqment.as_ref()[..record.fraqment.len() - 16]; // 1 = Inner ContentType
        let ahead = &record.fraqment.as_ref()[ciphertext.len()..];
        let ahead = bytes::to_u128_le(ahead);

        let nonce = if self.is_client {
            keys.server.get_per_record_nonce()
        } else {
            keys.client.get_per_record_nonce()
        };

        let key = if self.is_client {
            keys.server.key
        } else {
            keys.client.key
        };

        let plaintext = match self.cipher.decrypt(&key, &nonce, ciphertext, &record.header, ahead) {
            Ok(e) => e,
            Err(_) => return Err(TlsError::DecryptError),
        };

        // 5.4. Record Padding
        // The receiving implementation scans the field from the end toward the beginning until it
        // finds a non-zero octet. This non-zero octet is the content type of the message

        let mut content_type = RecordType::Invalid;
        let mut record_len = 0;
        for i in (0..plaintext.len()).rev() {
            if plaintext[i] != 0x00 {
                content_type = RecordType::new(plaintext[i])?;
                record_len = i;
                break;
            }
        }

        Ok((content_type, plaintext[..record_len].to_vec()))
    }
}
