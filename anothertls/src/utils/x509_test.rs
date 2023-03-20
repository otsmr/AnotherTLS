/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc5280#section-4.1
 *
 */

use ibig::IBig;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::net::alert::TlsError;

use super::bytes;

#[derive(Debug, PartialEq)]
#[repr(u8)]
enum DerType {
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    UTF8String = 0x0C,
    PrintableString = 0x13,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    Sequence = 0x10,
    Set = 0x11,
    ContextSpecific(TagNumber),
}
type TagNumber = u8;
#[derive(Debug)]
enum EncodedForm {
    Constructed(DerType),
    Primitive(DerType),
}

impl DerType {
    fn from_u8(tag: u8) -> Option<EncodedForm> {
        // println!("tag={:#x}", tag);

        let content = tag & 0x1F;
        let der_type = if (tag >> 6 & 0x3) == 0x2 {
            // Context-specific
            DerType::ContextSpecific(tag & 0xf)
        } else {
            match content {
                0x02 => DerType::Integer,
                0x03 => DerType::BitString,
                0x04 => DerType::OctetString,
                0x05 => DerType::Null,
                0x06 => DerType::ObjectIdentifier,
                0x0C => DerType::UTF8String,
                0x13 => DerType::PrintableString,
                0x17 => DerType::UTCTime,
                0x18 => DerType::GeneralizedTime,
                0x10 => DerType::Sequence,
                0x11 => DerType::Set,
                _ => return None,
            }
        };

        if tag >> 5 & 0x1 == 1 {
            if der_type == DerType::Integer
                || der_type == DerType::ObjectIdentifier
                || der_type == DerType::Null
            {
                return None; // Must always use primitive form
            }
            return Some(EncodedForm::Constructed(der_type));
        }
        if der_type == DerType::Sequence || der_type == DerType::Set {
            return None; // Must always use constructed form
        }
        Some(EncodedForm::Primitive(der_type))
    }
}

struct Der();
impl Der {
    fn parse(consumed: &mut usize, data: &[u8]) -> Result<(usize, EncodedForm), TlsError> {
        let der_type = match DerType::from_u8(data[*consumed]) {
            Some(a) => a,
            None => return Err(TlsError::DecodeError),
        };
        *consumed += 1;
        let size = X509::get_len(data, consumed);
        if size > data.len() {
            return Err(TlsError::DecodeError);
        }
        Ok((size, der_type))
    }
}

#[derive(Debug)]
enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}
impl Version {
    fn parse(consumed: &mut usize, data: &[u8]) -> Result<Version, TlsError> {
        let (size, encoded) = Der::parse(consumed, data)?;
        if let EncodedForm::Primitive(DerType::Integer) = encoded {
            if size == 1 {
                *consumed += 1;
                return Ok(match data[*consumed - 1] {
                    0 => Version::V1,
                    1 => Version::V2,
                    2 => Version::V3,
                    _ => return Err(TlsError::DecodeError),
                });
            }
        }
        Err(TlsError::DecodeError)
    }
}
pub type UtcTime = SystemTime;
pub struct Validity {
    not_before: UtcTime,
    not_after: UtcTime,
}
pub type Oid = [u8; 10];
pub type OctetString = Vec<u8>;
pub struct Extension {
    pub id: Oid,
    pub critical: Option<bool>,
    pub value: OctetString,
}

pub enum Algorithms {}
pub struct AlgorithmIdentifier {
    algorithm: Algorithms,
    parameters: Option<BitString>,
}
struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}
// type BitString = Vec<u8>;
struct BitString(Vec<u8>);
impl BitString {
    fn parse(consumed: &mut usize, data: &[u8]) -> Result<BitString, TlsError> {
        todo!()
    }
}
type UniqueIdentifier = BitString;
pub struct Extensions(Vec<Extension>);

pub struct Name(HashMap<String, String>);

pub struct TBSCertificateBuilder {
    version: Option<Version>,
    serial_number: Option<IBig>,
    signature: Option<AlgorithmIdentifier>,
    issuer: Option<Name>,
    validity: Option<Validity>,
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    // issuer_unique_id:
    // subject_unique_id:
    extension: Option<Extensions>,
    raw_data: Option<Vec<u8>>,
}

pub struct SignatureAlgorithm();
impl SignatureAlgorithm {
    fn parse(consumed: &mut usize, data: &[u8]) -> Result<SignatureAlgorithm, TlsError> {
        todo!()
    }
}

pub struct X509Builder {
    tbs_certificate: Option<TBSCertificate>,
    signature_algorithm: Option<SignatureAlgorithm>,
    signature_value: Option<BitString>,
}
