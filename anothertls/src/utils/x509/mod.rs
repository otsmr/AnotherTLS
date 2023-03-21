/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 * https://www.rfc-editor.org/rfc/rfc5280#section-4.1
 *
 */

use crate::crypto::ellipticcurve::Signature;
use crate::utils::bytes::str_to_u16;
use std::collections::HashMap;

use ibig::IBig;

use crate::net::alert::TlsError;
use crate::utils::bytes;

#[derive(Debug)]
pub struct UtcTime {
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
}

impl UtcTime {
    fn from_utc_timestamp(t: &str) -> Option<UtcTime> {
        if t.len() < 12 {
            return None;
        }
        let (mut year, month, day, hour, minute, second) = (
            str_to_u16(&t[0..]),
            str_to_u16(&t[2..]),
            str_to_u16(&t[4..]),
            str_to_u16(&t[6..]),
            str_to_u16(&t[8..]),
            str_to_u16(&t[10..]),
        );
        if year < 50 {
            year += 2000;
        } else {
            year += 1900;
        }
        Some(UtcTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }
}

pub struct Validity {
    not_before: Option<UtcTime>,
    not_after: Option<UtcTime>,
}
impl Validity {
    fn new() -> Validity {
        Validity {
            not_before: None,
            not_after: None,
        }
    }
}
pub type Oid = [u8; 10];
pub type OctetString = Vec<u8>;
pub struct Extension {
    pub id: Oid,
    pub critical: Option<bool>,
    pub value: OctetString,
}

#[derive(Debug, PartialEq)]
pub enum Algorithms {
    EcdsaWithSha256,
    EcPublicKey,
}
impl Algorithms {
    pub fn new(s: &str) -> Result<Algorithms, TlsError> {
        Ok(match s {
            "ecdsaWithSHA256" => Algorithms::EcdsaWithSha256,
            "ecPublicKey" => Algorithms::EcPublicKey,
            _ => return Err(TlsError::DecodeError),
        })
    }
}
pub struct AlgorithmIdentifier {
    algorithm: Algorithms,
    parameters: Option<String>,
}
impl AlgorithmIdentifier {
    pub fn new(algorithm: Algorithms) -> AlgorithmIdentifier {
        AlgorithmIdentifier {
            algorithm,
            parameters: None,
        }
    }
}
struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

struct SubjectPublicKeyInfoBuilder {
    algorithm: Option<AlgorithmIdentifier>,
    subject_public_key: Option<BitString>,
}
impl SubjectPublicKeyInfoBuilder {
    fn new() -> Self {
        Self {
            algorithm: None,
            subject_public_key: None,
        }
    }
    fn build(self) -> Result<SubjectPublicKeyInfo, TlsError> {
        if self.algorithm.is_none() {
            return Err(TlsError::DecodeError);
        }
        Ok(SubjectPublicKeyInfo {
            algorithm: self.algorithm.unwrap(),
            subject_public_key: self.subject_public_key.unwrap(),
        })
    }
}
fn parse_object_identifier(id: &[u8]) -> Result<String, TlsError> {
    let id = bytes::to_u128_le_fill(id);
    Ok(match id {
        0x550406 => "countryName".to_string(),
        0x550408 => "stateOrProvinceName".to_string(),
        0x55040a => "organizationName".to_string(),
        0x550403 => "commonName".to_string(),
        0x2a8648ce3d040302 => "ecdsaWithSHA256".to_string(),
        0x2a8648ce3d030107 => "prime256v1".to_string(),
        0x2a8648ce3d0201 => "ecPublicKey".to_string(),
        _ => todo!("Missing ObjectIdentifier = {id:#x}"),
    })
}
// type BitString = Vec<u8>;
struct BitString(Vec<u8>);

type UniqueIdentifier = BitString;
pub struct Extensions(Vec<Extension>);

pub struct Name(HashMap<String, String>, Option<String>);

impl Name {
    pub fn new() -> Self {
        Self(HashMap::new(), None)
    }
    pub fn get(&self, key: &str) -> Result<String, TlsError> {
        if let Some(value) = self.0.get(key) {
            return Ok(value.to_string());
        }
        return Err(TlsError::DecodeError);
    }
    pub fn add_object_identifier(&mut self, id: &[u8]) -> Result<(), TlsError> {
        self.1 = Some(parse_object_identifier(id)?);
        Ok(())
    }
    pub fn add_value(&mut self, value: String) -> Result<(), TlsError> {
        if let Some(name) = self.1.as_ref() {
            self.0.insert(name.to_string(), value);
            self.1 = None;
            return Ok(());
        }
        Err(TlsError::DecodeError)
    }
}

pub struct TBSCertificate {
    version: Version,
    serial_number: IBig,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id:
    // subject_unique_id:
    extension: Option<Extensions>,
    raw_data: Option<Vec<u8>>,
}
pub struct TBSCertificateBuilder {
    version: Option<Version>,
    serial_number: Option<IBig>,
    signature: Option<AlgorithmIdentifier>,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoBuilder,
    // issuer_unique_id:
    // subject_unique_id:
    extension: Option<Extensions>,
    raw_data: Option<Vec<u8>>,
}

impl TBSCertificateBuilder {
    pub fn new() -> TBSCertificateBuilder {
        TBSCertificateBuilder {
            version: None,
            serial_number: None,
            signature: None,
            issuer: Name::new(),
            validity: Validity::new(),
            subject: Name::new(),
            subject_public_key_info: SubjectPublicKeyInfoBuilder::new(),
            extension: None,
            raw_data: None,
        }
    }
    pub fn build(self) -> Result<TBSCertificate, TlsError> {
        if self.version.is_none() || self.serial_number.is_none() || self.signature.is_none() {
            return Err(TlsError::DecodeError);
        }
        Ok(TBSCertificate {
            version: self.version.as_ref().unwrap().clone(),
            serial_number: self.serial_number.as_ref().unwrap().clone(),
            signature: self.signature.unwrap(),
            issuer: self.issuer,
            validity: self.validity,
            subject: self.subject,
            subject_public_key_info: self.subject_public_key_info.build()?,
            extension: self.extension,
            raw_data: self.raw_data,
        })
    }
}

pub struct X509 {
    tbs_certificate: TBSCertificate,
    signature_algorithm: Algorithms,
    signature: Option<Signature>,
}
impl X509 {
    pub fn from_raw(data: &[u8]) -> Result<X509, TlsError> {
        let mut res = X509Builder::new();
        let mut consumed = 0;
        parse(&mut res, ParsingState::Init, data, &mut consumed)?;
        res.build()
    }
}
pub struct X509Builder {
    tbs_certificate: TBSCertificateBuilder,
    signature_algorithm: Option<Algorithms>,
    signature: (Option<IBig>, Option<IBig>),
}
impl X509Builder {
    fn new() -> X509Builder {
        X509Builder {
            tbs_certificate: TBSCertificateBuilder::new(),
            signature_algorithm: None,
            signature: (None, None),
        }
    }
    fn build(self) -> Result<X509, TlsError> {
        let mut signature = None;

        if self.signature.0.is_some() && self.signature.1.is_some() {
            signature = Some(Signature::new(
                self.signature.0.unwrap(),
                self.signature.1.unwrap(),
            ));
        }

        Ok(X509 {
            tbs_certificate: self.tbs_certificate.build()?,
            signature_algorithm: self.signature_algorithm.unwrap(),
            signature,
        })
    }
}
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

pub enum DerValue {
    Integer(IBig),
    PrintableString(String),
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

fn der_parse(consumed: &mut usize, data: &[u8]) -> Result<(usize, EncodedForm), TlsError> {
    let der_type = match DerType::from_u8(data[*consumed]) {
        Some(a) => a,
        None => return Err(TlsError::DecodeError),
    };
    *consumed += 1;
    let size = get_len(data, consumed);
    if size > data.len() {
        return Err(TlsError::DecodeError);
    }
    Ok((size, der_type))
}

fn get_len(len: &[u8], consumed: &mut usize) -> usize {
    let size;
    if len[*consumed] >> 7 & 1 == 1 {
        let consume_len = len[*consumed] & 0x7F;
        *consumed += 1;
        size = bytes::to_u128_le_fill(&len[*consumed..*consumed + consume_len as usize]) as usize;
        *consumed += consume_len as usize;
    } else {
        size = len[*consumed] as usize;
        *consumed += 1;
    }
    size
}

#[derive(PartialEq, Debug, Clone)]
enum ParsingState {
    Init,
    InBitString,
    InSet,
    HasObjectIdentifier(Box<String>),
}

#[derive(Debug, Clone)]
enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}
impl Version {
    fn parse(data: &[u8]) -> Result<Version, TlsError> {
        if data.len() == 1 {
            return Ok(match data[0] {
                0 => Version::V1,
                1 => Version::V2,
                2 => Version::V3,
                _ => return Err(TlsError::DecodeError),
            });
        }
        Err(TlsError::DecodeError)
    }
}
fn parse(
    res: &mut X509Builder,
    state: ParsingState,
    data: &[u8],
    consumed: &mut usize,
) -> Result<(), TlsError> {
    let (size, der) = der_parse(consumed, data)?;
    let body = &data[*consumed..*consumed + size];

    match der {
        EncodedForm::Constructed(cons) => match cons {
            DerType::Sequence => {
                let size_should = size + *consumed;
                while size_should > *consumed {
                    parse(res, state.clone(), data, consumed)?;
                }
            }
            DerType::ContextSpecific(tag) => {
                match tag {
                    0x00 => {
                        res.tbs_certificate.version = Some(Version::parse(&body[2..])?);
                    }
                    0x03 => println!("GOT Extenstions"),
                    _ => (),
                }
                *consumed += size;
            }
            DerType::Set => {
                parse(res, ParsingState::InSet, data, consumed)?;
                // *consumed += size;
            }
            _ => {
                todo!("cons={cons:?}");
            }
        },
        EncodedForm::Primitive(prim) => match prim {
            DerType::Integer => {
                let int = bytes::to_ibig_le(body);
                *consumed += size;
                if res.tbs_certificate.serial_number.is_none() {
                    res.tbs_certificate.serial_number = Some(int);
                } else if res.signature.0.is_none() {
                    res.signature.0 = Some(int);
                } else {
                    res.signature.1 = Some(int);
                }
            }
            DerType::ObjectIdentifier => match state {
                ParsingState::InSet => {
                    res.tbs_certificate.issuer.add_object_identifier(body)?;
                    *consumed += size;
                }
                ParsingState::Init => {
                    let oji = parse_object_identifier(body)?;
                    if res.tbs_certificate.signature.is_none() {
                        res.tbs_certificate.signature =
                            Some(AlgorithmIdentifier::new(Algorithms::new(&oji)?));
                    } else if res
                        .tbs_certificate
                        .subject_public_key_info
                        .algorithm
                        .is_none()
                    {
                        res.tbs_certificate.subject_public_key_info.algorithm =
                            Some(AlgorithmIdentifier::new(Algorithms::new(&oji)?));
                    } else if res
                        .tbs_certificate
                        .subject_public_key_info
                        .algorithm
                        .as_ref()
                        .unwrap()
                        .parameters
                        .is_none()
                    {
                        res.tbs_certificate
                            .subject_public_key_info
                            .algorithm
                            .as_mut()
                            .unwrap()
                            .parameters = Some(oji);
                    } else if res.signature_algorithm.is_none() {
                        res.signature_algorithm = Some(Algorithms::new(&oji)?);
                    }
                    *consumed += size;
                }
                _ => todo!("ObjectIdentifier {state:?}"),
            },
            DerType::PrintableString | DerType::UTF8String => {
                let string = match String::from_utf8(body.to_vec()) {
                    Ok(e) => e,
                    Err(_) => return Err(TlsError::DecodeError),
                };
                res.tbs_certificate.issuer.add_value(string)?;
                *consumed += size;
            }
            DerType::OctetString => {
                *consumed += size;
                todo!("GOT OctetString");
            }
            DerType::UTCTime => {
                let timestamp = match String::from_utf8(body.to_vec()) {
                    Ok(e) => e,
                    Err(_) => return Err(TlsError::DecodeError),
                };
                let timestamp = UtcTime::from_utc_timestamp(&timestamp);
                if timestamp.is_none() {
                    return Err(TlsError::DecodeError);
                }
                if res.tbs_certificate.validity.not_before.is_none() {
                    res.tbs_certificate.validity.not_before = timestamp;
                } else {
                    res.tbs_certificate.validity.not_after = timestamp;
                }
                *consumed += size;
            }
            DerType::BitString => {
                if data[*consumed - 1] == 0x48 {
                    *consumed += 1;
                    let size_should = size + *consumed - 1;
                    while size_should > *consumed {
                        parse(res, ParsingState::InBitString, data, consumed)?;
                    }
                } else {
                    if res
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .is_none()
                    {
                        res.tbs_certificate
                            .subject_public_key_info
                            .subject_public_key = Some(BitString(body.to_vec()));
                    }
                    *consumed += size;
                }
            }
            _ => {
                todo!("prim={prim:?}");
            }
        },
    }
    Ok(())
}


#[cfg(test)]
mod tests {

    use crate::utils::x509::{Algorithms, X509};

    #[test]
    fn test_parse_x509() {
        let data = super::bytes::from_hex("30820215308201bba0030201020214612fe409659dfe39c6a2d685db2c71fbbfbec7d4300a06082a8648ce3d0403023060310b30090603550406130244453113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c10616e6f74686572746c732e6c6f63616c301e170d3233303330393130313831325a170d3234303330383130313831325a3060310b30090603550406130244453113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c10616e6f74686572746c732e6c6f63616c3059301306072a8648ce3d020106082a8648ce3d030107034200046eed2bfee88db30f90001b34f24ad85a96aedc7c01d175f81d6da2a3d96f29c86d5e14735b63f2d579e067b503bb42c1d934f5b7316fa57a13d0454577d194e5a3533051301d0603551d0e04160414a9d135118bc5c3b7076c6248169e0087b5ed5c00301f0603551d23041830168014a9d135118bc5c3b7076c6248169e0087b5ed5c00300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203480030450220372c31a1401b8dce99a61cd3ac7f83d4aec628085ecab625093ac72e628fd1d4022100a28383292dc8d73f114f2c1694e4dffc51791aceca226cc83699b9467bbb78fc").unwrap();

        let x509 = match X509::from_raw(&data) {
            Ok(e) => e,
            Err(_) => {
                panic!("TLS ERROR");
            }
        };

        assert_eq!(x509.signature_algorithm, Algorithms::EcdsaWithSha256);
        assert_eq!(
            x509.tbs_certificate.issuer.get("commonName").unwrap(),
            "anothertls.local"
        );
        assert_eq!(
            x509.tbs_certificate.issuer.get("organizationName").unwrap(),
            "Internet Widgits Pty Ltd"
        );
    }
}
