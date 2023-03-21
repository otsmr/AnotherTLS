/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 *
 */

mod der;
use der::*;

use ibig::IBig;

use super::{bytes, bytes::str_to_u16, log};
use crate::crypto::ellipticcurve::Signature;
use std::collections::HashMap;

#[derive(Debug)]
pub enum ParseError {
    Algorithms,
    SubjectPublicKeyInfo,
    UTF8StringTimestamp,
    NameGet,
    NameAddValue,
    TBSBuilder,
    DerParseType,
    DerParseLen,
    Version,
    UTF8String,
    TimeStamp,
}

#[derive(Debug)]
pub struct UtcTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
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
    pub fn new(s: &str) -> Result<Algorithms, ParseError> {
        Ok(match s {
            "ecdsaWithSHA256" => Algorithms::EcdsaWithSha256,
            "ecPublicKey" => Algorithms::EcPublicKey,
            _ => return Err(ParseError::Algorithms),
        })
    }
}
#[derive(Debug)]
pub struct AlgorithmIdentifier {
    pub algorithm: Algorithms,
    pub parameters: Option<String>,
}
impl AlgorithmIdentifier {
    pub fn new(algorithm: Algorithms) -> AlgorithmIdentifier {
        AlgorithmIdentifier {
            algorithm,
            parameters: None,
        }
    }
}
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
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
    fn build(self) -> Result<SubjectPublicKeyInfo, ParseError> {
        if self.algorithm.is_none() {
            return Err(ParseError::SubjectPublicKeyInfo);
        }
        Ok(SubjectPublicKeyInfo {
            algorithm: self.algorithm.unwrap(),
            subject_public_key: self.subject_public_key.unwrap(),
        })
    }
}
fn parse_object_identifier(id: &[u8]) -> Result<String, ParseError> {
    let id = bytes::to_u128_le_fill(id);
    Ok(match id {
        0x550406 => "countryName".to_string(),
        0x550408 => "stateOrProvinceName".to_string(),
        0x55040a => "organizationName".to_string(),
        0x550403 => "commonName".to_string(),
        0x2a8648ce3d040302 => "ecdsaWithSHA256".to_string(),
        0x2a8648ce3d030107 => "prime256v1".to_string(),
        0x2a8648ce3d0201 => "ecPublicKey".to_string(),
        0x2a864886f70d010901 => "emailAddress".to_string(),
        0x550407 => "localityName".to_string(),
        0x55040B => "organizationalUnitName".to_string(),
        _ => todo!("Missing ObjectIdentifier = {id:#x}"),
    })
}
// type BitString = Vec<u8>;
pub struct BitString(Vec<u8>);

// type UniqueIdentifier = BitString;
pub struct Extensions(Vec<Extension>);

pub struct Name(HashMap<String, String>, Option<String>);

impl Name {
    pub fn new() -> Self {
        Self(HashMap::new(), None)
    }
    pub fn get(&self, key: &str) -> Result<String, ParseError> {
        if let Some(value) = self.0.get(key) {
            return Ok(value.to_string());
        }
        Err(ParseError::NameGet)
    }
    pub fn add_object_identifier(&mut self, id: &[u8]) -> Result<(), ParseError> {
        self.1 = Some(parse_object_identifier(id)?);
        Ok(())
    }
    pub fn add_value(&mut self, value: String) -> Result<(), ParseError> {
        if let Some(name) = self.1.as_ref() {
            self.0.insert(name.to_string(), value);
            self.1 = None;
            return Ok(());
        }
        Err(ParseError::NameAddValue)
    }
}

pub struct TBSCertificate {
    pub version: Option<Version>,
    pub serial_number: IBig,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id:
    // subject_unique_id:
    pub extension: Option<Extensions>,
    pub raw_data: Option<Vec<u8>>,
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
    pub fn build(self) -> Result<TBSCertificate, ParseError> {
        if self.serial_number.is_none() || self.signature.is_none() {
            return Err(ParseError::TBSBuilder);
        }
        Ok(TBSCertificate {
            version: self.version,
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
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: Algorithms,
    pub signature: Option<Signature>,
}
impl X509 {
    pub fn from_raw(data: &[u8]) -> Result<X509, ParseError> {
        let mut res = X509Builder::new();
        let mut consumed = 0;
        log::debug!("Start parsing X509 certificate");
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
    fn build(self) -> Result<X509, ParseError> {
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

#[derive(PartialEq, Debug, Clone)]
enum ParsingState {
    Init,
    InBitString,
    InSet,
}

#[derive(Debug, Clone)]
pub enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}
impl Version {
    fn parse(data: &[u8]) -> Result<Version, ParseError> {
        if data.len() == 1 {
            return Ok(match data[0] {
                0 => Version::V1,
                1 => Version::V2,
                2 => Version::V3,
                _ => return Err(ParseError::Version),
            });
        }
        Err(ParseError::Version)
    }
}
fn parse(
    res: &mut X509Builder,
    state: ParsingState,
    data: &[u8],
    consumed: &mut usize,
) -> Result<(), ParseError> {
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
                    if res.tbs_certificate.validity.not_after.is_none() {
                        res.tbs_certificate.issuer.add_object_identifier(body)?;
                    } else {
                        res.tbs_certificate.subject.add_object_identifier(body)?;
                    }
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
                    Err(_) => return Err(ParseError::UTF8String),
                };
                if res.tbs_certificate.validity.not_after.is_none() {
                    res.tbs_certificate.issuer.add_value(string)?;
                } else {
                    res.tbs_certificate.subject.add_value(string)?;
                }
                *consumed += size;
            }
            DerType::OctetString => {
                *consumed += size;
                todo!("GOT OctetString");
            }
            DerType::UTCTime => {
                let timestamp = match String::from_utf8(body.to_vec()) {
                    Ok(e) => e,
                    Err(_) => return Err(ParseError::UTF8StringTimestamp),
                };
                let timestamp = UtcTime::from_utc_timestamp(&timestamp);
                if timestamp.is_none() {
                    return Err(ParseError::TimeStamp);
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
    fn test_parse_x509_client() {
        let data = super::bytes::from_hex("308201f53082019b02145608da598885be938e65547ce4999f58fee38580300a06082a8648ce3d040302306c310b3009060355040613024445310d300b06035504080c044d6f6f6e31193017060355040a0c10416e6f746865724341207365637572653112301006035504030c09416e6f746865724341311f301d06092a864886f70d010901161073656375726974794074736d722e6575301e170d3233303331363138303335325a170d3234303331353138303335325a30818d310b3009060355040613024445310d300b06035504080c044d6f6f6e310e300c06035504070c05537061636531173015060355040a0c0e416e6f74686572436f6d70616e793111300f060355040b0c087a65637572697479310e300c06035504030c056f74736d723123302106092a864886f70d010901161474736d7240616e6f746865722e636f6d70616e793059301306072a8648ce3d020106082a8648ce3d03010703420004e206723a9057980587346a8dc604d729cb78eb2a26569bc6ef63d39bb004c4dbb8f3eb5ad2bcd70adfb182248bc32052dd9a58a0ba4578bb3e7aab71b6e4cbe3300a06082a8648ce3d040302034800304502201136f044a0c91932cc7c5f5ae3e6c13fafef1332f0fa2ebc413ec361c19a9ef10221009acdbf76f32fe17fc0b2d6acaf6c61d2f632cbfdb26a4cbeb53d5e30ca4aefea").unwrap();

        let x509 = match X509::from_raw(&data) {
            Ok(e) => e,
            Err(err) => {
                panic!("ParseError = {err:?}");
            }
        };

        assert_eq!(x509.signature_algorithm, Algorithms::EcdsaWithSha256);
        assert_eq!(
            x509.tbs_certificate.issuer.get("commonName").unwrap(),
            "AnotherCA"
        );
        assert_eq!(
            x509.tbs_certificate.subject.get("commonName").unwrap(),
            "otsmr"
        );
        assert_eq!(
            x509.tbs_certificate.issuer.get("organizationName").unwrap(),
            "AnotherCA secure"
        );
    }
    #[test]
    fn test_parse_x509_webpage() {
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
