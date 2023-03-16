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

pub enum Algorithms {
}
pub struct AlgorithmIdentifier {
    algorithm: Algorithms,
    parameters: Option<BitString>
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

struct TBSCertificate {
    version: Version,
    serial_number: IBig,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id:
    // subject_unique_id:
    extension: Extensions,
    raw_data: Option<Vec<u8>>,
}

impl TBSCertificate {
    fn parse(consumed: &mut usize, size: usize, data: &[u8]) -> Result<TBSCertificate, TlsError> {
        let mut version = None;
        let mut serial_number: Option<IBig> = None;

        let (total_size, der_type) = Der::parse(consumed, data)?;

        if *consumed + total_size > data.len() {
            return Err(TlsError::DecodeError);
        }

        // loop {
        while *consumed < total_size {

            let (size, encoded) = Der::parse(consumed, data)?;

            if *consumed + size > data.len() {
                return Err(TlsError::DecodeError);
            }

            println!("encoded={encoded:?}");

            if let EncodedForm::Primitive(der_type) = encoded {
                if der_type == DerType::Integer {
                    serial_number = Some(bytes::to_ibig_le(&data[*consumed..*consumed + size]));
                    *consumed += size;
                }
            } else if let EncodedForm::Constructed(der_type) = encoded {
                match der_type {
                    DerType::ContextSpecific(tag_number) => match tag_number {
                        0x00 => {
                            version = Some(Version::parse(consumed, data)?);
                        }
                        0x01 => {
                            todo!()
                        }
                        0x02 => {}
                        0x03 => {}
                        _ => (),
                    },
                    DerType::Integer => {}
                    DerType::Sequence => {

                        let (size, encoded) = Der::parse(consumed, data)?;
                        if *consumed + size > data.len() {
                            return Err(TlsError::DecodeError);
                        }

                        println!("encodedINSIDE={encoded:?}");


                    }
                    _ => (),
                }
            }
            // println!("serial_number={serial_number:?}");

            // return Err(TlsError::DecodeError);
        }

        todo!()
    }
}

pub struct SignatureAlgorithm();
impl SignatureAlgorithm {
    fn parse(consumed: &mut usize, data: &[u8]) -> Result<SignatureAlgorithm, TlsError> {
        todo!()
    }
}

pub struct X509 {
    tbs_certificate: TBSCertificate,
    signature_algorithm: SignatureAlgorithm,
    signature_value: BitString,
}

impl X509 {
    fn get_len(len: &[u8], consumed: &mut usize) -> usize {
        let size;
        if len[*consumed] >> 7 & 1 == 1 {
            let consume_len = len[*consumed] & 0x7F;
            *consumed += 1;
            size = bytes::to_u128_le(&len[*consumed..*consumed + consume_len as usize]) as usize;
            *consumed += consume_len as usize;
        } else {
            size = len[*consumed] as usize;
            *consumed += 1;
        }
        size
    }

    pub fn parse(data: &[u8]) -> Result<(), TlsError> {
        let mut consumed = 0;

        let mut tbs_certificate = None;
        let mut signature_algorithm = None;
        let mut signature = None;

        while consumed <= data.len() {
            let (size, encoded_form) = Der::parse(&mut consumed, data)?;

            if let EncodedForm::Constructed(der_type) = encoded_form {
                // println!("DerType={der_type:?}");
                // println!("Size={size}");

                if tbs_certificate.is_none() {
                    if der_type != DerType::Sequence {
                        return Err(TlsError::DecodeError);
                    }
                    tbs_certificate = Some(TBSCertificate::parse(&mut consumed, size, data)?);
                    continue;
                }

                if signature_algorithm.is_none() {
                    if der_type != DerType::Sequence {
                        return Err(TlsError::DecodeError);
                    }
                    signature_algorithm = Some(SignatureAlgorithm::parse(&mut consumed, data)?);
                    continue;
                }

                if signature.is_none() {
                    if der_type != DerType::BitString {
                        return Err(TlsError::DecodeError);
                    }
                    signature = Some(BitString::parse(&mut consumed, data)?);
                    break;
                }
            }

            return Err(TlsError::DecodeError);
        }

        Ok(())
        // X509 {}
    }
}

#[cfg(test)]
mod tests {

    use crate::utils::x509::X509;

    #[test]
    fn parse_x509() {
        let data = super::bytes::from_hex("30820215308201bba0030201020214612fe409659dfe39c6a2d685db2c71fbbfbec7d4300a06082a8648ce3d0403023060310b30090603550406130244453113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c10616e6f74686572746c732e6c6f63616c301e170d3233303330393130313831325a170d3234303330383130313831325a3060310b30090603550406130244453113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c10616e6f74686572746c732e6c6f63616c3059301306072a8648ce3d020106082a8648ce3d030107034200046eed2bfee88db30f90001b34f24ad85a96aedc7c01d175f81d6da2a3d96f29c86d5e14735b63f2d579e067b503bb42c1d934f5b7316fa57a13d0454577d194e5a3533051301d0603551d0e04160414a9d135118bc5c3b7076c6248169e0087b5ed5c00301f0603551d23041830168014a9d135118bc5c3b7076c6248169e0087b5ed5c00300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203480030450220372c31a1401b8dce99a61cd3ac7f83d4aec628085ecab625093ac72e628fd1d4022100a28383292dc8d73f114f2c1694e4dffc51791aceca226cc83699b9467bbb78fc").unwrap();

        let x509 = X509::parse(&data);

        println!("x509={:?}", x509);

        todo!()
    }
}
