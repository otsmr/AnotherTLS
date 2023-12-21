/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 *
 */

use super::bytes;
use crate::utils::x509::ParseError;

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum DerType {
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

pub type TagNumber = u8;
#[derive(Debug, PartialEq)]
pub enum EncodedForm {
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
                0x16 => DerType::UTF8String,
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

pub fn der_parse(consumed: &mut usize, data: &[u8]) -> Result<(usize, EncodedForm), ParseError> {
    let der_type = match DerType::from_u8(data[*consumed]) {
        Some(a) => a,
        None => return Err(ParseError::DerParseType),
    };
    *consumed += 1;
    let size = get_len(data, consumed);
    if size > data.len() {
        return Err(ParseError::DerParseLen);
    }
    Ok((size, der_type))
}

fn get_len(len: &[u8], consumed: &mut usize) -> usize {
    let size;
    if len[*consumed] >> 7 & 1 == 1 {
        let consume_len = len[*consumed] & 0x7F;
        *consumed += 1;
        size = bytes::to_u128_be_fill(&len[*consumed..*consumed + consume_len as usize]) as usize;
        *consumed += consume_len as usize;
    } else {
        size = len[*consumed] as usize;
        *consumed += 1;
    }
    size
}
