/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub enum AlertLevel {
    Warning = 0x01,
    Fatal = 0x02,
}
impl AlertLevel {
    pub fn get_from_error(desc: TlsError) -> AlertLevel {
        match desc {
            TlsError::CloseNotify => AlertLevel::Warning,
            _ => AlertLevel::Fatal,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TlsError {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecryptError = 50,
    DecodeError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    MissingExtension = 109,
    UnrecognizedName = 112,
    CertificateRequired = 116,

    NotOfficial = 250,
    GotAlert(u8) = 253, // Not official
    BrokenPipe = 254,   // Not official
}

impl TlsError {
    pub fn new(code: u8) -> TlsError {
        match code {
            0 => TlsError::CloseNotify,
            10 => TlsError::UnexpectedMessage,
            40 => TlsError::HandshakeFailure,
            42 => TlsError::BadCertificate,
            43 => TlsError::UnsupportedCertificate,
            44 => TlsError::CertificateRevoked,
            45 => TlsError::CertificateExpired,
            46 => TlsError::CertificateUnknown,
            47 => TlsError::IllegalParameter,
            48 => TlsError::UnknownCa,
            49 => TlsError::AccessDenied,
            50 => TlsError::DecryptError,
            51 => TlsError::DecodeError,
            70 => TlsError::ProtocolVersion,
            71 => TlsError::InsufficientSecurity,
            80 => TlsError::InternalError,
            109 => TlsError::MissingExtension,
            112 => TlsError::UnrecognizedName,
            116 => TlsError::CertificateRequired,
            250 => TlsError::NotOfficial,
            253 => TlsError::NotOfficial, // GotAlert has an associated value that we can't match here
            254 => TlsError::BrokenPipe,
            _ => TlsError::DecodeError,
        }
    }

    pub fn as_u8(&self) -> u8 {
        // TODO: Ho to solve this better? ChatGPT is currently the best solution?
        match self {
            TlsError::CloseNotify => 0,
            TlsError::UnexpectedMessage => 10,
            TlsError::HandshakeFailure => 40,
            TlsError::BadCertificate => 42,
            TlsError::UnsupportedCertificate => 43,
            TlsError::CertificateRevoked => 44,
            TlsError::CertificateExpired => 45,
            TlsError::CertificateUnknown => 46,
            TlsError::IllegalParameter => 47,
            TlsError::UnknownCa => 48,
            TlsError::AccessDenied => 49,
            TlsError::DecryptError => 50,
            TlsError::DecodeError => 51,
            TlsError::ProtocolVersion => 70,
            TlsError::InsufficientSecurity => 71,
            TlsError::InternalError => 80,
            TlsError::MissingExtension => 109,
            TlsError::UnrecognizedName => 112,
            TlsError::CertificateRequired => 116,
            TlsError::GotAlert(alert) => *alert,
            TlsError::BrokenPipe => 254,
            _ => 0,
        }
    }
}
