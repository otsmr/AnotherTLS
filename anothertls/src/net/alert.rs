/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

pub enum AlertLevel {
    Warning = 0x01,
    Fatal= 0x02
}
impl AlertLevel {
    pub fn get_from_error (desc: TlsError) -> AlertLevel {
        match desc {
            TlsError::CloseNotify => AlertLevel::Warning,
            _ => AlertLevel::Fatal
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub enum TlsError {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    HandshakeFailure = 40,
    IllegalParameter = 47,
    DecryptError = 50,
    DecodeError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    MissingExtension = 109,
    BrokenPipe = 254 // Not official
}

