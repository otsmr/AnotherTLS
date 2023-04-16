/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::{net::{
    alert::{AlertLevel, TlsError},
    record::{Record, RecordPayloadProtection, RecordType, Value},
}, utils::log};

use std::{
    io::{Read, Write},
    net::TcpStream,
    result::Result,
};

pub struct TlsStream {
    stream: TcpStream,
    pub protection: Option<RecordPayloadProtection>,
    buffer: Vec<u8>
}

impl TlsStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            protection: None,
            buffer: Vec::with_capacity(2048)
        }
    }

    /// The function write_record buffers the data before sending.
    /// This is useful in the handshake process, where multiple
    /// TLS records are send to the client.
    pub(crate) fn write_record(&mut self, typ: RecordType, data: &[u8]) -> Result<(), TlsError> {

        let record = Record::new(typ, Value::Ref(data));

        if let Some(protect) = self.protection.as_mut() {
            self.buffer.append(&mut protect.encrypt(record)?);
        } else {
            self.buffer.append(&mut record.as_bytes());
        }

        // TODO: Find a smart value
        if self.buffer.len() >= 2048 {
            self.flush()?;
        }

        Ok(())

    }

    pub(crate) fn flush(&mut self) -> Result<(), TlsError>{
        if self.stream.write_all(&self.buffer).is_err() {
            return Err(TlsError::BrokenPipe);
        };
        self.buffer.clear();
        Ok(())
    }

    pub(crate) fn set_protection(&mut self, protection: Option<RecordPayloadProtection>) {
        self.protection = protection;
    }

    /// Write directly to the TCP socket
    pub(crate) fn tcp_write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        match self.stream.write(buf) {
            Ok(n) => Ok(n),
            Err(_) => Err(TlsError::BrokenPipe),
        }
    }

    /// Read directly from the TCP socket
    pub(crate) fn tcp_read<'b>(&'b mut self, buf: &'b mut [u8]) -> Result<usize, TlsError> {
        match self.stream.read(buf) {
            Ok(n) => Ok(n),
            Err(_) => Err(TlsError::BrokenPipe),
        }
    }

    /// Write an TLS Alert message
    pub fn write_alert(&mut self, err: TlsError) -> Result<(), TlsError> {
        let data = vec![AlertLevel::get_from_error(err) as u8, err.as_u8()];

        let record = Record::new(RecordType::Alert, Value::Owned(data));

        let record_raw = if let Some(protect) = self.protection.as_mut() {
            protect.encrypt(record)?
        } else {
            record.as_bytes()
        };

        if self.stream.write_all(&record_raw).is_err() {
            return Err(TlsError::BrokenPipe);
        };

        Ok(())
    }

    /// Read from the TLS stream.
    pub fn tls_read<'b>(&'b mut self, buf: &'b mut [u8]) -> Result<usize, TlsError> {
        let mut rx_buf: [u8; 4096] = [0; 4096];

        let n = self.tcp_read(&mut rx_buf)?;

        let (_consumed, mut record) = Record::from_raw(&rx_buf[..n])?;

        log::debug!("--> EncryptedData");

        if record.len != record.fraqment.len() {
            // create internal buffer to store the decrypted TLS packages
            todo!("Problem, when multiple TLS packages in one TCP package");
        }

        if let Some(protection) = self.protection.as_mut() {
            let (typ, data) = protection.decrypt(record)?;
            record = Record::new(typ, Value::Owned(data));
            if record.content_type != RecordType::ApplicationData {
                todo!("Handle handshake messages");
            }
        } else if record.content_type != RecordType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }

        if record.len > buf.len() {
            todo!("Handle records bigger than the buf.len()");
        }

        for (i, b) in record.fraqment.as_ref().iter().enumerate() {
            buf[i] = *b;
        }

        Ok(record.fraqment.len())
    }

    /// Write to the TLS stream.
    pub fn tls_write<'b>(&'b mut self, src: &'b [u8]) -> Result<(), TlsError> {

        if self.protection.is_none() {
            // Don't write to the socket, if no secure
            // channel is present.
            return Err(TlsError::InternalError);
        }

        let record = Record::new(RecordType::ApplicationData, Value::Ref(src));
        let record = self.protection.as_mut().unwrap().encrypt(record)?;

        log::debug!("<-- EncryptedData");
        if self.stream.write_all(&record).is_err() {
            return Err(TlsError::BrokenPipe);
        };

        Ok(())
    }
}

// TODO: create tests
