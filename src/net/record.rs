/// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
#[derive(PartialEq)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn new(byte: u8) -> Option<ContentType> {
        Some(match byte {
            0 => ContentType::Invalid,
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => return None,
        })
    }
}

pub struct Record<'a> {
    pub content_type: ContentType,
    pub version: u16,
    pub len: u16,
    pub fraqment: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn from_raw(buf: &[u8]) -> Option<Record> {
        if buf.len() < 5 {
            return None;
        }

        let content_type = ContentType::new(buf[0])?;
        let version = ((buf[1] as u16) << 8) | buf[2] as u16;
        let len = ((buf[3] as u16) << 8) | buf[4] as u16;

        Some(Record {
            content_type,
            version,
            len,
            fraqment: &buf[5..],
        })
    }

    pub fn is_full(&self) -> bool {
        self.len == self.fraqment.len() as u16
    }
}
