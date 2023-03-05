/// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
#[derive(PartialEq)]
pub enum RecordType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl RecordType {
    pub fn new(byte: u8) -> Option<RecordType> {
        Some(match byte {
            0 => RecordType::Invalid,
            20 => RecordType::ChangeCipherSpec,
            21 => RecordType::Alert,
            22 => RecordType::Handshake,
            23 => RecordType::ApplicationData,
            _ => return None,
        })
    }
}

pub struct Record<'a> {
    pub content_type: RecordType,
    pub version: u16,
    pub len: u16,
    pub fraqment: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn from_raw(buf: &[u8]) -> Option<Record> {
        if buf.len() < 5 {
            return None;
        }

        let content_type = RecordType::new(buf[0])?;
        let version = ((buf[1] as u16) << 8) | buf[2] as u16;
        let len = ((buf[3] as u16) << 8) | buf[4] as u16;

        Some(Record {
            content_type,
            version,
            len,
            fraqment: &buf[5..],
        })
    }
    pub fn to_raw(typ: RecordType, mut data: Vec<u8>) -> Vec<u8> {
        let len = data.len();
        let mut t = vec![typ as u8, 0x3, 0x3, (len >> 8) as u8, len as u8];
        t.append(&mut data);
        t
    }
    pub fn is_full(&self) -> bool {
        self.len == self.fraqment.len() as u16
    }
}
