use crate::utils::pem::get_pem_content_from_file;

pub struct Certificate {
    pub raw: Vec<u8>,
}

impl Certificate {
    pub fn from_pem(filepath: String) -> Option<Self> {
        let raw = get_pem_content_from_file(filepath)?;
        Some(Certificate {
            raw: raw.get("CERTIFICATE")?.to_vec(),
        })
    }

    pub fn get_certificate_for_handshake(&self) -> Vec<u8> {

        let len = self.raw.len();
        let mut certificate_raw = vec![
            0x00,
            // CertificateS Length + Extensions
            (len << 16) as u8,
            (len << 8) as u8,
            (len as u8) + 5,
            // Certificate Length
            (len << 16) as u8,
            (len << 8) as u8,
            (len as u8),
        ];
        certificate_raw.extend_from_slice(&self.raw);
        // Certificate Extensions
        certificate_raw.push(0x00);
        certificate_raw.push(0x00);
        certificate_raw
    }
}
