use crate::{
    crypto::ellipticcurve::{Ecdsa, PrivateKey},
    hash::{sha_x, HashType, TranscriptHash},
    net::stream::TlsError,
    utils::{bytes, pem::get_pem_content_from_file},
};

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
        let lens = len + 5;
        let mut certificate_raw = vec![
            0x00,
            // CertificateS Length + Extensions
            (lens << 16) as u8,
            (lens << 8) as u8,
            (lens as u8),
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

    pub fn get_certificate_verify_for_handshake(
        &self,
        hash_type: HashType,
        privkey: &PrivateKey,
        ts_hash: &dyn TranscriptHash,
    ) -> std::result::Result<Vec<u8>, TlsError> {
        // 4.4.3.  Certificate Verify

        let mut content = Vec::with_capacity(150);
        content.resize(64, 0x20);
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend(ts_hash.clone().finalize());

        let hash = sha_x(hash_type, &content);

        let mut ecdsa = Ecdsa::urandom();
        let signature = match ecdsa.sign(privkey, &hash) {
            Ok(a) => a,
            Err(_) => return Err(TlsError::InternalError),
        };
        let der = signature.to_der();
        let mut res = vec![0x04, 0x03, (der.len() >> 8) as u8, der.len() as u8]; // ecdsa_secp256r1_sha256 + Length
        res.extend(der);
        Ok(res)
    }
}

