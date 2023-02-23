use ibig::IBig;

use super::{AES, Blocksize};






pub struct GCM {

}


impl GCM {


    pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {

        let blocksize = Blocksize::new(key.len()*8)?;

        let ciphertext = Vec::new();
        let auth_tag = Vec::new();

        // let counter;
        let mut aes = AES::init(key, blocksize)?;
        let h = aes.encrypt([0; 16]);


        Ok((ciphertext, auth_tag))
    }

    pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8], auth_tag: &[u8]) -> Result<Vec<u8>, ()> {

        let plaintext = Vec::new();


        Ok(plaintext)
    }

}

