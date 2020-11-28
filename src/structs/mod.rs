use std::collections::HashMap;

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

struct Wrapper {
    pub proto: HashMap<String, Vec<u8>>,
    pub enc_metadata: Vec<u8>,
    pub metadata_digest: Vec<u8>,
    pub digest: Vec<u8>,
    pub next: Vec<u8>,
}

struct Block {
    pub block_digest: Vec<u8>,
    pub data: Vec<u8>,
    pub next: Vec<u8>,
}

pub struct EncryptedFile(Wrapper);

impl EncryptedFile {
    pub fn from_bytes(buf: &[u8], key: &[u8]) -> Result<Self, String> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

        // todo: generate nonce randomly
        let nonce = GenericArray::from_slice(b"000000000000");
        let ciphertext = cipher.encrypt(nonce, buf).unwrap();

        let mut proto = HashMap::<String, Vec<u8>>::new();
        proto.insert("nonce".to_string(), nonce.to_vec());

        // todo: replace stub values
        let head = Wrapper {
            proto: proto,
            enc_metadata: ciphertext, // todo: ciphertext should be in block
            metadata_digest: Vec::<u8>::new(),
            digest: Vec::<u8>::new(),
            next: Vec::<u8>::new(),
        };

        return Ok(EncryptedFile { 0: head });
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = GenericArray::from_slice(self.0.proto.get("nonce").unwrap());
        let plaintext = cipher.decrypt(nonce, self.0.enc_metadata.as_ref()).unwrap();

        Ok(plaintext)
    }
}
