use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use cid::{Cid, Version};
use multihash::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};

const NONCE_SIZE_BYTES: usize = 12;
const SHA256_CODE: u64 = 0x12;

/// Trait Match allows a query to run against object that implements it. The
/// result of the query is a boolean, representing whether the query has matched
/// the object or not. The query is encoded as a vector of bytes.
pub trait Match {
    fn query(&self, query: String) -> Result<bool, String>;
}

// type Tags
#[derive(Debug, Serialize, Deserialize)]
pub struct Tags {
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub cid: String,
    pub encoded_tags: Vec<u8>,
}

impl Match for Metadata {
    fn query(&self, query: String) -> Result<bool, String> {
        // decode tags
        let tags: Tags = serde_json::from_slice(&self.encoded_tags).unwrap();

        for tag in tags.values {
            if tag == query {
                return Ok(true);
            };
        }
        return Ok(false);
    }
}

impl Metadata {
    pub fn new(tags: Tags) -> Result<Self, String> {
        let encoded_tags = serde_json::to_vec(&tags).unwrap();

        let h = Code::Sha2_256.digest(&encoded_tags);
        let cid = match Cid::new(Version::V1, SHA256_CODE, h) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };

        Ok(Metadata {
            cid: cid.to_string(),
            encoded_tags,
        })
    }

    pub fn encrypt(self, key: &[u8; 32]) -> Result<Self, String> {
        let nonce = GenericArray::from_slice(&self.cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let k = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(k);

        let enc_tags = cipher.encrypt(nonce, self.encoded_tags.as_slice()).unwrap();

        Ok(Metadata {
            cid: self.cid + "/encrypted",
            encoded_tags: enc_tags,
        })
    }

    pub fn decrypt(self, key: &[u8; 32]) -> Result<Self, String> {
        let cid_split: Vec<&str> = self.cid.split('/').collect();
        let cid = cid_split[0].to_string();

        let nonce = GenericArray::from_slice(&cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let key = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let encoded_tags = cipher.decrypt(nonce, self.encoded_tags.as_slice()).unwrap();

        Ok(Metadata { cid, encoded_tags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor() {
        let tags = Tags {
            values: vec!["hello".to_string(), "world".to_string()],
        };

        let expected_tags = serde_json::to_vec(&tags).unwrap();
        let expected_cid =
            "baejbeibftkdybljjeqmqwdvk2wolyyjvnrfi5zjfgbgcu2u27chuvqc3xq".to_string();

        let m = Metadata::new(tags).unwrap();

        assert_eq!(expected_cid, m.cid);
        assert_eq!(expected_tags, m.encoded_tags);
    }

    #[test]
    fn metadata_match() {
        let tags = Tags {
            values: vec!["hello".to_string(), "world".to_string()],
        };

        let meta = Metadata::new(tags).unwrap();

        assert!(meta.query("hello".to_string()).unwrap() == true);
        assert!(meta.query("world".to_string()).unwrap() == true);
        assert!(meta.query("moon".to_string()).unwrap() == false);
    }

    #[test]
    fn encrypt_decrypt() {
        let tags = Tags {
            values: vec!["hello".to_string(), "world".to_string()],
        };
        let meta = Metadata::new(tags).unwrap();

        let key = b"hello darkness my good ol friend";
        let encrypted_meta = meta.clone().encrypt(key).unwrap();

        assert_eq!(meta.cid.clone() + &"/encrypted", encrypted_meta.cid);
        assert_ne!(meta.encoded_tags, encrypted_meta.encoded_tags);

        let decrypted_meta = encrypted_meta.decrypt(key).unwrap();

        assert_eq!(meta.cid, decrypted_meta.cid);
        assert_eq!(meta.encoded_tags, decrypted_meta.encoded_tags);
    }
}
