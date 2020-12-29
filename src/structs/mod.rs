#![allow(dead_code)]
#![allow(unused_must_use)]

use cid::{Cid, Version};
use multihash::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

const BLOCK_SIZE: usize = 256 * 8; // 256 bytes
const SHA256_CODE: u64 = 0x12;
const NONCE_SIZE_BYTES: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Wrapper {
    pub cid: String,
    pub metadata: Box<[u8]>,
    pub head_block: Option<String>,
    pub blocks: Vec<Block>,
}

impl Read for Wrapper {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        unimplemented!();
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
        let mut count_bytes: usize = 0;

        for block in &self.blocks {
            let mut tmp_buf: Vec<u8> = vec![];
            let bytes = block.data.as_ref().read_to_end(&mut tmp_buf).unwrap();
            buf.extend_from_slice(tmp_buf.as_slice());
            count_bytes += bytes;
        }

        Ok(count_bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Block {
    pub cid: String,
    pub next: Option<String>,
    pub data: Box<[u8]>,
}

impl Block {
    pub fn into_raw(&self) -> &[u8] {
        &self.data
    }

    pub fn new_empty() -> Self {
        Block {
            cid: "".to_string(),
            next: None,
            data: Box::new([]),
        }
    }

    pub fn encrypt(self, key: &[u8; 32]) -> Block {
        let nonce = GenericArray::from_slice(&self.cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let k = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(k);

        let ctext = cipher.encrypt(nonce, self.data.as_ref()).unwrap();

        let mut enc_data: Vec<u8> = vec![];
        enc_data.extend_from_slice(&ctext);

        Block {
            cid: self.cid + "/encrypted",
            next: self.next,
            data: enc_data.into_boxed_slice(),
        }
    }

    pub fn decrypt(self, key: &[u8; 32]) -> Block {
        let cid_split: Vec<&str> = self.cid.split('/').collect();
        let cid = cid_split[0].to_string();

        let nonce = GenericArray::from_slice(&cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let key = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let ptext = cipher.decrypt(nonce, self.data.as_ref()).unwrap();

        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&ptext.as_slice());

        Block {
            cid: cid,
            next: self.next,
            data: data.into_boxed_slice(),
        }
    }
}

impl Read for Block {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.data.as_ref().read(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
        self.data.as_ref().read_to_end(buf)
    }
}

impl Write for Block {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() > BLOCK_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Data too large to store by a single block. Max {:?} bytes",
                    BLOCK_SIZE
                ),
            ));
        }

        let mut new_data: Vec<u8> = vec![];
        new_data.extend_from_slice(&buf);

        let h = Code::Sha2_256.digest(&new_data);
        let cid = match Cid::new(Version::V1, SHA256_CODE, h) {
            Ok(c) => c,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };

        self.cid = cid.to_string();
        self.data = new_data.into_boxed_slice();

        Ok(self.data.len())
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.data = Box::new([]);
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pointer(Wrapper);

impl Read for Pointer {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        unimplemented!();
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
        self.0.read_to_end(buf)
    }
}

impl Pointer {
    pub fn from(buf: &[u8]) -> Result<Self, cid::Error> {
        let mut chunker = buf.chunks(BLOCK_SIZE);

        let mut blocks = Vec::<Block>::new();
        let mut concat_block_cids = vec![];
        let mut head_block = None;

        let mut idx = 0;
        loop {
            let chunk = match chunker.next() {
                Some(c) => c,
                None => break,
            };
            let mut data = Vec::new();
            data.extend_from_slice(&chunk);

            let mut block = Block::new_empty();
            block.write(&mut data);

            if idx == 0 {
                head_block = Some(block.cid.to_string());
            }

            concat_block_cids.append(&mut Vec::from(block.cid.to_string()));
            blocks.push(block);
            idx += 1;
        }

        let h = Code::Sha2_256.digest(&concat_block_cids);
        let cid = match Cid::new(Version::V1, SHA256_CODE, h) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let wrapper = Wrapper {
            cid: cid.to_string(),
            blocks,
            head_block,
            metadata: Box::new([0]),
        };

        Ok(Pointer { 0: wrapper })
    }

    pub fn encrypt(self, key: &[u8; 32]) -> Result<Pointer, String> {
        let nonce = GenericArray::from_slice(&self.0.cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let k = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(k);

        let metadata = self.0.metadata.as_ref();
        let ctext = cipher.encrypt(nonce, metadata).unwrap();

        let mut enc_metadata: Vec<u8> = vec![];
        enc_metadata.extend_from_slice(&ctext);

        let mut enc_blocks: Vec<Block> = vec![];

        // encrypt blocks
        for block in self.0.blocks {
            let enc_block = block.encrypt(key);
            enc_blocks.push(enc_block);
        }

        let wrapper = Wrapper {
            cid: self.0.cid + "/encrypted",
            head_block: self.0.head_block,
            metadata: enc_metadata.into_boxed_slice(),
            blocks: enc_blocks,
        };

        Ok(Pointer { 0: wrapper })
    }

    pub fn decrypt(self, key: &[u8; 32]) -> Result<Pointer, String> {
        let cid_split: Vec<&str> = self.0.cid.split('/').collect();
        let cid = cid_split[0].to_string();

        let nonce = GenericArray::from_slice(&cid.as_bytes()[0..NONCE_SIZE_BYTES]);
        let k = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(k);

        let ptext = match cipher.decrypt(nonce, self.0.metadata.as_ref()) {
            Ok(pt) => pt,
            Err(e) => {
                println!("{:?}", e);
                return Err(e.to_string());
            }
        };

        let mut metadata: Vec<u8> = vec![];
        metadata.extend_from_slice(&ptext.as_slice());

        let mut dec_blocks: Vec<Block> = vec![];

        // decrypt blocks
        for block in self.0.blocks {
            let dec_block = block.decrypt(key);
            dec_blocks.push(dec_block);
        }

        let wrapper = Wrapper {
            cid,
            metadata: metadata.into_boxed_slice(),
            head_block: self.0.head_block,
            blocks: dec_blocks,
        };

        Ok(Pointer { 0: wrapper })
    }

    pub fn metadata(&self) -> &[u8] {
        &self.0.metadata
    }

    pub fn cid(&self) -> &str {
        &self.0.cid
    }

    pub fn blocks_len(&self) -> usize {
        return self.0.blocks.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_constructor() {
        let synthetic_data = [1_u8; BLOCK_SIZE + 1];
        let expected_ptr_cid =
            "baejbeidf3xehfzoocgwqaddxr64ggxzuh5yucgzpzhgv772z4ws552kui4".to_string();

        let p = Pointer::from(&synthetic_data).unwrap();
        assert_eq!(p.cid(), expected_ptr_cid);
        assert_eq!(p.blocks_len(), 2);
    }

    #[test]
    fn pointer_read() {
        let synthetic_data = [1_u8; BLOCK_SIZE + 1];
        let expected_ptr_cid =
            "baejbeidf3xehfzoocgwqaddxr64ggxzuh5yucgzpzhgv772z4ws552kui4".to_string();
        let expected_total_bytes = BLOCK_SIZE + 1;

        let mut p = Pointer::from(&synthetic_data).unwrap();
        assert_eq!(p.cid(), expected_ptr_cid);
        assert_eq!(p.blocks_len(), 2);

        let mut dst_vec: Vec<u8> = vec![];
        let bytes = p.read_to_end(&mut dst_vec).unwrap();

        assert_eq!(bytes, expected_total_bytes);
        assert_eq!(dst_vec.len(), expected_total_bytes);
    }

    #[test]
    fn serialization() {
        use serde_cbor::de;

        let synthetic_data = [1_u8; BLOCK_SIZE + 1];
        let p = Pointer::from(&synthetic_data).unwrap();
        let serial_p = serde_cbor::to_vec(&p).unwrap();
        let p_deser: Pointer = de::from_slice(&serial_p).unwrap();

        assert_eq!(p.cid(), p_deser.cid());
        assert_eq!(p.blocks_len(), p_deser.blocks_len());
    }

    #[test]
    fn block_writer_reader() {
        // empty block
        let mut dst = Vec::<u8>::new();
        let mut b = Block::new_empty();
        let res = b.read(&mut dst);
        assert!(res.is_ok(), "Error reading from block");
        assert_eq!(res.unwrap(), 0);
        assert_eq!(dst.to_vec(), Vec::<u8>::new());

        // write to block using Writer interface
        let src = [1, 2, 3, 4];
        let expected_block_cid =
            "baejbeie7mstupynzp4jr7k5wwrdss3e3n4badz47wpctk3tmo7ujw2uani".to_string();

        let _ = b.write(&src);

        let mut dst = Vec::from([0; 3]);
        let res = b.read(&mut dst);
        assert!(res.is_ok(), "Error reading from block");
        assert_eq!(res.unwrap(), 3);
        assert_eq!(dst.to_vec(), Vec::from([1, 2, 3]));
        assert_eq!(b.cid, expected_block_cid);

        let mut dst = Vec::new();
        let res = b.read_to_end(&mut dst);
        assert!(res.is_ok(), "Error reading from block");
        assert_eq!(res.unwrap(), src.len());
        assert_eq!(dst[0], src[0]);
        assert_eq!(dst[1], src[1]);
        assert_eq!(dst[2], src[2]);
        assert_eq!(dst[3], src[3]);
    }

    #[test]
    fn block_encrypt_decrypt() {
        let mut original_block = Block::new_empty();
        let src = [1, 2, 3, 4];
        let expected_block_cid =
            "baejbeie7mstupynzp4jr7k5wwrdss3e3n4badz47wpctk3tmo7ujw2uani".to_string();
        let res = original_block.write(&src);
        assert!(res.is_ok(), "Error creating block");
        assert_eq!(original_block.cid, expected_block_cid);

        // encrypts content
        let key = b"an example very very secret key.";
        let enc_b = original_block.clone().encrypt(key);
        assert_eq!(enc_b.cid, expected_block_cid + "/encrypted");

        // decrypts encrypted block
        let dec_b = enc_b.clone().decrypt(key);
        assert_eq!(original_block.cid, dec_b.cid);
        assert_eq!(original_block.data, dec_b.data);
    }

    #[test]
    fn end_to_end() {
        use serde_cbor::de;

        let file_buffer = std::fs::read(file!()).unwrap();

        // creates pointer for file
        let pointer = Pointer::from(&file_buffer).unwrap();

        assert!(pointer.blocks_len() > 1);

        // encrypts pointer
        let key = b"hello darkness my good ol friend";
        let encrypted_pointer = pointer.clone().encrypt(key).unwrap();

        assert_eq!(pointer.blocks_len(), encrypted_pointer.blocks_len());

        // serialise and deserialise pointer
        let serial_pointer = serde_cbor::to_vec(&encrypted_pointer).unwrap();
        let current_pointer: Pointer = de::from_slice(&serial_pointer).unwrap();

        assert_eq!(encrypted_pointer.blocks_len(), current_pointer.blocks_len());
        assert_eq!(encrypted_pointer.cid(), current_pointer.cid());

        // decrypts pointer
        let mut decrypted_pointer = current_pointer.decrypt(key).unwrap();

        // compares raw pointer contents to original file (no metadata, etc)
        let mut final_buffer: Vec<u8> = vec![];
        decrypted_pointer.read_to_end(&mut final_buffer);

        // final buffer should be the same as intial file buffer after all
        // the transformations
        assert_eq!(final_buffer, file_buffer);
        assert_eq!(final_buffer.len(), file_buffer.len());
    }
}
