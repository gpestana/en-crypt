#![allow(dead_code)]
#![allow(unused_must_use)]

use cid::{Cid, Version};
use multihash::{Code, MultihashDigest};
use std::io::{Read, Write};

const BLOCK_SIZE: usize = 256 * 8; // 256 bytes
const SHA256_CODE: u64 = 0x12;

#[derive(Clone, Debug)]
struct Wrapper {
    pub cid: String,
    pub metadata: Box<[u8]>,
    pub head_block: Option<String>,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug)]
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
        let mut new_data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        new_data[..buf.len()].clone_from_slice(buf);
        self.data = Box::new(new_data);

        let h = Code::Sha2_256.digest(&new_data);
        let cid = match Cid::new(Version::V1, SHA256_CODE, h) {
            Ok(c) => c,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };
        self.cid = cid.to_string();

        Ok(self.data.len())
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.data = Box::new([]);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Pointer(Wrapper);

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
            "baejbeidzs6e7xnrm3oec43pkmblr6ypq6rkxyjnjxdut5d5m2voxraakca".to_string();

        let p = Pointer::from(&synthetic_data).unwrap();
        assert_eq!(p.cid(), expected_ptr_cid);
        assert_eq!(p.blocks_len(), 2);
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
            "baejbeibd5xwwexac5cnvy2gwjzelt67k5ldp7fnwlpw4ctqn3iyloz23ri".to_string();

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
        assert_eq!(res.unwrap(), BLOCK_SIZE);
        assert_eq!(dst[0], src[0]);
        assert_eq!(dst[1], src[1]);
        assert_eq!(dst[2], src[2]);
        assert_eq!(dst[3], src[3]);
    }
}
