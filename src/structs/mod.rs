use std::io::{ Read, Write };

const BLOCK_SIZE: usize = 256 * 8; // 256 bytes

#[derive(Clone, Debug)]
struct Wrapper {
    pub cid: String,
    pub metadata: Box<[u8]>,
    pub head_block: Option<String>, // cid for first block
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug)]
struct Block {
    pub cid: String,
    pub digest: Box<[u8]>,
    pub next: Option<String>,
    pub data: Box<[u8]>,
}

impl Block {
    pub fn into_raw(&self) -> &[u8] {
        &self.data
    }

    pub fn new_empty() -> Self {
        Block{
            cid: "".to_string(),
            digest: Box::new([]),
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
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                format!("Data too large to store by a single block. Max {:?} bytes", BLOCK_SIZE)));
        }
        let mut new_data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        new_data[..buf.len()].clone_from_slice(buf);
        self.data = Box::new(new_data);
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
    pub fn new(buf: &[u8]) -> Self {
        let mut blocks = Vec::<Block>::new();
        let mut chunker = buf.chunks(BLOCK_SIZE);

        loop {
            let chunk = match chunker.next() {
                Some(c) => c,
                None => break,
            };
            let mut data = Vec::new();
            data.extend_from_slice(&chunk);

            let block = Block {
                cid: "".to_string(),
                digest: Box::new([0]),
                next: None,
                data: Box::new([12, 12, 3, 1]), // TODO consume data
            };

            blocks.push(block);
        }

        let wrapper = Wrapper {
            cid: "wrapper_cid".to_string(),
            metadata: Box::new([0]),
            head_block: Some("".to_string()),
            blocks,
        };

        Pointer { 0: wrapper }
    }

    pub fn metadata(&self) -> &[u8] {
        &self.0.metadata
    }

    pub fn cid(&self) -> &str {
        &self.0.cid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor() {
        let p = Pointer::new(&[1, 2, 3]);
        assert_eq!(p.cid(), "wrapper_cid");
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
        let res = b.write(&src);
        
        let mut dst = Vec::from([0; 3]);
        let res = b.read(&mut dst);
        assert!(res.is_ok(), "Error reading from block");
        assert_eq!(res.unwrap(), 3);
        assert_eq!(dst.to_vec(), Vec::from([1, 2, 3]));

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
