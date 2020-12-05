const BLOCK_SIZE: usize = 256 * 8; // 256 bytes

#[derive(Clone, Debug)]
struct Wrapper {
    pub cid: String,
    pub metadata: Box<[u8]>,
    pub head_block: String, // cid for first block
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug)]
struct Block {
    pub cid: String,
    pub digest: Box<[u8]>,
    pub next: String,
    pub data: Box<[u8]>,
}

impl Block {
    pub fn into_raw(&self) -> &[u8] {
        &self.data
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
                next: "".to_string(),
                data: Box::new([12, 12, 3, 1]),
            };

            blocks.push(block);
        }

        let wrapper = Wrapper {
            cid: "wrapper_cid".to_string(),
            metadata: Box::new([0]),
            head_block: "".to_string(),
            blocks,
        };

        Pointer { 0: wrapper }
    }

    pub fn raw_data(&self) -> &Box<[u8]> {
        // TODO: wrap data from all boxes in pointer
        &self.0.blocks[0].data
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

        let expected: Box<[u8]> = Box::new([12, 12, 3, 1]);
        assert_eq!(*p.raw_data(), expected);
    }
}
