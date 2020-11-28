use crate::structs::EncryptedFile;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub fn store(file_path: &str) -> Result<(), String> {
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Error opening file: {}", e)),
    };

    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf);

    // get from configs
    let key = b"secret key is 32*8 (256) bits   ";
    let encrypted_file = EncryptedFile::from_bytes(&buf, key).unwrap();

    // todo: serialize and store encrypted_file

    // todo: remove
    let plaintext = encrypted_file.decrypt(key).unwrap();
    println!("{:?}", std::str::from_utf8(&plaintext).unwrap());

    Ok(())
}
