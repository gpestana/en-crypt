use serde_cbor::de;
use std::fs::File;
use std::io::Read;

use crate::structs::Pointer;

pub fn handle_store_command(file_path: &str, key: &str) -> Vec<u8> {
    // opens and read input file
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(err) => {
            println!("Error opening file: {:?}", err);
            std::process::exit(0);
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    if let Err(err) = f.read_to_end(&mut buf) {
        println!("Error reading file: {:?}", err);
        std::process::exit(0);
    };

    let pointer = match Pointer::from(&buf) {
        Ok(p) => p,
        Err(err) => {
            println!("Error transforming file: {:?}", err);
            std::process::exit(0);
        }
    };

    // refactor
    let mut buf_key: [u8; 32] = [0; 32];
    let mut i = 0;
    for b in key.as_bytes() {
        buf_key[i] = *b;
        i = i + 1;
    }
    let encrypted_pointer = match pointer.encrypt(&buf_key) {
        Ok(p) => p,
        Err(err) => {
            println!("Error encrypting file: {:?}", err);
            std::process::exit(0);
        }
    };

    serde_cbor::to_vec(&encrypted_pointer).unwrap()
}

pub fn handle_read_command(file_path: &str, key: &str) -> Vec<u8> {
    // opens and read input file
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(err) => {
            println!("Error opening file: {:?}", err);
            std::process::exit(0);
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    if let Err(err) = f.read_to_end(&mut buf) {
        println!("Error reading file: {:?}", err);
        std::process::exit(0);
    };

    let encrypted_pointer: Pointer = match de::from_slice(&buf) {
        Ok(p) => p,
        Err(err) => {
            println!(
                "Error deserializing file from contents of {}. Error: {}",
                file_path, err
            );
            std::process::exit(0);
        }
    };

    // refactor
    let mut buf_key: [u8; 32] = [0; 32];
    let mut i = 0;
    for b in key.as_bytes() {
        buf_key[i] = *b;
        i = i + 1;
    }

    let mut decrypted_pointer = match encrypted_pointer.decrypt(&buf_key) {
        Ok(p) => p,
        Err(err) => {
            println!("Error decrypting file: {:?}", err);
            std::process::exit(0);
        }
    };

    let mut buffer: Vec<u8> = vec![];
    let _ = decrypted_pointer.read_to_end(&mut buffer);

    buffer
}
