use std::fs::File;
use std::io::Read;

pub fn store(file_path: &str) -> Result<(), String> {
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(err) => return Err(format!("Error opening file: {}", err)),
    };

    let mut buf: Vec<u8> = Vec::new();
    if let Err(err) = f.read_to_end(&mut buf) {
        return Err(format!("Error reading file: {}", err));
    };

    Ok(())
}
