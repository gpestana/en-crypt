mod crypto;

use clap::{App, Arg, SubCommand};

fn main() {
    let matches = App::new("en-crypt")
        .version("0.1")
        .author("@gpestana <g6pestana@gmail.com>")
        .about("CLI for the en-crypt protocol - store, search and recover encrypted data")
        .subcommand(
            SubCommand::with_name("store")
                .about("stores encrypted file in a backend")
                .arg(
                    Arg::with_name("file")
                        .long("file")
                        .short("f")
                        .value_name("FILE")
                        .takes_value(true)
                        .help("path to file to store")
                    )
                .arg(
                    Arg::with_name("config")
                        .long("config")
                        .short("c")
                        .value_name("CONFIG")
                        .help("config file. Defaults to ~/.en-crypt/config.json")
                )
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("store") {
        if matches.is_present("file") {
            let file_path = matches.value_of("file").unwrap();
            let config = matches.value_of("config").unwrap_or("./config.json");

            println!("File: {}, config: {}", file_path, config);

        crypto::encrypt(file_path);

        } else {
            println!("Not storing anything, for now..");
        }
    }
}
