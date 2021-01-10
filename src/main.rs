mod crypto;
mod structs;

mod commands;

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
                        .help("path to file to store"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .short("k")
                        .value_name("KEY")
                        .takes_value(true)
                        .help("secret key to encrypt/decrypt data"),
                )
                .arg(
                    Arg::with_name("config")
                        .long("config")
                        .short("c")
                        .value_name("CONFIG")
                        .help("config file. Defaults to ~/.en-crypt/config.json"),
                ),
        )
        .subcommand(
            SubCommand::with_name("read")
                .about("decrypts and reads encrypted blob")
                .arg(
                    Arg::with_name("file")
                        .long("file")
                        .short("f")
                        .value_name("FILE")
                        .takes_value(true)
                        .help("path to file to store"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .short("k")
                        .value_name("KEY")
                        .takes_value(true)
                        .help("secret key to encrypt/decrypt data"),
                )
                .arg(
                    Arg::with_name("config")
                        .long("config")
                        .short("c")
                        .value_name("CONFIG")
                        .help("config file. Defaults to ~/.en-crypt/config.json"),
                ),
        )
        .get_matches();

    // No subcommands of args
    if matches.subcommand.is_none() && matches.args.is_empty() {
        println!("{}", matches.usage.clone().unwrap());
    }

    // Handles store command
    if let Some(matches) = matches.subcommand_matches("store") {
        let file_path = match matches.value_of("file") {
            Some(f) => f,
            None => {
                println!("File (-f) param not provided");
                std::process::exit(0);
            }
        };

        let key = match matches.value_of("key") {
            Some(f) => f,
            None => {
                println!("Key (-k) param not provided");
                std::process::exit(0);
            }
        };

        let encrypted_raw = commands::handle_store_command(file_path, key);
        println!("{:?}", encrypted_raw);
    }

    // Handles read command
    if let Some(matches) = matches.subcommand_matches("read") {
        let file_path = match matches.value_of("file") {
            Some(f) => f,
            None => {
                println!("File (-f) param not provided");
                std::process::exit(0);
            }
        };

        let key = match matches.value_of("key") {
            Some(f) => f,
            None => {
                println!("Key (-k) param not provided");
                std::process::exit(0);
            }
        };

        let raw = commands::handle_read_command(file_path, key);
        println!("{:?}", raw);
    }
}
