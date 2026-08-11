#![crate_type = "bin"]

extern crate clap;
extern crate env_logger;
extern crate xdrgen;

use std::fs::File;
use std::io::{stderr, stdin, stdout};
use std::io::{BufReader, Write};

use clap::App;

use xdrgen::generate;

fn main() {
    let _ = env_logger::init();

    let matches = App::new("XDR code generator")
        .version(env!("CARGO_PKG_VERSION"))
        .arg_from_usage("[FILE] 'Set .x file'")
        .get_matches();

    let output = stdout();
    let mut err = stderr();

    let res = if let Some(fname) = matches.value_of("FILE") {
        let f = match File::open(fname) {
            Ok(f) => f,
            Err(e) => {
                let _ = writeln!(&mut err, "Failed to open {}: {}", fname, e);
                std::process::exit(1);
            }
        };
        generate(fname, BufReader::new(f), output)
    } else {
        generate("stdin", BufReader::new(stdin()), output)
    };

    if let Err(e) = res {
        let _ = writeln!(&mut err, "Failed: {}", e);
    }
}
