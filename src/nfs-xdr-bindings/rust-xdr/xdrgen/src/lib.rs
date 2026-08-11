//! XDR codec generation
//!
//! This crate provides library interfaces for programatically generating Rust code to implement
//! RFC4506 XDR encoding/decoding, as well as a command line tool "xdrgen".
//!
//! It is intended to be used with the "xdr-codec" crate, which provides the runtime library for
//! encoding/decoding primitive types, strings, opaque data and arrays.

#![recursion_limit = "128"]

extern crate xdr_codec as xdr;

#[macro_use]
extern crate quote;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate bitflags;

use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::result;

use xdr::Result;

mod spec;
use spec::{Emit, Emitpack, Symtab};

fn result_option<T, E>(resopt: result::Result<Option<T>, E>) -> Option<result::Result<T, E>> {
    match resopt {
        Ok(None) => None,
        Ok(Some(v)) => Some(Ok(v)),
        Err(e) => Some(Err(e)),
    }
}

/// Generate Rust code from an RFC4506 XDR specification
///
/// `infile` is simply a string used in error messages; it may be empty. `input` is a read stream of
/// the specification, and `output` is where the generated code is sent.
pub fn generate<In, Out>(infile: &str, mut input: In, mut output: Out) -> Result<()>
where
    In: Read,
    Out: Write,
{
    let mut source = String::new();

    input.read_to_string(&mut source)?;

    let xdr = match spec::specification(&source) {
        Ok(defns) => Symtab::new(&defns),
        Err(e) => return Err(xdr::Error::from(format!("parse error: {}", e))),
    };

    let xdr = xdr;

    let res: Vec<_> = {
        let consts = xdr
            .constants()
            .filter_map(|(c, &(v, ref scope))| {
                if scope.is_none() {
                    Some(spec::Const(c.clone(), v))
                } else {
                    None
                }
            })
            .map(|c| c.define(&xdr));

        let typespecs = xdr
            .typespecs()
            .map(|(n, ty)| spec::Typespec(n.clone(), ty.clone()))
            .map(|c| c.define(&xdr));

        let typesyns = xdr
            .typesyns()
            .map(|(n, ty)| spec::Typesyn(n.clone(), ty.clone()))
            .map(|c| c.define(&xdr));

        let packers = xdr
            .typespecs()
            .map(|(n, ty)| spec::Typespec(n.clone(), ty.clone()))
            .filter_map(|c| result_option(c.pack(&xdr)));

        let unpackers = xdr
            .typespecs()
            .map(|(n, ty)| spec::Typespec(n.clone(), ty.clone()))
            .filter_map(|c| result_option(c.unpack(&xdr)));

        consts
            .chain(typespecs)
            .chain(typesyns)
            .chain(packers)
            .chain(unpackers)
            .collect::<Result<Vec<_>>>()?
    };

    let _ = writeln!(
        output,
        r#"
// GENERATED CODE
//
// Generated from {} by xdrgen.
//
// DO NOT EDIT

"#,
        infile
    );

    for it in res {
        let _ = writeln!(output, "{}\n", it.as_str());
    }

    Ok(())
}

/// Simplest possible way to generate Rust code from an XDR specification.
///
/// It is intended for use in a build.rs script:
///
/// ```ignore
/// extern crate xdrgen;
///
/// fn main() {
///    xdrgen::compile("src/simple.x").unwrap();
/// }
/// ```
///
/// Output is put into OUT_DIR, and can be included:
///
/// ```ignore
/// mod simple {
///    use xdr_codec;
///
///    include!(concat!(env!("OUT_DIR"), "/simple_xdr.rs"));
/// }
/// ```
///
/// If your specification uses types which are not within the specification, you can provide your
/// own implementations of `Pack` and `Unpack` for them.
pub fn compile<P>(infile: P) -> Result<()>
where
    P: AsRef<Path> + Display,
{
    let input = File::open(&infile)?;

    let mut outdir = PathBuf::from(env::var("OUT_DIR").unwrap_or(String::from(".")));
    let outfile = PathBuf::from(infile.as_ref())
        .file_stem()
        .unwrap()
        .to_owned()
        .into_string()
        .unwrap()
        .replace("-", "_");

    outdir.push(&format!("{}_xdr.rs", outfile));

    let output = File::create(outdir)?;

    generate(
        infile.as_ref().as_os_str().to_str().unwrap_or("<unknown>"),
        input,
        output,
    )
}
