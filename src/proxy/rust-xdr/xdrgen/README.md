# Rust XDR library

[![Build Status](https://travis-ci.org/jsgf/rust-xdr.svg?branch=master)](https://travis-ci.org/jsgf/rust-xdr)
[![Crates.io](https://img.shields.io/crates/v/xdrgen.svg)](https://crates.io/crates/xdrgen)
[![Coverage Status](https://coveralls.io/repos/github/jsgf/promising-future/badge.svg?branch=master)](https://coveralls.io/github/jsgf/promising-future?branch=master)

This crate provides xdrgen, which takes an XDR specification in a .x
file, and produces Rust code to serialize and deserialize the
specified types. It is intended to be used in conjunction with
[xdr-codec](https://github.com/jsgf/rust-xdr-codec).

The syntax of the .x file follows
[RFC4506](https://tools.ietf.org/html/rfc4506.html). This has type definitions
for XDR but does not include RPC protocol specifications. Correspondingly,
xdrgen does not support auto-generation of RPC clients/servers.

## Changes in 0.4.0

- Now uses the `quote` package, so it will work on stable Rust
- Detects the use of Rust keywords in XDR specifications, and appends a `_` to them.

## Usage

Usage is straightforward. You can generate the Rust code from a spec a build.rs:

```
extern crate xdrgen;

fn main() {
    xdrgen::compile("src/simple.x").expect("xdrgen simple.x failed");
}
```

This code can then be included into a module:

```
mod simple {
    use xdr_codec;

    #[allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/simple_xdr.rs"));
}
```

Once you have this, you can call `mytype.pack(&mut output)`, and
`let mything: MyThing = xdr_codec::unpack(&mut input)?;`.

The serializers require your types to implement the `Pack` and `Unpack`
traits, and generate code to write to `std::io::Write` implementation, and
read from `std::io::Read`.

All types and fields are generated public, so you can control their access
outside your module or crate. If your spec references other types which are
not defined within the spec, then you can define them within the module
as well, either by aliasing them with other defined types, or implementing
the `Pack` and `Unpack` traits yourself.

Use can use xdr-codec's `XdrRecordReader` and `XdrRecordWriter` types as IO
filters that implement XDR-RPC record marking.

More [documentation for xdrgen
here](https://docs.rs/xdrgen/). See the
[documentation for
xdr-codec](https://docs.rs/xdr-codec/) for more
details about using the generated types and code.

## Limitations

There are currently a few limitations:
   * The generated code uses identifiers as specified in the .x file, so the
     Rust code will not use normal formatting conventions.
   * Generated code follows no formatting convention - use rustfmt if desired.
   * XDR has discriminated unions, which are a good match for Rust enums.
     However, it also supports a `default` case if an unknown discriminator
     is encountered. This crate supports this for unpacking, but not for
     packing, as Rust does not allow enums to have unknown values.
   * The generated code uses `#[derive(Debug, Clone, ...)]` to generate
     implementations for common traits. However, rustc only supports `#[derive]`
     on fixed-size arrays with 0..32 elements; if you have an array larger than
     this, the generated code will fail to compile. Right now, the only workaround
     is to manually implement `Pack` and `Unpack` for such types.
     (TODO: add an option to omit derived traits.)

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
 * MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
