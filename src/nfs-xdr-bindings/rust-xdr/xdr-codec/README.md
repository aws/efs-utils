# Rust XDR library

[![Build Status](https://travis-ci.org/jsgf/rust-xdr.svg?branch=master)](https://travis-ci.org/jsgf/rust-xdr)
[![Crates.io](https://img.shields.io/crates/v/xdr-codec.svg)]()
[![Coverage Status](https://coveralls.io/repos/github/jsgf/rust-xdr/badge.svg?branch=master)](https://coveralls.io/github/jsgf/rust-xdr?branch=master)

This crate provides a set of runtime routines to encode and decode
basic XDR types, which can be used with
[xdrgen's](https://github.com/jsgf/rust-xdrgen) automatically
generated code, or with hand-written codecs.

This crate also implements XDR-RPC record marking in the form of the
`XdrRecordReader` and `XdrRecordWriter` IO filters.

## Usage

The easiest way to use this library is with [xdrgen](https://crates.io/crates/xdrgen),
which takes takes a specification in a `.x` file and generates all the necessary
definitions for you.

However, you can manually implement the `Pack` and `Unpack` traits for your own
types:

```
struct MyType {
    a: u32,
    b: Vec<u8>,
}

impl Pack<W> for MyType
    where W: Write
{
    fn pack(&self, out: &mut W) -> xdr_codec::Result<usize> {
        let mut sz = 0;

        sz += try!(self.a.pack(out));
        sz += try!(Opaque::borrowed(self.b).pack(out));

        Ok(sz)
    }
}

impl Unpack<R> for MyType
    where R: Read
{
    fn unpack(input: &mut In) -> Result<(Self, usize)> {
        let mut rsz = 0;
        let ret = MyType {
            a: { let (v, sz) = try!(Unpack::unpack(input)); rsz += sz; v },
            b: { let (v, sz) = try!(Opaque::unpack(input)); rsz += sz; v.into_owned() },
        };

        Ok((ret, rsz))
    }
}
```

or alternatively, put the following in src/mytype.x:

```
struct MyType {
    unsigned int a;
    opaque b<>;
}
```

then add a build.rs to your Cargo.toml:

```
extern crate xdrgen;

fn main() {
    xdrgen::compile("src/mytype.x").expect("xdrgen mytype.x failed");
}
```

then include the generated code in one of your modules:
```
extern crate xdr_codec;

// ...

include!(concat!(env!("OUT_DIR"), "/mytype_xdr.rs"));
```

## Documentation

Complete documentation is [here](https://docs.rs/xdr-codec/).

## Changes in 0.4.2

Implement standard traits for `char`/`unsigned char` (`i8`/`u8` in Rust).

Also handle `short`/`unsigned short` as an extension in .x files. They are still
represented in memory as `i32`/`u32`.

## Changes in 0.4

Version 0.4 added the `bytecodec` feature, which implements `Pack` and `Unpack`
for byte types (`i8` and `u8`). This is normally unwanted, since bytes suffer from
massive padding on the wire when used individually, or in an array of bytes (`opaque`
is the preferred way to transport compact byte arrays). However, some protocols
are mis-specified to use padded byte arrays, so `bytecodec` is available for them.

## Changes in 0.2

Versions starting with 0.2 introduced a number of breaking changes:

 * `u8` no longer implements `Pack`/`Unpack`

   XDR doesn't directly support encoding individual bytes; if it did, it would
   require each one to be padded out to 4 bytes. xdr-codec 0.1 implemented
   `Pack` and `Unpack` for `u8` primarily to allow direct use of a `Vec<u8>`
   as an XDR `opaque<>`. However, this also allowed direct use of
   `u8::pack()` which makes it too easy to accidentally generate a malformed
   XDR stream without proper padding.

   In 0.2, u8 no longer implements `Pack` and `Unpack`. Instead, xdr-codec
   has a `Opaque<'a>(&'a [u8])` wrapper which does. This allows any `[u8]`
   slice to be packed and unpacked.

   It also has a set of helper functions for packing and unpacking both
   flexible and fixed-sized opaques, strings and general arrays. These make
   it straightforward to manage arrays in a way that is robust. This also allows
   xdrgen to generate code for fixed-sized arrays that's not completely unrolled
   unpack calls.

   (I'm not entirely happy with the proliferation of functions however, so
   I'm thinking about a trait-based approach that is more idiomatic Rust. That
   may have to be 0.3.)

* Extensions to XDR record marking

   I added `XdrRecordReaderIter` which allows iteration over records. Previously
   all the records in the stream were flattened into a plain byte stream, which
   defeats the purpose of the records. `XdrRecordReader` still implements `Read`
   so that's still available, but it also implements `IntoIterator` so you can
   iterate records.

   The addition of more unit tests (see below) pointed out some poorly thought
   out corner cases, so now record generation and use of the EOR marker is more
   consistent.

* More unit tests, including quickcheck generated ones

   I've increased the number of tests, and added quickcheck generated tests
   which cleared up a few corner cases.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
 * MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
