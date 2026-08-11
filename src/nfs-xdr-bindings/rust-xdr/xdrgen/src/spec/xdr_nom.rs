// Grammar for a .x file specifying XDR type codecs. Does not include any RPC syntax. Should match RFC4506.
use nom::IResult::*;
use nom::{is_digit, is_space, not_line_ending, Err, ErrorKind, IResult, Needed};

use std::str;

use super::{Decl, Defn, EnumDefn, Type, UnionCase, Value};
use super::{CLONE, COPY, DEBUG, EQ, PARTIALEQ};

#[inline]
fn ignore<T>(_: T) -> () {
    ()
}

// Complete tag
fn ctag<T: AsRef<[u8]>>(input: &[u8], tag: T) -> IResult<&[u8], &[u8]> {
    complete!(input, tag!(tag.as_ref()))
}

fn eof(input: &[u8]) -> IResult<&[u8], ()> {
    if input.len() == 0 {
        IResult::Done(input, ())
    } else {
        IResult::Error(Err::Position(ErrorKind::Eof, input))
    }
}

pub fn specification(input: &str) -> Result<Vec<Defn>, String> {
    match spec(input.as_bytes()) {
        Done(_, spec) => Ok(spec),
        Error(Err::Position(kind, input)) => Err(format!(
            "{:?}: {}",
            kind,
            String::from(str::from_utf8(input).unwrap())
        )),
        Error(err) => Err(format!("Error: {:?}", err)),
        Incomplete(need) => Err(format!("Incomplete {:?}", need)),
    }
}

named!(
    spec<Vec<Defn>>,
    do_parse!(
        opt!(directive) >>
        defns: many0!(definition) >>
        spaces >> eof >>
        (defns))
);

#[test]
fn test_spec() {
    assert_eq!(spec(&b"#include <foo>"[..]), Done(&b""[..], vec!()));

    assert_eq!(
        spec(&b"// hello\n#include <foo>"[..]),
        Done(&b""[..], vec!())
    );

    assert_eq!(
        spec(&b"#include <foo>\ntypedef int foo;"[..]),
        Done(&b""[..], vec!(Defn::typesyn("foo", Type::Int)))
    );

    assert_eq!(
        spec(
            &br#"
/* test file */
#define foo bar
const mip = 123;
% passthrough
typedef int foo;
struct bar {
        int a;
        int b;
};
#include "other"
enum bop { a = 2, b = 1 };
"#[..]
        ),
        Done(
            &b""[..],
            vec!(
                Defn::constant("mip", 123),
                Defn::typesyn("foo", Type::Int),
                Defn::typespec(
                    "bar",
                    Type::Struct(vec!(
                        Decl::named("a", Type::Int),
                        Decl::named("b", Type::Int)
                    ))
                ),
                Defn::typespec(
                    "bop",
                    Type::Enum(vec!(
                        EnumDefn::new("a", Some(Value::Const(2))),
                        EnumDefn::new("b", Some(Value::Const(1)))
                    ))
                )
            )
        )
    );
}

named!(
    definition<Defn>,
    alt!(type_def => { |t| t } |
            const_def => { |c| c })
);

fn is_hexdigit(ch: u8) -> bool {
    match ch as char {
        '0'..='9' | 'A'..='F' | 'a'..='f' => true,
        _ => false,
    }
}

fn is_octdigit(ch: u8) -> bool {
    match ch as char {
        '0'..='7' => true,
        _ => false,
    }
}

fn digit<F: Fn(u8) -> bool>(input: &[u8], isdigit: F) -> IResult<&[u8], &[u8]> {
    for (idx, item) in input.iter().enumerate() {
        if !isdigit(*item) {
            if idx == 0 {
                return Error(Err::Position(ErrorKind::Digit, input));
            } else {
                return Done(&input[idx..], &input[0..idx]);
            }
        }
    }
    Incomplete(Needed::Unknown)
}

named!(lbrace, preceded!(spaces, apply!(ctag, "{")));
named!(rbrace, preceded!(spaces, apply!(ctag, "}")));
named!(lbrack, preceded!(spaces, apply!(ctag, "[")));
named!(rbrack, preceded!(spaces, apply!(ctag, "]")));
named!(lparen, preceded!(spaces, apply!(ctag, "(")));
named!(rparen, preceded!(spaces, apply!(ctag, ")")));
named!(lt, preceded!(spaces, apply!(ctag, "<")));
named!(gt, preceded!(spaces, apply!(ctag, ">")));
named!(colon, preceded!(spaces, apply!(ctag, ":")));
named!(semi, preceded!(spaces, apply!(ctag, ";")));
named!(comma, preceded!(spaces, apply!(ctag, ",")));
named!(eq, preceded!(spaces, apply!(ctag, "=")));
named!(star, preceded!(spaces, apply!(ctag, "*")));

named!(
    hexnumber<i64>,
    do_parse!(
        apply!(ctag, "0x") >>
        val: map_res!(apply!(digit, is_hexdigit), str::from_utf8) >>
        (i64::from_str_radix(val, 16).unwrap())
    )
);

named!(
    octnumber<i64>,
    do_parse!(
        sign: opt!(apply!(ctag, "-")) >>
        apply!(ctag, "0") >>
        val: opt!(map_res!(apply!(digit, is_octdigit), str::from_utf8)) >>
        (i64::from_str_radix(val.unwrap_or("0"), 8).unwrap() * (if sign.is_some() { -1 } else { 1 }))
    )
);

named!(
    decnumber<i64>,
    do_parse!(
        sign: opt!(apply!(ctag, "-")) >>
        val: map_res!(apply!(digit, is_digit), str::from_utf8) >>
        (i64::from_str_radix(val, 10).unwrap() * (if sign.is_some() { -1 } else { 1 }))
    )
);

named!(
    number<i64>,
    preceded!(spaces, alt!(hexnumber | octnumber | decnumber))
);

#[test]
fn test_nums() {
    // Complete number
    assert_eq!(number(&b"0x12344+"[..]), Done(&b"+"[..], 0x12344));
    assert_eq!(number(&b"012344+"[..]), Done(&b"+"[..], 0o12344));
    assert_eq!(number(&b"-012344+"[..]), Done(&b"+"[..], -0o12344));
    assert_eq!(number(&b"12344+"[..]), Done(&b"+"[..], 12344));
    assert_eq!(number(&b"-12344+"[..]), Done(&b"+"[..], -12344));
    assert_eq!(number(&b"0+"[..]), Done(&b"+"[..], 0));
    assert_eq!(number(&b"-0+"[..]), Done(&b"+"[..], 0));

    // Space prefix number
    assert_eq!(number(&b" 0x12344+"[..]), Done(&b"+"[..], 0x12344));
    assert_eq!(number(&b" 012344+"[..]), Done(&b"+"[..], 0o12344));
    assert_eq!(number(&b" -012344+"[..]), Done(&b"+"[..], -0o12344));
    assert_eq!(number(&b" 12344+"[..]), Done(&b"+"[..], 12344));
    assert_eq!(number(&b" -12344+"[..]), Done(&b"+"[..], -12344));
    assert_eq!(number(&b" 0+"[..]), Done(&b"+"[..], 0));
    assert_eq!(number(&b" -0+"[..]), Done(&b"+"[..], 0));

    // Incomplete number
    assert_eq!(number(&b"0x12344"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"012344"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"-012344"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"12344"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"-12344"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"0"[..]), Incomplete(Needed::Unknown));
    assert_eq!(number(&b"-0"[..]), Incomplete(Needed::Unknown));
}

fn token(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let input = ws(input);

    for (idx, item) in input.iter().enumerate() {
        match *item as char {
            'a'..='z' | 'A'..='Z' | '_' => continue,
            '0'..='9' if idx > 0 => continue,
            _ => {
                if idx > 0 {
                    return Done(&input[idx..], &input[0..idx]);
                } else {
                    return Error(Err::Position(ErrorKind::AlphaNumeric, input));
                }
            }
        }
    }
    Incomplete(Needed::Unknown)
}

macro_rules! kw {
    ($fnname:ident, $kw:expr) => {
        fn $fnname(input: &[u8]) -> IResult<&[u8], ()> {
            match token(input) {
                Done(rest, val) => {
                    if val == $kw {
                        Done(rest, ())
                    } else {
                        Error(Err::Position(ErrorKind::Custom(0), input))
                    }
                }
                Error(e) => Error(e),
                Incomplete(_) => {
                    // If its either incomplete but longer that what we're looking for, or what we
                    // have doesn't match, then its not for us.
                    if input.len() > $kw.len() || input != &$kw[..input.len()] {
                        Error(Err::Position(ErrorKind::Custom(0), input))
                    } else {
                        Incomplete(Needed::Size($kw.len() - input.len()))
                    }
                }
            }
        }
    };
}

kw!(kw_bool, b"bool");
kw!(kw_case, b"case");
kw!(kw_char, b"char"); // special case - part time keyword
kw!(kw_const, b"const");
kw!(kw_default, b"default");
kw!(kw_double, b"double");
kw!(kw_enum, b"enum");
kw!(kw_float, b"float");
kw!(kw_hyper, b"hyper");
kw!(kw_int, b"int");
kw!(kw_long, b"long"); // special case - part time keyword
kw!(kw_opaque, b"opaque");
kw!(kw_quadruple, b"quadruple");
kw!(kw_short, b"short"); // special case - part time keyword
kw!(kw_string, b"string");
kw!(kw_struct, b"struct");
kw!(kw_switch, b"switch");
kw!(kw_typedef, b"typedef");
kw!(kw_union, b"union");
kw!(kw_unsigned, b"unsigned");
kw!(kw_void, b"void");

named!(
    keyword<()>,
    alt!(
        kw_bool
            | kw_case
            | kw_const
            | kw_default
            | kw_double
            | kw_enum
            | kw_float
            | kw_hyper
            | kw_int
            | kw_opaque
            | kw_quadruple
            | kw_string
            | kw_struct
            | kw_switch
            | kw_typedef
            | kw_union
            | kw_unsigned
            | kw_void
    )
);

#[test]
fn test_kw() {
    let kws = vec![
        "bool",
        "case",
        "const",
        "default",
        "double",
        "enum",
        "float",
        "hyper",
        "int",
        "opaque",
        "quadruple",
        "string",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
    ];

    for k in &kws {
        println!("testing \"{}\"", k);
        match keyword((*k).as_bytes()) {
            Incomplete(_) => (),
            err => panic!("failed \"{}\": {:?}", k, err),
        }
    }

    for k in &kws {
        println!("testing \"{} \"", k);
        match keyword((String::from(*k) + " ").as_bytes()) {
            Done(rest, ()) if rest == &b" "[..] => (),
            err => panic!("failed \"{} \": {:?}", k, err),
        }
    }

    for k in &kws {
        println!("testing \"{}x \"", k);
        match keyword((String::from(*k) + "x ").as_bytes()) {
            Error(_) => (),
            err => panic!("failed \"{}x \": {:?}", k, err),
        }
    }

    for k in &kws {
        println!("testing \"{}x \"", k);
        match keyword((String::from(" ") + *k + " ").as_bytes()) {
            Done(rest, ()) if rest == &b" "[..] => (),
            err => panic!("failed \" {} \": {:?}", k, err),
        }
    }

    for nk in &vec!["boo", "in", "inx", "booll"] {
        match keyword((*nk).as_bytes()) {
            e @ Done(..) => panic!("{:?} => {:?}", nk, e),
            e => println!("{:?} => {:?}", nk, e),
        }
    }
}

fn ident(input: &[u8]) -> IResult<&[u8], &str> {
    // Grab an identifier and make sure it isn't a keyword
    match token(input) {
        Done(rest, val) => match keyword(input) {
            Done(..) => Error(Err::Position(ErrorKind::Custom(1), val)),
            Error(..) | Incomplete(..) => Done(rest, str::from_utf8(val).unwrap()),
        },
        Error(e) => Error(e),
        Incomplete(need) => Incomplete(need),
    }
}

#[test]
fn test_ident() {
    assert_eq!(ident(&b"foo "[..]), Done(&b" "[..], "foo"));
    assert_eq!(ident(&b" foo "[..]), Done(&b" "[..], "foo"));
    assert_eq!(
        ident(&b" bool "[..]),
        Error(Err::Position(ErrorKind::Custom(1), &b"bool"[..]))
    );
}

named!(
    blockcomment<()>,
    do_parse!(apply!(ctag, "/*") >> take_until_and_consume!(&b"*/"[..]) >> (()))
);

// `linecomment`, and `directive` end at eol, but do not consume it
named!(
    linecomment<()>,
    do_parse!(apply!(ctag, "//") >> opt!(not_line_ending) >> peek!(alt!(eol | eof)) >> (()))
);

// Directive should always follow eol unless its the first thing in the file
named!(
    directive<()>,
    do_parse!(
        opt!(whitespace)
            >> alt!(apply!(ctag, "#") | apply!(ctag, "%"))
            >> opt!(not_line_ending)
            >> peek!(alt!(eol | eof))
            >> (())
    )
);

#[test]
fn test_comments() {
    assert_eq!(blockcomment(&b"/* foo */bar"[..]), Done(&b"bar"[..], ()));
    assert_eq!(
        blockcomment(&b"/* blip /* foo */bar"[..]),
        Done(&b"bar"[..], ())
    );
    assert_eq!(
        blockcomment(&b"x"[..]),
        Error(Err::Position(ErrorKind::Tag, &b"x"[..]))
    );
    assert_eq!(linecomment(&b"// foo\nbar"[..]), Done(&b"\nbar"[..], ()));
    assert_eq!(linecomment(&b"// foo bar\n "[..]), Done(&b"\n "[..], ()));
    assert_eq!(
        linecomment(&b"x"[..]),
        Error(Err::Position(ErrorKind::Tag, &b"x"[..]))
    );

    assert_eq!(directive(&b"#define foo bar\n "[..]), Done(&b"\n "[..], ()));
    assert_eq!(
        directive(&b"%#define foo bar\n "[..]),
        Done(&b"\n "[..], ())
    );

    assert_eq!(
        directive(&b"x"[..]),
        Error(Err::Position(ErrorKind::Alt, &b"x"[..]))
    );

    assert_eq!(
        preceded!(&b"\n#define x\n"[..], eol, directive),
        Done(&b"\n"[..], ())
    );
}

named!(
    eol<()>,
    map!(
        alt!(
            apply!(ctag, "\n")
                | apply!(ctag, "\r\n")
                | apply!(ctag, "\u{2028}")
                | apply!(ctag, "\u{2029}")
        ),
        ignore
    )
);

named!(whitespace<()>, map!(take_while1!(is_space), ignore));

// `spaces` consumes spans of space and tab characters interpolated
// with comments, c-preproc and passthrough lines.
named!(
    spaces<()>,
    map!(
        many0!(alt!(
            do_parse!(eol >> opt!(complete!(directive)) >> (()))
                | whitespace
                | blockcomment
                | linecomment
        )),
        ignore
    )
);

fn ws(input: &[u8]) -> &[u8] {
    match spaces(input) {
        Done(rest, _) => rest,
        _ => input,
    }
}

#[test]
fn test_spaces() {
    assert_eq!(eol(&b"\nx"[..]), Done(&b"x"[..], ()));
    assert_eq!(eol(&b"\r\nx"[..]), Done(&b"x"[..], ()));
    assert_eq!(eol(&b"\nx"[..]), Done(&b"x"[..], ()));

    assert_eq!(
        whitespace(&b"x"[..]),
        Error(Err::Position(ErrorKind::TakeWhile1, &b"x"[..]))
    );
    assert_eq!(whitespace(&b" x"[..]), Done(&b"x"[..], ()));
    assert_eq!(whitespace(&b"  x"[..]), Done(&b"x"[..], ()));
    assert_eq!(whitespace(&b"\tx"[..]), Done(&b"x"[..], ()));
    assert_eq!(whitespace(&b" \tx"[..]), Done(&b"x"[..], ()));
    assert_eq!(whitespace(&b"\t x"[..]), Done(&b"x"[..], ()));

    assert_eq!(spaces(&b"x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"\nx"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b" x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"      x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"\n\n  x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"\r\n  x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"//foo\n      x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"/*\n*/       x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"\n#define a b\n       x"[..]), Done(&b"x"[..], ()));
    assert_eq!(spaces(&b"\n%foo a b\n       x"[..]), Done(&b"x"[..], ()));
}

named!(enum_type_spec<Vec<EnumDefn>>, preceded!(kw_enum, enum_body));

named!(
    enum_body<Vec<EnumDefn>>,
    do_parse!(
        lbrace >>
        b: separated_nonempty_list!(comma, enum_assign) >>
        rbrace >>
        (b)
    )
);

named!(
    enum_assign<EnumDefn>,
    do_parse!(
        id: ident >>
        v: opt!(preceded!(eq, value)) >>
        (EnumDefn::new(id, v))
    )
);

named!(
    value<Value>,
    alt!(number => { |c| Value::Const(c) } |
    ident => { |id| Value::ident(id) }
    )
);

named!(
    struct_type_spec<Vec<Decl>>,
    preceded!(kw_struct, struct_body)
);

named!(
    struct_body<Vec<Decl>>,
    do_parse!(
        lbrace >>
        decls: many1!(terminated!(declaration, semi)) >>
        rbrace >>
        (decls)
    )
);

named!(
    union_type_spec<(Decl, Vec<UnionCase>, Option<Decl>)>,
    do_parse!(kw_union >> body:union_body >> (body))
);

named!(
    union_body<(Decl, Vec<UnionCase>, Option<Decl>)>,
    do_parse!(
        kw_switch >> lparen >> decl:declaration >> rparen >>
        lbrace >>
        ucss: many1!(union_case) >>
        dfl: opt!(union_default) >>
        rbrace >>
        (decl, ucss.into_iter().flat_map(|v| v).collect(), dfl)
    )
);

named!(
    union_case<Vec<UnionCase>>,
    do_parse!(
        vs: many1!(do_parse!(kw_case >> v:value >> colon >> (v))) >>
        decl: declaration >> semi >>
        (vs.into_iter().map(|v| UnionCase(v, decl.clone())).collect())
    )
);

named!(
    union_default<Decl>,
    do_parse!(
        kw_default >> colon >>
        decl: declaration >> semi >>
        (decl)
    )
);

named!(
    declaration<Decl>,
    alt!(kw_void => { |_| Decl::Void } |
        nonvoid_declaration)
);

named!(
    nonvoid_declaration<Decl>,
    alt!(
        do_parse!(ty: array_type_spec >> id: ident >> lbrack >> sz:value >> rbrack >>
            (Decl::named(id, Type::array(ty, sz))))
            | do_parse!(ty: array_type_spec >> id: ident >> lt >> sz:opt!(value) >> gt >>
            (Decl::named(id, Type::flex(ty, sz))))
            | do_parse!(ty: type_spec >> star >> id: ident >>
            (Decl::named(id, Type::option(ty))))
            | do_parse!(ty: type_spec >> id: ident >>
            (Decl::named(id, ty)))
    )
);

named!(
    array_type_spec<Type>,
    alt!(kw_opaque => { |_| Type::Opaque } |
    kw_string => { |_| Type::String } |
    type_spec
    )
);

#[test]
fn test_decls() {
    assert_eq!(declaration(&b"void "[..]), Done(&b" "[..], Decl::Void));

    assert_eq!(
        declaration(&b"int foo;"[..]),
        Done(&b";"[..], Decl::named("foo", Type::Int))
    );
    assert_eq!(
        declaration(&b"int foo[123] "[..]),
        Done(
            &b" "[..],
            Decl::named("foo", Type::Array(Box::new(Type::Int), Value::Const(123)))
        )
    );

    assert_eq!(
        declaration(&b"int foo<123> "[..]),
        Done(
            &b" "[..],
            Decl::named(
                "foo",
                Type::Flex(Box::new(Type::Int), Some(Value::Const(123)))
            )
        )
    );
    assert_eq!(
        declaration(&b"int foo<> "[..]),
        Done(
            &b" "[..],
            Decl::named("foo", Type::Flex(Box::new(Type::Int), None))
        )
    );
    assert_eq!(
        declaration(&b"int *foo "[..]),
        Done(
            &b" "[..],
            Decl::named("foo", Type::Option(Box::new(Type::Int)))
        )
    );

    assert_eq!(
        declaration(&b"opaque foo[123] "[..]),
        Done(
            &b" "[..],
            Decl::named(
                "foo",
                Type::Array(Box::new(Type::Opaque), Value::Const(123))
            )
        )
    );
    assert_eq!(
        declaration(&b"opaque foo<123> "[..]),
        Done(
            &b" "[..],
            Decl::named(
                "foo",
                Type::Flex(Box::new(Type::Opaque), Some(Value::Const(123)))
            )
        )
    );
    assert_eq!(
        declaration(&b"opaque foo<> "[..]),
        Done(
            &b" "[..],
            Decl::named("foo", Type::Flex(Box::new(Type::Opaque), None))
        )
    );

    assert_eq!(
        declaration(&b"string foo<123> "[..]),
        Done(
            &b" "[..],
            Decl::named(
                "foo",
                Type::Flex(Box::new(Type::String), Some(Value::Const(123)))
            )
        )
    );
    assert_eq!(
        declaration(&b"string foo<> "[..]),
        Done(
            &b" "[..],
            Decl::named("foo", Type::Flex(Box::new(Type::String), None))
        )
    );
}

named!(
    type_spec<Type>,
    preceded!(
        spaces,
        alt!(
            do_parse!(kw_unsigned >> kw_int >> (Type::UInt)) |
            do_parse!(kw_unsigned >> kw_long >> (Type::UInt)) |          // backwards compat with rpcgen
            do_parse!(kw_unsigned >> kw_char >>                          // backwards compat with rpcgen
                (Type::ident_with_derives("u8", COPY | CLONE | EQ | PARTIALEQ | DEBUG))) |
            do_parse!(kw_unsigned >> kw_short >> (Type::UInt)) |         // backwards compat with rpcgen
            do_parse!(kw_unsigned >> kw_hyper >> (Type::UHyper)) |
            kw_unsigned => { |_| Type::UInt } |                     // backwards compat with rpcgen
            kw_long => { |_| Type::Int } |                          // backwards compat with rpcgen
            kw_char => {                                            // backwards compat with rpcgen
                |_| Type::ident_with_derives("i8", COPY | CLONE | EQ | PARTIALEQ | DEBUG)
            } |
            kw_short => { |_| Type::Int } |                         // backwards compat with rpcgen
            kw_int => { |_| Type::Int } |
            kw_hyper => { |_| Type::Hyper } |
            kw_float => { |_| Type::Float } |
            kw_double => { |_| Type::Double } |
            kw_quadruple => { |_| Type::Quadruple } |
            kw_bool => { |_| Type::Bool } |
            enum_type_spec => { |defns| Type::Enum(defns) } |
            struct_type_spec => { |defns| Type::Struct(defns) } |
            do_parse!(kw_struct >> id:ident >> (Type::ident(id))) |    // backwards compat with rpcgen
            union_type_spec => { |u| Type::union(u) } |
            ident => { |id| Type::ident(id) }
        )
    )
);

#[test]
fn test_type() {
    assert_eq!(type_spec(&b"int "[..]), Done(&b" "[..], Type::Int));
    assert_eq!(
        type_spec(&b"unsigned int "[..]),
        Done(&b" "[..], Type::UInt)
    );
    assert_eq!(
        type_spec(&b"unsigned\nint "[..]),
        Done(&b" "[..], Type::UInt)
    );
    assert_eq!(
        type_spec(&b"unsigned/* foo */int "[..]),
        Done(&b" "[..], Type::UInt)
    );
    assert_eq!(
        type_spec(&b"unsigned//\nint "[..]),
        Done(&b" "[..], Type::UInt)
    );

    assert_eq!(
        type_spec(&b"unsigned hyper "[..]),
        Done(&b" "[..], Type::UHyper)
    );

    assert_eq!(
        type_spec(&b"unsigned char "[..]),
        Done(
            &b" "[..],
            Type::Ident("u8".into(), Some(COPY | CLONE | EQ | PARTIALEQ | DEBUG))
        )
    );
    assert_eq!(
        type_spec(&b"unsigned short "[..]),
        Done(&b" "[..], Type::UInt)
    );

    assert_eq!(type_spec(&b" hyper "[..]), Done(&b" "[..], Type::Hyper));
    assert_eq!(type_spec(&b" double "[..]), Done(&b" "[..], Type::Double));
    assert_eq!(
        type_spec(&b"// thing\nquadruple "[..]),
        Done(&b" "[..], Type::Quadruple)
    );
    assert_eq!(
        type_spec(&b"// thing\n bool "[..]),
        Done(&b" "[..], Type::Bool)
    );

    assert_eq!(
        type_spec(&b"char "[..]),
        Done(
            &b" "[..],
            Type::Ident("i8".into(), Some(COPY | CLONE | EQ | PARTIALEQ | DEBUG))
        )
    );

    assert_eq!(type_spec(&b"short "[..]), Done(&b" "[..], Type::Int));

    assert_eq!(
        type_spec(&b"struct { int a; int b; } "[..]),
        Done(
            &b" "[..],
            Type::Struct(vec!(
                Decl::named("a", Type::Int),
                Decl::named("b", Type::Int)
            ))
        )
    );

    assert_eq!(
        type_spec(&b"union switch (int a) { case 1: void; case 2: int a; default: void; } "[..]),
        Done(
            &b" "[..],
            Type::Union(
                Box::new(Decl::named("a", Type::Int)),
                vec!(
                    UnionCase(Value::Const(1), Decl::Void),
                    UnionCase(Value::Const(2), Decl::named("a", Type::Int))
                ),
                Some(Box::new(Decl::Void))
            )
        )
    );
}

#[test]
fn test_enum() {
    assert_eq!(
        type_spec(&b"enum { a, b, c } "[..]),
        Done(
            &b" "[..],
            Type::Enum(vec!(
                EnumDefn::new("a", None),
                EnumDefn::new("b", None),
                EnumDefn::new("c", None)
            ))
        )
    );

    assert_eq!(
        type_spec(&b"enum { a = 1, b, c } "[..]),
        Done(
            &b" "[..],
            Type::Enum(vec!(
                EnumDefn::new("a", Some(Value::Const(1))),
                EnumDefn::new("b", None),
                EnumDefn::new("c", None)
            ))
        )
    );

    assert_eq!(
        type_spec(&b"enum { a = Bar, b, c } "[..]),
        Done(
            &b" "[..],
            Type::Enum(vec!(
                EnumDefn::new("a", Some(Value::ident("Bar"))),
                EnumDefn::new("b", None),
                EnumDefn::new("c", None)
            ))
        )
    );

    assert_eq!(
        type_spec(&b"enum { } "[..]),
        Error(Err::Position(ErrorKind::Alt, &b"enum { } "[..]))
    );
}

named!(
    const_def<Defn>,
    do_parse!(
        kw_const >> id:ident >> eq >> v:number >> semi >>
            (Defn::constant(id, v)))
);

#[test]
fn test_const() {
    assert_eq!(
        const_def(&b"const foo = 123;"[..]),
        Done(&b""[..], Defn::constant("foo", 123))
    );
}

named!(
    type_def<Defn>,
    alt!(
        do_parse!(kw_typedef >> decl: nonvoid_declaration >> semi >>
            ({
                match decl.clone() {
                    Decl::Named(name, ty) => {
                        if ty.is_syn() {
                            Defn::typesyn(name, ty)
                        } else {
                            Defn::typespec(name, ty)
                        }
                    },
                    Decl::Void => panic!("void non-void declaration?"),
                }
            })
        ) | do_parse!(kw_enum >> id:ident >> e:enum_body >> semi >> (Defn::typespec(id, Type::Enum(e))))
            | do_parse!(kw_struct >> id:ident >> s:struct_body >> semi >> (Defn::typespec(id, Type::Struct(s))))
            | do_parse!(kw_union >> id:ident >> u:union_body >> semi >> (Defn::typespec(id, Type::union(u))))
    )
);

#[test]
fn test_typedef() {
    assert_eq!(
        type_def(&b"typedef int foo;"[..]),
        Done(&b""[..], Defn::typesyn("foo", Type::Int))
    );
    assert_eq!(
        type_def(&b"typedef unsigned int foo;"[..]),
        Done(&b""[..], Defn::typesyn("foo", Type::UInt))
    );
    assert_eq!(
        type_def(&b"typedef int foo<>;"[..]),
        Done(
            &b""[..],
            Defn::typespec("foo", Type::Flex(Box::new(Type::Int), None))
        )
    );

    assert_eq!(
        type_def(&b"enum foo { a };"[..]),
        Done(
            &b""[..],
            Defn::typespec("foo", Type::Enum(vec!(EnumDefn::new("a", None))))
        )
    );

    assert_eq!(
        type_def(&b"struct foo { int a; };"[..]),
        Done(
            &b""[..],
            Defn::typespec("foo", Type::Struct(vec!(Decl::named("a", Type::Int))))
        )
    );

    assert_eq!(
        type_def(&b"union foo switch(int a) { case 1: int a; };"[..]),
        Done(
            &b""[..],
            Defn::typespec(
                "foo",
                Type::Union(
                    Box::new(Decl::named("a", Type::Int)),
                    vec!(UnionCase(Value::Const(1), Decl::named("a", Type::Int))),
                    None
                )
            )
        )
    );
}
