// Don't rustfmt in here to avoid trashing vec![] formatting
#![cfg_attr(rustfmt, rustfmt_skip)]

use std::io::Cursor;
use super::{Error, ErrorKind, Pack, Unpack, Opaque,
            pack_flex, pack_opaque_flex, pack_string, pack_array, pack_opaque_array,
            unpack_array, unpack_opaque_array, unpack_string, unpack_flex, unpack_opaque_flex};


#[cfg(feature = "bytecodec")]
#[test]
fn basic_8() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0u8.pack(&mut out).unwrap(), 4);
        assert_eq!(100u8.pack(&mut out).unwrap(), 4);
        assert_eq!((-1i8).pack(&mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x64,
                           0xff, 0xff, 0xff, 0xff,  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0u8, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (100u8, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (-1i8, 4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0i8.pack(&mut out).unwrap(), 4);
        assert_eq!((-123i8).pack(&mut out).unwrap(), 4);
        assert_eq!((-128i8).pack(&mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00,
                           0xff, 0xff, 0xff, 0x85,
                           0xff, 0xff, 0xff, 0x80  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0i8, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (-123i8, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), ((1<<7) as i8, 4));
    }
}

#[test]
fn basic_32() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0u32.pack(&mut out).unwrap(), 4);
        assert_eq!(1000u32.pack(&mut out).unwrap(), 4);
        assert_eq!(823987423u32.pack(&mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x03, 0xe8,
                           0x31, 0x1d, 0x0c, 0xdf,  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0u32, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (1000u32, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (823987423u32, 4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0i32.pack(&mut out).unwrap(), 4);
        assert_eq!((-1238i32).pack(&mut out).unwrap(), 4);
        assert_eq!(((1i32<<31) as i32).pack(&mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00,
                           0xff, 0xff, 0xfb, 0x2a,
                           0x80, 0x00, 0x00, 0x00  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0i32, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (-1238i32, 4));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), ((1<<31) as i32, 4));
    }
}

#[test]
fn basic_64() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0u64.pack(&mut out).unwrap(), 8);
        assert_eq!(0x0011223344556677u64.pack(&mut out).unwrap(), 8);
        assert_eq!(0xff00ff00ff00ff00u64.pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 24);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0u64, 8));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (4822678189205111u64, 8));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (18374966859414961920u64, 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(0i64.pack(&mut out).unwrap(), 8);
        assert_eq!((-2938928374982749237i64).pack(&mut out).unwrap(), 8);
        assert_eq!(((1i64<<63) as i64).pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 24);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0xd7, 0x36, 0xd4, 0x36, 0xcc, 0xd6, 0x53, 0xcb,
                           0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  ]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (0i64, 8));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (-2938928374982749237i64, 8));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), ((1i64<<63) as i64, 8));
    }
}

#[test]
fn basic_bool() {
    let mut out = Cursor::new(Vec::new());

    assert_eq!(true.pack(&mut out).unwrap(), 4);
    assert_eq!(false.pack(&mut out).unwrap(), 4);

    let v = out.into_inner();

    assert_eq!(v.len(), 8);
    assert_eq!(v, vec![0, 0, 0, 1,  0, 0, 0, 0]);

    let mut input = Cursor::new(v);
    assert_eq!(Unpack::unpack(&mut input).unwrap(), (true, 4));
    assert_eq!(Unpack::unpack(&mut input).unwrap(), (false, 4));

    let bad = vec![0, 0, 0, 2];
    let mut input = Cursor::new(bad);
    match bool::unpack(&mut input) {
        Err(Error(ErrorKind::InvalidEnum(_), _)) => (),
        res => panic!("bad result {:?}", res),
    }
}

#[test]
fn basic_string() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!("foo!".pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x04, 0x66, 0x6f, 0x6f, 0x21]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (String::from("foo!"), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!("foo".pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03, 0x66, 0x6f, 0x6f, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (String::from("foo"), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!("foobar".pack(&mut out).unwrap(), 12);
        assert_eq!("piff".pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 20);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x06,  0x66, 0x6f, 0x6f, 0x62,  0x61, 0x72, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x04,  0x70, 0x69, 0x66, 0x66]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (String::from("foobar"), 12));
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (String::from("piff"), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(pack_string("foo!", Some(10), &mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x04, 0x66, 0x6f, 0x6f, 0x21]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (String::from("foo!"), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        match pack_string("foo!", Some(2), &mut out) {
            Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("bad result {:?}", e),
        }
    }
}

#[test]
fn basic_flex() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(vec![0x11u32, 0x22, 0x33, 0x44].pack(&mut out).unwrap(), 4*4 + 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*4 + 4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x04,
                           0x00, 0x00, 0x00, 0x11,  0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,  0x00, 0x00, 0x00, 0x44]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22, 0x33, 0x44], 4*4+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(vec![0x11u32, 0x22].pack(&mut out).unwrap(), 2*4+4);

        let v = out.into_inner();

        assert_eq!(v.len(), 2*4+4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x02,
                           0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22], 4*2+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(vec![0x11u32, 0x22, 0x00].pack(&mut out).unwrap(), 3*4+4);

        let v = out.into_inner();

        assert_eq!(v.len(), 3*4+4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03,
                           0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22, 0x00], 3*4+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(vec![0x11u32, 0x22, 0x33].pack(&mut out).unwrap(), 3*4+4);

        let v = out.into_inner();

        assert_eq!(v.len(), 3*4+4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03,
                           0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22, 0x33], 3*4+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(vec![0x11u32, 0x22, 0x33, 0x44, 0x55].pack(&mut out).unwrap(), 4*5+4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*5+4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x05,
                           0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,
                           0x00, 0x00, 0x00, 0x44,
                           0x00, 0x00, 0x00, 0x55]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22, 0x33, 0x44, 0x55], 5*4+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(pack_flex(&vec![0x11u32, 0x22, 0x33, 0x44, 0x55], Some(10), &mut out).unwrap(), 4*5+4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*5+4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x05,
                           0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,
                           0x00, 0x00, 0x00, 0x44,
                           0x00, 0x00, 0x00, 0x55]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (vec![0x11u32, 0x22, 0x33, 0x44, 0x55], 5*4+4));
    }

    {
        let mut out = Cursor::new(Vec::new());

        match pack_flex(&vec![0x11u32, 0x22, 0x33, 0x44, 0x55], Some(4), &mut out) {
            Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("bad result {:?}", e)
        }
    }
}

#[test]
fn basic_opaque_flex() {
    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44]).pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44]), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22]).pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22]), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22, 0x00]).pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03, 0x11, 0x22, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22, 0x00]), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22, 0x33]).pack(&mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22, 0x33]), 8));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55]).pack(&mut out).unwrap(), 12);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55]), 12));
    }

    {
        let mut out = Cursor::new(Vec::new());

        assert_eq!(pack_opaque_flex(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55], Some(10), &mut out).unwrap(), 12);

        let v = out.into_inner();

        assert_eq!(v.len(), 12);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        assert_eq!(Unpack::unpack(&mut input).unwrap(), (Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55]), 12));
    }

    {
        let mut out = Cursor::new(Vec::new());

        match pack_opaque_flex(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55], Some(3), &mut out) {
            Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("bad result {:?}", e),
        }
    }
}

#[test]
fn bounded_flex() {
    let mut out = Cursor::new(Vec::new());

    assert_eq!(vec![0x11u32, 0x22, 0x33, 0x44, 0x55].pack(&mut out).unwrap(), 4*5+4);

    let v = out.into_inner();

    {
        let mut input = Cursor::new(v.clone());
        assert_eq!(unpack_flex(&mut input, Some(10)).unwrap(), (vec![0x11u32, 0x22, 0x33, 0x44, 0x55], 5*4+4));
    }
    {
        let mut input = Cursor::new(v.clone());
        match unpack_flex::<_, Vec<u32>>(&mut input, Some(4)) {
            Result::Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("Unexpected {:?}", e),
        }
    }
}

#[test]
fn bounded_opaque_flex() {
    let mut out = Cursor::new(Vec::new());

    assert_eq!(Opaque::borrowed(&vec![0x11u8, 0x22, 0x33, 0x44, 0x55]).pack(&mut out).unwrap(), 12);

    let v = out.into_inner();

    {
        let mut input = Cursor::new(v.clone());
        assert_eq!(unpack_opaque_flex(&mut input, Some(10)).unwrap(), (vec![0x11u8, 0x22, 0x33, 0x44, 0x55], 12));
    }
    {
        let mut input = Cursor::new(v.clone());
        match unpack_opaque_flex(&mut input, Some(4)) {
            Result::Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("Unexpected {:?}", e),
        }
    }
}

#[test]
fn bounded_string() {
    let mut out = Cursor::new(Vec::new());

    assert_eq!(String::from("hello, world").pack(&mut out).unwrap(), 16);

    let v = out.into_inner();

    {
        let mut input = Cursor::new(v.clone());
        assert_eq!(unpack_string(&mut input, Some(16)).expect("unpack_string failed"),
                   (String::from("hello, world"), 16));
    }
    {
        let mut input = Cursor::new(v.clone());
        match unpack_string(&mut input, Some(5)) {
            Result::Err(Error(ErrorKind::InvalidLen(_), _)) => (),
            e => panic!("Unexpected {:?}", e),
        }
    }
}

#[test]
fn basic_array() {
    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u32, 0x22, 0x33];


        assert_eq!(pack_array(&a, a.len(), &mut out, Some(&0)).unwrap(), 3*4);

        let v = out.into_inner();

        assert_eq!(v.len(), 3*4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33]);

        let mut input = Cursor::new(v);
        let mut b = [0u32; 3];
        let bsz = unpack_array(&mut input, &mut b[..], 3, Some(&0)).expect("unpack failed");
        assert_eq!(bsz, 4*3);
        assert_eq!(&a[..], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u32, 0x22, 0x33, 0x44];

        assert_eq!(pack_array(&a, a.len(), &mut out, Some(&0)).unwrap(), 4*4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x44]);

        let mut input = Cursor::new(v);
        let mut b = [0u32; 3];
        let bsz = unpack_array(&mut input, &mut b[..], 4, Some(&0)).expect("unpack_array");
        assert_eq!(bsz, 4*4);
        assert_eq!(&a[..3], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u32, 0x22, 0x33, 0x44, 0x55];

        assert_eq!(pack_array(&a, a.len(), &mut out, Some(&0)).unwrap(), 5*4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*5);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,
                           0x00, 0x00, 0x00, 0x44,
                           0x00, 0x00, 0x00, 0x55]);

        let mut input = Cursor::new(v);
        let mut b = [0u32; 5];
        let bsz = unpack_array(&mut input, &mut b[..], a.len(), Some(&0)).expect("unpack_array");
        assert_eq!(bsz, 5*4);
        assert_eq!(&a[..], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u32, 0x22, 0x33, 0x44, 0x55];

        assert_eq!(pack_array(&a, 4, &mut out, Some(&0)).unwrap(), 4*4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,
                           0x00, 0x00, 0x00, 0x44]);

        let mut input = Cursor::new(v);
        let mut b = [0u32; 4];
        let bsz = unpack_array(&mut input, &mut b[..], 4, Some(&0)).expect("unpack_array");
        assert_eq!(bsz, 4*4);
        assert_eq!(&a[..4], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u32, 0x22, 0x33];

        assert_eq!(pack_array(&a, 4, &mut out, Some(&0)).unwrap(), 4*4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4*4);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x11,
                           0x00, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x33,
                           0x00, 0x00, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        let mut b = [0u32; 4];
        let bsz = unpack_array(&mut input, &mut b[..], 4, Some(&0)).expect("unpack_array");
        assert_eq!(bsz, 4*4);
        assert_eq!(vec![0x11,0x22,0x33,0x00], b);
    }
}

#[test]
fn basic_opaque_array() {
    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u8, 0x22, 0x33];


        assert_eq!(pack_opaque_array(&a, a.len(), &mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4);
        assert_eq!(v, vec![0x11, 0x22, 0x33, 0x00]);

        let mut input = Cursor::new(v);
        let mut b = [0u8; 3];
        let bsz = unpack_opaque_array(&mut input, &mut b[..], 3).expect("unpack opaque failed");
        assert_eq!(bsz, 4);
        assert_eq!(&a[..], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u8, 0x22, 0x33, 0x44];

        assert_eq!(pack_opaque_array(&a, a.len(), &mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4);
        assert_eq!(v, vec![0x11, 0x22, 0x33, 0x44]);

        let mut input = Cursor::new(v);
        let mut b = [0u8; 4];
        let bsz = unpack_opaque_array(&mut input, &mut b[..], 4).expect("unpack_opaque_array");
        assert_eq!(bsz, 4);
        assert_eq!(&a[..], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u8, 0x22, 0x33, 0x44, 0x55];

        assert_eq!(pack_opaque_array(&a, a.len(), &mut out).unwrap(), 8);

        let v = out.into_inner();

        assert_eq!(v.len(), 8);
        assert_eq!(v, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00]);

        let mut input = Cursor::new(v);
        let mut b = [0u8; 5];
        let bsz = unpack_opaque_array(&mut input, &mut b[..], a.len()).expect("unpack_opaque_array");
        assert_eq!(bsz, 8);
        assert_eq!(&a[..], &b[..]);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u8, 0x22, 0x33, 0x44, 0x55];

        assert_eq!(pack_opaque_array(&a, 4, &mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4);
        assert_eq!(v, vec![0x11, 0x22, 0x33, 0x44]);

        let mut input = Cursor::new(v);
        let mut b = [0u8; 5];
        let bsz = unpack_opaque_array(&mut input, &mut b[..], 4).expect("unpack_opaque_array");
        assert_eq!(bsz, 4);
        assert_eq!(&a[..4], &b[..4]);
        assert_eq!(b[4], 0);
    }

    {
        let mut out = Cursor::new(Vec::new());
        let a = [0x11u8, 0x22, 0x33];

        assert_eq!(pack_opaque_array(&a, 4, &mut out).unwrap(), 4);

        let v = out.into_inner();

        assert_eq!(v.len(), 4);
        assert_eq!(v, vec![0x11, 0x22, 0x33, 0x00]);

        let mut input = Cursor::new(v);
        let mut b = [0u8; 4];
        let bsz = unpack_opaque_array(&mut input, &mut b[..], 4).expect("unpack_opaque_array");
        assert_eq!(bsz, 4);
        assert_eq!(vec![0x11, 0x22, 0x33, 0x00], b);
    }
}

#[test]
fn basic_option() {
    let mut out = Cursor::new(Vec::new());
    let none: Option<u32> = None;
    let some: Option<u32> = Some(0x11223344_u32);

    assert_eq!(none.pack(&mut out).unwrap(), 4);
    assert_eq!(some.pack(&mut out).unwrap(), 8);

    let v = out.into_inner();

    assert_eq!(v.len(), 12);
    assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x01,  0x11, 0x22, 0x33, 0x44,]);

    let mut input = Cursor::new(v);
    assert_eq!(Option::<u32>::unpack(&mut input).unwrap(), (None, 4));
    assert_eq!(Unpack::unpack(&mut input).unwrap(), (Some(0x11223344_u32), 8));

    let bad = vec![0, 0, 0, 2];
    let mut input = Cursor::new(bad);

    match Option::<u32>::unpack(&mut input) {
        Err(Error(ErrorKind::InvalidEnum(_), _)) => (),
        res => panic!("bad result {:?}", res),
    }
}
