// Don't rustfmt in here to avoid trashing vec![] formatting
#![cfg_attr(rustfmt, rustfmt_skip)]

use std::io::{Cursor, Read, Write};

use xdr_codec::record::{XdrRecordReader, XdrRecordWriter};

#[test]
fn recread_full() {
    let inbuf = vec![128, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let cur = Cursor::new(inbuf);

    let mut recread = XdrRecordReader::new(cur);
    let mut buf = vec![0; 20];

    assert_eq!(recread.read(&mut buf[..]).unwrap(), 10);
    assert_eq!(
        buf,
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert!(recread.eor());
}

#[test]
fn recread_short() {
    let inbuf = vec![128, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let cur = Cursor::new(inbuf);

    let mut recread = XdrRecordReader::new(cur);
    let mut buf = vec![0; 5];

    assert_eq!(recread.read(&mut buf[..]).unwrap(), 5);
    assert!(recread.eor());
    assert_eq!(buf, vec![0, 1, 2, 3, 4]);

    assert_eq!(recread.read(&mut buf[..]).unwrap(), 5);
    assert!(recread.eor());
    assert_eq!(buf, vec![5, 6, 7, 8, 9]);
}

#[test]
fn recread_half() {
    let inbuf = vec![0, 0, 0, 5, 0, 1, 2, 3, 4, 128, 0, 0, 5, 5, 6, 7, 8, 9];
    let cur = Cursor::new(inbuf);

    let mut recread = XdrRecordReader::new(cur);
    let mut buf = vec![0; 10];

    assert_eq!(recread.read(&mut buf[..]).unwrap(), 5);
    assert_eq!(buf, vec![0, 1, 2, 3, 4, 0, 0, 0, 0, 0]);
    assert!(!recread.eor());

    assert_eq!(recread.read(&mut buf[..]).unwrap(), 5);
    assert_eq!(buf, vec![5, 6, 7, 8, 9, 0, 0, 0, 0, 0]);
    assert!(recread.eor());
}

#[test]
fn recread_iter() {
    let inbuf = vec![
        0,
        0,
        0,
        5,
        0,
        1,
        2,
        3,
        4,
        128,
        0,
        0,
        5,
        5,
        6,
        7,
        8,
        9,
        128,
        0,
        0,
        1,
        99,
    ];
    let cur = Cursor::new(inbuf);
    let recread = XdrRecordReader::new(cur);

    let expected = vec![vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9], vec![99]];
    let got: Vec<_> = recread.into_iter().map(|r| r.expect("IO error")).collect();

    assert_eq!(expected, got);
}

#[test]
fn read_zerorec() {
    let inbuf = vec![0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0];

    let cur = Cursor::new(inbuf);
    let mut recread = XdrRecordReader::new(cur);

    let mut buf = [0; 100];
    assert_eq!(recread.read(&mut buf).unwrap(), 0);
    assert!(recread.eor());
}

#[test]
#[should_panic(expected = "must be non-zero")]
fn zerosz() {
    let buf = Vec::new();
    let _ = XdrRecordWriter::with_buffer(buf, 0);
}

#[test]
fn smallrec() {
    let mut buf = Vec::new();

    {
        let mut xw = XdrRecordWriter::new(&mut buf);

        assert_eq!(write!(xw, "hello").unwrap(), ());
    }

    assert_eq!(buf, vec![128, 0, 0, 5, 104, 101, 108, 108, 111])
}

#[test]
fn largerec() {
    let mut buf = Vec::new();

    {
        let mut xw = XdrRecordWriter::with_buffer(&mut buf, 3);

        assert_eq!(write!(xw, "hello").unwrap(), ());
    }

    assert_eq!(buf, vec![0, 0, 0, 3, 104, 101, 108, 128, 0, 0, 2, 108, 111])
}

#[test]
fn largerec_flush() {
    let mut buf = Vec::new();

    {
        let mut xw = XdrRecordWriter::with_buffer(&mut buf, 10);

        assert_eq!(write!(xw, "hel").unwrap(), ());
        xw.flush().unwrap();
        assert_eq!(write!(xw, "lo").unwrap(), ());
        xw.flush().unwrap();
    }

    assert_eq!(
        buf,
        vec![
            0,
            0,
            0,
            3,
            104,
            101,
            108,
            0,
            0,
            0,
            2,
            108,
            111,
            128,
            0,
            0,
            0,
        ]
    )
}
