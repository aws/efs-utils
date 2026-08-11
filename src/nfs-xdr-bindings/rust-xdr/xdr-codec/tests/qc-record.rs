extern crate quickcheck;

use std::io::{Cursor, Write};

use quickcheck::{quickcheck, TestResult};

use xdr_codec::record::{XdrRecordReader, XdrRecordWriter};
use xdr_codec::Pack;

// Make sure XdrRecordWriter writes the right stuff
fn check_writerec(bufsz: usize, eor: bool, ref bytes: Vec<u8>) -> TestResult {
    const EOR: u32 = 1 << 31;

    if bufsz == 0 {
        return TestResult::discard();
    }

    // Make an expected serialization into fragments
    let mut expected = Vec::new();
    let nchunks = (bytes.len() + bufsz - 1) / bufsz;

    for (idx, c) in bytes.chunks(bufsz).enumerate() {
        let mut len = c.len() as u32;
        if nchunks - 1 == idx && eor {
            len |= EOR;
        }

        if let Err(e) = len.pack(&mut expected) {
            return TestResult::error(format!("pack failed: {:?}", e));
        }
        expected.extend(c);
    }
    if !eor || nchunks == 0 {
        if let Err(e) = EOR.pack(&mut expected) {
            return TestResult::error(format!("eor pack failed: {:?}", e));
        }
    }

    // Write the same data with XdrRecordWriter
    let mut buf = Vec::new();
    {
        let mut xw = XdrRecordWriter::with_buffer(&mut buf, bufsz);
        if let Err(e) = xw.write(bytes) {
            return TestResult::error(format!("xw write failed: {:?}", e));
        }
        if let Err(e) = xw.flush_eor(eor) {
            return TestResult::error(format!("xw flush_eor failed: {:?}", e));
        }
    }

    if buf != expected {
        println!(
            "eor {} bufsz {} bytes {:?} len {}",
            eor,
            bufsz,
            bytes,
            bytes.len()
        );
        println!("expected {:?} len {}", expected, expected.len());
        println!("     buf {:?} len {}", buf, buf.len());
    }

    TestResult::from_bool(buf == expected)
}

#[test]
fn record_writerec() {
    quickcheck(check_writerec as fn(usize, bool, Vec<u8>) -> TestResult);
}

// Make sure record structure survives a round trip
fn check_codec(bufsz: usize, ref records: Vec<Vec<u8>>) -> TestResult {
    if bufsz == 0 {
        return TestResult::discard();
    }

    let mut buf = Vec::new();

    for rec in records {
        let mut xw = XdrRecordWriter::with_buffer(&mut buf, bufsz);

        if let Err(e) = xw.write(rec) {
            return TestResult::error(format!("xw write failed: {:?}", e));
        }
    }

    {
        let cur = Cursor::new(buf);
        let xr = XdrRecordReader::new(cur);

        for (res, orig) in xr.into_iter().zip(records) {
            match res {
                Err(e) => return TestResult::error(format!("xr failed {:?}", e)),
                Ok(ref rx) => {
                    if rx != orig {
                        println!(
                            "bufsz {} mismatch orig {:?}, len {}",
                            bufsz,
                            orig,
                            orig.len()
                        );
                        println!("                    rx {:?}, len {}", rx, rx.len());
                        return TestResult::failed();
                    }
                }
            }
        }
    }

    TestResult::passed()
}

#[test]
fn record_codec() {
    quickcheck(check_codec as fn(usize, Vec<Vec<u8>>) -> TestResult);
}
