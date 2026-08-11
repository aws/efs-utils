//! XDR record marking
//!
//! This module implements wrappers for `Write` and `BufRead` which
//! implement "Record Marking" from [RFC1831](https://tools.ietf.org/html/rfc1831.html#section-10),
//! used for encoding XDR structures onto a bytestream such as TCP.
//!
//! The format is simple - each record is broken up into one or more
//! record fragments. Each record fragment is prefixed with a 32-bit
//! big-endian value. The low 31 bits is the fragment size, and the
//! top bit is the "end of record" marker, indicating the last
//! fragment of the record.
//!
//! There's no magic number or other way to determine whether a stream
//! is using record marking; both ends must agree.
use std::cmp::min;
use std::io::{self, BufRead, Read, Write};

use error::*;

use super::{pack, unpack, Error};

const LAST_REC: u32 = 1u32 << 31;

fn mapioerr(xdrerr: Error) -> io::Error {
    match xdrerr {
        Error(ErrorKind::IOError(ioerr), _) => ioerr,
        other => io::Error::new(io::ErrorKind::Other, other),
    }
}

/// Read records from a bytestream.
///
/// Reads will read up to the end of the current fragment, and not
/// beyond. The `BufRead` trait doesn't otherwise allow for record
/// boundaries to be deliniated. Callers can use the `eor` method to
/// determine record ends.
#[derive(Debug)]
pub struct XdrRecordReader<R: BufRead> {
    size: usize,     // record size
    consumed: usize, // bytes consumed
    eor: bool,       // is last record

    reader: R, // reader
}

impl<R: BufRead> XdrRecordReader<R> {
    /// Wrapper a record reader around an existing implementation of
    /// `BufRead`, such as `BufReader`.
    pub fn new(rd: R) -> XdrRecordReader<R> {
        XdrRecordReader {
            size: 0,
            consumed: 0,
            eor: false,
            reader: rd,
        }
    }

    // read next record, returns true on EOF
    fn nextrec(&mut self) -> io::Result<bool> {
        assert_eq!(self.consumed, self.size);

        let rechdr: u32 = match unpack(&mut self.reader) {
            Ok(v) => v,
            Err(Error(ErrorKind::IOError(ref err), _))
                if err.kind() == io::ErrorKind::UnexpectedEof =>
            {
                return Ok(true)
            }
            Err(e) => return Err(mapioerr(e)),
        };

        self.size = (rechdr & !LAST_REC) as usize;
        self.consumed = 0;
        self.eor = (rechdr & LAST_REC) != 0;

        Ok(false)
    }

    fn totremains(&self) -> usize {
        self.size - self.consumed
    }

    /// Current fragment is the end of the record.
    pub fn eor(&self) -> bool {
        self.eor
    }
}

impl<R: BufRead> Read for XdrRecordReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = {
            let data = self.fill_buf()?;
            let len = min(buf.len(), data.len());

            (&data[..len]).read(buf)?
        };

        self.consume(nread);
        Ok(nread)
    }
}

impl<R: BufRead> BufRead for XdrRecordReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.totremains() == 0 {
            if self.nextrec()? {
                return Ok(&[]);
            }
        }

        let remains = self.totremains();
        let data = self.reader.fill_buf()?;
        Ok(&data[..min(data.len(), remains)])
    }

    fn consume(&mut self, sz: usize) {
        assert!(sz <= self.totremains());
        self.consumed += sz;
        self.reader.consume(sz);
    }
}

impl<R: BufRead> IntoIterator for XdrRecordReader<R> {
    type Item = io::Result<Vec<u8>>;
    type IntoIter = XdrRecordReaderIter<R>;

    fn into_iter(self) -> Self::IntoIter {
        XdrRecordReaderIter(Some(self))
    }
}

/// Iterator over records in the stream.
///
/// Each iterator result is either:
///
///  * A complete record, or
///  * an IO error.
///
/// It will return an IO error once, and then end the iterator.
/// A short read or an unterminated record will also end the iterator. It will not return a partial
/// record.
#[derive(Debug)]
pub struct XdrRecordReaderIter<R: BufRead>(Option<XdrRecordReader<R>>);

impl<R: BufRead> Iterator for XdrRecordReaderIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut rr) = self.0.take() {
            let mut buf = Vec::new();

            // loop over fragments until we get a complete record
            loop {
                // Do we need next fragment?
                if rr.totremains() == 0 {
                    match rr.nextrec() {
                        Err(e) => return Some(Err(e)), // IO error
                        Ok(true) => return None,       // EOF
                        Ok(false) => (),               // keep going
                    }
                }

                let remains = rr.totremains();
                let eor = rr.eor();

                match rr.by_ref().take(remains as u64).read_to_end(&mut buf) {
                    Ok(sz) if sz == remains => (), // OK, keep going
                    Ok(_) => return None,          // short read
                    Err(e) => return Some(Err(e)), // error
                };

                if eor {
                    break;
                }
            }
            self.0 = Some(rr);
            Some(Ok(buf))
        } else {
            None
        }
    }
}

const WRBUF: usize = 65536;

/// Write records into a bytestream.
///
/// Flushes the current buffer as end of record when destroyed.
pub struct XdrRecordWriter<W: Write> {
    buf: Vec<u8>, // accumulated record fragment
    bufsz: usize, // max fragment size
    eor: bool,    // last fragment was eor
    writer: W,    // writer we're passing on to
}

impl<W: Write> XdrRecordWriter<W> {
    /// Create a new `XdrRecordWriter` wrapped around a `Write`
    /// implementation, using a default buffer size (64k).
    pub fn new(w: W) -> XdrRecordWriter<W> {
        XdrRecordWriter::with_buffer(w, WRBUF)
    }

    /// Create an instance with a specific buffer size. Panics if the
    /// size is zero.
    pub fn with_buffer(w: W, bufsz: usize) -> XdrRecordWriter<W> {
        if bufsz == 0 {
            panic!("bufsz must be non-zero")
        }
        XdrRecordWriter {
            buf: Vec::with_capacity(bufsz),
            bufsz: bufsz,
            eor: false,
            writer: w,
        }
    }

    /// Flush the current buffer. If `eor` is true, the end of record
    /// marker is set.
    pub fn flush_eor(&mut self, eor: bool) -> io::Result<()> {
        if !eor && self.buf.len() == 0 {
            return Ok(());
        }

        let rechdr = self.buf.len() as u32 | (if eor { LAST_REC } else { 0 });

        pack(&rechdr, &mut self.writer).map_err(mapioerr)?;
        let _ = self.writer.write_all(&self.buf).map(|_| ())?;
        self.buf.truncate(0);

        self.eor = eor;
        self.writer.flush()
    }
}

impl<W: Write> Drop for XdrRecordWriter<W> {
    fn drop(&mut self) {
        if self.buf.len() > 0 || !self.eor {
            let _ = self.flush_eor(true);
        }
    }
}

impl<W: Write> Write for XdrRecordWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut off = 0;

        while off < buf.len() {
            let chunk = &buf[off..off + min(buf.len() - off, self.bufsz)];
            if self.buf.len() + chunk.len() > self.bufsz {
                self.flush()?;
            }

            self.buf.extend(chunk);
            off += chunk.len();
        }

        Ok(off)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_eor(false)
    }
}
