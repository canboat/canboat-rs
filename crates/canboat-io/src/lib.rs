//! Sync `std::io` adapters for `canboat-core`.
//!
//! These types are thin wrappers around `BufRead` / `Read` /
//! `serialport`. They exist so the standalone binaries can read from
//! stdin, files, TCP sockets, or serial ports without each binary
//! re-implementing buffering and EOF handling.
//!
//! No tokio. No async. No threads. The sans-I/O decoder in
//! `canboat-core` is driven directly from these synchronous reads.

use std::io::{self, BufRead, Read};
use std::time::Duration;

/// Read lines one at a time from a [`BufRead`] source.
///
/// Mirrors what the analyzer binary needs from stdin (or a `.in` test
/// file): a line-by-line iterator that hands out borrowed `&str`s and
/// reuses its internal buffer so per-line allocation stays out of the
/// hot path.
///
/// Lines are returned with any trailing `\r` / `\n` stripped.
///
/// ```no_run
/// use std::io::BufReader;
/// use canboat_io::LineReader;
/// let stdin = std::io::stdin();
/// let mut lr = LineReader::new(stdin.lock());
/// while let Some(line) = lr.next_line().expect("read") {
///     println!("got: {}", line);
/// }
/// ```
pub struct LineReader<R: BufRead> {
    reader: R,
    buf: String,
}

impl<R: BufRead> LineReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: String::with_capacity(1024),
        }
    }

    /// Read the next line. Returns `Ok(None)` on EOF.
    pub fn next_line(&mut self) -> io::Result<Option<&str>> {
        self.buf.clear();
        let n = self.reader.read_line(&mut self.buf)?;
        if n == 0 {
            return Ok(None);
        }
        // Strip trailing newline / CRLF.
        let trimmed = self.buf.trim_end_matches(['\r', '\n']).len();
        self.buf.truncate(trimmed);
        Ok(Some(&self.buf))
    }
}

/// Read bytes from a [`Read`] source in fixed-size chunks.
///
/// Intended for the actisense-serial binary: pull a chunk off the
/// serial port and shovel it straight into `Ngt1Decoder::push_bytes`.
/// The internal buffer is reused so steady-state is allocation-free.
pub struct BytePump<R: Read> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: Read> BytePump<R> {
    /// Construct with a default 4096-byte read buffer.
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 4096)
    }

    pub fn with_capacity(reader: R, cap: usize) -> Self {
        Self {
            reader,
            buf: vec![0; cap.max(64)],
        }
    }

    /// Read the next chunk. Returns:
    /// - `Ok(Some(&bytes))` — at least one byte available
    /// - `Ok(None)` — EOF
    /// - `Err(io::Error)` — underlying I/O error (the caller decides
    ///   whether `TimedOut` is benign)
    pub fn read_chunk(&mut self) -> io::Result<Option<&[u8]>> {
        let n = self.reader.read(&mut self.buf)?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(&self.buf[..n]))
        }
    }
}

/// Open a serial port with canboat-typical defaults (8N1, no flow
/// control, a small read timeout so callers can poll without blocking
/// forever).
///
/// `baud` is in bits per second. The Actisense NGT-1 uses 115200;
/// iKonvert uses 230400.
pub fn open_serial(path: &str, baud: u32) -> io::Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .flow_control(serialport::FlowControl::None)
        .timeout(Duration::from_millis(250))
        .open()
        .map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn line_reader_handles_crlf_and_eof() {
        let data = b"first\r\nsecond\nthird".to_vec();
        let mut lr = LineReader::new(Cursor::new(data));
        assert_eq!(lr.next_line().unwrap(), Some("first"));
        assert_eq!(lr.next_line().unwrap(), Some("second"));
        assert_eq!(lr.next_line().unwrap(), Some("third"));
        assert_eq!(lr.next_line().unwrap(), None);
    }

    #[test]
    fn byte_pump_returns_eof_as_none() {
        let mut p = BytePump::new(Cursor::new(b"hello".to_vec()));
        let first = p.read_chunk().unwrap().unwrap().to_vec();
        assert_eq!(&first, b"hello");
        assert!(p.read_chunk().unwrap().is_none());
    }
}
