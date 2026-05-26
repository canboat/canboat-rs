//! Canboat PLAIN / FAST line format.
//!
//! ```text
//! <timestamp>,<prio>,<pgn>,<src>,<dst>,<len>,<hex0>,<hex1>,...,<hexN>
//! ```
//!
//! `len` is the payload byte count (`0..=223`). When `len <= 8` the
//! line is conventionally called PLAIN (a single CAN frame); otherwise
//! it is FAST (a pre-coalesced fast-packet payload). Both share the
//! same syntax — this module parses and writes both.

use std::fmt;

use smallvec::SmallVec;

use crate::frame::{RawFrame, FASTPACKET_MAX_SIZE};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("line is empty")]
    Empty,
    #[error("missing timestamp separator")]
    MissingTimestamp,
    #[error("expected {expected} comma-separated header fields, found {found}")]
    BadHeader { expected: usize, found: usize },
    #[error("malformed integer in field {field}: {value:?}")]
    BadInteger { field: &'static str, value: String },
    #[error("declared length {len} exceeds max {max}", max = FASTPACKET_MAX_SIZE)]
    LengthTooLarge { len: usize },
    #[error("expected {expected} hex bytes, found {found}")]
    BadPayloadCount { expected: usize, found: usize },
    #[error("malformed hex byte {value:?} at index {index}")]
    BadHexByte { index: usize, value: String },
}

/// Parse one PLAIN/FAST line.
///
/// The input may have a trailing newline; it is ignored. The timestamp
/// is preserved verbatim (whatever appears before the first comma).
pub fn parse_line(line: &str) -> Result<RawFrame, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }

    // Split off the timestamp (everything up to the first comma).
    let (ts, rest) = line.split_once(',').ok_or(ParseError::MissingTimestamp)?;
    let timestamp = if ts.is_empty() {
        None
    } else {
        Some(ts.to_string())
    };

    // Header: prio, pgn, src, dst, len.
    let mut parts = rest.split(',');
    let prio = take_int::<u8>(&mut parts, "prio")?;
    let pgn = take_int::<u32>(&mut parts, "pgn")?;
    let src = take_int::<u8>(&mut parts, "src")?;
    let dst = take_int::<u8>(&mut parts, "dst")?;
    let len = take_int::<usize>(&mut parts, "len")?;

    if len > FASTPACKET_MAX_SIZE {
        return Err(ParseError::LengthTooLarge { len });
    }

    // Payload: exactly `len` hex bytes, comma-separated.
    let mut data: SmallVec<[u8; 8]> = SmallVec::with_capacity(len);
    for (i, tok) in (&mut parts).take(len).enumerate() {
        let byte = u8::from_str_radix(tok.trim(), 16).map_err(|_| ParseError::BadHexByte {
            index: i,
            value: tok.to_string(),
        })?;
        data.push(byte);
    }

    if data.len() != len {
        return Err(ParseError::BadPayloadCount {
            expected: len,
            found: data.len(),
        });
    }

    Ok(RawFrame {
        timestamp,
        prio,
        pgn,
        src,
        dst,
        data,
    })
}

fn take_int<T: std::str::FromStr>(
    parts: &mut std::str::Split<'_, char>,
    field: &'static str,
) -> Result<T, ParseError> {
    let raw = parts.next().ok_or(ParseError::BadHeader {
        expected: 5,
        found: 0,
    })?;
    raw.trim().parse::<T>().map_err(|_| ParseError::BadInteger {
        field,
        value: raw.to_string(),
    })
}

/// Write one PLAIN/FAST line to `w`. The timestamp is emitted exactly as
/// stored (empty if `None`). Hex bytes are lowercase, two digits each.
///
/// The output never includes a trailing newline; the caller decides.
pub fn write_line<W: fmt::Write>(w: &mut W, frame: &RawFrame) -> fmt::Result {
    if let Some(ts) = &frame.timestamp {
        w.write_str(ts)?;
    }
    write!(
        w,
        ",{prio},{pgn},{src},{dst},{len}",
        prio = frame.prio,
        pgn = frame.pgn,
        src = frame.src,
        dst = frame.dst,
        len = frame.data.len(),
    )?;
    for b in &frame.data {
        write!(w, ",{:02x}", b)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_8byte_frame() {
        let line = "2011-04-25-06:25:03.603,3,129029,36,255,8,e6,f1,3a,80,9c,c6,0d,b3";
        let f = parse_line(line).unwrap();
        assert_eq!(f.timestamp.as_deref(), Some("2011-04-25-06:25:03.603"));
        assert_eq!(f.prio, 3);
        assert_eq!(f.pgn, 129029);
        assert_eq!(f.src, 36);
        assert_eq!(f.dst, 255);
        assert_eq!(
            &f.data[..],
            &[0xe6, 0xf1, 0x3a, 0x80, 0x9c, 0xc6, 0x0d, 0xb3]
        );
    }

    #[test]
    fn parses_fast_43byte_payload() {
        let mut line =
            String::from("2011-04-25-06:25:03.603,3,129029,36,255,43");
        for i in 0..43 {
            line.push_str(&format!(",{:02x}", i as u8));
        }
        let f = parse_line(&line).unwrap();
        assert_eq!(f.data.len(), 43);
        assert_eq!(f.data[0], 0);
        assert_eq!(f.data[42], 42);
    }

    #[test]
    fn writes_round_trip() {
        let frame = RawFrame::new(
            Some("2011-04-25-06:25:03.603".into()),
            3,
            129029,
            36,
            255,
            vec![0xe6, 0xf1, 0x3a, 0x80, 0x9c, 0xc6, 0x0d, 0xb3],
        );
        let mut out = String::new();
        write_line(&mut out, &frame).unwrap();
        let again = parse_line(&out).unwrap();
        assert_eq!(again, frame);
    }

    #[test]
    fn rejects_empty_line() {
        assert!(matches!(parse_line(""), Err(ParseError::Empty)));
    }

    #[test]
    fn rejects_oversized_len() {
        let line = "ts,3,129029,36,255,250";
        assert!(matches!(
            parse_line(line),
            Err(ParseError::LengthTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_short_payload() {
        // Declared 8 bytes, only 3 supplied.
        let line = "ts,3,129029,36,255,8,01,02,03";
        assert!(matches!(
            parse_line(line),
            Err(ParseError::BadPayloadCount {
                expected: 8,
                found: 3
            })
        ));
    }

    #[test]
    fn empty_timestamp_field() {
        let line = ",3,129029,36,255,1,ff";
        let f = parse_line(line).unwrap();
        assert!(f.timestamp.is_none());
        assert_eq!(&f.data[..], &[0xff]);
    }
}
