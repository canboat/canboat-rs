//! Digital Yacht iKonvert serial protocol — line-based, ASCII control
//! sentences interleaved with binary frames carrying Base64 payload.
//!
//! Two prefixes matter:
//!
//! ```text
//!   !PDGY,<pgn>,<prio>,<src>,<dst>,<sec>.<ms>,<base64 data>
//!   $PDGY,...                          # control sentences
//! ```
//!
//! Only `!PDGY,` lines carry N2K traffic; `$PDGY,` lines are
//! management traffic (init/alive/list) handled by the caller.
//!
//! Reference: `canboat/ikonvert-serial/ikonvert.h`.

use smallvec::SmallVec;

use crate::frame::RawFrame;
use crate::format::plain::ParseError;

/// One parsed line from an iKonvert stream.
#[derive(Debug, Clone)]
pub enum IkonvertLine {
    /// `!PDGY,...` — an N2K frame.
    Frame(RawFrame),
    /// `$PDGY,...` — control / status sentence (carried as-is for the
    /// caller to log or interpret).
    Control(String),
    /// Anything else — typically blank or pre-init noise.
    Other,
}

/// Parse one iKonvert line.
pub fn parse_line(line: &str) -> Result<IkonvertLine, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    if let Some(rest) = line.strip_prefix("!PDGY,") {
        return parse_n2k_line(rest).map(IkonvertLine::Frame);
    }
    if let Some(rest) = line.strip_prefix("$PDGY,") {
        return Ok(IkonvertLine::Control(rest.to_string()));
    }
    Ok(IkonvertLine::Other)
}

fn parse_n2k_line(rest: &str) -> Result<RawFrame, ParseError> {
    // Fields: pgn, prio, src, dst, sec.ms, base64-data
    let mut it = rest.splitn(6, ',');
    let pgn = parse_int::<u32>(it.next(), "pgn")?;
    let prio = parse_int::<u8>(it.next(), "prio")?;
    let src = parse_int::<u8>(it.next(), "src")?;
    let dst = parse_int::<u8>(it.next(), "dst")?;
    let ts = it.next().ok_or(ParseError::BadHeader {
        expected: 6,
        found: 4,
    })?;
    let b64 = it.next().ok_or(ParseError::BadHeader {
        expected: 6,
        found: 5,
    })?;
    let data_vec = b64_decode(b64).ok_or(ParseError::BadHexByte {
        index: 0,
        value: b64.to_string(),
    })?;
    let data: SmallVec<[u8; 8]> = data_vec.into_iter().collect();
    Ok(RawFrame {
        timestamp: Some(ts.to_string()),
        prio,
        pgn,
        src,
        dst,
        data,
    })
}

fn parse_int<T: std::str::FromStr>(
    raw: Option<&str>,
    field: &'static str,
) -> Result<T, ParseError> {
    let s = raw.ok_or(ParseError::BadHeader {
        expected: 6,
        found: 0,
    })?;
    s.trim().parse().map_err(|_| ParseError::BadInteger {
        field,
        value: s.to_string(),
    })
}

/// Minimal RFC 4648 Base64 decoder for the iKonvert payload. Returns
/// `None` on any malformed input. We carry the table inline rather
/// than depend on the `base64` crate to keep canboat-core's dep tree
/// small.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() {
        return Some(Vec::new());
    }
    let bytes = s.as_bytes();
    // Padding lengths must yield a 4-byte-aligned group count.
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut group = [0u8; 4];
    let mut pad = 0;
    for chunk in bytes.chunks(4) {
        for (i, b) in chunk.iter().enumerate() {
            group[i] = match *b {
                b'A'..=b'Z' => *b - b'A',
                b'a'..=b'z' => *b - b'a' + 26,
                b'0'..=b'9' => *b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                _ => return None,
            };
        }
        let combined = (u32::from(group[0]) << 18)
            | (u32::from(group[1]) << 12)
            | (u32::from(group[2]) << 6)
            | u32::from(group[3]);
        out.push(((combined >> 16) & 0xff) as u8);
        out.push(((combined >> 8) & 0xff) as u8);
        out.push((combined & 0xff) as u8);
    }
    // Pop bytes that correspond to padding chars (1 pad = -1 byte,
    // 2 pad = -2 bytes).
    if pad > 0 {
        out.truncate(out.len() - pad);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip_known_vectors() {
        // RFC 4648 examples.
        assert_eq!(b64_decode("").unwrap(), b"");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(b64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn parses_pdgy_frame() {
        // PGN 127257 (Attitude), prio 3, src 35, dst 255, ts 12.345,
        // data = [0x01, 0x02, 0x03] → Base64 "AQID".
        let line = "!PDGY,127257,3,35,255,12.345,AQID";
        let ev = parse_line(line).unwrap();
        match ev {
            IkonvertLine::Frame(f) => {
                assert_eq!(f.pgn, 127257);
                assert_eq!(f.prio, 3);
                assert_eq!(f.src, 35);
                assert_eq!(f.dst, 255);
                assert_eq!(f.timestamp.as_deref(), Some("12.345"));
                assert_eq!(&f.data[..], &[0x01, 0x02, 0x03]);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
    }

    #[test]
    fn classifies_control_sentence() {
        let ev = parse_line("$PDGY,,000000,,,,,").unwrap();
        assert!(matches!(ev, IkonvertLine::Control(_)));
    }
}
