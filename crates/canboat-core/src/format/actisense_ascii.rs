//! Actisense N2K ASCII line format.
//!
//! Example line:
//!
//! ```text
//!   A173321.107 23FF7 1F119 01 02 ...
//! ```
//!
//! Layout (whitespace-separated):
//!   1. `A<HHMMSS.mmm>` — timestamp (UTC time-of-day; no date).
//!   2. `<SDP>` in hex — encoded as `(src << 12) | (dst << 4) | prio`.
//!   3. `<PGN>` in hex.
//!   4. Subsequent tokens are hex data bytes.
//!
//! Mirrors `parseRawFormatActisenseN2KAscii` in canboat/common/parse.c.

use smallvec::SmallVec;

use crate::format::plain::ParseError;
use crate::frame::RawFrame;

pub fn parse_line(line: &str) -> Result<RawFrame, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut toks = line.split_whitespace();

    // Token 1: A + 6-digit time, optionally with .mmm fraction.
    let ts_tok = toks.next().ok_or(ParseError::MissingTimestamp)?;
    if !ts_tok.starts_with('A') || ts_tok.len() < 7 {
        return Err(ParseError::BadInteger {
            field: "timestamp",
            value: ts_tok.to_string(),
        });
    }
    let timestamp = format_actisense_timestamp(&ts_tok[1..])?;

    // Token 2: SDP packed hex.
    let sdp_tok = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 1,
    })?;
    let sdp = u32::from_str_radix(sdp_tok, 16).map_err(|_| ParseError::BadInteger {
        field: "sdp",
        value: sdp_tok.to_string(),
    })?;
    let prio = (sdp & 0xf) as u8;
    let dst = ((sdp >> 4) & 0xff) as u8;
    let src = ((sdp >> 12) & 0xff) as u8;

    // Token 3: PGN.
    let pgn_tok = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 2,
    })?;
    let pgn = u32::from_str_radix(pgn_tok, 16).map_err(|_| ParseError::BadInteger {
        field: "pgn",
        value: pgn_tok.to_string(),
    })?;

    // Remaining tokens: hex data bytes.
    let mut data: SmallVec<[u8; 8]> = SmallVec::new();
    for (i, t) in toks.enumerate() {
        let b = u8::from_str_radix(t, 16).map_err(|_| ParseError::BadHexByte {
            index: i,
            value: t.to_string(),
        })?;
        data.push(b);
    }

    Ok(RawFrame {
        timestamp: Some(timestamp),
        prio,
        pgn,
        src,
        dst,
        data,
    })
}

/// Convert Actisense's `HHMMSS[.mmm]` to canboat's `HH:MM:SS,mmm`
/// style.
fn format_actisense_timestamp(rest: &str) -> Result<String, ParseError> {
    let (h_str, mm_str, ss_str, ms_str) = if let Some((time, frac)) = rest.split_once('.') {
        if time.len() < 6 {
            return Err(ParseError::BadInteger {
                field: "timestamp",
                value: rest.to_string(),
            });
        }
        (&time[..2], &time[2..4], &time[4..6], frac)
    } else if rest.len() >= 6 {
        (&rest[..2], &rest[2..4], &rest[4..6], "000")
    } else {
        return Err(ParseError::BadInteger {
            field: "timestamp",
            value: rest.to_string(),
        });
    };
    let _h: u32 = h_str.parse().map_err(|_| ParseError::BadInteger {
        field: "timestamp",
        value: rest.to_string(),
    })?;
    let _m: u32 = mm_str.parse().map_err(|_| ParseError::BadInteger {
        field: "timestamp",
        value: rest.to_string(),
    })?;
    let _s: u32 = ss_str.parse().map_err(|_| ParseError::BadInteger {
        field: "timestamp",
        value: rest.to_string(),
    })?;
    // canboat formats with comma + 3-digit milliseconds.
    let ms: u32 = ms_str.parse().map_err(|_| ParseError::BadInteger {
        field: "timestamp",
        value: rest.to_string(),
    })?;
    Ok(format!("{h_str}:{mm_str}:{ss_str},{:03}", ms % 1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actisense_ascii_line() {
        // Pulled from canboat/common/parse.c documentation. Synthetic:
        //   time 17:33:21.107, src 0x23, dst 0xff, prio 0x7,
        //   pgn 0x1f119 = 127257.
        let line = "A173321.107 23FF7 1F119 01 02 03 04 05 06 07 08";
        let f = parse_line(line).unwrap();
        assert_eq!(f.timestamp.as_deref(), Some("17:33:21,107"));
        assert_eq!(f.prio, 7);
        assert_eq!(f.dst, 0xff);
        assert_eq!(f.src, 0x23);
        assert_eq!(f.pgn, 0x1f119);
        assert_eq!(&f.data[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn rejects_missing_timestamp_prefix() {
        let line = "173321.107 23FF7 1F119";
        assert!(parse_line(line).is_err());
    }
}
