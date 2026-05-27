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

use crate::format::plain::ParseError;
use crate::frame::RawFrame;

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

/// Encode `bytes` as RFC 4648 Base64 with `=` padding into `out`.
/// Companion to [`b64_decode`]; kept inline for the same minimal-deps
/// reason.
pub(crate) fn b64_encode(bytes: &[u8], out: &mut String) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        0 => {}
        1 => {
            let n = u32::from(bytes[i]) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
}

/// Build the line to send to the device for a transmit request.
///
/// iKonvert's TX format is intentionally shorter than the RX format:
/// `!PDGY,<pgn>,<dst>,<base64-data>\r\n`. The device fills in prio
/// and src from its own state. CRLF terminator matches the C code.
pub fn encode_tx_frame(frame: &crate::frame::RawFrame) -> String {
    let mut out = String::with_capacity(32 + frame.data.len() * 4 / 3 + 4);
    out.push_str("!PDGY,");
    out.push_str(&frame.pgn.to_string());
    out.push(',');
    out.push_str(&frame.dst.to_string());
    out.push(',');
    b64_encode(&frame.data, &mut out);
    out.push_str("\r\n");
    out
}

/// `$PDGY,N2NET_INIT,ALL\r\n` — bring the device online with all PGNs.
pub const TX_ONLINE_ALL: &str = "$PDGY,N2NET_INIT,ALL\r\n";

/// `$PDGY,N2NET_INIT,NORMAL\r\n` — bring the device online filtered by RX list.
pub const TX_ONLINE_NORMAL: &str = "$PDGY,N2NET_INIT,NORMAL\r\n";

/// `$PDGY,N2NET_OFFLINE\r\n` — take the device offline.
pub const TX_OFFLINE: &str = "$PDGY,N2NET_OFFLINE\r\n";

/// `$PDGY,N2NET_RESET\r\n` — clear RX/TX lists.
pub const TX_RESET: &str = "$PDGY,N2NET_RESET\r\n";

/// `$PDGY,TX_LIMIT,OFF\r\n` — disable the rate limiter.
pub const TX_LIMIT_OFF: &str = "$PDGY,TX_LIMIT,OFF\r\n";

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

    #[test]
    fn tx_frame_format_matches_canboat() {
        use crate::frame::RawFrame;
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 0,
            dst: 255,
            data: smallvec::smallvec![0x01, 0x02, 0x03],
        };
        // canboat C uses TX_PGN_MSG_PREFIX "!PDGY,%u,%u," (pgn, dst)
        // then base64 then CRLF. prio and src are NOT included on TX.
        let line = encode_tx_frame(&frame);
        assert_eq!(line, "!PDGY,60928,255,AQID\r\n");
    }

    #[test]
    fn b64_encode_round_trips_known_vectors() {
        let mut out = String::new();
        b64_encode(b"foobar", &mut out);
        assert_eq!(out, "Zm9vYmFy");
        out.clear();
        b64_encode(b"fooba", &mut out);
        assert_eq!(out, "Zm9vYmE=");
        out.clear();
        b64_encode(b"foob", &mut out);
        assert_eq!(out, "Zm9vYg==");
        out.clear();
        b64_encode(b"", &mut out);
        assert_eq!(out, "");
    }
}
