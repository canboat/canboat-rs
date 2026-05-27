//! Yacht Devices YDWG-02 / YDEN line format.
//!
//! Example line (from YDWG02 docs):
//!
//! ```text
//!   00:17:55.475 R 0DF50B23 FF FF FF FF FF 00 00 FF
//! ```
//!
//! Layout (whitespace-separated):
//!   1. `<HH:MM:SS.mmm>` — time-of-day, no date.
//!   2. Direction marker (`R` = received, `T` = transmitted). We
//!      preserve received frames; transmit lines are skipped by the
//!      caller (return value carries direction).
//!   3. `<CANID>` — 8-hex-digit ISO 11783 29-bit CAN identifier
//!      (prio in bits 26..28, PGN spanning bits 8..26, src in bits 0..8).
//!   4. Subsequent tokens are hex data bytes.
//!
//! Mirrors `parseRawFormatYDWG02` in canboat/common/parse.c.

use smallvec::SmallVec;

use crate::format::plain::ParseError;
use crate::frame::RawFrame;

pub fn parse_line(line: &str) -> Result<RawFrame, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut toks = line.split_whitespace();
    let time_tok = toks.next().ok_or(ParseError::MissingTimestamp)?;
    // YDWG02 carries time-of-day only — synthesize an ISO date from
    // the host's local clock so downstream emitters can produce the
    // same `<YYYY-MM-DD>T<HH:MM:SS.mmm>` shape canboat C does
    // (`parse.c:parseRawFormatYDWG02`).
    let timestamp = synth_iso_timestamp(time_tok);
    let _dir = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 1,
    })?;
    let canid_tok = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 2,
    })?;
    let canid = u32::from_str_radix(canid_tok, 16).map_err(|_| ParseError::BadInteger {
        field: "canid",
        value: canid_tok.to_string(),
    })?;
    let (prio, pgn, src, dst) = iso11783_decompose(canid);

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

/// Synthesize `<YYYY-MM-DD>T<time>` from the host clock. Falls back
/// to just `time` if the system clock isn't readable (e.g. the test
/// environment freezes time). Mirrors canboat's `parseRawFormatYDWG02`
/// which does `localtime_r + strftime("%Y-%m-%dT")` then appends the
/// parsed time-of-day verbatim.
fn synth_iso_timestamp(time: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // We don't pull in chrono here — compute the civil date from the
    // Howard-Hinnant days→YMD algorithm we already have in
    // `output/mod.rs`. Keep it inlined to avoid widening the
    // pub(crate) surface.
    let days = secs.div_euclid(86_400);
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{time}")
}

/// Days-since-1970-01-01 → `(year, month, day)`. Public-domain
/// civil-from-days algorithm (Howard Hinnant). Duplicated here so the
/// YDWG02 parser doesn't depend on `output/`.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Decompose an ISO 11783 29-bit CAN identifier into (prio, pgn, src, dst).
/// Matches `getISO11783BitsFromCanId` in canboat/common/common.c.
///
///   priority (3 bits) | reserved+dp (2 bits) | PF (8) | PS (8) | SA (8)
///
/// - PDU1 (PF < 240): PGN = (RDP << 16) | (PF << 8); dst = PS.
/// - PDU2 (PF ≥ 240): PGN = (RDP << 16) | (PF << 8) | PS; dst = 255.
///
/// The RDP (Reserved + DataPage) bits are the two just below the
/// priority bits — they push PGNs above 0x10000 into the data-page-1
/// range (e.g. CAN-id 0x09FD020D → PGN 130306 = 0x1FD02, not 0xFD02).
pub fn iso11783_decompose(id: u32) -> (u8, u32, u8, u8) {
    let prio = ((id >> 26) & 0x7) as u8;
    let rdp = (id >> 24) & 0x3;
    let pf = ((id >> 16) & 0xff) as u8;
    let ps = ((id >> 8) & 0xff) as u8;
    let src = (id & 0xff) as u8;
    let (pgn, dst) = if pf < 240 {
        ((rdp << 16) | ((pf as u32) << 8), ps)
    } else {
        ((rdp << 16) | ((pf as u32) << 8) | ps as u32, 0xff)
    };
    (prio, pgn, src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ydwg02_pdu2_frame() {
        // CAN id 0x0DF50B23 — bits laid out as
        //   prio (3) | RDP (2) | PF (8) | PS (8) | SA (8)
        // = 011_01_11110101_00001011_00100011
        //   prio=3, RDP=1, PF=0xF5, PS=0x0B, SA=0x23.
        // PF >= 240 → PDU2; PGN = (RDP<<16) | (PF<<8) | PS = 0x1F50B
        // = 128267 (canboat's "Position, Rapid Update"); dst=255.
        let line = "00:17:55.475 R 0DF50B23 FF FF FF FF FF 00 00 FF";
        let f = parse_line(line).unwrap();
        // YDWG02 synthesises an ISO date from the host clock; the time
        // portion must round-trip verbatim regardless of which day the
        // test runs.
        assert!(
            f.timestamp
                .as_deref()
                .is_some_and(|t| t.ends_with("T00:17:55.475")),
            "timestamp: {:?}",
            f.timestamp
        );
        assert_eq!(f.prio, 3);
        assert_eq!(f.pgn, 0x1f50b);
        assert_eq!(f.src, 0x23);
        assert_eq!(f.dst, 0xff);
        assert_eq!(f.data.len(), 8);
    }

    #[test]
    fn pdu1_keeps_destination() {
        // PF=0xEE (<240) → PDU1; PS becomes dst, PGN = 0xEE00.
        // 0x18EEFF05 → prio=6, PF=0xEE, PS=0xFF, src=0x05.
        let line = "00:00:00.000 R 18EEFF05 01 02 03 04 05 06 07 08";
        let f = parse_line(line).unwrap();
        assert_eq!(f.prio, 6);
        assert_eq!(f.pgn, 0xee00);
        assert_eq!(f.dst, 0xff);
        assert_eq!(f.src, 0x05);
    }
}
