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

use crate::frame::RawFrame;
use crate::format::plain::ParseError;

pub fn parse_line(line: &str) -> Result<RawFrame, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut toks = line.split_whitespace();
    let time_tok = toks.next().ok_or(ParseError::MissingTimestamp)?;
    let _dir = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 1,
    })?;
    let canid_tok = toks.next().ok_or(ParseError::BadHeader {
        expected: 3,
        found: 2,
    })?;
    let canid =
        u32::from_str_radix(canid_tok, 16).map_err(|_| ParseError::BadInteger {
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
        timestamp: Some(time_tok.to_string()),
        prio,
        pgn,
        src,
        dst,
        data,
    })
}

/// Decompose an ISO 11783 29-bit CAN identifier into (prio, pgn, src, dst).
/// PDU1 (PF < 240): PGN = PF << 8; dst = PS.
/// PDU2 (PF ≥ 240): PGN = (PF << 8) | PS; dst = 255 (broadcast).
pub(crate) fn iso11783_decompose(id: u32) -> (u8, u32, u8, u8) {
    let prio = ((id >> 26) & 0x7) as u8;
    let pf = ((id >> 16) & 0xff) as u8;
    let ps = ((id >> 8) & 0xff) as u8;
    let src = (id & 0xff) as u8;
    let (pgn, dst) = if pf < 240 {
        ((pf as u32) << 8, ps)
    } else {
        ((pf as u32) << 8 | ps as u32, 0xff)
    };
    (prio, pgn, src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ydwg02_pdu2_frame() {
        // CAN id 0x0DF50B23: prio=3, PF=0xF5, PS=0x0B → PGN 0xF50B (62731).
        // Wait — PF=0xF5 >= 240 → PDU2, PGN = 0xF50B = 62731, dst=255.
        // src = 0x23 = 35.
        let line = "00:17:55.475 R 0DF50B23 FF FF FF FF FF 00 00 FF";
        let f = parse_line(line).unwrap();
        assert_eq!(f.timestamp.as_deref(), Some("00:17:55.475"));
        assert_eq!(f.prio, 3);
        assert_eq!(f.pgn, 0xf50b);
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
