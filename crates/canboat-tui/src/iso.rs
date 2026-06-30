//! Outgoing PGN payload builders.
//!
//! The TUI sends two kinds of frames upstream:
//!
//! * **ISO Request (PGN 59904)** — three-byte LE PGN body, used to
//!   ask a device to (re-)emit a record (PGN 126464 PGN List, PGN
//!   126996 Product Info, …).
//!
//! * **NMEA Group Function — Command (PGN 126208, function code 1)**
//!   — variable-length payload used to ask a device to change the
//!   transmission interval of one of its outgoing PGNs (the
//!   `Transmission interval` parameter, units of 1 ms). The
//!   proprietary form prepends Manufacturer Code + Industry Code so
//!   the target only acts on it if the manufacturer matches.
//!
//! Output shape is the canboat PLAIN text line — `<ts>,<prio>,<pgn>,
//! <src>,<dst>,<len>,<hex>,...` — exactly what canboat-pipeline
//! accepts on its analyzer port (2598) for client-side injection and
//! what n2kd's downstream serial writers send back to the bus.

use std::time::{SystemTime, UNIX_EPOCH};

use canboat_core::format_iso_ms;

/// Our local source address — canboat C n2kd uses 0 for synthetic
/// outbound traffic and that suffices for the TUI.
pub const TUI_SRC: u8 = 0;

/// Format a canboat PLAIN line. `data` is the raw PGN payload (max
/// 223 bytes for fast-packet).
pub fn format_plain(prio: u8, pgn: u32, src: u8, dst: u8, data: &[u8]) -> String {
    let ts = current_timestamp();
    let mut out = String::with_capacity(ts.len() + 16 + 4 + data.len() * 3);
    out.push_str(&ts);
    out.push(',');
    out.push_str(&prio.to_string());
    out.push(',');
    out.push_str(&pgn.to_string());
    out.push(',');
    out.push_str(&src.to_string());
    out.push(',');
    out.push_str(&dst.to_string());
    out.push(',');
    out.push_str(&data.len().to_string());
    for b in data {
        out.push(',');
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// PLAIN line for `PGN 59904` (ISO Request) addressed to `dst`, asking
/// it to emit `requested_pgn`.
pub fn iso_request(dst: u8, requested_pgn: u32) -> String {
    let payload = [
        (requested_pgn & 0xff) as u8,
        ((requested_pgn >> 8) & 0xff) as u8,
        ((requested_pgn >> 16) & 0xff) as u8,
    ];
    format_plain(6, 59904, TUI_SRC, dst, &payload)
}

/// PLAIN line for the standard (non-proprietary) form of PGN 126208
/// Command — request a change to `Transmission interval` (1 ms units,
/// 0xFFFFFFFF = restore default, 0xFFFFFFFE = turn off) on `commanded_pgn`
/// at `dst`.
///
/// Body layout per the NMEA 2000 Standardized Group Function spec:
///
/// ```text
///   B0       : Function Code = 1 (Command)
///   B1..B3   : Commanded PGN (LE)
///   B4 hi:lo : Priority Setting (4) : Reserved (3) : 1 (1)
///   B5       : Number of Parameter Pairs = 1
///   B6       : Parameter index = 6 (Transmission interval)
///   B7..B10  : New value (LE, 1 ms units)
/// ```
///
/// Only the "transmission interval" parameter is set; transmission
/// interval offset is left untouched.
pub fn command_transmission_interval(dst: u8, commanded_pgn: u32, interval_ms: u32) -> String {
    let mut data = Vec::with_capacity(11);
    data.push(0x01); // Function: Command
    data.extend_from_slice(&commanded_pgn.to_le_bytes()[..3]);
    // Priority Setting (4 bits) = 0x8 ("don't change"), Reserved (3
    // bits) all-set per the spec, low bit = 1 ("don't change
    // priority"). 0xF9 packs that cleanly.
    data.push(0xf9);
    data.push(0x01); // Number of Parameter Pairs
    data.push(6); // Parameter index: Transmission interval
    data.extend_from_slice(&interval_ms.to_le_bytes());
    format_plain(3, 126208, TUI_SRC, dst, &data)
}

/// Same as [`command_transmission_interval`] but for the proprietary
/// (group-function-code-1, manufacturer-scoped) variant. The body
/// prepends Manufacturer Code (11 bits) + Reserved (2 bits, all-set)
/// + Industry Code (3 bits) to the standard fields.
pub fn command_transmission_interval_proprietary(
    dst: u8,
    commanded_pgn: u32,
    manufacturer_code: u16,
    industry_code: u8,
    interval_ms: u32,
) -> String {
    let mut data = Vec::with_capacity(13);
    data.push(0x01); // Function: Command
    data.extend_from_slice(&commanded_pgn.to_le_bytes()[..3]);
    data.push(0xf9); // Priority/Reserved/don't-change-prio
    // Manufacturer (11) | Reserved (2 all-set) | Industry (3).
    let mfr = manufacturer_code & 0x07ff;
    let ind = (industry_code as u16) & 0x07;
    let packed: u16 = mfr | (0b11 << 11) | (ind << 13);
    data.extend_from_slice(&packed.to_le_bytes());
    data.push(0x01); // Number of Parameter Pairs
    data.push(6); // Parameter index: Transmission interval
    data.extend_from_slice(&interval_ms.to_le_bytes());
    format_plain(3, 126208, TUI_SRC, dst, &data)
}

fn current_timestamp() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format_iso_ms(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_request_payload_is_le_pgn() {
        // PGN 126464 little-endian = 0x00, 0xee, 0x01.
        let line = iso_request(35, 126464);
        assert!(line.ends_with(",6,59904,0,35,3,00,ee,01"));
    }

    #[test]
    fn command_transmission_interval_layout() {
        // commanded_pgn 127251 = 0x01F113 -> LE 0x13, 0xf1, 0x01.
        // interval_ms 250 -> LE 0xfa, 0x00, 0x00, 0x00.
        let line = command_transmission_interval(17, 127251, 250);
        assert!(
            line.contains(",126208,0,17,11,01,13,f1,01,f9,01,06,fa,00,00,00"),
            "got: {line}"
        );
    }

    #[test]
    fn command_transmission_interval_proprietary_packs_manufacturer_and_industry() {
        // commanded_pgn 130824 = 0x01FF08 -> LE 0x08, 0xff, 0x01.
        // Manufacturer = 381 (B&G), Industry = 4 (Marine).
        // 381 = 0x017D. Packed = 0x017D | (0x03 << 11) | (0x04 << 13)
        //               = 0x017D | 0x1800 | 0x8000 = 0x997D → LE 7d 99.
        // interval_ms 1000 -> LE 0xe8, 0x03, 0x00, 0x00.
        let line = command_transmission_interval_proprietary(17, 130824, 381, 4, 1000);
        assert!(
            line.contains(",126208,0,17,13,01,08,ff,01,f9,7d,99,01,06,e8,03,00,00"),
            "got: {line}"
        );
    }
}
