// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Outgoing PGN payload builders.
//!
//! The TUI sends two kinds of frames upstream:
//!
//! * **ISO Request (PGN 59904)** — three-byte LE PGN body, used to
//!   ask a device to (re-)emit a record (PGN 126464 PGN List, PGN
//!   126996 Product Info, …).
//!
//! * **NMEA Request group function (PGN 126208, function code 0)**
//!   — variable-length payload used to ask a device to change the
//!   transmission cadence of one of its outgoing PGNs.
//!   `Transmission interval` is a dedicated 32‑bit DURATION field
//!   inside the envelope (1 ms units; `0` = stop transmitting), so
//!   no parameter pair is needed for the standard form. The
//!   proprietary form appends two parameter pairs so the target
//!   only reacts when the Manufacturer Code + Industry Code on its
//!   own PGN schema match.
//!
//! The Command form (function code 1, parameter index 6 =
//! "Transmission interval") is **not** what real targets implement
//! for rate changes — the captured Furuno SCX‑20 setting tool
//! traffic in `../canboat/samples/scx20-setting-tool-pgn-*.raw`
//! uses Request exclusively. Schema authority for this layout is
//! `../canboat/docs/canboat.json` PGN 126208 variant
//! `nmeaRequestGroupFunction` (see comments below for the bit
//! layout); the SCX‑20 sample lines double as byte‑exact tests at
//! the bottom of this module.
//!
//! Output shape is the canboat PLAIN text line — `<ts>,<prio>,<pgn>,
//! <src>,<dst>,<len>,<hex>,...`. ISO / override frames go to the
//! server's write-only input port for bus injection; the filter control
//! PGN (262657) goes to the bidirectional filter control port. The
//! [`crate::tui::client::Writer`] routes each line to the right port by
//! PGN.

use std::time::{SystemTime, UNIX_EPOCH};

use canboat_core::format_iso_ms;

/// Our local source address — canboat C n2kd uses 0 for synthetic
/// outbound traffic and that suffices for the TUI.
pub const TUI_SRC: u8 = 0;

/// "Don't change" sentinel for the 16‑bit Transmission interval
/// offset field. Real captures always send `0xFFFF` here.
const OFFSET_DONT_CHANGE: u16 = 0xFFFF;

/// Format a canboat PLAIN line. `data` is the raw PGN payload.
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

/// PLAIN line for the pipeline's NMEA 0183 filter control PGN (262657),
/// **Set** form (Function 1): mute or unmute `sentence` — a 3-letter
/// formatter (e.g. `"VHW"`) or `"ALL"` for the whole source — on the
/// device currently at source address `source`. The pipeline
/// intercepts this before bus injection; it never reaches the wire.
///
/// Payload: `[Function=1, Source, s0, s1, s2, Muted, 0xff, 0xff]`.
pub fn nmea0183_filter_set(source: u8, sentence: &str, muted: bool) -> String {
    let s = sentence.as_bytes();
    let data = [
        1u8, // Function: Set
        source,
        *s.first().unwrap_or(&b' '),
        *s.get(1).unwrap_or(&b' '),
        *s.get(2).unwrap_or(&b' '),
        u8::from(muted),
        0xff,
        0xff,
    ];
    format_plain(7, 262657, TUI_SRC, 255, &data)
}

/// PLAIN line for the filter control PGN (262657), **Request** form
/// (Function 2): ask the server to (re-)send the current filter state on
/// the control connection. Only the function byte is significant; the
/// rest is `0xff` padding. See [`nmea0183_filter_set`] for the Set form.
pub fn nmea0183_filter_request() -> String {
    let data = [
        crate::n2kd::nmea_filter::FILTER_FN_REQUEST,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
    ];
    format_plain(7, 262657, TUI_SRC, 255, &data)
}

/// PLAIN line for PGN 126208 **Request** (function code 0) addressed
/// to `dst`, asking it to set the transmission interval of
/// `commanded_pgn` to `interval_ms` (1 ms units; `0` means stop
/// transmitting).
///
/// Body layout (matches `nmeaRequestGroupFunction` in
/// `../canboat/docs/canboat.json`):
///
/// ```text
///   B0       : Function Code = 0 (Request)
///   B1..B3   : Requested PGN (LE, 24 bits)
///   B4..B7   : Transmission interval (LE, 32 bits, 1 ms units)
///   B8..B9   : Transmission interval offset (LE, 16 bits)
///   B10      : Number of Parameters = 0
/// ```
///
/// Use this overload for **standard** (non‑proprietary) PGNs.
pub fn request_transmission_interval(dst: u8, commanded_pgn: u32, interval_ms: u32) -> String {
    let mut data = Vec::with_capacity(11);
    write_request_header(&mut data, commanded_pgn, interval_ms);
    data.push(0); // Number of Parameters
    format_plain(3, 126208, TUI_SRC, dst, &data)
}

/// PLAIN line for PGN 126208 **Request** scoping the rate change to
/// the manufacturer + industry whose proprietary PGN this is —
/// appends two parameter pairs at field indices 1 (Manufacturer
/// Code, 11‑bit → 2 bytes) and 3 (Industry Code, 3‑bit → 1 byte).
/// These are the field positions every proprietary PGN uses for
/// those values (see e.g. `../canboat/docs/canboat.json` PGN 130842
/// `furunoSixDegreesOfFreedomMovement`).
///
/// Captured Furuno SCX‑20 traffic in
/// `../canboat/samples/scx20-setting-tool-pgn-130578to130846-on.raw`
/// is byte‑identical to what this builder emits — see the test at
/// the bottom of the module.
pub fn request_transmission_interval_proprietary(
    dst: u8,
    commanded_pgn: u32,
    manufacturer_code: u16,
    industry_code: u8,
    interval_ms: u32,
) -> String {
    let mut data = Vec::with_capacity(16);
    write_request_header(&mut data, commanded_pgn, interval_ms);
    data.push(2); // Number of Parameters = 2 (mfr + industry)
    // Parameter pair 1: index = 1 (Manufacturer Code), value = 11‑bit
    // field rounded up to 2 LE bytes. The top 5 bits of the value
    // word stay 0 — only the 11‑bit Manufacturer Code is carried
    // here, the adjacent Reserved + Industry Code bits live in their
    // own field indices.
    data.push(1);
    data.extend_from_slice(&(manufacturer_code & 0x07FF).to_le_bytes());
    // Parameter pair 2: index = 3 (Industry Code), value = 3‑bit
    // field rounded up to 1 byte.
    data.push(3);
    data.push(industry_code & 0x07);
    format_plain(3, 126208, TUI_SRC, dst, &data)
}

/// Write B0..B9 of the PGN 126208 Request envelope (everything up to
/// and not including the `Number of Parameters` byte).
fn write_request_header(out: &mut Vec<u8>, commanded_pgn: u32, interval_ms: u32) {
    out.push(0x00); // Function Code: Request
    out.extend_from_slice(&commanded_pgn.to_le_bytes()[..3]);
    out.extend_from_slice(&interval_ms.to_le_bytes());
    out.extend_from_slice(&OFFSET_DONT_CHANGE.to_le_bytes());
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

    /// Strip the leading ISO timestamp so the assertion is stable.
    fn no_ts(line: &str) -> &str {
        line.split_once(',').map(|(_, rest)| rest).unwrap_or(line)
    }

    #[test]
    fn nmea0183_filter_set_whole_source() {
        // Function=1, source=33 (0x21), "ALL" = 41,4c,4c, muted=1.
        let line = nmea0183_filter_set(33, "ALL", true);
        assert_eq!(no_ts(&line), "7,262657,0,255,8,01,21,41,4c,4c,01,ff,ff");
    }

    #[test]
    fn nmea0183_filter_set_one_sentence_unmute() {
        // source=35 (0x23), "VLW" = 56,4c,57, muted=0.
        let line = nmea0183_filter_set(35, "VLW", false);
        assert_eq!(no_ts(&line), "7,262657,0,255,8,01,23,56,4c,57,00,ff,ff");
    }

    #[test]
    fn nmea0183_filter_request_is_a_request_frame() {
        // Function=2, rest padding. The server recognises it via
        // `is_request_frame`, and it must NOT look like a Set.
        let line = nmea0183_filter_request();
        assert_eq!(no_ts(&line), "7,262657,0,255,8,02,ff,ff,ff,ff,ff,ff,ff");
        let frame = canboat_core::format::parse_plain(&line).unwrap();
        assert!(crate::n2kd::nmea_filter::is_request_frame(&frame));
        assert!(!crate::n2kd::nmea_filter::is_set_frame(&frame));
    }

    #[test]
    fn iso_request_payload_is_le_pgn() {
        // PGN 126464 little-endian = 0x00, 0xee, 0x01.
        let line = iso_request(35, 126464);
        assert!(line.ends_with(",6,59904,0,35,3,00,ee,01"));
    }

    /// Reproduces the exact 11‑byte standard‑PGN Request line emitted
    /// by the Furuno SCX‑20 setting tool when disabling PGN 130578:
    ///
    /// ```text
    /// ,3,126208,0,52,11,00,12,fe,01,00,00,00,00,ff,ff,00
    /// ```
    ///
    /// (See `../canboat/samples/scx20-setting-tool-pgn-130578to130846-off.raw`.)
    #[test]
    fn request_standard_pgn_disable_matches_scx20_sample() {
        let line = request_transmission_interval(52, 130578, 0);
        assert_eq!(
            no_ts(&line),
            "3,126208,0,52,11,00,12,fe,01,00,00,00,00,ff,ff,00",
            "got: {line}"
        );
    }

    /// Same standard PGN with a 1000 ms interval — taken from the
    /// `…-on.raw` companion sample.
    #[test]
    fn request_standard_pgn_enable_matches_scx20_sample() {
        let line = request_transmission_interval(52, 130578, 1000);
        assert_eq!(
            no_ts(&line),
            "3,126208,0,52,11,00,12,fe,01,e8,03,00,00,ff,ff,00",
            "got: {line}"
        );
    }

    /// Reproduces the 16‑byte proprietary Request line that disables
    /// Furuno's PGN 130842:
    ///
    /// ```text
    /// ,3,126208,0,52,16,00,1a,ff,01,00,00,00,00,ff,ff,02,01,3f,07,03,04
    /// ```
    ///
    /// Furuno = manufacturer 1855 (0x73F), Marine industry = 4. The
    /// two parameter pairs at the tail are `(idx=1, mfr 2B LE)` and
    /// `(idx=3, industry 1B)` — the schema field positions for those
    /// values on every proprietary PGN.
    #[test]
    fn request_proprietary_pgn_disable_matches_scx20_sample() {
        let line = request_transmission_interval_proprietary(52, 130842, 1855, 4, 0);
        assert_eq!(
            no_ts(&line),
            "3,126208,0,52,16,00,1a,ff,01,00,00,00,00,ff,ff,02,01,3f,07,03,04",
            "got: {line}"
        );
    }

    /// Companion to the disable test — same envelope but the four
    /// interval bytes carry 200 ms (`c8,00,00,00`). Taken verbatim
    /// from the `…-on.raw` sample line for PGN 130842.
    #[test]
    fn request_proprietary_pgn_enable_matches_scx20_sample() {
        let line = request_transmission_interval_proprietary(52, 130842, 1855, 4, 200);
        assert_eq!(
            no_ts(&line),
            "3,126208,0,52,16,00,1a,ff,01,c8,00,00,00,ff,ff,02,01,3f,07,03,04",
            "got: {line}"
        );
    }

    /// Manufacturer Code mask: a value with bits above the 11‑bit
    /// limit set must still emit only the low 11 bits, so a careless
    /// caller can't poison the wire format. The constants 0xF800 +
    /// 1855 share the low 11 bits with plain 1855.
    #[test]
    fn proprietary_request_masks_manufacturer_to_11_bits() {
        let careful = request_transmission_interval_proprietary(52, 130842, 1855, 4, 0);
        let careless =
            request_transmission_interval_proprietary(52, 130842, 0xF800 | 1855, 4 | 0xF0, 0);
        // Compare payloads only — the leading ISO timestamp is sampled
        // per call, so two calls that straddle a millisecond would
        // otherwise differ despite identical wire bytes.
        assert_eq!(no_ts(&careful), no_ts(&careless));
    }
}
