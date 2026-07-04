// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Struct-path equivalent of [`crate::ais`] — converts AIS PGNs to
//! NMEA 0183 `!AIVDM` sentences by reading fields directly from a
//! `DecodedPgn` instead of round-tripping through analyzer JSON.
//!
//! The bit-packing semantics are identical to `ais.rs` (which is the
//! canboat C reference). The only difference is the value lookup
//! path: `field_by_name(...)` + `as_i64()/as_f64()/as_str()` instead
//! of `json::int/number/value`.
//!
//! `field_by_name` is a linear scan over the record's top-level
//! fields — AIS PGNs carry on the order of 10–25 fields, so the scan
//! cost is far below a JSON-substring search and we avoid the JSON
//! serialization step entirely. Pre-resolved [`FieldHandle`]s would
//! shave another ~5% off but at the cost of ~80 handles to wire up;
//! we leave them on the table for now.

use canboat_core::{DecodedPgn, FieldValue};

use crate::ais::{
    AIS_TRANSCEIVER_NAMES, BitVector, POSITION_ACCURACY_NAMES, RAIM_NAMES, REPEAT_NAMES,
    emit_sentences,
};

/// Convert a decoded AIS PGN into one or more `!AIVDM,…` sentences.
/// Returns the number of sentences emitted. Mirrors
/// [`crate::ais::convert`].
pub fn convert(out: &mut String, decoded: &DecodedPgn, seq_counter: &mut u8) -> usize {
    let pgn = decoded.pgn as i64;
    let msgid = match pgn_to_msgid(pgn, decoded) {
        Some(m) => m,
        None => return 0,
    };
    let channel = ais_channel(decoded);
    let talker = ais_talker(decoded);
    let mut bv = BitVector::new();
    if !encode_payload(&mut bv, msgid, pgn, decoded) {
        return 0;
    }
    emit_sentences(out, &bv, talker, channel, seq_counter)
}

fn pgn_to_msgid(pgn: i64, decoded: &DecodedPgn) -> Option<i64> {
    if let Some(f) = decoded.field_by_name("Message ID") {
        if let Some(n) = f.value.lookup_value() {
            return Some(n as i64);
        }
        if let Some(n) = f.value.as_i64() {
            return Some(n);
        }
        if let Some(s) = f.value.as_str() {
            match s {
                "Scheduled Class A position report"
                | "Assigned scheduled Class A position report"
                | "Interrogated Class A position report" => return Some(1),
                "Standard Class B position report" => return Some(18),
                "AIS UTC and Date Report" => return Some(4),
                "Static and Voyage Related Data" => return Some(5),
                "Standard SAR Aircraft Position Report" => return Some(9),
                "Addressed safety related message" => return Some(12),
                "Safety related broadcast message" => return Some(14),
                "Extended Class B position report" => return Some(19),
                "ATON report" => return Some(21),
                "Static data report" => return Some(24),
                _ => {}
            }
        }
    }
    Some(match pgn {
        129038 => 1,
        129039 => 18,
        129040 => 19,
        129041 => 21,
        129793 => 4,
        129794 => 5,
        129798 => 9,
        129801 => 12,
        129802 => 14,
        129809 | 129810 => 24,
        _ => return None,
    })
}

fn ais_channel(decoded: &DecodedPgn) -> char {
    let info = enum_or_name(
        decoded,
        "AIS Transceiver information",
        AIS_TRANSCEIVER_NAMES,
    );
    if matches!(info, 1 | 3) { 'B' } else { 'A' }
}

fn ais_talker(decoded: &DecodedPgn) -> &'static str {
    match enum_or_name(
        decoded,
        "AIS Transceiver information",
        AIS_TRANSCEIVER_NAMES,
    ) {
        2..=4 => "VDO",
        _ => "VDM",
    }
}

fn encode_payload(bv: &mut BitVector, msgid: i64, pgn: i64, decoded: &DecodedPgn) -> bool {
    match msgid {
        1..=3 => encode_class_a_position(bv, msgid, decoded),
        4 => encode_utc_date(bv, msgid, decoded),
        5 => encode_class_a_static(bv, msgid, decoded),
        9 => encode_sar_aircraft(bv, msgid, decoded),
        12 => encode_addressed_safety(bv, msgid, decoded),
        14 => encode_broadcast_safety(bv, msgid, decoded),
        18 => encode_class_b_position(bv, msgid, decoded),
        19 => encode_class_b_extended(bv, msgid, decoded),
        21 => encode_aton(bv, msgid, decoded),
        24 => encode_class_b_static(bv, msgid, pgn, decoded),
        _ => return false,
    }
    true
}

// ---------- per-message-type encoders ----------

fn encode_class_a_position(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(enum_or_name(d, "Nav Status", &[]), 4);
    bv.add_int(rate_of_turn(d), 8);
    bv.add_int(sog(d, "SOG"), 10);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(cog(d, "COG"), 12);
    bv.add_int(heading(d, "Heading"), 9);
    bv.add_int(int_field(d, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(enum_or_name(d, "Special Maneuver Indicator", &[]), 2);
    bv.add_int(0, 3); // Spare
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(comm_state(d), 19);
}

fn encode_utc_date(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(ais_date(d, "Position Date"), 23);
    bv.add_int(ais_time(d, "Position Time"), 17);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(enum_or_name(d, "GNSS type", &[]), 4);
    bv.add_int(0, 10); // Spare
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(comm_state(d), 19);
}

fn encode_class_a_static(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(enum_or_name(d, "AIS version indicator", &[]), 2);
    bv.add_int(user_id(d, "IMO number", 0), 30);
    bv.add_string(str_field(d, "Callsign").unwrap_or(""), 42);
    bv.add_string(str_field(d, "Name").unwrap_or(""), 120);
    bv.add_int(enum_or_name(d, "Type of ship", &[]), 8);
    bv.add_int(ship_dimensions(d, true), 30);
    bv.add_int(enum_or_name(d, "GNSS type", &[]), 4);
    bv.add_int(ais_eta(d), 20);
    bv.add_int(draft(d), 8);
    bv.add_string(str_field(d, "Destination").unwrap_or(""), 120);
    bv.add_int(enum_or_name(d, "DTE", &[]), 1);
    bv.add_int(0, 1); // Spare
}

fn encode_sar_aircraft(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(altitude(d), 12);
    bv.add_int((sog(d, "SOG") + 5) / 10, 10);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(cog(d, "COG"), 12);
    bv.add_int(int_field(d, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(enum_or_name(d, "DTE", &[]), 1);
    bv.add_int(0, 3); // Spare
    bv.add_int(enum_or_name(d, "AIS mode", &[]), 1);
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(d, "AIS communication state", &[]), 1);
    bv.add_int(comm_state(d), 19);
}

fn encode_addressed_safety(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "Source ID", 0), 30);
    bv.add_int(int_field(d, "Sequence Number").unwrap_or(0).clamp(0, 3), 2);
    bv.add_int(user_id(d, "Destination ID", 0), 30);
    bv.add_int(int_field(d, "Retransmit flag").unwrap_or(0).clamp(0, 1), 1);
    bv.add_int(0, 1); // Spare
    let text = str_field(d, "Safety Related Text").unwrap_or("");
    let mut bits = text.chars().count() * 6;
    if bits > 156 {
        bits = 156;
    }
    if !bits.is_multiple_of(8) {
        bits += 8 - bits % 8;
    }
    bv.add_string(text, bits);
}

fn encode_broadcast_safety(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "Source ID", 0), 30);
    bv.add_int(0, 2); // Spare
    let text = str_field(d, "Safety Related Text").unwrap_or("");
    let mut bits = text.chars().count() * 6;
    if bits > 161 {
        bits = 161;
    }
    if !bits.is_multiple_of(8) {
        bits += 8 - bits % 8;
    }
    bv.add_string(text, bits);
}

fn encode_class_b_position(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(sog(d, "SOG"), 10);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(cog(d, "COG"), 12);
    bv.add_int(heading(d, "Heading"), 9);
    bv.add_int(int_field(d, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 2); // Regional reserved
    bv.add_int(enum_or_name(d, "Unit type", &[]), 1);
    bv.add_int(enum_or_name(d, "Integrated Display", &[]), 1);
    bv.add_int(enum_or_name(d, "DSC", &[]), 1);
    bv.add_int(enum_or_name(d, "Band", &[]), 1);
    bv.add_int(enum_or_name(d, "Can handle Msg 22", &[]), 1);
    bv.add_int(enum_or_name(d, "AIS mode", &[]), 1);
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(d, "AIS communication state", &[]), 1);
    bv.add_int(comm_state(d), 19);
}

fn encode_class_b_extended(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(sog(d, "SOG"), 10);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(cog(d, "COG"), 12);
    bv.add_int(heading(d, "True Heading"), 9);
    bv.add_int(int_field(d, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 4); // Regional reserved
    bv.add_string(str_field(d, "Name").unwrap_or(""), 120);
    bv.add_int(enum_or_name(d, "Type of ship", &[]), 8);
    bv.add_int(ship_dimensions(d, true), 30);
    bv.add_int(enum_or_name(d, "GNSS type", &[]), 4);
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(d, "DTE", &[]), 1);
    bv.add_int(enum_or_name(d, "AIS mode", &[]), 1);
    bv.add_int(0, 4); // Spare
}

fn encode_aton(bv: &mut BitVector, msgid: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    bv.add_int(enum_or_name(d, "AtoN Type", &[]), 5);
    let aton_name = str_field(d, "AtoN Name").unwrap_or("");
    let (name20, ext) = split_aton_name(aton_name);
    bv.add_string(name20, 120);
    bv.add_int(
        enum_or_name(d, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(d, "Longitude"), 28);
    bv.add_int(latitude(d, "Latitude"), 27);
    bv.add_int(ship_dimensions(d, false), 30);
    bv.add_int(enum_or_name(d, "GNSS type", &[]), 4);
    bv.add_int(int_field(d, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(enum_or_name(d, "Off Position Indicator", &[]), 1);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(enum_or_name(d, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(d, "Virtual AtoN Flag", &[]), 1);
    bv.add_int(enum_or_name(d, "Assigned Mode Flag", &[]), 1);
    bv.add_int(0, 1); // Spare
    let mut ext_bits = ext.chars().count() * 6;
    if ext_bits % 8 != 0 {
        ext_bits += 8 - ext_bits % 8;
    }
    bv.add_string(ext, ext_bits);
}

fn encode_class_b_static(bv: &mut BitVector, msgid: i64, pgn: i64, d: &DecodedPgn) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(d), 2);
    bv.add_int(user_id(d, "User ID", 0), 30);
    match pgn {
        129809 => {
            bv.add_int(0, 2); // Part number = A
            bv.add_string(str_field(d, "Name").unwrap_or(""), 120);
            bv.add_int(0, 8); // Spare
        }
        129810 => {
            bv.add_int(1, 2); // Part number = B
            bv.add_int(enum_or_name(d, "Type of ship", &[]), 8);
            bv.add_string(str_field(d, "Vendor ID").unwrap_or(""), 42);
            bv.add_string(str_field(d, "Callsign").unwrap_or(""), 42);
            bv.add_int(ship_dimensions(d, true), 30);
            bv.add_int(user_id(d, "Mothership User ID", 0), 30);
            bv.add_int(0, 6); // Spare
        }
        _ => {}
    }
}

// ---------- helpers ----------

fn int_field(d: &DecodedPgn, name: &str) -> Option<i64> {
    d.field_by_name(name).and_then(|f| f.value.as_i64())
}

fn num_field(d: &DecodedPgn, name: &str) -> Option<f64> {
    d.field_by_name(name).and_then(|f| f.value.as_f64())
}

fn str_field<'a>(d: &'a DecodedPgn, name: &str) -> Option<&'a str> {
    d.field_by_name(name).and_then(|f| f.value.as_str())
}

fn repeat_indicator(d: &DecodedPgn) -> i64 {
    enum_or_name(d, "Repeat Indicator", REPEAT_NAMES).clamp(0, 3)
}

/// Read an MMSI or 30-bit user ID. canboat-core decodes MMSI fields
/// to `FieldValue::Mmsi(u32)` which `as_i64()` widens cleanly.
fn user_id(d: &DecodedPgn, field: &str, default: i64) -> i64 {
    int_field(d, field).unwrap_or(default)
}

/// Resolve an enum field. `Lookup` carries the integer code directly;
/// the `names` fallback list handles the rare case where the decoder
/// produced a bare string we still need to map.
fn enum_or_name(d: &DecodedPgn, field: &str, names: &[(&str, i64)]) -> i64 {
    let Some(f) = d.field_by_name(field) else {
        return -1;
    };
    if let Some(n) = f.value.lookup_value() {
        return n as i64;
    }
    if let Some(n) = f.value.as_i64() {
        return n;
    }
    if let Some(s) = f.value.as_str() {
        for (name, val) in names {
            if s == *name {
                return *val;
            }
        }
    }
    -1
}

/// `Rate of Turn` — non-linear AIS encoding. Identical math to
/// [`crate::ais::rate_of_turn`].
fn rate_of_turn(d: &DecodedPgn) -> i64 {
    let Some(rot) = num_field(d, "Rate of Turn") else {
        return -128;
    };
    let v = rot * 60.0;
    let sign = if v >= 0.0 { 1.0 } else { -1.0 };
    let r = 4.733 * v.abs().sqrt();
    let r = (r + 0.5) as i64;
    let r = r.clamp(-127, 127) * sign as i64;
    if (-127..=127).contains(&r) { r } else { -128 }
}

fn sog(d: &DecodedPgn, field: &str) -> i64 {
    let Some(v) = num_field(d, field) else {
        return 1023;
    };
    let n = (v * 19.438_444_92 + 0.5) as i64;
    if (0..=1022).contains(&n) { n } else { 1023 }
}

fn cog(d: &DecodedPgn, field: &str) -> i64 {
    let Some(v) = num_field(d, field) else {
        return 3600;
    };
    let n = (v * 10.0 + 0.5) as i64;
    if (0..=3599).contains(&n) { n } else { 3600 }
}

fn heading(d: &DecodedPgn, field: &str) -> i64 {
    let Some(v) = num_field(d, field) else {
        return 511;
    };
    let n = (v + 0.5) as i64;
    if (0..=359).contains(&n) { n } else { 511 }
}

fn longitude(d: &DecodedPgn, field: &str) -> i64 {
    let Some(v) = num_field(d, field) else {
        return 0x6791AC0;
    };
    let n = (v * 600_000.0).round() as i64;
    if (-108_000_000..=108_000_000).contains(&n) {
        n
    } else {
        0x6791AC0
    }
}

fn latitude(d: &DecodedPgn, field: &str) -> i64 {
    let Some(v) = num_field(d, field) else {
        return 0x3412140;
    };
    let n = (v * 600_000.0).round() as i64;
    if (-54_000_000..=54_000_000).contains(&n) {
        n
    } else {
        0x3412140
    }
}

fn altitude(d: &DecodedPgn) -> i64 {
    let Some(v) = num_field(d, "Altitude") else {
        return 4095;
    };
    let n = (v + 0.5) as i64;
    if (0..=4094).contains(&n) { n } else { 4095 }
}

fn draft(d: &DecodedPgn) -> i64 {
    let Some(v) = num_field(d, "Draft") else {
        return 0;
    };
    let n = (v * 10.0 + 0.5) as i64;
    n.clamp(0, 255)
}

/// `Communication State` is decoded as a `FieldValue::Binary` (raw
/// bytes) or `FieldValue::Number` depending on the canboat.json
/// field type. We accept either: numeric path returns the value
/// directly; binary path packs the first 3 bytes little-endian into
/// the 19-bit slot, matching canboat C's text-form parser.
fn comm_state(d: &DecodedPgn) -> i64 {
    let Some(f) = d.field_by_name("Communication State") else {
        return 393_222;
    };
    if let Some(n) = f.value.as_i64() {
        return n & ((1 << 19) - 1);
    }
    if let FieldValue::Binary(bytes) = &f.value
        && bytes.len() >= 3
    {
        let v = (bytes[0] as i64) | ((bytes[1] as i64) << 8) | ((bytes[2] as i64) << 16);
        return v & ((1 << 19) - 1);
    }
    if let Some(s) = f.value.as_str() {
        let trimmed = s.trim_matches([' ', '"']);
        if let Ok(v) = trimmed.parse::<i64>() {
            return v & ((1 << 19) - 1);
        }
        let bytes: Vec<u8> = trimmed
            .split_whitespace()
            .filter_map(|t| u8::from_str_radix(t, 16).ok())
            .collect();
        if bytes.len() >= 3 {
            let v = (bytes[0] as i64) | ((bytes[1] as i64) << 8) | ((bytes[2] as i64) << 16);
            return v & ((1 << 19) - 1);
        }
    }
    0
}

/// Format a `FieldValue::Date(days)` as `YYYY.MM.DD`, then return a
/// 10-byte buffer in canboat's canonical date string form. Returns
/// `None` if the named field is missing or not a date.
fn date_string(d: &DecodedPgn, field: &str) -> Option<String> {
    let f = d.field_by_name(field)?;
    let FieldValue::Date(days) = f.value else {
        return None;
    };
    let mut buf = String::with_capacity(10);
    canboat_core::output::format_date(days, &mut buf).ok()?;
    Some(buf)
}

/// `Position Date` (or any DATE-typed field) packed as
/// `(year << 9) | (month << 5) | day`.
fn ais_date(d: &DecodedPgn, field: &str) -> i64 {
    let Some(s) = date_string(d, field) else {
        return 0;
    };
    let mut parts = s.split('.');
    let y: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let m: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let d: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let y = if y > 9999 { 0 } else { y };
    let m = if m > 12 { 0 } else { m };
    let d = if d > 31 { 0 } else { d };
    ((y as i64) << 9) | ((m as i64) << 5) | d as i64
}

/// `Position Time` packed as `(hour << 12) | (minute << 6) | second`.
fn ais_time(d: &DecodedPgn, field: &str) -> i64 {
    let Some(f) = d.field_by_name(field) else {
        return 0;
    };
    let FieldValue::Time { seconds, .. } = f.value else {
        return 0;
    };
    if !seconds.is_finite() || seconds < 0.0 {
        return 0;
    }
    let whole = seconds.trunc() as u64;
    let h = (whole / 3600) as u32;
    let m = ((whole / 60) % 60) as u32;
    let sec_int = (whole % 60) as u32;
    let h = if h > 24 { 24 } else { h };
    let m = if m > 60 { 60 } else { m };
    let sec_int = if sec_int > 60 { 60 } else { sec_int };
    ((h as i64) << 12) | ((m as i64) << 6) | sec_int as i64
}

/// `ETA Date` + `ETA Time` packed into the type-5 ETA field
/// (month/day/hour/minute). Canboat C reads bytes 5,6 and 8,9 of the
/// formatted date string, which works for both `YYYY.MM.DD` and
/// `YYYY-MM-DD` separators — we do the same.
fn ais_eta(d: &DecodedPgn) -> i64 {
    let (mut month, mut day) = (0u32, 0u32);
    if let Some(s) = date_string(d, "ETA Date") {
        let bytes = s.as_bytes();
        if bytes.len() >= 10 {
            month =
                10 * (bytes[5].wrapping_sub(b'0')) as u32 + (bytes[6].wrapping_sub(b'0')) as u32;
            day = 10 * (bytes[8].wrapping_sub(b'0')) as u32 + (bytes[9].wrapping_sub(b'0')) as u32;
        }
        if month > 12 {
            month = 0;
        }
        if day > 31 {
            day = 0;
        }
    }
    let (mut hour, mut minute) = (24u32, 60u32);
    if let Some(f) = d.field_by_name("ETA Time")
        && let FieldValue::Time { seconds, .. } = f.value
        && seconds.is_finite()
        && seconds >= 0.0
    {
        let whole = seconds.trunc() as u64;
        hour = (whole / 3600) as u32;
        minute = ((whole / 60) % 60) as u32;
        if hour > 24 {
            hour = 24;
        }
        if minute > 60 {
            minute = 60;
        }
    }
    ((month as i64) << 16) | ((day as i64) << 11) | ((hour as i64) << 6) | minute as i64
}

/// Pack the four `Position reference / Length / Beam` fields into
/// the 30-bit AIS dimension field. Mirrors `aisShipDimensions` in
/// canboat C.
fn ship_dimensions(d: &DecodedPgn, ship: bool) -> i64 {
    let (length, beam, ref_bow, ref_starboard) = if ship {
        (
            num_field(d, "Length").unwrap_or(0.0) * 10.0,
            num_field(d, "Beam").unwrap_or(0.0) * 10.0,
            num_field(d, "Position reference from Bow").unwrap_or(0.0) * 10.0,
            num_field(d, "Position reference from Starboard").unwrap_or(0.0) * 10.0,
        )
    } else {
        (
            num_field(d, "Length/Diameter").unwrap_or(0.0) * 10.0,
            num_field(d, "Beam/Diameter").unwrap_or(0.0) * 10.0,
            num_field(d, "Position Reference from True North Facing Edge").unwrap_or(0.0) * 10.0,
            num_field(d, "Position Reference from Starboard Edge").unwrap_or(0.0) * 10.0,
        )
    };
    let to_stern = (length - ref_bow).clamp(0.0, 5110.0);
    let to_port = (beam - ref_starboard).clamp(0.0, 630.0);
    (((ref_bow + 5.0) / 10.0) as i64) << 21
        | (((to_stern + 5.0) / 10.0) as i64) << 12
        | (((to_port + 5.0) / 10.0) as i64) << 6
        | ((ref_starboard + 5.0) / 10.0) as i64
}

fn split_aton_name(s: &str) -> (&str, &str) {
    if s.len() <= 20 {
        return (s, "");
    }
    (&s[..20], s[20..].trim_end_matches('\0'))
}
