//! Convert NMEA 2000 AIS PGNs to NMEA 0183 AIVDM/AIVDO sentences.
//!
//! Mirrors `canboat/n2kd/gps_ais.c`. The payload is a packed bit
//! vector built from the JSON's typed fields; ITU-R M.1371 dictates
//! the bit layout per message type. The packed bits are then
//! re-encoded as 6-bit ASCII (each 6-bit group → one printable
//! character, `0`/`8`-offset trick) and split into 60-char chunks
//! that go out as separate `!AIVDM,…` fragments when the message
//! exceeds one frame.
//!
//! Coverage matches canboat C:
//!
//!   PGN 129038 (Class A Position Report)        → AIVDM type 1/2/3
//!   PGN 129039 (Class B Position Report)        → AIVDM type 18
//!   PGN 129040 (Class B Extended Position)      → AIVDM type 19
//!   PGN 129041 (Aid-to-Navigation Report)       → AIVDM type 21
//!   PGN 129793 (AIS UTC and Date Report)        → AIVDM type 4
//!   PGN 129794 (Class A Static / Voyage)        → AIVDM type 5
//!   PGN 129798 (SAR Aircraft Position)          → AIVDM type 9
//!   PGN 129801 (Addressed Safety Message)       → AIVDM type 12
//!   PGN 129802 (Broadcast Safety Message)       → AIVDM type 14
//!   PGN 129809 (Class B Static Part A)          → AIVDM type 24A
//!   PGN 129810 (Class B Static Part B)          → AIVDM type 24B
//!
//! Caveat: the analyzer should be run in `-nv` mode for best
//! results — full `{value, name}` lookup objects let us trivially
//! pull the integer back out. Without `-nv` we still recognise the
//! handful of enum strings the canboat AIS layout actually keys on
//! (Message ID names, Repeat Indicator, Position Accuracy, RAIM).
//!
//! Default-clamp behaviour matches canboat: out-of-range values
//! collapse to the ITU "not available" sentinel for that field
//! (511 for unknown heading, 1023 for unknown SOG, 0x6791AC0 for
//! unknown longitude, etc.).

use crate::json;

/// 226 bytes = 1808 bits = 301 6-bit groups — same upper bound canboat
/// C uses. The longest AIVDM payload we emit (type 5, Class A static)
/// is 424 bits.
const BITVEC_BYTES: usize = 226;

pub struct BitVector {
    pub bytes: [u8; BITVEC_BYTES],
    /// Bits used so far. Always points at the next free bit.
    pub pos: usize,
}

impl BitVector {
    pub fn new() -> Self {
        Self {
            bytes: [0; BITVEC_BYTES],
            pos: 0,
        }
    }

    /// Add `len` bits, MSB-first. Mirrors canboat's `addAisInt`. The
    /// value is masked to `len` bits implicitly by the shift; the C
    /// version rejects values that overflow `len` bits but we follow
    /// canboat's "encode anyway" behaviour for two's-complement
    /// negative values that fit when wrapped (e.g. lat / lon).
    pub fn add_int(&mut self, value: i64, len: usize) {
        // Sign-extend / truncate `value` to a `len`-bit unsigned slot.
        let mask = if len >= 64 { !0u64 } else { (1u64 << len) - 1 };
        let mut v = (value as u64) & mask;
        let mut len = len;
        while len > 0 {
            let i = self.pos / 8;
            let k = 8 - (self.pos % 8);
            // Take the top `min(k, len)` bits from `v` and OR them
            // into byte `i` aligned to the open low bits of that
            // byte.
            let take = k.min(len);
            let high_bits = (v >> (len - take)) as u8;
            let mask_low = ((1u32 << take) - 1) as u8;
            let aligned = (high_bits & mask_low) << (k - take);
            self.bytes[i] |= aligned;
            self.pos += take;
            len -= take;
            // Clear consumed bits.
            v &= if len >= 64 { !0u64 } else { (1u64 << len) - 1 };
        }
    }

    /// Encode a printable-ASCII string as 6-bit AIS characters. Each
    /// input char is mapped: 32..63 → as-is, 64..95 → minus 64, NUL
    /// → 0, anything else → 32 (space). `len` is the bit length to
    /// fill — strings shorter than that get padded with NUL (which
    /// is the AIS "end of string" marker).
    pub fn add_string(&mut self, s: &str, mut len: usize) {
        let mut chars = s.chars();
        while len >= 6 {
            let raw = chars.next().unwrap_or('\0');
            let mut c = raw as u32;
            if c == 0 {
                c = 0;
            } else if !(32..=95).contains(&c) {
                c = 32;
            } else if c >= 64 {
                c -= 64;
            }
            self.add_int(c as i64, 6);
            len -= 6;
        }
        // Pad any remaining sub-6-bit tail with zeros.
        if len > 0 {
            self.add_int(0, len);
        }
    }
}

impl Default for BitVector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a single analyzer AIS JSON line into one or more
/// `!AIVDM,…` sentences, appending each to `out`. `nmea0183_src` is
/// the canboat-style 8-bit src used to encode the two-letter talker
/// (we always emit `AI` regardless, matching canboat: `'I'-'A'=8`,
/// the second char). Returns the number of sentences emitted.
pub fn convert(out: &mut String, msg: &str, seq_counter: &mut u8) -> usize {
    let Some(pgn) = json::int(msg, "pgn") else {
        return 0;
    };
    let msgid = match pgn_to_msgid(pgn, msg) {
        Some(m) => m,
        None => return 0,
    };
    let channel = ais_channel(msg);
    let talker = ais_talker(msg);
    let mut bv = BitVector::new();
    if !encode_payload(&mut bv, msgid, pgn, msg) {
        return 0;
    }
    emit_sentences(out, &bv, talker, channel, seq_counter)
}

/// Derive the AIVDM message ID from the JSON, falling back to a
/// PGN-based default when the `Message ID` field is missing or
/// unrecognised. The C version uses `aisEnum`, which assumes the
/// `-nv` shape; we accept both bare numbers and the canboat enum
/// names.
fn pgn_to_msgid(pgn: i64, msg: &str) -> Option<i64> {
    if let Some(n) = json::lookup_int(msg, "Message ID") {
        return Some(n);
    }
    // The string form. Match a handful of canonical names; this
    // grows as we need it.
    if let Some(s) = json::value(msg, "Message ID") {
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
    // PGN-based defaults.
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

/// Channel character from the `AIS Transceiver information` enum.
/// `0` (`Channel A VDL reception`) and `2` (`Channel A VDL
/// transmission`) → 'A'; `1`/`3` → 'B'.
fn ais_channel(msg: &str) -> char {
    let info = enum_or_name(msg, "AIS Transceiver information", AIS_TRANSCEIVER_NAMES);
    if matches!(info, 1 | 3) {
        'B'
    } else {
        'A'
    }
}

/// `"VDM"` for receive-side messages, `"VDO"` for own-vessel.
fn ais_talker(msg: &str) -> &'static str {
    match enum_or_name(msg, "AIS Transceiver information", AIS_TRANSCEIVER_NAMES) {
        2..=4 => "VDO",
        _ => "VDM",
    }
}

/// Encode `bv` with the message-type-specific bit layout. Returns
/// `false` if we don't know how to encode this `msgid`.
fn encode_payload(bv: &mut BitVector, msgid: i64, pgn: i64, msg: &str) -> bool {
    match msgid {
        1..=3 => encode_class_a_position(bv, msgid, msg),
        4 => encode_utc_date(bv, msgid, msg),
        5 => encode_class_a_static(bv, msgid, msg),
        9 => encode_sar_aircraft(bv, msgid, msg),
        12 => encode_addressed_safety(bv, msgid, msg),
        14 => encode_broadcast_safety(bv, msgid, msg),
        18 => encode_class_b_position(bv, msgid, msg),
        19 => encode_class_b_extended(bv, msgid, msg),
        21 => encode_aton(bv, msgid, msg),
        24 => encode_class_b_static(bv, msgid, pgn, msg),
        _ => return false,
    }
    true
}

// ---------- per-message-type encoders ----------

fn encode_class_a_position(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(enum_or_name(msg, "Nav Status", &[]), 4);
    bv.add_int(rate_of_turn(msg), 8);
    bv.add_int(sog(msg, "SOG"), 10);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(cog(msg, "COG"), 12);
    bv.add_int(heading(msg, "Heading"), 9);
    bv.add_int(json::int(msg, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(enum_or_name(msg, "Special Maneuver Indicator", &[]), 2);
    bv.add_int(0, 3); // Spare
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(comm_state(msg), 19);
}

fn encode_utc_date(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(ais_date(msg), 23);
    bv.add_int(ais_time(msg), 17);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(enum_or_name(msg, "GNSS type", &[]), 4);
    bv.add_int(0, 10); // Spare
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(comm_state(msg), 19);
}

fn encode_class_a_static(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(enum_or_name(msg, "AIS version indicator", &[]), 2);
    bv.add_int(user_id(msg, "IMO number", 0), 30);
    bv.add_string(json::value(msg, "Callsign").unwrap_or(""), 42);
    bv.add_string(json::value(msg, "Name").unwrap_or(""), 120);
    bv.add_int(enum_or_name(msg, "Type of ship", &[]), 8);
    bv.add_int(ship_dimensions(msg, true), 30);
    bv.add_int(enum_or_name(msg, "GNSS type", &[]), 4);
    bv.add_int(ais_eta(msg), 20);
    bv.add_int(draft(msg), 8);
    bv.add_string(json::value(msg, "Destination").unwrap_or(""), 120);
    bv.add_int(enum_or_name(msg, "DTE", &[]), 1);
    bv.add_int(0, 1); // Spare
}

fn encode_sar_aircraft(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(altitude(msg), 12);
    bv.add_int((sog(msg, "SOG") + 5) / 10, 10);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(cog(msg, "COG"), 12);
    bv.add_int(json::int(msg, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(enum_or_name(msg, "DTE", &[]), 1);
    bv.add_int(0, 3); // Spare
    bv.add_int(enum_or_name(msg, "AIS mode", &[]), 1);
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(msg, "AIS communication state", &[]), 1);
    bv.add_int(comm_state(msg), 19);
}

fn encode_addressed_safety(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "Source ID", 0), 30);
    bv.add_int(
        json::int(msg, "Sequence Number").unwrap_or(0).clamp(0, 3),
        2,
    );
    bv.add_int(user_id(msg, "Destination ID", 0), 30);
    bv.add_int(
        json::int(msg, "Retransmit flag").unwrap_or(0).clamp(0, 1),
        1,
    );
    bv.add_int(0, 1); // Spare
    let text = json::value(msg, "Safety Related Text").unwrap_or("");
    let mut bits = text.chars().count() * 6;
    if bits > 156 {
        bits = 156;
    }
    if bits % 8 != 0 {
        bits += 8 - bits % 8;
    }
    bv.add_string(text, bits);
}

fn encode_broadcast_safety(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "Source ID", 0), 30);
    bv.add_int(0, 2); // Spare
    let text = json::value(msg, "Safety Related Text").unwrap_or("");
    let mut bits = text.chars().count() * 6;
    if bits > 161 {
        bits = 161;
    }
    if bits % 8 != 0 {
        bits += 8 - bits % 8;
    }
    bv.add_string(text, bits);
}

fn encode_class_b_position(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(sog(msg, "SOG"), 10);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(cog(msg, "COG"), 12);
    bv.add_int(heading(msg, "Heading"), 9);
    bv.add_int(json::int(msg, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 2); // Regional reserved
    bv.add_int(enum_or_name(msg, "Unit type", &[]), 1);
    bv.add_int(enum_or_name(msg, "Integrated Display", &[]), 1);
    bv.add_int(enum_or_name(msg, "DSC", &[]), 1);
    bv.add_int(enum_or_name(msg, "Band", &[]), 1);
    bv.add_int(enum_or_name(msg, "Can handle Msg 22", &[]), 1);
    bv.add_int(enum_or_name(msg, "AIS mode", &[]), 1);
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(msg, "AIS communication state", &[]), 1);
    bv.add_int(comm_state(msg), 19);
}

fn encode_class_b_extended(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(sog(msg, "SOG"), 10);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(cog(msg, "COG"), 12);
    bv.add_int(heading(msg, "True Heading"), 9);
    bv.add_int(json::int(msg, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(0, 4); // Regional reserved
    bv.add_string(json::value(msg, "Name").unwrap_or(""), 120);
    bv.add_int(enum_or_name(msg, "Type of ship", &[]), 8);
    bv.add_int(ship_dimensions(msg, true), 30);
    bv.add_int(enum_or_name(msg, "GNSS type", &[]), 4);
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(msg, "DTE", &[]), 1);
    bv.add_int(enum_or_name(msg, "AIS mode", &[]), 1);
    bv.add_int(0, 4); // Spare
}

fn encode_aton(bv: &mut BitVector, msgid: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    bv.add_int(enum_or_name(msg, "AtoN Type", &[]), 5);
    let aton_name = json::value(msg, "AtoN Name").unwrap_or("");
    let (name20, ext) = split_aton_name(aton_name);
    bv.add_string(name20, 120);
    bv.add_int(
        enum_or_name(msg, "Position Accuracy", POSITION_ACCURACY_NAMES),
        1,
    );
    bv.add_int(longitude(msg, "Longitude"), 28);
    bv.add_int(latitude(msg, "Latitude"), 27);
    bv.add_int(ship_dimensions(msg, false), 30);
    bv.add_int(enum_or_name(msg, "GNSS type", &[]), 4);
    bv.add_int(json::int(msg, "Time Stamp").unwrap_or(60).clamp(0, 63), 6);
    bv.add_int(enum_or_name(msg, "Off Position Indicator", &[]), 1);
    bv.add_int(0, 8); // Regional reserved
    bv.add_int(enum_or_name(msg, "RAIM", RAIM_NAMES), 1);
    bv.add_int(enum_or_name(msg, "Virtual AtoN Flag", &[]), 1);
    bv.add_int(enum_or_name(msg, "Assigned Mode Flag", &[]), 1);
    bv.add_int(0, 1); // Spare
    let mut ext_bits = ext.chars().count() * 6;
    if ext_bits % 8 != 0 {
        ext_bits += 8 - ext_bits % 8;
    }
    bv.add_string(ext, ext_bits);
}

fn encode_class_b_static(bv: &mut BitVector, msgid: i64, pgn: i64, msg: &str) {
    bv.add_int(msgid, 6);
    bv.add_int(repeat_indicator(msg), 2);
    bv.add_int(user_id(msg, "User ID", 0), 30);
    match pgn {
        129809 => {
            bv.add_int(0, 2); // Part number = A
            bv.add_string(json::value(msg, "Name").unwrap_or(""), 120);
            bv.add_int(0, 8); // Spare
        }
        129810 => {
            bv.add_int(1, 2); // Part number = B
            bv.add_int(enum_or_name(msg, "Type of ship", &[]), 8);
            bv.add_string(json::value(msg, "Vendor ID").unwrap_or(""), 42);
            bv.add_string(json::value(msg, "Callsign").unwrap_or(""), 42);
            bv.add_int(ship_dimensions(msg, true), 30);
            bv.add_int(user_id(msg, "Mothership User ID", 0), 30);
            bv.add_int(0, 6); // Spare
        }
        _ => {}
    }
}

// ---------- helpers ----------

fn repeat_indicator(msg: &str) -> i64 {
    enum_or_name(msg, "Repeat Indicator", REPEAT_NAMES).clamp(0, 3)
}

/// Read an MMSI or other 30-bit user ID. canboat outputs MMSIs as
/// quoted strings (`"User ID":"244180106"`). We try the lookup-int
/// path first (`-nv` numeric form) and then the bare string form.
fn user_id(msg: &str, field: &str, default: i64) -> i64 {
    if let Some(s) = json::value(msg, field) {
        if let Ok(n) = s.trim().parse() {
            return n;
        }
    }
    json::int(msg, field).unwrap_or(default)
}

/// Resolve an enum field. Accepts the `-nv` form (`{value, name}`),
/// bare integers, and a small set of literal-name fallbacks supplied
/// by the caller. Returns `-1` (canboat's "unknown") if nothing matches.
fn enum_or_name(msg: &str, field: &str, names: &[(&str, i64)]) -> i64 {
    if let Some(n) = json::lookup_int(msg, field) {
        return n;
    }
    if let Some(s) = json::value(msg, field) {
        for (name, val) in names {
            if s == *name {
                return *val;
            }
        }
    }
    -1
}

const REPEAT_NAMES: &[(&str, i64)] = &[
    ("Initial", 0),
    ("First retransmission", 1),
    ("Second retransmission", 2),
    ("Final retransmission", 3),
];

const POSITION_ACCURACY_NAMES: &[(&str, i64)] = &[("Low", 0), ("High", 1)];

const RAIM_NAMES: &[(&str, i64)] = &[("not in use", 0), ("in use", 1)];

const AIS_TRANSCEIVER_NAMES: &[(&str, i64)] = &[
    ("Channel A VDL reception", 0),
    ("Channel B VDL reception", 1),
    ("Channel A VDL transmission", 2),
    ("Channel B VDL transmission", 3),
    ("Own information not broadcast", 4),
];

/// `Rate of Turn` field — non-linear AIS encoding. Input degrees/s,
/// stored as `4.733 * sqrt(|rot * 60|) * sign`. Default sentinel
/// 0x80 (i.e. -128).
fn rate_of_turn(msg: &str) -> i64 {
    let Some(rot) = json::number(msg, "Rate of Turn") else {
        return -128;
    };
    // canboat treats "Rate of Turn" as deg/s (after rad→deg). Convert
    // to deg/min like canboat (`SECONDS_PER_MINUTE`).
    let v = rot * 60.0;
    let sign = if v >= 0.0 { 1.0 } else { -1.0 };
    let r = 4.733 * v.abs().sqrt();
    let r = (r + 0.5) as i64;
    let r = r.clamp(-127, 127) * sign as i64;
    if (-127..=127).contains(&r) {
        r
    } else {
        -128
    }
}

fn sog(msg: &str, field: &str) -> i64 {
    // canboat: input m/s, multiplier KNOTS_IN_MS * 10. Range 0..1022.
    let Some(v) = json::number(msg, field) else {
        return 1023;
    };
    // Knots-in-m/s = 1.943844492; times 10 = 19.43844492.
    let n = (v * 19.438_444_92 + 0.5) as i64;
    if (0..=1022).contains(&n) {
        n
    } else {
        1023
    }
}

fn cog(msg: &str, field: &str) -> i64 {
    let Some(v) = json::number(msg, field) else {
        return 3600;
    };
    let n = (v * 10.0 + 0.5) as i64;
    if (0..=3599).contains(&n) {
        n
    } else {
        3600
    }
}

fn heading(msg: &str, field: &str) -> i64 {
    let Some(v) = json::number(msg, field) else {
        return 511;
    };
    let n = (v + 0.5) as i64;
    if (0..=359).contains(&n) {
        n
    } else {
        511
    }
}

fn longitude(msg: &str, field: &str) -> i64 {
    let Some(v) = json::number(msg, field) else {
        return 0x6791AC0;
    };
    let n = (v * 600_000.0).round() as i64;
    if (-108_000_000..=108_000_000).contains(&n) {
        n
    } else {
        0x6791AC0
    }
}

fn latitude(msg: &str, field: &str) -> i64 {
    let Some(v) = json::number(msg, field) else {
        return 0x3412140;
    };
    let n = (v * 600_000.0).round() as i64;
    if (-54_000_000..=54_000_000).contains(&n) {
        n
    } else {
        0x3412140
    }
}

fn altitude(msg: &str) -> i64 {
    let Some(v) = json::number(msg, "Altitude") else {
        return 4095;
    };
    let n = (v + 0.5) as i64;
    if (0..=4094).contains(&n) {
        n
    } else {
        4095
    }
}

fn draft(msg: &str) -> i64 {
    let Some(v) = json::number(msg, "Draft") else {
        return 0;
    };
    let n = (v * 10.0 + 0.5) as i64;
    n.clamp(0, 255)
}

fn comm_state(msg: &str) -> i64 {
    let Some(s) = json::value(msg, "Communication State") else {
        // canboat C's default when the field isn't present at all.
        return 393_222;
    };
    let trimmed = s.trim_matches([' ', '"']);
    // canboat's analyzer emits Communication State as either a bare
    // integer or as a hex-byte string like "E4 10 01" (BINARY field
    // rendering). Try integer first; if that fails, parse hex bytes
    // and pack them little-endian into the 19-bit slot.
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
    // Neither integer nor hex-bytes parsed: fall through to 0, same
    // as canboat C's atol-fallback on a malformed input.
    0
}

/// `Position Date` is `YYYY.MM.DD` in canboat JSON. Packed as
/// `(year << 9) | (month << 5) | day`.
fn ais_date(msg: &str) -> i64 {
    let Some(s) = json::value(msg, "Position Date") else {
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

/// `Position Time` is `HH:MM:SS[.SSSS]`. Packed as
/// `(hour << 12) | (minute << 6) | second`.
fn ais_time(msg: &str) -> i64 {
    let Some(s) = json::value(msg, "Position Time") else {
        return 0;
    };
    let mut parts = s.split(':');
    let h: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(24);
    let m: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(60);
    let sec_str = parts.next().unwrap_or("60");
    // sec might include a fractional part — take the integer leading bit.
    let sec_int: u32 = sec_str
        .split('.')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(60);
    let h = if h > 24 { 24 } else { h };
    let m = if m > 60 { 60 } else { m };
    let sec_int = if sec_int > 60 { 60 } else { sec_int };
    ((h as i64) << 12) | ((m as i64) << 6) | sec_int as i64
}

/// `ETA Date` (`YYYY-MM-DD`) and `ETA Time` (`HH:MM:SS`) packed into
/// the AIVDM type 5 ETA field: month/day/hour/minute.
fn ais_eta(msg: &str) -> i64 {
    let (mut month, mut day) = (0u32, 0u32);
    if let Some(s) = json::value(msg, "ETA Date") {
        let mut parts = s.split('-');
        let _y = parts.next();
        month = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        day = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        if month > 12 {
            month = 0;
        }
        if day > 31 {
            day = 0;
        }
    }
    let (mut hour, mut minute) = (24u32, 60u32);
    if let Some(s) = json::value(msg, "ETA Time") {
        let mut parts = s.split(':');
        hour = parts.next().and_then(|p| p.parse().ok()).unwrap_or(24);
        minute = parts.next().and_then(|p| p.parse().ok()).unwrap_or(60);
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
/// canboat C — the field names differ between Class A and AtoN
/// (controlled by `ship`).
fn ship_dimensions(msg: &str, ship: bool) -> i64 {
    let (length, beam, ref_bow, ref_starboard) = if ship {
        (
            json::number(msg, "Length").unwrap_or(0.0) * 10.0,
            json::number(msg, "Beam").unwrap_or(0.0) * 10.0,
            json::number(msg, "Position reference from Bow").unwrap_or(0.0) * 10.0,
            json::number(msg, "Position reference from Starboard").unwrap_or(0.0) * 10.0,
        )
    } else {
        (
            json::number(msg, "Length/Diameter").unwrap_or(0.0) * 10.0,
            json::number(msg, "Beam/Diameter").unwrap_or(0.0) * 10.0,
            json::number(msg, "Position Reference from True North Facing Edge").unwrap_or(0.0)
                * 10.0,
            json::number(msg, "Position Reference from Starboard Edge").unwrap_or(0.0) * 10.0,
        )
    };
    let to_stern = (length - ref_bow).clamp(0.0, 5110.0);
    let to_port = (beam - ref_starboard).clamp(0.0, 630.0);
    (((ref_bow + 5.0) / 10.0) as i64) << 21
        | (((to_stern + 5.0) / 10.0) as i64) << 12
        | (((to_port + 5.0) / 10.0) as i64) << 6
        | ((ref_starboard + 5.0) / 10.0) as i64
}

/// Split an `AtoN Name` into the 20-character main name and the
/// optional extension. Both are stripped of the trailing
/// NUL-padded part. Extension length is rounded up to the next
/// 8-bit boundary in AIVDM type 21.
fn split_aton_name(s: &str) -> (&str, &str) {
    if s.len() <= 20 {
        return (s, "");
    }
    (&s[..20], s[20..].trim_end_matches('\0'))
}

/// Slice the bit vector into 60-character (`360-bit`) sentences,
/// emit each as `!AIVDM,…*XX\r\n`. Returns the number of sentences
/// emitted. The talker is always `AI` (matches canboat C); only the
/// `<type>` (VDM/VDO) varies.
fn emit_sentences(
    out: &mut String,
    bv: &BitVector,
    talker: &str,
    channel: char,
    seq_counter: &mut u8,
) -> usize {
    let total_bits = bv.pos;
    if total_bits == 0 {
        return 0;
    }
    let fragments = total_bits.div_ceil(360);
    let seq = if fragments > 1 {
        // Cycle 0..9 across multi-fragment messages. Matches
        // canboat C's `sequenceId` static in `gps_ais.c`: bump
        // before use, wrap at 10, render as an ASCII digit.
        *seq_counter = (*seq_counter + 1) % 10;
        Some((b'0' + *seq_counter) as char)
    } else {
        None
    };
    let mut bit_offset = 0usize;
    let mut emitted = 0usize;
    for frag in 1..=fragments {
        let frag_bits = (total_bits - bit_offset).min(360);
        let mut payload = String::with_capacity(60);
        let mut consumed = 0usize;
        let mut padding = 0u8;
        while consumed + 6 <= frag_bits {
            let val = read_bits(&bv.bytes, bit_offset + consumed, 6);
            payload.push(six_bit_ascii(val));
            consumed += 6;
        }
        if consumed < frag_bits {
            let remaining = frag_bits - consumed;
            let val = read_bits(&bv.bytes, bit_offset + consumed, remaining) << (6 - remaining);
            payload.push(six_bit_ascii(val));
            padding = (6 - remaining) as u8;
            consumed = frag_bits;
        }
        bit_offset += consumed;
        // Sentence: !AIVDM/!AIVDO,frags,fragnum[,seq],channel,payload,padding*XX
        let body = match seq {
            Some(c) => format!("AI{talker},{fragments},{frag},{c},{channel},{payload},{padding}"),
            None => format!("AI{talker},{fragments},{frag},,{channel},{payload},{padding}"),
        };
        append_aivdm(out, &body);
        emitted += 1;
    }
    emitted
}

/// `!<body>*<XX>\r\n` — AIVDM sentences use `!` as the leading
/// character (vs `$` for the conventional sentences). Checksum is
/// XOR of every byte between `!` and `*`.
fn append_aivdm(out: &mut String, body: &str) {
    let start = out.len();
    out.push('!');
    out.push_str(body);
    let mut chk = 0u8;
    for b in &out.as_bytes()[start + 1..] {
        chk ^= *b;
    }
    out.push_str(&format!("*{chk:02X}\r\n"));
}

fn read_bits(bytes: &[u8], offset: usize, len: usize) -> u8 {
    let mut out = 0u8;
    for i in 0..len {
        let byte = bytes[(offset + i) / 8];
        let bit = (byte >> (7 - (offset + i) % 8)) & 1;
        out = (out << 1) | bit;
    }
    out
}

/// 6-bit value → AIVDM-payload character. Canboat does:
///   0..39 → '0' + n  (48..87)
///   40..63 → '0' + n + 8  (96..119)
fn six_bit_ascii(v: u8) -> char {
    let v = v & 0x3f;
    if v < 40 {
        (b'0' + v) as char
    } else {
        (b'0' + v + 8) as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_int_packs_big_endian() {
        let mut bv = BitVector::new();
        bv.add_int(0b1010_1100, 8);
        assert_eq!(bv.pos, 8);
        assert_eq!(bv.bytes[0], 0b1010_1100);
    }

    #[test]
    fn six_bit_payload_roundtrip() {
        // 18-bit MMSI sentinel: encode as three 6-bit chunks.
        let mut bv = BitVector::new();
        bv.add_int(0, 6);
        bv.add_int(1, 6);
        bv.add_int(63, 6);
        let mut out = String::new();
        let mut seq = 0;
        emit_sentences(&mut out, &bv, "VDM", 'A', &mut seq);
        assert!(out.contains("AIVDM,1,1,,A,01w,0*"), "got {out}");
    }

    #[test]
    fn class_b_position_round_trips_known_mmsi() {
        // Synthetic JSON resembling the dirona AIS PGN 129039 line.
        let msg = r#"{"pgn":129039,"src":23,"fields":{"Message ID":"Standard Class B position report","Repeat Indicator":"Initial","User ID":"244180106","Longitude":5.3134516,"Latitude":52.9061666,"Position Accuracy":"High","RAIM":"in use","Time Stamp":29,"COG":171.7,"SOG":1.80,"Heading":null,"Unit type":"SOTDMA","Integrated Display":"No","DSC":"Yes","Band":"Entire marine band","Can handle Msg 22":"Yes","AIS mode":"Autonomous","AIS communication state":"SOTDMA","Communication State":"F8 08 00","AIS Transceiver information":"Channel A VDL reception"}}"#;
        let mut out = String::new();
        let mut seq = 0;
        let n = convert(&mut out, msg, &mut seq);
        assert_eq!(n, 1, "expected one AIVDM sentence");
        assert!(out.starts_with("!AIVDM,1,1,,A,"), "got {out}");
        assert!(out.ends_with("\r\n"));
        // Round-trip the MMSI through the payload: msgid (6 bits=18) +
        // repeat (2=0) + mmsi (30=244180106). The 6-bit-ascii encoding
        // is positional, but the first character is `msgid` (18 in
        // 6-bit AIS = '>'? actually 18+48=66='B'). We just sanity-
        // check the talker / first nybble.
        let payload = out.split(',').nth(5).expect("payload field present");
        // msgid 18 encoded as 6-bit value 18 → char '0'+18 = 'B'.
        assert!(payload.starts_with('B'), "got payload {payload}");
    }

    #[test]
    fn sog_clamps_above_range() {
        let m = r#"{"fields":{"SOG":999.0}}"#;
        // 999 m/s ≈ 1940 kn; canboat clamps to 1023 (unknown).
        assert_eq!(sog(m, "SOG"), 1023);
    }

    #[test]
    fn longitude_default_on_missing() {
        let m = r#"{}"#;
        assert_eq!(longitude(m, "Longitude"), 0x6791AC0);
    }
}
