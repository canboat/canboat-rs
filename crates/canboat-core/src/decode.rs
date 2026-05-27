//! Decode a `RawFrame` into a structured `DecodedPgn`.
//!
//! The decoder looks the frame's PGN up in the database, picks the
//! matching variant (manufacturer-specific PGNs disambiguated by
//! `Match` field values), and walks each field, extracting raw bits
//! and applying scaling, units, and lookup-table resolution.
//!
//! No I/O. No formatting — the result is a structured event ready for
//! the output formatter or for direct consumption by merrimac-rs.

use crate::bits::{extract_bits, is_unavailable, Extracted};
use crate::db::PgnDatabase;
use crate::frame::RawFrame;
use crate::types::{FieldInfo, FieldType, PgnInfo};

/// canboat-style "not available" check with the RangeMax exception:
/// if the field's explicit `RangeMax` (after applying resolution) equals
/// the bit-width max, the entire range is valid and no sentinel
/// stripping is performed. Matches the threshold logic in
/// `analyzer/print.c:418`.
fn unavailable_with_range(f: &FieldInfo, ex: Extracted) -> bool {
    if let (Some(rmax), Some(res)) = (f.range_max, f.resolution) {
        if res > 0.0 {
            let range_max_raw = (rmax / res + 0.5) as i64;
            if range_max_raw == ex.max {
                return false;
            }
        }
    }
    is_unavailable(ex)
}

/// One decoded field.
#[derive(Debug, Clone)]
pub struct DecodedField {
    pub order: u8,
    pub id: String,
    pub name: String,
    pub unit: Option<String>,
    /// Resolution as carried in canboat.json. The formatter uses this
    /// to pick a sensible number of decimal digits.
    pub resolution: Option<f64>,
    /// Zero-based iteration index for fields inside a repeating set;
    /// `None` for non-repeating fields.
    pub repeat_index: Option<u32>,
    /// True if this field participates in the PGN's primary key. The
    /// JSON formatter under `-nv` annotates these with `"key":true`.
    pub part_of_primary_key: bool,
    pub value: FieldValue,
}

/// The decoded value of one field.
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// Scaled numeric value (`resolution * raw + offset`).
    Number(f64),
    /// Unscaled integer (used for fields with `resolution == 1` and no
    /// unit — counts, instances, etc.).
    Integer(i64),
    /// IEEE 754 float decoded from 32 raw bits.
    Float(f64),
    /// Raw bytes (BINARY) — uninterpreted.
    Binary(Vec<u8>),
    /// LOOKUP / INDIRECT_LOOKUP result.
    Lookup { value: u64, name: Option<String> },
    /// BITLOOKUP result — set-bit list.
    BitField { value: u64, names: Vec<String> },
    /// Decoded text (STRING_FIX, STRING_LZ, STRING_LAU).
    String(String),
    /// 16-bit days since 1970-01-01.
    Date(u16),
    /// Seconds since midnight (post-resolution scaling).
    Time(f64),
    /// MMSI as a 9-digit identifier.
    Mmsi(u32),
    /// 24-bit PGN number.
    Pgn(u32),
    /// ISO_NAME — a 64-bit packed identifier that is also a valid
    /// PGN 60928 (ISO Address Claim) payload. We carry the raw value
    /// and the recursively-decoded subfields side by side so the
    /// formatter can choose either form.
    IsoName {
        value: u64,
        subfields: Vec<DecodedField>,
    },
    /// RESERVED / SPARE — value preserved but the field is meaningless.
    /// The raw bytes (in field order, no resolution) ride along so the
    /// JSON formatter can emit them as hex strings, matching canboat.
    Reserved {
        value: u64,
        bytes: Vec<u8>,
        bit_length: u32,
    },
    Spare {
        value: u64,
        bytes: Vec<u8>,
        bit_length: u32,
    },
    /// Field exists but raw value is the canboat "not-available" sentinel.
    NotAvailable,
    /// Field decoding not yet implemented for this `FieldType`.
    Unsupported { field_type: &'static str },
}

/// A fully decoded PGN event.
#[derive(Debug, Clone)]
pub struct DecodedPgn {
    pub timestamp: Option<String>,
    pub prio: u8,
    pub pgn: u32,
    pub src: u8,
    pub dst: u8,
    pub description: String,
    /// canboat.json `Id` — stable camelCase identifier.
    pub id: String,
    pub fields: Vec<DecodedField>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("PGN {pgn} not found in database")]
    UnknownPgn { pgn: u32 },
    #[error("PGN {pgn} payload too short for field {field:?}")]
    ShortPayload { pgn: u32, field: String },
}

impl PgnDatabase {
    /// Decode one frame.
    ///
    /// Picks the matching PGN variant (via `Match` field values) and
    /// walks every field. For unknown PGNs returns
    /// `DecodeError::UnknownPgn`.
    pub fn decode(&self, frame: &RawFrame) -> Result<DecodedPgn, DecodeError> {
        let info = self
            .pick_variant(frame)
            .ok_or(DecodeError::UnknownPgn { pgn: frame.pgn })?;

        let fields = decode_fields(info, &frame.data, self)?;

        Ok(DecodedPgn {
            timestamp: frame.timestamp.clone(),
            prio: frame.prio,
            pgn: frame.pgn,
            src: frame.src,
            dst: frame.dst,
            description: info.description.clone(),
            id: info.id.clone(),
            fields,
        })
    }

    /// Choose the best PGN definition for a frame.
    ///
    /// Priority — strict canboat semantics:
    ///
    ///   1. **JSON-order scan of variants for this PGN number.** Return
    ///      the first variant whose every `Match` field equals the raw
    ///      bits at that field's offset. JSON insertion order encodes
    ///      author-defined priority; an earlier matching specific
    ///      variant always beats a later one, and a matching specific
    ///      variant always beats the per-PGN-number fallback even when
    ///      the fallback is listed first (as in PGN 126208 etc).
    ///
    ///   2. **In-PGN fallback.** If no specific variant matched, return
    ///      the `Fallback: true` variant for this PGN number, if any.
    ///      Falls back further to any no-`Match` variant — though in
    ///      canboat.json those two are the same entry.
    ///
    ///   3. **Inter-PGN fallback.** If the PGN number itself is not in
    ///      the database, return the largest `Fallback: true` entry
    ///      whose PGN number is `<= frame.pgn`. This is the catch-all
    ///      that covers the range — e.g. unknown PGNs in
    ///      `[0x1ef00, 0x1ef00]` get
    ///      `0x1ef00ManufacturerProprietaryFastPacketAddressed`.
    pub fn pick_variant(&self, frame: &RawFrame) -> Option<&PgnInfo> {
        let mut in_pgn_fallback: Option<&PgnInfo> = None;
        let mut saw_variant = false;
        for info in self.pgn_variants(frame.pgn) {
            saw_variant = true;
            let mut has_match = false;
            let mut all_ok = true;
            for f in &info.fields {
                let Some(expected) = f.match_value else {
                    continue;
                };
                has_match = true;
                let Some(bit_offset) = f.bit_offset else {
                    all_ok = false;
                    break;
                };
                let Some(bit_length) = f.bit_length else {
                    all_ok = false;
                    break;
                };
                match extract_bits(
                    &frame.data,
                    bit_offset as usize,
                    bit_length as usize,
                    f.signed.unwrap_or(false),
                    f.offset.unwrap_or(0),
                ) {
                    Some(ex) if ex.value == expected => {}
                    _ => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if has_match && all_ok {
                return Some(info);
            }
            // Record the in-PGN fallback. Prefer an explicit
            // `Fallback: true` over a happenstance no-Match variant if
            // both exist; otherwise take the first no-Match variant
            // (canboat keeps at most one no-Match variant per PGN, and
            // it carries the Fallback flag).
            if !has_match && (info.fallback.unwrap_or(false) || in_pgn_fallback.is_none()) {
                in_pgn_fallback = Some(info);
            }
        }
        if let Some(v) = in_pgn_fallback {
            return Some(v);
        }
        if !saw_variant {
            return self.find_catchall(frame.pgn);
        }
        None
    }

    /// Inter-PGN catch-all: the latest `Fallback: true` definition
    /// whose PGN number is `<= pgn`. PGN numbers in canboat.json are
    /// non-decreasing, so a linear scan finds the right one in JSON
    /// order. Called only when no entry for `pgn` exists at all.
    fn find_catchall(&self, pgn: u32) -> Option<&PgnInfo> {
        let mut best: Option<&PgnInfo> = None;
        for info in self.pgns() {
            if info.pgn > pgn {
                break;
            }
            if info.fallback.unwrap_or(false) {
                best = Some(info);
            }
        }
        best
    }
}

/// Walk a PGN's fields, decoding each in turn.
///
/// v0 does not yet handle repeating field sets — those fields decode
/// once as if non-repeating, with `repeat_index = None`. Will be added
/// when the analyzer's golden tests need it.
fn decode_fields(
    info: &PgnInfo,
    data: &[u8],
    db: &PgnDatabase,
) -> Result<Vec<DecodedField>, DecodeError> {
    let mut out = Vec::with_capacity(info.fields.len());
    for f in &info.fields {
        // Skip conditional alternative fields (`Condition`) for v0 —
        // they need cross-field state evaluation.
        if f.condition.is_some() {
            continue;
        }
        if let Some(decoded) = decode_one_field(f, info, data, db) {
            out.push(decoded);
        }
    }
    Ok(out)
}

fn decode_one_field(
    f: &FieldInfo,
    info: &PgnInfo,
    data: &[u8],
    db: &PgnDatabase,
) -> Option<DecodedField> {
    let bit_offset = f.bit_offset?;
    let bit_length = f.bit_length?;
    let signed = f.signed.unwrap_or(false);
    let offset_k = f.offset.unwrap_or(0);

    let value = match f.field_type {
        Some(FieldType::Number) | Some(FieldType::Decimal) => {
            decode_number(f, data, bit_offset, bit_length, signed, offset_k)
        }
        Some(FieldType::Float) => decode_float(data, bit_offset, bit_length),
        Some(FieldType::Lookup) => decode_lookup(f, data, bit_offset, bit_length, db),
        Some(FieldType::IndirectLookup) => {
            decode_indirect_lookup(f, info, data, bit_offset, bit_length, db)
        }
        Some(FieldType::BitLookup) => decode_bitlookup(f, data, bit_offset, bit_length, db),
        Some(FieldType::Reserved) => {
            decode_reserved(data, bit_offset, bit_length, signed, offset_k, true)
        }
        Some(FieldType::Spare) => {
            decode_reserved(data, bit_offset, bit_length, signed, offset_k, false)
        }
        Some(FieldType::Binary) => decode_binary(data, bit_offset, bit_length),
        Some(FieldType::Mmsi) => decode_mmsi(data, bit_offset, bit_length),
        Some(FieldType::Pgn) => decode_pgn_field(data, bit_offset, bit_length),
        Some(FieldType::Date) => decode_date(data, bit_offset, bit_length),
        Some(FieldType::Time) | Some(FieldType::Duration) => {
            decode_time(f, data, bit_offset, bit_length, signed)
        }
        Some(FieldType::StringFix) => decode_string_fix(data, bit_offset, bit_length),
        Some(FieldType::StringLz) => decode_string_lz(data, bit_offset, bit_length),
        Some(FieldType::StringLau) => FieldValue::Unsupported {
            field_type: "STRING_LAU",
        },
        Some(FieldType::Variable) => FieldValue::Unsupported {
            field_type: "VARIABLE",
        },
        Some(FieldType::IsoName) => decode_iso_name(data, bit_offset, bit_length, db),
        Some(FieldType::DynamicFieldKey) => FieldValue::Unsupported {
            field_type: "DYNAMIC_FIELD_KEY",
        },
        Some(FieldType::DynamicFieldLength) => FieldValue::Unsupported {
            field_type: "DYNAMIC_FIELD_LENGTH",
        },
        Some(FieldType::DynamicFieldValue) => FieldValue::Unsupported {
            field_type: "DYNAMIC_FIELD_VALUE",
        },
        Some(FieldType::FieldIndex) => decode_number(f, data, bit_offset, bit_length, signed, 0),
        None => FieldValue::Unsupported {
            field_type: "<no field type>",
        },
    };

    Some(DecodedField {
        order: f.order,
        id: f.id.clone(),
        name: f.name.clone(),
        unit: f.unit.clone(),
        resolution: f.resolution,
        repeat_index: None,
        part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
        value,
    })
}

fn decode_number(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
    offset_k: i64,
) -> FieldValue {
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        signed,
        offset_k,
    ) else {
        return FieldValue::NotAvailable;
    };
    if unavailable_with_range(f, ex) {
        return FieldValue::NotAvailable;
    }
    let resolution = f.resolution.unwrap_or(1.0);
    let unit = f.unit.as_deref();
    if resolution == 1.0 && unit.is_none() && f.physical_quantity.is_none() {
        FieldValue::Integer(ex.value)
    } else {
        FieldValue::Number(ex.value as f64 * resolution)
    }
}

fn decode_float(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 32 {
        return FieldValue::Unsupported {
            field_type: "FLOAT (non-32-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 32, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let bits = ex.value as u32;
    FieldValue::Float(f32::from_bits(bits) as f64)
}

fn decode_lookup(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    // canboat allows reserved sentinels in some lookup tables, so don't
    // pre-filter via is_unavailable here — emit the raw value and let
    // the formatter decide.
    let raw = ex.value as u64;
    let name = f
        .lookup_enumeration
        .as_deref()
        .and_then(|n| db.lookup(n))
        .and_then(|t| t.values.iter().find(|v| v.value == raw))
        .map(|v| v.name.clone());
    FieldValue::Lookup { value: raw, name }
}

/// INDIRECT_LOOKUP: resolve `(value1, value2)` where `value1` is
/// pulled from another field within the same PGN, identified by
/// `LookupIndirectEnumerationFieldOrder`.
fn decode_indirect_lookup(
    f: &FieldInfo,
    info: &PgnInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    let name = (|| -> Option<String> {
        let table_name = f.lookup_indirect_enumeration.as_deref()?;
        let val1_order = f.lookup_indirect_enumeration_field_order?;
        let val1_field = info.fields.iter().find(|x| x.order == val1_order)?;
        let val1_off = val1_field.bit_offset?;
        let val1_len = val1_field.bit_length?;
        let val1 = extract_bits(data, val1_off as usize, val1_len as usize, false, 0)?;
        let resolved = db.indirect_lookup(table_name, val1.value as u64, raw)?;
        Some(resolved.to_string())
    })();
    FieldValue::Lookup { value: raw, name }
}

fn decode_bitlookup(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    let mut names = Vec::new();
    if let Some(t) = f
        .lookup_bit_enumeration
        .as_deref()
        .and_then(|n| db.bit_lookup(n))
    {
        for v in &t.values {
            if raw & (1u64 << v.bit) != 0 {
                names.push(v.name.clone());
            }
        }
    }
    FieldValue::BitField { value: raw, names }
}

fn decode_reserved(
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
    offset_k: i64,
    is_reserved: bool,
) -> FieldValue {
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        signed,
        offset_k,
    ) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    // Pack just the field's value into bytes (little-endian), one byte
    // per `ceil(bit_length / 8)`. This avoids leaking neighboring
    // fields' bits when the reserved span shares a byte with adjacent
    // payload (which slicing `data[start..end]` would do).
    let n_bytes = bit_length.div_ceil(8).max(1) as usize;
    let mut bytes = Vec::with_capacity(n_bytes);
    for i in 0..n_bytes {
        bytes.push(((raw >> (i * 8)) & 0xff) as u8);
    }
    if is_reserved {
        FieldValue::Reserved {
            value: raw,
            bytes,
            bit_length,
        }
    } else {
        FieldValue::Spare {
            value: raw,
            bytes,
            bit_length,
        }
    }
}

/// ISO_NAME: 64-bit packed identifier. The same 8 bytes also form a
/// valid PGN 60928 (ISO Address Claim) payload, so the structured form
/// is built by re-running the decoder against PGN 60928's field list
/// on those 8 bytes — matching `fieldPrintName` in `analyzer/print.c`.
fn decode_iso_name(data: &[u8], bit_offset: u32, bit_length: u32, db: &PgnDatabase) -> FieldValue {
    if bit_length != 64 || (bit_offset & 7) != 0 {
        return FieldValue::Unsupported {
            field_type: "ISO_NAME (unaligned or non-64-bit)",
        };
    }
    let byte_off = (bit_offset / 8) as usize;
    if byte_off + 8 > data.len() {
        return FieldValue::NotAvailable;
    }
    let mut value: u64 = 0;
    for i in 0..8 {
        value |= (data[byte_off + i] as u64) << (i * 8);
    }
    let sub = &data[byte_off..byte_off + 8];
    let subfields = match db.first_pgn(60928) {
        Some(pgn) => decode_fields(pgn, sub, db).unwrap_or_default(),
        None => Vec::new(),
    };
    FieldValue::IsoName { value, subfields }
}

fn decode_binary(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bit_offset = bit_offset as usize;
    let bit_length = bit_length as usize;
    // Whole-byte aligned: take a clean slice.
    if bit_offset & 7 == 0 && bit_length & 7 == 0 {
        let start = bit_offset / 8;
        let end = start + bit_length / 8;
        if end > data.len() {
            return FieldValue::NotAvailable;
        }
        return FieldValue::Binary(data[start..end].to_vec());
    }
    // Bit-aligned binary: pack into bytes LSB-first to keep round-trip
    // semantics with extract_bits.
    let bytes = bit_length.div_ceil(8);
    let mut out = vec![0u8; bytes];
    let mut bo = bit_offset;
    let mut remaining = bit_length;
    let mut byte_i = 0usize;
    while remaining > 0 {
        let chunk = remaining.min(8);
        let Some(ex) = extract_bits(data, bo, chunk, false, 0) else {
            return FieldValue::NotAvailable;
        };
        out[byte_i] = ex.value as u8;
        byte_i += 1;
        bo += chunk;
        remaining -= chunk;
    }
    FieldValue::Binary(out)
}

fn decode_mmsi(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 32 {
        return FieldValue::Unsupported {
            field_type: "MMSI (non-32-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 32, false, 0) else {
        return FieldValue::NotAvailable;
    };
    if is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    FieldValue::Mmsi(ex.value as u32)
}

fn decode_pgn_field(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 24 {
        return FieldValue::Unsupported {
            field_type: "PGN (non-24-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 24, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u32;
    // PDU1 (PF < 240): low byte of the PGN is the destination address,
    // so it's masked out. PDU2: low byte is the PS and part of the PGN.
    let pf = (raw >> 8) & 0xff;
    let pgn = if pf < 240 {
        raw & 0x00ff_ff00
    } else {
        raw & 0x00ff_ffff
    };
    FieldValue::Pgn(pgn)
}

fn decode_date(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 16 {
        return FieldValue::Unsupported {
            field_type: "DATE (non-16-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 16, false, 0) else {
        return FieldValue::NotAvailable;
    };
    if ex.value == 0xffff {
        return FieldValue::NotAvailable;
    }
    FieldValue::Date(ex.value as u16)
}

fn decode_time(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
) -> FieldValue {
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        signed,
        f.offset.unwrap_or(0),
    ) else {
        return FieldValue::NotAvailable;
    };
    if is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    let resolution = f.resolution.unwrap_or(1.0);
    FieldValue::Time(ex.value as f64 * resolution)
}

fn decode_string_fix(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bo = bit_offset as usize;
    let bl = bit_length as usize;
    if bo & 7 != 0 || bl & 7 != 0 {
        return FieldValue::Unsupported {
            field_type: "STRING_FIX (unaligned)",
        };
    }
    let start = bo / 8;
    let end = start + bl / 8;
    if end > data.len() {
        return FieldValue::NotAvailable;
    }
    // Canboat strips trailing '@', '\0', spaces, and 0xff padding.
    let raw = &data[start..end];
    let mut len = raw.len();
    while len > 0 {
        let b = raw[len - 1];
        if b == 0 || b == b'@' || b == b' ' || b == 0xff {
            len -= 1;
        } else {
            break;
        }
    }
    let s = String::from_utf8_lossy(&raw[..len]).into_owned();
    FieldValue::String(s)
}

fn decode_string_lz(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bo = bit_offset as usize;
    let bl = bit_length as usize;
    if bo & 7 != 0 {
        return FieldValue::Unsupported {
            field_type: "STRING_LZ (unaligned)",
        };
    }
    let start = bo / 8;
    let mut end = start
        + if bl == 0 {
            data.len().saturating_sub(start)
        } else {
            bl / 8
        };
    end = end.min(data.len());
    if start >= data.len() {
        return FieldValue::NotAvailable;
    }
    let nul = data[start..end].iter().position(|&b| b == 0);
    let stop = nul.map(|n| start + n).unwrap_or(end);
    let s = String::from_utf8_lossy(&data[start..stop]).into_owned();
    FieldValue::String(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PgnDatabase;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn db() -> &'static PgnDatabase {
        static DB: OnceLock<PgnDatabase> = OnceLock::new();
        DB.get_or_init(|| {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let path = manifest
                .parent()
                .and_then(|p| p.parent())
                .unwrap()
                .join("data")
                .join("canboat.json");
            PgnDatabase::load(path).expect("load canboat.json")
        })
    }

    #[test]
    fn decodes_iso_address_claim() {
        // From canboat/analyzer/tests/pgn-test.in:
        //   2022-09-10T12:10:16.614Z,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0
        // Expected (per pgn-test.out): Unique Number=1088507,
        // Manufacturer Code=Navico (275), Device Function=Rudder (155).
        let data = smallvec::smallvec![0xfb, 0x9b, 0x70, 0x22, 0x00, 0x9b, 0x50, 0xc0];
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 5,
            dst: 255,
            data,
        };
        let dec = db().decode(&frame).expect("decode");
        assert_eq!(dec.id, "isoAddressClaim");
        assert_eq!(dec.fields.len(), 10);

        // Field 1: Unique Number (21-bit unsigned) = 1088507.
        match dec.fields[0].value {
            FieldValue::Integer(v) => assert_eq!(v, 1_088_507),
            ref other => panic!("expected integer, got {other:?}"),
        }
        // Field 2: Manufacturer Code (11-bit LOOKUP) = 275 / Navico.
        match &dec.fields[1].value {
            FieldValue::Lookup { value, name } => {
                assert_eq!(*value, 275);
                assert_eq!(name.as_deref(), Some("Navico"));
            }
            other => panic!("expected lookup, got {other:?}"),
        }
        // Field 5: Device Function (8-bit LOOKUP→INDIRECT) = 155 / Rudder.
        match &dec.fields[4].value {
            FieldValue::Lookup { value, .. } => assert_eq!(*value, 155),
            other => panic!("expected lookup, got {other:?}"),
        }
    }

    #[test]
    fn unknown_pgn_below_any_fallback_returns_error() {
        // PGN 1 is below the lowest Fallback (59392) so no catchall
        // applies — decode must report UnknownPgn.
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 1,
            src: 1,
            dst: 255,
            data: smallvec::smallvec![0u8; 8],
        };
        assert!(matches!(
            db().decode(&frame),
            Err(DecodeError::UnknownPgn { pgn: 1 })
        ));
    }

    #[test]
    fn match_variant_beats_fallback_listed_first() {
        // PGN 126208 has the FALLBACK variant first in JSON, then 7
        // specific variants distinguished by Function Code (field 1,
        // 8 bits at offset 0). Function Code = 3 must select
        // nmeaReadFieldsGroupFunction, NOT the leading fallback.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![
            3, // Function Code = 3 → Read Fields
            0, 0, 0, 0, 0, 0, 0,
        ];
        let frame = RawFrame {
            timestamp: None,
            prio: 3,
            pgn: 126208,
            src: 0,
            dst: 0,
            data,
        };
        let picked = db().pick_variant(&frame).expect("variant");
        assert_eq!(picked.id, "nmeaReadFieldsGroupFunction");
    }

    #[test]
    fn fallback_when_no_specific_variant_matches() {
        // PGN 126208 with Function Code = 99 (none of the 0..6
        // specific variants match) → return the listed fallback.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![99, 0, 0, 0, 0, 0, 0, 0];
        let frame = RawFrame {
            timestamp: None,
            prio: 3,
            pgn: 126208,
            src: 0,
            dst: 0,
            data,
        };
        let picked = db().pick_variant(&frame).expect("variant");
        assert!(
            picked.fallback.unwrap_or(false),
            "expected Fallback variant, got id={}",
            picked.id
        );
    }

    #[test]
    fn cross_pgn_catchall_for_unknown_proprietary() {
        // PGN 65500 is not defined in canboat.json. The latest
        // Fallback:true PGN with pgn <= 65500 covers it — that's
        // 65280 / "0xff000xffffManufacturerProprietarySingleFrameNonAddressed".
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 65500,
            src: 0,
            dst: 255,
            data: smallvec::smallvec![0u8; 8],
        };
        let picked = db().pick_variant(&frame).expect("catchall");
        assert!(picked.fallback.unwrap_or(false));
        assert_eq!(picked.pgn, 65280);
    }

    #[test]
    fn not_available_sentinel_on_all_ones() {
        // PGN 127245 Rudder: first field is Instance (8 bits). 0xFF is
        // the unavailable sentinel.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![0xff; 8];
        let frame = RawFrame {
            timestamp: None,
            prio: 2,
            pgn: 127245,
            src: 0,
            dst: 255,
            data,
        };
        let dec = db().decode(&frame).expect("decode");
        let instance = &dec.fields[0];
        assert!(matches!(instance.value, FieldValue::NotAvailable));
    }
}
