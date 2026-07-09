// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Encode a PGN from field values into a wire [`RawFrame`] — the
//! inverse of [`crate::decode`].
//!
//! The entry point is [`PgnDatabase::message`] /
//! [`PgnDatabase::message_by_pgn`], which hand back a [`MessageBuilder`]
//! for a specific schema PGN variant. Push field values by name (or id),
//! then [`build`](MessageBuilder::build) packs them at their schema bit
//! offsets — LSB-first, exactly the layout [`crate::bits::extract_bits`]
//! reads back — and returns a [`RawFrame`]. Because the result is a
//! `RawFrame`, any [`crate::format`] writer (PLAIN, YDWG02, Actisense,
//! `.ebl`) turns it into wire text/bytes.
//!
//! Fields the caller doesn't set are filled automatically: a field with
//! a `match_value` (the raw value that selects this PGN variant) gets
//! that value, so proprietary/variant PGNs come out valid without the
//! caller restating their manufacturer/industry/selector fields; a
//! `Spare` field gets zero; everything else gets its "not available"
//! sentinel (the schema `unknown_value`, else all-ones).
//!
//! Scope: this phase encodes fixed-length fields — the numeric,
//! enum/lookup, and PGN/MMSI families that make up the large majority
//! of PGNs. Strings, `BINARY`/`VARIABLE`, and repeating field sets
//! return [`EncodeError::NotFixedLength`] for now.

use std::error::Error;
use std::fmt;

use canboat_schema::{FieldInfo, FieldType, PgnInfo};

use crate::db::PgnDatabase;
use crate::frame::RawFrame;

/// A value to place into a PGN field when encoding. Owned and
/// caller-constructible (unlike the decode [`crate::FieldValue`], which
/// borrows `&'static` schema references).
#[derive(Debug, Clone, PartialEq)]
pub enum EncodeValue {
    /// A scaled physical value in the field's unit (e.g. `1.23` rad/s).
    /// Inverse of the decoder's `raw * resolution + offset + unit_offset`.
    Number(f64),
    /// A raw, unscaled integer written to the field bits verbatim
    /// (instances, counts, enum values, a PGN number, …). Signed values
    /// are two's-complemented into the field width.
    Int(i64),
    /// A `LOOKUP` / `BITLOOKUP` selected by its label (e.g. `"Apparent"`).
    Lookup(String),
    /// Text for a `STRING_*` field. (Phase 2 — currently unsupported.)
    Text(String),
    /// Raw bytes for a `BINARY` / `VARIABLE` field. (Phase 2.)
    Bytes(Vec<u8>),
    /// A PGN number for a `PGN`-type field (packed as its bit-width,
    /// LSB-first → little-endian bytes).
    Pgn(u32),
    /// Leave the field at its "not available" sentinel.
    NotAvailable,
}

impl From<f64> for EncodeValue {
    fn from(v: f64) -> Self {
        EncodeValue::Number(v)
    }
}
impl From<i64> for EncodeValue {
    fn from(v: i64) -> Self {
        EncodeValue::Int(v)
    }
}
impl From<i32> for EncodeValue {
    fn from(v: i32) -> Self {
        EncodeValue::Int(v as i64)
    }
}
impl From<u32> for EncodeValue {
    fn from(v: u32) -> Self {
        EncodeValue::Int(v as i64)
    }
}

/// Why a message could not be encoded.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodeError {
    /// No PGN with this schema id (e.g. `"isoRequest"`).
    NoSuchPgnId(String),
    /// No PGN with this number in the schema.
    NoSuchPgn(u32),
    /// This PGN number has several schema variants; use
    /// [`PgnDatabase::message`] with the specific id.
    AmbiguousPgn { pgn: u32, variants: usize },
    /// No field with this name/id in the PGN.
    NoSuchField { pgn_id: &'static str, field: String },
    /// A `LOOKUP` field was given a label that isn't in its table.
    UnknownLookupLabel { field: &'static str, label: String },
    /// A value doesn't fit the field's bit width / range.
    ValueOutOfRange { field: &'static str, value: f64 },
    /// The field isn't fixed-length (string / binary / variable), which
    /// this phase can't encode yet.
    NotFixedLength(&'static str),
    /// The field type can't accept the [`EncodeValue`] variant given.
    TypeMismatch {
        field: &'static str,
        expected: &'static str,
    },
    /// The packed byte length didn't match the PGN's declared length —
    /// an internal consistency failure (repeating/variable PGN, or a
    /// schema/encoder mismatch).
    LengthMismatch { pgn: u32, expected: u32, got: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::NoSuchPgnId(id) => write!(f, "no PGN with id '{id}'"),
            EncodeError::NoSuchPgn(p) => write!(f, "no PGN {p} in the schema"),
            EncodeError::AmbiguousPgn { pgn, variants } => {
                write!(f, "PGN {pgn} has {variants} variants; select one by id")
            }
            EncodeError::NoSuchField { pgn_id, field } => {
                write!(f, "PGN '{pgn_id}' has no field '{field}'")
            }
            EncodeError::UnknownLookupLabel { field, label } => {
                write!(f, "field '{field}': '{label}' is not a valid value")
            }
            EncodeError::ValueOutOfRange { field, value } => {
                write!(f, "field '{field}': value {value} out of range")
            }
            EncodeError::NotFixedLength(field) => {
                write!(
                    f,
                    "field '{field}': variable-length encoding not yet supported"
                )
            }
            EncodeError::TypeMismatch { field, expected } => {
                write!(f, "field '{field}': expected {expected}")
            }
            EncodeError::LengthMismatch { pgn, expected, got } => {
                write!(f, "PGN {pgn}: packed {got} bytes, schema says {expected}")
            }
        }
    }
}

impl Error for EncodeError {}

/// Fluent builder for one PGN message. Created via
/// [`PgnDatabase::message`] / [`PgnDatabase::message_by_pgn`].
pub struct MessageBuilder {
    db: &'static PgnDatabase,
    pgn: &'static PgnInfo,
    prio: u8,
    src: u8,
    dst: u8,
    timestamp: Option<String>,
    /// Staged raw bit patterns per field, indexed by `order - 1`.
    /// `None` → fill with the field default at build time.
    staged: Vec<Option<u64>>,
}

impl MessageBuilder {
    /// Construct for a resolved PGN variant. Crate-internal; callers go
    /// through [`PgnDatabase::message`].
    pub(crate) fn for_pgn(db: &'static PgnDatabase, pgn: &'static PgnInfo) -> Self {
        Self {
            db,
            pgn,
            prio: pgn.priority.unwrap_or(6),
            src: 0,
            dst: 255,
            timestamp: None,
            staged: vec![None; pgn.fields.len()],
        }
    }

    /// Override the CAN priority (default: the schema priority, else 6).
    pub fn priority(mut self, prio: u8) -> Self {
        self.prio = prio;
        self
    }
    /// Set the source address (default 0).
    pub fn source(mut self, src: u8) -> Self {
        self.src = src;
        self
    }
    /// Set the destination address (default 255 = broadcast).
    pub fn destination(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }
    /// Stamp a timestamp onto the produced frame (default: none — the
    /// caller/writer decides).
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Set a field by schema name (`"Wind Speed"`) or id (`"windSpeed"`).
    pub fn push(
        &mut self,
        field: &str,
        value: impl Into<EncodeValue>,
    ) -> Result<&mut Self, EncodeError> {
        let idx = self.find_field(field)?;
        let raw = self.value_to_raw(&self.pgn.fields[idx], value.into())?;
        self.staged[idx] = Some(raw);
        Ok(self)
    }

    /// Set a field from a textual value, coercing per the field's type
    /// (numbers, `0x`-hex, lookup labels). For CLI `FIELD=VALUE` args.
    pub fn push_arg(&mut self, field: &str, value: &str) -> Result<&mut Self, EncodeError> {
        let idx = self.find_field(field)?;
        let f = &self.pgn.fields[idx];
        let ev = coerce_arg(f, value)?;
        let raw = self.value_to_raw(f, ev)?;
        self.staged[idx] = Some(raw);
        Ok(self)
    }

    /// Build the wire frame: pack every field (staged value or default)
    /// LSB-first at its schema offset, verify the length, and return the
    /// [`RawFrame`].
    pub fn build(&self) -> Result<RawFrame, EncodeError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut next_bit = 0usize;
        for (idx, f) in self.pgn.fields.iter().enumerate() {
            let bl = f.bit_length.ok_or(EncodeError::NotFixedLength(f.name))? as usize;
            let raw = match self.staged[idx] {
                Some(v) => v,
                None => default_raw(f),
            };
            write_bits(&mut buf, &mut next_bit, bl, raw);
        }
        // Flush a trailing partial byte (LSB-first packing already grew
        // the buffer as it went, so this is only defensive).
        if !next_bit.is_multiple_of(8) {
            // pad the final byte with 1s (canboat reserved/pad convention)
            let pad = 8 - (next_bit % 8);
            write_bits(&mut buf, &mut next_bit, pad, u64::MAX);
        }
        if let Some(expected) = self.pgn.length
            && buf.len() != expected as usize
        {
            return Err(EncodeError::LengthMismatch {
                pgn: self.pgn.pgn,
                expected,
                got: buf.len(),
            });
        }
        Ok(RawFrame {
            timestamp: self.timestamp.clone(),
            prio: self.prio,
            pgn: self.pgn.pgn,
            src: self.src,
            dst: self.dst,
            data: buf.into_iter().collect(),
        })
    }

    /// The resolved PGN this builder targets (for CLI help / listing).
    pub fn pgn_info(&self) -> &'static PgnInfo {
        self.pgn
    }

    fn find_field(&self, key: &str) -> Result<usize, EncodeError> {
        self.pgn
            .fields
            .iter()
            .position(|f| f.name == key || f.id == key)
            .ok_or_else(|| EncodeError::NoSuchField {
                pgn_id: self.pgn.id,
                field: key.to_string(),
            })
    }

    /// Convert an [`EncodeValue`] to the raw bit pattern for `f`,
    /// masked/two's-complemented into the field width.
    fn value_to_raw(&self, f: &FieldInfo, v: EncodeValue) -> Result<u64, EncodeError> {
        let bl = f.bit_length.ok_or(EncodeError::NotFixedLength(f.name))?;
        let raw_i64: i64 = match (f.field_type, v) {
            // Explicit "leave unset".
            (_, EncodeValue::NotAvailable) => return Ok(default_raw(f)),

            // Lookup by label → its raw value; or a raw integer.
            (
                Some(FieldType::Lookup) | Some(FieldType::IndirectLookup),
                EncodeValue::Lookup(label),
            ) => self.resolve_lookup(f, &label)? as i64,
            (Some(FieldType::Lookup) | Some(FieldType::IndirectLookup), EncodeValue::Int(n)) => n,

            // BitLookup: a raw bitmask integer (label-per-bit is phase 2).
            (Some(FieldType::BitLookup), EncodeValue::Int(n)) => n,

            // PGN-type: the requested PGN number.
            (Some(FieldType::Pgn), EncodeValue::Pgn(p)) => p as i64,
            (Some(FieldType::Pgn), EncodeValue::Int(n)) => n,

            // Text / binary — not yet.
            (_, EncodeValue::Text(_)) | (_, EncodeValue::Bytes(_)) => {
                return Err(EncodeError::NotFixedLength(f.name));
            }

            // A PGN number on any field is just a raw integer.
            (_, EncodeValue::Pgn(p)) => p as i64,

            // Numeric families: a raw integer is written verbatim…
            (_, EncodeValue::Int(n)) => n,
            // …a scaled Number is inverted through resolution/offset.
            (_, EncodeValue::Number(x)) => scaled_to_raw(f, x)?,

            // A bare Lookup label on a non-lookup field.
            (_, EncodeValue::Lookup(_)) => {
                return Err(EncodeError::TypeMismatch {
                    field: f.name,
                    expected: "a numeric value",
                });
            }
        };
        Ok(mask_to_width(raw_i64, bl))
    }

    fn resolve_lookup(&self, f: &FieldInfo, label: &str) -> Result<u64, EncodeError> {
        let table_name = f.lookup_enumeration.ok_or(EncodeError::TypeMismatch {
            field: f.name,
            expected: "a value for a lookup field",
        })?;
        if let Some(table) = self.db.lookup(table_name) {
            for lv in table.values {
                if lv.name == label || lv.id == Some(label) {
                    return Ok(lv.value);
                }
            }
        }
        Err(EncodeError::UnknownLookupLabel {
            field: f.name,
            label: label.to_string(),
        })
    }
}

/// Invert the decoder's `raw * resolution + offset + unit_offset`.
/// Mirrors the extraction-signedness quirk: a non-zero schema `offset`
/// forces the field unsigned, so the raw is a plain magnitude.
fn scaled_to_raw(f: &FieldInfo, scaled: f64) -> Result<i64, EncodeError> {
    let resolution = f.resolution.unwrap_or(1.0);
    let display_offset = f.offset.map(|o| o as f64).unwrap_or(0.0);
    let raw = (scaled - f.unit_offset - display_offset) / resolution;
    let rounded = raw.round();
    if !rounded.is_finite() {
        return Err(EncodeError::ValueOutOfRange {
            field: f.name,
            value: scaled,
        });
    }
    Ok(rounded as i64)
}

/// The default raw bit pattern for a field the caller left unset.
fn default_raw(f: &FieldInfo) -> u64 {
    let bl = f.bit_length.unwrap_or(0);
    // A variant-selector field: emit the value that identifies this PGN.
    if let Some(mv) = f.match_value {
        return mask_to_width(mv, bl);
    }
    match f.field_type {
        Some(FieldType::Spare) => 0,
        _ => f.unknown_value.unwrap_or_else(|| all_ones(bl)),
    }
}

/// Two's-complement / mask `value` into `bits` low bits.
fn mask_to_width(value: i64, bits: u32) -> u64 {
    (value as u64) & all_ones(bits)
}

fn all_ones(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Append `bits` low bits of `value`, LSB-first, growing `buf` as needed
/// — the exact layout [`crate::bits::extract_bits`] reads back.
fn write_bits(buf: &mut Vec<u8>, next_bit: &mut usize, bits: usize, mut value: u64) {
    for _ in 0..bits {
        let idx = *next_bit >> 3;
        let bitpos = *next_bit & 7;
        if bitpos == 0 {
            buf.push(0);
        }
        if value & 1 != 0 {
            buf[idx] |= 1 << bitpos;
        }
        value >>= 1;
        *next_bit += 1;
    }
}

/// Coerce a `FIELD=VALUE` string argument per the field's type.
fn coerce_arg(f: &FieldInfo, s: &str) -> Result<EncodeValue, EncodeError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("n/a") || s.is_empty() {
        return Ok(EncodeValue::NotAvailable);
    }
    // 0x-hex → raw integer.
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && let Ok(n) = i64::from_str_radix(hex, 16)
    {
        return Ok(EncodeValue::Int(n));
    }
    match f.field_type {
        Some(FieldType::Lookup) | Some(FieldType::IndirectLookup) => {
            // Numeric → raw value; otherwise treat as a label.
            match s.parse::<i64>() {
                Ok(n) => Ok(EncodeValue::Int(n)),
                Err(_) => Ok(EncodeValue::Lookup(s.to_string())),
            }
        }
        Some(FieldType::Pgn) => {
            s.parse::<u32>()
                .map(EncodeValue::Pgn)
                .map_err(|_| EncodeError::ValueOutOfRange {
                    field: f.name,
                    value: f64::NAN,
                })
        }
        Some(FieldType::StringFix)
        | Some(FieldType::StringLz)
        | Some(FieldType::StringLau)
        | Some(FieldType::Variable) => Ok(EncodeValue::Text(s.to_string())),
        _ => {
            // Numeric field: an integer literal is a raw value, a decimal
            // is a scaled physical value.
            if let Ok(n) = s.parse::<i64>() {
                Ok(EncodeValue::Int(n))
            } else if let Ok(x) = s.parse::<f64>() {
                Ok(EncodeValue::Number(x))
            } else {
                Err(EncodeError::ValueOutOfRange {
                    field: f.name,
                    value: f64::NAN,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> &'static PgnDatabase {
        PgnDatabase::embedded(crate::Units::Metric)
    }

    #[test]
    fn iso_request_matches_c_format_message() {
        // The canboat `format-message` example: request Product Info
        // (126996 = 0x1F014) → PGN 59904, data 14 f0 01.
        let frame = db()
            .message("isoRequest")
            .unwrap()
            .priority(6)
            .destination(255)
            .push("PGN", 126996)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(frame.pgn, 59904);
        assert_eq!(frame.prio, 6);
        assert_eq!(frame.dst, 255);
        assert_eq!(frame.data.as_slice(), &[0x14, 0xf0, 0x01]);
    }

    #[test]
    fn ambiguous_pgn_number_is_rejected() {
        // 59904 is unique; 126208 (group function) has several variants.
        assert!(db().message_by_pgn(59904).is_ok());
        assert!(matches!(
            db().message_by_pgn(126208),
            Err(EncodeError::AmbiguousPgn { pgn: 126208, .. })
        ));
    }

    #[test]
    fn unset_fields_default_and_length_checks() {
        // Encoding with no fields set still produces a schema-length
        // frame (defaults fill in), and match_value selector fields are
        // auto-populated so the variant stays valid.
        let frame = db().message("isoRequest").unwrap().build();
        // isoRequest has a single PGN field with no match_value; unset →
        // not-available (all ones), 3 bytes.
        let f = frame.unwrap();
        assert_eq!(f.data.len(), 3);
        assert_eq!(f.data.as_slice(), &[0xff, 0xff, 0xff]);
    }

    #[test]
    fn wind_data_round_trips_through_decode() {
        // The real invariant: decode(encode(x)) == x. Encode a scaled
        // number, an integer, and a lookup-by-label, then decode the
        // frame back and compare physical values (unit-agnostic — the
        // compiled schema may store angles in degrees, etc.).
        let db = db();
        let frame = db
            .message("windData")
            .unwrap()
            .push("SID", 7)
            .unwrap()
            .push("Wind Speed", 5.23)
            .unwrap()
            .push("Wind Angle", 1.5)
            .unwrap()
            .push("Reference", EncodeValue::Lookup("Apparent".into()))
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(frame.pgn, 130306);
        assert_eq!(frame.data.len(), 8);

        let decoded = db.decode(&frame).unwrap();
        assert_eq!(decoded.id, "windData");

        let num = |name: &str| match &decoded.field_by_name(name).unwrap().value {
            crate::FieldValue::Number(x) => *x,
            crate::FieldValue::Integer(n) => *n as f64,
            other => panic!("field {name}: expected a number, got {other:?}"),
        };
        // Within a resolution step (rounding on the way in).
        assert!((num("Wind Speed") - 5.23).abs() < 0.01);
        assert!((num("Wind Angle") - 1.5).abs() < 0.01);
        assert_eq!(num("SID"), 7.0);

        match &decoded.field_by_name("Reference").unwrap().value {
            crate::FieldValue::Lookup { value, name } => {
                assert_eq!(*value, 2);
                assert_eq!(*name, Some("Apparent"));
            }
            other => panic!("Reference: expected lookup, got {other:?}"),
        }
    }

    #[test]
    fn unknown_lookup_label_is_rejected() {
        assert!(matches!(
            db().message("windData")
                .unwrap()
                .push("Reference", EncodeValue::Lookup("Nonsense".into())),
            Err(EncodeError::UnknownLookupLabel { .. })
        ));
    }

    #[test]
    fn no_such_field_and_pgn() {
        assert!(matches!(
            db().message("isoRequest").unwrap().push("Nope", 1),
            Err(EncodeError::NoSuchField { .. })
        ));
        assert!(matches!(
            db().message("notAPgnId"),
            Err(EncodeError::NoSuchPgnId(_))
        ));
    }
}
