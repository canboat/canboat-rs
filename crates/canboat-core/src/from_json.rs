// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Rebuild a [`DecodedPgn`] from one analyzer name-value JSON line.
//!
//! This is the near-inverse of [`crate::output::write_json`]: given a
//! line of canboat analyzer JSON (always the `-nv` / NameValue variant,
//! human field-name keys), reconstruct the [`DecodedPgn`] a live decode
//! would have produced. It is the input adapter that lets a JSON stream
//! feed the same `DecodedPgn`-based pipeline a live device does — the
//! `.j2k` front door to the n2kd / server converters.
//!
//! It reconstructs only what those downstream consumers read: top-level
//! (non-repeating) fields, in the [`FieldValue`] variants the converters
//! match on (`Number`/`Integer`/`Float`/`Lookup`/`Date`/`Time`/`String`/
//! `Mmsi`/`Pgn`). Repeating sets, `data` bytes, and lossless round-trip
//! of every field type are out of scope — this feeds conversion and
//! serving, not wire re-encoding.

use crate::analyzer_json as json;
use crate::db::PgnDatabase;
use crate::decode::{DecodedField, DecodedPgn, FieldValue, build_index_by_order};
use crate::types::{FieldInfo, FieldType};

/// Reconstruct a [`DecodedPgn`] from one analyzer `-nv` JSON line, or
/// `None` if the line has no `pgn`, the PGN is unknown, or it isn't the
/// object we expect.
pub fn json_to_decoded(line: &str, db: &PgnDatabase) -> Option<DecodedPgn> {
    let pgn = json::int(line, "pgn")? as u32;
    let info = db.first_pgn(pgn)?;

    let src = json::int(line, "src").unwrap_or(0) as u8;
    let dst = json::int(line, "dst").unwrap_or(255) as u8;
    let prio = json::int(line, "prio").unwrap_or(0) as u8;
    let timestamp = json::value(line, "timestamp").map(str::to_owned);

    let mut fields = Vec::with_capacity(info.fields.len());
    for fi in info.fields {
        if let Some(value) = field_value_from_json(line, fi) {
            fields.push(DecodedField {
                info: fi,
                value,
                bit_offset: None,
                bit_length: None,
                repeat_index: None,
                repeat_set: 0,
                overrides: None,
            });
        }
    }
    let index_by_order = build_index_by_order(&fields);

    Some(DecodedPgn {
        timestamp,
        prio,
        pgn,
        src,
        dst,
        description: info.description,
        id: info.id,
        id_is_pinned: info.id_is_pinned,
        data: Vec::new(),
        fields,
        has_repeating_set: [false, false],
        index_by_order,
    })
}

/// Build the [`FieldValue`] for one field from its JSON representation,
/// keyed by the human `name` (canboat default, non-camel). Returns
/// `None` when the field is absent from the line or its type isn't one
/// the converters consume.
fn field_value_from_json(line: &str, fi: &FieldInfo) -> Option<FieldValue> {
    use FieldType::*;
    let name = fi.name;
    match fi.field_type {
        // Lookups (and lookup-shaped fields): `-nv` carries the integer
        // in a nested `"value"`, which `lookup_int` extracts. The
        // resolved name is `&'static` in a live decode; we don't have
        // one here, and no `-nv` consumer needs it (they read the int).
        Some(Lookup | BitLookup | IndirectLookup | DynamicFieldKey | FieldIndex) => {
            let v = json::lookup_int(line, name)?;
            Some(FieldValue::Lookup {
                value: v as u64,
                name: None,
            })
        }
        // `-nv`: {"value":<days>,"name":"YYYY.MM.DD"} — take the raw days.
        Some(Date) => Some(FieldValue::Date(nested_or_bare_int(line, name)? as u16)),
        // `-nv`: {"value":N,"name":"HH:MM:SS.SSSS"}. N is `seconds` for
        // resolution >= 1 s, the raw scaled integer for sub-second — see
        // output::json. Recover `seconds` (what the converters read)
        // accordingly; keep the wire integer in `raw`.
        Some(Time | Duration) => {
            let v = nested_or_bare_int(line, name)?;
            let res = fi.resolution.unwrap_or(1.0);
            let seconds = if res >= 1.0 { v as f64 } else { v as f64 * res };
            Some(FieldValue::Time { raw: v, seconds })
        }
        Some(Mmsi) => Some(FieldValue::Mmsi(mmsi_from_json(line, name)?)),
        Some(Pgn) => Some(FieldValue::Pgn {
            value: nested_or_bare_int(line, name)? as u32,
            description: None,
        }),
        Some(StringFix | StringLz | StringLau | Variable) => {
            Some(FieldValue::String(json::value(line, name)?.to_owned()))
        }
        Some(Float) => Some(FieldValue::Float(json::number(line, name)?)),
        // Plain numerics: an unscaled integer (resolution 1, no unit) is
        // an `Integer` — matching the decoder — so `as_i64` stays exact;
        // everything else is a scaled `Number`.
        Some(Number | Decimal) | None => {
            if is_integer_field(fi) {
                Some(FieldValue::Integer(json::int(line, name)?))
            } else {
                Some(FieldValue::Number(json::number(line, name)?))
            }
        }
        // Binary / IsoName / Reserved / Spare / dynamic-length markers:
        // no converter reads them; skip.
        _ => None,
    }
}

/// `true` for fields the decoder keeps as a bare integer: resolution of
/// exactly 1 (or unset) and no unit.
fn is_integer_field(fi: &FieldInfo) -> bool {
    fi.resolution.is_none_or(|r| r == 1.0) && fi.unit.is_none()
}

/// Read an integer that may be either bare (`"F":5`) or wrapped by `-nv`
/// (`"F":{"value":5,...}`).
fn nested_or_bare_int(line: &str, field: &str) -> Option<i64> {
    json::lookup_int(line, field).or_else(|| json::int(line, field))
}

/// MMSI is emitted as a 9-digit quoted string (`"F":"123456789"`) or,
/// for primary-key fields under `-nv`, as `{"value":123456789,...}`.
fn mmsi_from_json(line: &str, field: &str) -> Option<u32> {
    if let Some(v) = json::lookup_int(line, field) {
        return u32::try_from(v).ok();
    }
    json::value(line, field)?.trim().parse().ok()
}
