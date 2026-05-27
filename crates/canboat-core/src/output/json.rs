//! JSON format — matches the canboat C analyzer's `-json` output.
//!
//! Output shape:
//!
//! ```json
//! {"timestamp":"...","prio":N,"src":N,"dst":N,"pgn":N,
//!  "description":"...","fields":{"Name":Value,"Name":Value,...}}
//! ```
//!
//! Compact (no whitespace), keys in canboat order. Field names use the
//! human-readable `Name` from canboat.json by default. The output is
//! written without a trailing newline.
//!
//! JSON is hand-emitted rather than constructed via serde_json so the
//! output bytes match canboat exactly (number formatting, key order,
//! lack of whitespace, escape handling).

use std::fmt;

use crate::decode::{DecodedField, DecodedPgn, FieldValue};

use super::effective_precision;

/// Knobs for JSON output.
#[derive(Debug, Default, Clone)]
pub struct JsonOptions {
    /// Emit `null` for unavailable fields instead of omitting them
    /// (matches canboat's `-empty`).
    pub include_empty: bool,
    /// Emit lookup values as `{"value":N,"name":"..."}` instead of the
    /// bare name string (matches canboat's `-nv`).
    pub name_value: bool,
    /// Wrap every field in a `{"value":...,"bytes":"..."[,"bits":"..."]}`
    /// object with per-field byte/bit-level diagnostics (matches
    /// canboat's `-debug`).
    pub debug: bool,
}

pub fn write_json<W: fmt::Write>(w: &mut W, pgn: &DecodedPgn, opts: &JsonOptions) -> fmt::Result {
    w.write_char('{')?;
    if let Some(ts) = &pgn.timestamp {
        w.write_str("\"timestamp\":")?;
        write_json_string(w, ts)?;
        w.write_char(',')?;
    }
    write!(
        w,
        "\"prio\":{},\"src\":{},\"dst\":{},\"pgn\":{}",
        pgn.prio, pgn.src, pgn.dst, pgn.pgn
    )?;
    w.write_str(",\"description\":")?;
    write_json_string(w, &pgn.description)?;

    // Fields object — opens even if empty so consumers always see it.
    w.write_str(",\"fields\":{")?;
    let mut top_sep = "";
    // Active repeating-list state: which set (1 → "list", 2 → "list2")
    // and which iteration index we're inside.
    let mut current_set: u8 = 0;
    let mut current_iter: Option<u32> = None;

    for f in &pgn.fields {
        // Under `-debug` we keep unavailable fields so the byte/bit
        // diagnostic is preserved; otherwise honour the canboat
        // suppress rule.
        if !opts.include_empty && !opts.debug && matches!(f.value, FieldValue::NotAvailable) {
            continue;
        }
        if matches!(f.value, FieldValue::Spare { .. }) {
            continue;
        }
        // Reserved fields whose raw value is all-ones (the "unused"
        // default) are skipped entirely — even under -debug, matching
        // canboat. Other Reserved values flow through and emit their
        // hex string.
        if let FieldValue::Reserved {
            value, bit_length, ..
        } = &f.value
        {
            let max = if *bit_length >= 64 {
                u64::MAX
            } else {
                (1u64 << bit_length) - 1
            };
            if *value == max {
                continue;
            }
        }

        // Determine "where is this field going":
        // - non-repeating (repeat_set == 0): top-level field.
        // - repeat_set == 1: under "list".
        // - repeat_set == 2: under "list2".
        // Crossing set boundaries closes the previous list and opens the
        // next; crossing iterations within the same set inserts "},{".
        if f.repeat_set == 0 {
            if current_set != 0 {
                w.write_str("}]")?;
                current_set = 0;
                current_iter = None;
            }
            w.write_str(top_sep)?;
            write_json_string(w, &f.name)?;
            w.write_char(':')?;
            write_field_value(w, f, opts, &pgn.data)?;
            top_sep = ",";
        } else {
            let iter = f.repeat_index.unwrap_or(0);
            if current_set != f.repeat_set {
                if current_set != 0 {
                    w.write_str("}]")?;
                }
                w.write_str(top_sep)?;
                let key = if f.repeat_set == 1 {
                    "\"list\":[{"
                } else {
                    "\"list2\":[{"
                };
                w.write_str(key)?;
                current_set = f.repeat_set;
                current_iter = Some(iter);
                top_sep = ",";
                write_json_string(w, &f.name)?;
                w.write_char(':')?;
                write_field_value(w, f, opts, &pgn.data)?;
            } else if Some(iter) != current_iter {
                w.write_str("},{")?;
                current_iter = Some(iter);
                write_json_string(w, &f.name)?;
                w.write_char(':')?;
                write_field_value(w, f, opts, &pgn.data)?;
            } else {
                w.write_char(',')?;
                write_json_string(w, &f.name)?;
                w.write_char(':')?;
                write_field_value(w, f, opts, &pgn.data)?;
            }
        }
    }
    if current_set != 0 {
        w.write_str("}]")?;
    }
    w.write_char('}')?; // close "fields"
    w.write_char('}')?; // close top
    Ok(())
}

/// Emit a `bytes` / `bits` suffix for `-debug` output. Caller must
/// have already opened the wrapping object and written the value (and
/// any `name`); this appends the diagnostic keys and nothing else.
///
/// canboat's `bytes` is the field's *raw value bits placed in their
/// byte slot* — not the underlying payload bytes. So a 3-bit field at
/// bit offset 13 with value `4` shows up as `"80"` (4 shifted left by
/// 5 to land at bits 5–7 of one byte), not `"9F"` (the underlying
/// payload byte). For whole-byte-aligned fields the two are the same.
fn write_debug_suffix<W: fmt::Write>(w: &mut W, f: &DecodedField, payload: &[u8]) -> fmt::Result {
    let (Some(bo), Some(bl)) = (f.bit_offset, f.bit_length) else {
        return Ok(());
    };
    if bl == 0 {
        return Ok(());
    }
    use crate::bits::extract_bits;
    let signed = matches!(
        f.value,
        FieldValue::Number(_) if f.unit.is_some()
    );
    let Some(ex) = extract_bits(payload, bo as usize, bl as usize, signed, 0) else {
        return Ok(());
    };
    let raw_unsigned = ex.value as u64;
    let shift = bo % 8;
    let byte_span = ((shift + bl).div_ceil(8)) as usize;
    let shifted: u128 = (raw_unsigned as u128) << shift;
    w.write_str(",\"bytes\":\"")?;
    for i in 0..byte_span {
        if i > 0 {
            w.write_char(' ')?;
        }
        let byte = ((shifted >> (i * 8)) & 0xff) as u8;
        write!(w, "{:02X}", byte)?;
    }
    w.write_char('"')?;
    // `bits`: only emitted when the field width isn't a whole number
    // of bytes — diagnostic for sub-byte fields.
    if bl % 8 != 0 {
        w.write_str(",\"bits\":\"")?;
        // LSB-first bit string of length `bl`.
        for i in (0..bl).rev() {
            let bit = (raw_unsigned >> i) & 1;
            w.write_char(if bit == 1 { '1' } else { '0' })?;
        }
        w.write_char('"')?;
    }
    Ok(())
}

/// Under `-debug`, every field is wrapped in
/// `{"value":<bare>,"name":"..."?,"bytes":"...","bits":"..."?,"key":true?}`.
///
/// This is canboat's `-debug` JSON form: even Number / String / Float
/// fields that are normally emitted bare get wrapped so the
/// per-field byte/bit annotation is attached.
fn write_field_value_debug<W: fmt::Write>(
    w: &mut W,
    f: &DecodedField,
    opts: &JsonOptions,
    payload: &[u8],
) -> fmt::Result {
    w.write_char('{')?;
    w.write_str("\"value\":")?;
    // The "bare value" emission for the inner `value` key.
    match &f.value {
        FieldValue::Number(v) => {
            let p = effective_precision(f.precision, f.resolution);
            if p == 7 && f.unit.as_deref() == Some("deg") {
                write!(w, "{:>10.7}", v)?;
            } else {
                write!(w, "{:.*}", p, v)?;
            }
        }
        FieldValue::Integer(v) => write!(w, "{}", v)?,
        FieldValue::Float(v) => write!(w, "{}", v)?,
        FieldValue::Binary(bytes) => {
            w.write_char('"')?;
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    w.write_char(' ')?;
                }
                write!(w, "{:02X}", b)?;
            }
            w.write_char('"')?;
        }
        FieldValue::Lookup { value, name } => {
            write!(w, "{}", value)?;
            if let Some(n) = name {
                w.write_str(",\"name\":")?;
                write_json_string(w, n)?;
            }
        }
        FieldValue::BitField { value, bits } => {
            if bits.is_empty() {
                write!(w, "{}", value)?;
            } else {
                w.write_char('[')?;
                for (i, (bv, n)) in bits.iter().enumerate() {
                    if i > 0 {
                        w.write_char(',')?;
                    }
                    write!(w, "{{\"value\":{},\"name\":", bv)?;
                    write_json_string(w, n)?;
                    w.write_char('}')?;
                }
                w.write_char(']')?;
            }
        }
        FieldValue::String(s) => write_json_string(w, s)?,
        FieldValue::Date(d) => {
            let mut buf = String::with_capacity(10);
            super::format_date(*d, &mut buf)?;
            write!(w, "{}", d)?;
            w.write_str(",\"name\":")?;
            write_json_string(w, &buf)?;
        }
        FieldValue::Time { raw, seconds } => {
            let p = effective_precision(f.precision, f.resolution);
            let mut buf = String::with_capacity(12);
            super::format_time(*seconds, p, &mut buf)?;
            write!(w, "{}", raw)?;
            w.write_str(",\"name\":")?;
            write_json_string(w, &buf)?;
        }
        FieldValue::Mmsi(v) => write!(w, "\"{:09}\"", v)?,
        FieldValue::Pgn { value, description } => {
            write!(w, "{}", value)?;
            if let Some(desc) = description {
                w.write_str(",\"name\":")?;
                write_json_string(w, desc)?;
            }
        }
        FieldValue::IsoName { value, .. } => {
            // -debug doesn't expand the nested subfields here — it just
            // shows the raw 64-bit identifier. (canboat does the same.)
            write!(w, "{}", value)?;
        }
        FieldValue::Reserved { bytes, .. } => {
            // Same shape as canboat's Binary: uppercase hex, space-
            // separated.
            w.write_char('"')?;
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    w.write_char(' ')?;
                }
                write!(w, "{:02X}", b)?;
            }
            w.write_char('"')?;
        }
        FieldValue::Spare { .. } | FieldValue::NotAvailable => {
            w.write_str("null")?;
        }
        FieldValue::Unsupported { field_type } => {
            let mut buf = String::with_capacity(field_type.len() + 16);
            buf.push_str("<unsupported:");
            buf.push_str(field_type);
            buf.push('>');
            write_json_string(w, &buf)?;
        }
    }
    write_debug_suffix(w, f, payload)?;
    if opts.name_value && f.part_of_primary_key {
        w.write_str(",\"key\":true")?;
    }
    w.write_char('}')
}

fn write_field_value<W: fmt::Write>(
    w: &mut W,
    f: &DecodedField,
    opts: &JsonOptions,
    payload: &[u8],
) -> fmt::Result {
    if opts.debug {
        return write_field_value_debug(w, f, opts, payload);
    }
    match &f.value {
        FieldValue::Number(v) => {
            let p = effective_precision(f.precision, f.resolution);
            // canboat's fieldPrintLatLon uses `%10.7f` — width 10
            // + precision 7 — which left-pads short longitudes
            // (`5.1815566` → ` 5.1815566`). We detect that field type
            // by the load-time precision=7 + unit=deg signal set in
            // db.rs.
            if p == 7 && f.unit.as_deref() == Some("deg") {
                write!(w, "{:>10.7}", v)
            } else {
                write!(w, "{:.*}", p, v)
            }
        }
        FieldValue::Integer(v) => {
            // Under -nv, primary-key fields wear an annotation matching
            // canboat's JSON: {"value":N,"key":true}.
            if opts.name_value && f.part_of_primary_key {
                write!(w, "{{\"value\":{},\"key\":true}}", v)
            } else {
                write!(w, "{}", v)
            }
        }
        FieldValue::Float(v) => {
            // canboat uses %g — Rust's `{}` is acceptably close.
            write!(w, "{}", v)
        }
        FieldValue::Binary(bytes) => {
            // canboat emits binary as uppercase hex with space-separated
            // bytes (matches fieldPrintBinary's `%s%2.02X` w/ " " sep).
            w.write_char('"')?;
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    w.write_char(' ')?;
                }
                write!(w, "{:02X}", b)?;
            }
            w.write_char('"')
        }
        FieldValue::Lookup { value, name } => {
            if opts.name_value {
                w.write_char('{')?;
                write!(w, "\"value\":{}", value)?;
                match (name, opts.include_empty) {
                    // Resolved → always emit the name.
                    (Some(n), _) => {
                        w.write_str(",\"name\":")?;
                        write_json_string(w, n)?;
                    }
                    // Unresolved + -empty: emit null. Matches canboat's
                    // print.c:725-728 path.
                    (None, true) => w.write_str(",\"name\":null")?,
                    // Unresolved + default: omit "name" entirely.
                    // Matches print.c when showJsonEmpty is false.
                    (None, false) => {}
                }
                // Same primary-key annotation rule as Integer.
                if f.part_of_primary_key {
                    w.write_str(",\"key\":true")?;
                }
                w.write_char('}')
            } else {
                match name {
                    Some(n) => write_json_string(w, n),
                    None => write!(w, "{}", value),
                }
            }
        }
        FieldValue::BitField { bits, value } => {
            if bits.is_empty() {
                write!(w, "{}", value)
            } else if opts.name_value {
                // -nv: [{"value":bit_value,"name":"..."},...]
                w.write_char('[')?;
                for (i, (bv, n)) in bits.iter().enumerate() {
                    if i > 0 {
                        w.write_char(',')?;
                    }
                    write!(w, "{{\"value\":{},\"name\":", bv)?;
                    write_json_string(w, n)?;
                    w.write_char('}')?;
                }
                w.write_char(']')
            } else {
                // Plain JSON: bare-string array.
                w.write_char('[')?;
                for (i, (_, n)) in bits.iter().enumerate() {
                    if i > 0 {
                        w.write_char(',')?;
                    }
                    write_json_string(w, n)?;
                }
                w.write_char(']')
            }
        }
        FieldValue::String(s) => write_json_string(w, s),
        FieldValue::Date(d) => {
            let mut buf = String::with_capacity(10);
            super::format_date(*d, &mut buf)?;
            if opts.name_value {
                // canboat -nv: {"value":<days>,"name":"YYYY.MM.DD"}
                w.write_str("{\"value\":")?;
                write!(w, "{}", d)?;
                w.write_str(",\"name\":")?;
                write_json_string(w, &buf)?;
                w.write_char('}')
            } else {
                write_json_string(w, &buf)
            }
        }
        FieldValue::Time { raw, seconds } => {
            let p = effective_precision(f.precision, f.resolution);
            let mut buf = String::with_capacity(12);
            super::format_time(*seconds, p, &mut buf)?;
            if opts.name_value {
                // canboat -nv: {"value":<raw>,"name":"HH:MM:SS.SSSS"}
                w.write_str("{\"value\":")?;
                write!(w, "{}", raw)?;
                w.write_str(",\"name\":")?;
                write_json_string(w, &buf)?;
                w.write_char('}')
            } else {
                write_json_string(w, &buf)
            }
        }
        FieldValue::Mmsi(v) => {
            // canboat emits MMSI as a 9-digit zero-padded string. Under
            // -nv, primary-key MMSI fields wear the same {"value":...,
            // "key":true} annotation as primary-key integers.
            if opts.name_value && f.part_of_primary_key {
                write!(w, "{{\"value\":\"{:09}\",\"key\":true}}", v)
            } else {
                write!(w, "\"{:09}\"", v)
            }
        }
        FieldValue::Pgn { value, description } => {
            if opts.name_value {
                w.write_char('{')?;
                write!(w, "\"value\":{}", value)?;
                if let Some(desc) = description {
                    w.write_str(",\"name\":")?;
                    write_json_string(w, desc)?;
                }
                w.write_char('}')
            } else {
                write!(w, "{}", value)
            }
        }
        FieldValue::Reserved { bytes, .. } => {
            // canboat emits Reserved as the field's bytes hex-
            // stringified, uppercase, space-separated (same shape as
            // Binary).
            w.write_char('"')?;
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    w.write_char(' ')?;
                }
                write!(w, "{:02X}", b)?;
            }
            w.write_char('"')
        }
        FieldValue::Spare { .. } => w.write_str("null"),
        FieldValue::IsoName { value, subfields } => {
            // -nv: {"value":N,"name":{<recursive>}}
            // default: bare N
            if opts.name_value {
                w.write_char('{')?;
                write!(w, "\"value\":{}", value)?;
                w.write_str(",\"name\":{")?;
                let mut sep = "";
                for sf in subfields {
                    // The recursive sub-decode runs the full field set;
                    // drop unavailable subfields (unless -empty) and
                    // collapse Reserved per the parent rules.
                    if !opts.include_empty && matches!(sf.value, FieldValue::NotAvailable) {
                        continue;
                    }
                    if matches!(sf.value, FieldValue::Spare { .. }) {
                        continue;
                    }
                    w.write_str(sep)?;
                    write_json_string(w, &sf.name)?;
                    w.write_char(':')?;
                    write_field_value(w, sf, opts, payload)?;
                    sep = ",";
                }
                w.write_char('}')?;
                w.write_char('}')
            } else {
                write!(w, "{}", value)
            }
        }
        FieldValue::NotAvailable => w.write_str("null"),
        FieldValue::Unsupported { field_type } => {
            // Encode as a string so the JSON stays valid; consumers can
            // detect by leading "<".
            let mut buf = String::with_capacity(field_type.len() + 16);
            buf.push_str("<unsupported:");
            buf.push_str(field_type);
            buf.push('>');
            write_json_string(w, &buf)
        }
    }
}

/// Write `s` as a JSON-quoted string, escaping per RFC 8259.
fn write_json_string<W: fmt::Write>(w: &mut W, s: &str) -> fmt::Result {
    w.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => w.write_str("\\\"")?,
            '\\' => w.write_str("\\\\")?,
            '\u{0008}' => w.write_str("\\b")?,
            '\u{000c}' => w.write_str("\\f")?,
            '\n' => w.write_str("\\n")?,
            '\r' => w.write_str("\\r")?,
            '\t' => w.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(w, "\\u{:04x}", c as u32)?,
            c => w.write_char(c)?,
        }
    }
    w.write_char('"')?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{DecodedField, FieldValue};

    fn sample_pgn() -> DecodedPgn {
        DecodedPgn {
            timestamp: Some("2018-10-16T22:25:25.166".into()),
            prio: 3,
            pgn: 128267,
            src: 35,
            dst: 255,
            description: "Water Depth".into(),
            id: "waterDepth".into(),
            data: Vec::new(),
            fields: vec![DecodedField {
                order: 1,
                id: "depthOffset".into(),
                name: "Offset".into(),
                unit: Some("m".into()),
                resolution: Some(0.001),
                precision: 0,
                repeat_index: None,
                bit_offset: None,
                bit_length: None,
                repeat_set: 0,
                part_of_primary_key: false,
                value: FieldValue::Number(0.0),
            }],
        }
    }

    #[test]
    fn matches_canboat_json_shape() {
        let pgn = sample_pgn();
        let mut out = String::new();
        write_json(&mut out, &pgn, &JsonOptions::default()).unwrap();
        assert_eq!(
            out,
            r#"{"timestamp":"2018-10-16T22:25:25.166","prio":3,"src":35,"dst":255,"pgn":128267,"description":"Water Depth","fields":{"Offset":0.000}}"#
        );
    }

    #[test]
    fn empty_fields_object_when_all_unavailable() {
        let mut pgn = sample_pgn();
        pgn.fields[0].value = FieldValue::NotAvailable;
        let mut out = String::new();
        write_json(&mut out, &pgn, &JsonOptions::default()).unwrap();
        assert!(out.ends_with(r#""fields":{}}"#), "got: {}", out);
    }

    #[test]
    fn include_empty_emits_null() {
        let mut pgn = sample_pgn();
        pgn.fields[0].value = FieldValue::NotAvailable;
        let mut out = String::new();
        write_json(
            &mut out,
            &pgn,
            &JsonOptions {
                include_empty: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(out.contains(r#""Offset":null"#), "got: {}", out);
    }

    #[test]
    fn name_value_emits_object_for_lookup() {
        let mut pgn = sample_pgn();
        pgn.fields[0].value = FieldValue::Lookup {
            value: 275,
            name: Some("Navico".into()),
        };
        pgn.fields[0].resolution = Some(1.0);
        pgn.fields[0].unit = None;
        let mut out = String::new();
        write_json(
            &mut out,
            &pgn,
            &JsonOptions {
                name_value: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            out.contains(r#""Offset":{"value":275,"name":"Navico"}"#),
            "got: {}",
            out
        );
    }

    #[test]
    fn escapes_quotes_in_strings() {
        let mut pgn = sample_pgn();
        pgn.description = r#"He said "hi""#.into();
        let mut out = String::new();
        write_json(&mut out, &pgn, &JsonOptions::default()).unwrap();
        assert!(
            out.contains(r#""description":"He said \"hi\"""#),
            "got: {}",
            out
        );
    }
}
