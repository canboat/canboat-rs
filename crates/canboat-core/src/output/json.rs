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

use super::precision_for;

/// Knobs for JSON output.
#[derive(Debug, Default, Clone)]
pub struct JsonOptions {
    /// Emit `null` for unavailable fields instead of omitting them
    /// (matches canboat's `-empty`).
    pub include_empty: bool,
    /// Emit lookup values as `{"value":N,"name":"..."}` instead of the
    /// bare name string (matches canboat's `-nv`).
    pub name_value: bool,
}

pub fn write_json<W: fmt::Write>(
    w: &mut W,
    pgn: &DecodedPgn,
    opts: &JsonOptions,
) -> fmt::Result {
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
    let mut sep = "";
    for f in &pgn.fields {
        if !opts.include_empty && matches!(f.value, FieldValue::NotAvailable) {
            continue;
        }
        if matches!(f.value, FieldValue::Reserved(_) | FieldValue::Spare(_)) {
            continue;
        }
        w.write_str(sep)?;
        write_json_string(w, &f.name)?;
        w.write_char(':')?;
        write_field_value(w, f, opts)?;
        sep = ",";
    }
    w.write_char('}')?; // close "fields"
    w.write_char('}')?; // close top
    Ok(())
}

fn write_field_value<W: fmt::Write>(
    w: &mut W,
    f: &DecodedField,
    opts: &JsonOptions,
) -> fmt::Result {
    match &f.value {
        FieldValue::Number(v) => {
            let p = precision_for(f.resolution.unwrap_or(1.0));
            write!(w, "{:.*}", p, v)
        }
        FieldValue::Integer(v) => write!(w, "{}", v),
        FieldValue::Float(v) => {
            // canboat uses %g — Rust's `{}` is acceptably close.
            write!(w, "{}", v)
        }
        FieldValue::Binary(bytes) => {
            // canboat emits binary as an uppercase hex string.
            w.write_char('"')?;
            for b in bytes {
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
                w.write_char('}')
            } else {
                match name {
                    Some(n) => write_json_string(w, n),
                    None => write!(w, "{}", value),
                }
            }
        }
        FieldValue::BitField { names, value } => {
            if names.is_empty() {
                write!(w, "{}", value)
            } else {
                w.write_char('[')?;
                for (i, n) in names.iter().enumerate() {
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
            write_json_string(w, &buf)
        }
        FieldValue::Time(s) => {
            let p = precision_for(f.resolution.unwrap_or(1.0));
            let mut buf = String::with_capacity(12);
            super::format_time(*s, p, &mut buf)?;
            write_json_string(w, &buf)
        }
        FieldValue::Mmsi(v) => {
            // canboat emits MMSI as a 9-digit zero-padded string.
            write!(w, "\"{:09}\"", v)
        }
        FieldValue::Pgn(v) => write!(w, "{}", v),
        FieldValue::Reserved(_) | FieldValue::Spare(_) => w.write_str("null"),
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
            fields: vec![DecodedField {
                order: 1,
                id: "depthOffset".into(),
                name: "Offset".into(),
                unit: Some("m".into()),
                resolution: Some(0.001),
                repeat_index: None,
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
        assert!(out.contains(r#""description":"He said \"hi\"""#), "got: {}", out);
    }
}
