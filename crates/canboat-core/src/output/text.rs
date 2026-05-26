//! Text format — matches the canboat C analyzer's default text output.
//!
//! Layout, replicated from `analyzer/analyzer.c:1205` and `print.c`:
//!
//! ```text
//!   <ts> <prio> <src:3> <dst:3> <pgn:6> <description>: <field>; <field>; ...
//! ```
//!
//! The first field is prefixed with a single space (so `:` is followed
//! by two spaces). Subsequent fields are prefixed `; `. Each field is
//! emitted as `<Field Name> = <value>[ <unit>]`. Date/time values use
//! their canboat printable forms.

use std::fmt;

use crate::decode::{DecodedField, DecodedPgn, FieldValue};

use super::{format_date, format_time, precision_for};

/// Knobs for text output. Reserved for `-debug`, `-si`, `-geo`
/// extensions — for v0 just `show_unavailable`.
#[derive(Debug, Default, Clone)]
pub struct TextOptions {
    /// When true, emit fields whose value is
    /// [`FieldValue::NotAvailable`] (matches `-empty` semantics in the
    /// C analyzer). Default: omit them entirely.
    pub show_unavailable: bool,
}

/// Write one decoded PGN as a canboat text line. Does not append a
/// trailing newline — the caller decides.
pub fn write_text<W: fmt::Write>(
    w: &mut W,
    pgn: &DecodedPgn,
    opts: &TextOptions,
) -> fmt::Result {
    // Header: `<ts> <prio> <src:3> <dst:3> <pgn:6> <description>:`
    if let Some(ts) = &pgn.timestamp {
        w.write_str(ts)?;
        w.write_char(' ')?;
    }
    write!(
        w,
        "{prio} {src:>3} {dst:>3} {pgn:>6} {desc}:",
        prio = pgn.prio,
        src = pgn.src,
        dst = pgn.dst,
        pgn = pgn.pgn,
        desc = pgn.description,
    )?;

    // First-field separator is " " (single space); after `:` that puts
    // a total of two spaces before the first field name. Subsequent
    // separators are "; ".
    let mut sep = " ";
    for f in &pgn.fields {
        if !opts.show_unavailable && matches!(f.value, FieldValue::NotAvailable) {
            continue;
        }
        // Reserved/Spare are noise in text output — drop them.
        if matches!(f.value, FieldValue::Reserved(_) | FieldValue::Spare(_)) {
            continue;
        }
        // C format string is `"%s %s = "` (sep + space + name + space
        // + = + space). With sep=" " on the first field that yields two
        // spaces after the header's `:`. With sep=";" on subsequent
        // fields it's "; Name = ".
        w.write_str(sep)?;
        w.write_char(' ')?;
        write!(w, "{name} = ", name = f.name)?;
        write_field_value(w, f)?;
        sep = ";";
    }
    Ok(())
}

fn write_field_value<W: fmt::Write>(w: &mut W, f: &DecodedField) -> fmt::Result {
    match &f.value {
        FieldValue::Number(v) => {
            let p = precision_for(f.resolution.unwrap_or(1.0));
            write!(w, "{:.*}", p, v)?;
            if let Some(unit) = &f.unit {
                write!(w, " {}", unit)?;
            }
            Ok(())
        }
        FieldValue::Integer(v) => {
            write!(w, "{}", v)?;
            if let Some(unit) = &f.unit {
                write!(w, " {}", unit)?;
            }
            Ok(())
        }
        FieldValue::Float(v) => {
            // canboat uses %g for floats — Rust's `{}` for f64 is close
            // enough for v0.
            write!(w, "{}", v)?;
            if let Some(unit) = &f.unit {
                write!(w, " {}", unit)?;
            }
            Ok(())
        }
        FieldValue::Binary(bytes) => {
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    w.write_char(' ')?;
                }
                write!(w, "{:02x}", b)?;
            }
            Ok(())
        }
        FieldValue::Lookup { value, name } => {
            if let Some(n) = name {
                w.write_str(n)
            } else {
                write!(w, "{}", value)
            }
        }
        FieldValue::BitField { names, value } => {
            if names.is_empty() {
                write!(w, "{}", value)
            } else {
                for (i, n) in names.iter().enumerate() {
                    if i > 0 {
                        w.write_str(", ")?;
                    }
                    w.write_str(n)?;
                }
                Ok(())
            }
        }
        FieldValue::String(s) => w.write_str(s),
        FieldValue::Date(d) => format_date(*d, w),
        FieldValue::Time(s) => {
            let p = precision_for(f.resolution.unwrap_or(1.0));
            format_time(*s, p, w)
        }
        FieldValue::Mmsi(v) => write!(w, "{:09}", v),
        FieldValue::Pgn(v) => write!(w, "{}", v),
        FieldValue::Reserved(_) | FieldValue::Spare(_) => Ok(()),
        FieldValue::NotAvailable => w.write_str("Unknown"),
        FieldValue::Unsupported { field_type } => write!(w, "<unsupported:{}>", field_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{DecodedField, DecodedPgn, FieldValue};

    fn sample_pgn() -> DecodedPgn {
        DecodedPgn {
            timestamp: Some("2022-09-10T12:10:16.614Z".into()),
            prio: 6,
            pgn: 60928,
            src: 5,
            dst: 255,
            description: "ISO Address Claim".into(),
            id: "isoAddressClaim".into(),
            fields: vec![
                DecodedField {
                    order: 1,
                    id: "uniqueNumber".into(),
                    name: "Unique Number".into(),
                    unit: None,
                    resolution: Some(1.0),
                    repeat_index: None,
                    value: FieldValue::Integer(1_088_507),
                },
                DecodedField {
                    order: 2,
                    id: "manufacturerCode".into(),
                    name: "Manufacturer Code".into(),
                    unit: None,
                    resolution: Some(1.0),
                    repeat_index: None,
                    value: FieldValue::Lookup {
                        value: 275,
                        name: Some("Navico".into()),
                    },
                },
            ],
        }
    }

    #[test]
    fn header_format_matches_canboat() {
        let pgn = sample_pgn();
        let mut out = String::new();
        write_text(&mut out, &pgn, &TextOptions::default()).unwrap();
        // The header is `<ts> <prio> <src:3> <dst:3> <pgn:6> <desc>:`
        // The first field is prefixed with " " yielding ": " before the
        // separator's space and a further space-then-name: total 2
        // spaces between `:` and `Unique`.
        assert!(out.starts_with(
            "2022-09-10T12:10:16.614Z 6   5 255  60928 ISO Address Claim:  Unique Number = 1088507"
        ));
    }

    #[test]
    fn separates_fields_with_semicolon_space() {
        let pgn = sample_pgn();
        let mut out = String::new();
        write_text(&mut out, &pgn, &TextOptions::default()).unwrap();
        assert!(out.contains("; Manufacturer Code = Navico"));
    }

    #[test]
    fn end_to_end_iso_address_claim() {
        // Decode the exact PGN 60928 frame from canboat tests and
        // verify the text header + first three fields render in the
        // expected shape.
        use crate::{PgnDatabase, RawFrame};
        use std::path::PathBuf;
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .join("data")
            .join("canboat.json");
        let db = PgnDatabase::load(path).expect("load canboat.json");
        let frame = RawFrame {
            timestamp: Some("2022-09-10T12:10:16.614Z".into()),
            prio: 6,
            pgn: 60928,
            src: 5,
            dst: 255,
            data: smallvec::smallvec![0xfb, 0x9b, 0x70, 0x22, 0x00, 0x9b, 0x50, 0xc0],
        };
        let pgn = db.decode(&frame).unwrap();
        let mut out = String::new();
        write_text(&mut out, &pgn, &TextOptions::default()).unwrap();
        // Canboat reference:
        //   2022-09-10T12:10:16.614Z 6   5 255  60928 ISO Address Claim:
        //     Unique Number = 1088507; Manufacturer Code = Navico; ...
        assert!(
            out.starts_with(
                "2022-09-10T12:10:16.614Z 6   5 255  60928 ISO Address Claim:  \
                 Unique Number = 1088507; Manufacturer Code = Navico;"
            ),
            "got: {}",
            out
        );
    }

    #[test]
    fn omits_unavailable_by_default() {
        let mut pgn = sample_pgn();
        pgn.fields[1].value = FieldValue::NotAvailable;
        let mut out = String::new();
        write_text(&mut out, &pgn, &TextOptions::default()).unwrap();
        assert!(!out.contains("Manufacturer Code"));
        assert!(out.contains("Unique Number = 1088507"));
    }
}
