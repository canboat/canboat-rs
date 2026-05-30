//! Snapshot cache for the "full state on connect" TCP port.
//!
//! Mirrors canboat C `n2kd`'s base-port output verbatim:
//!
//! ```text
//! {"<pgn>":
//!   {"description":"<short-desc>"
//!   ,"<src>[_<secondary>]":<analyzer-json-line>
//!   ...
//!   }
//! ,"<pgn>":
//!   ...
//! }
//! ```
//!
//! - `<short-desc>` is the PGN's full description truncated at the
//!   first `:` (so `"Simnet: Device Status"` → `"Simnet"`).
//! - `<secondary>` is the readable value of the first
//!   discriminating field (Instance / Reference / User ID /
//!   Message ID / Proprietary ID), e.g. `"True"`, `"Apparent"`,
//!   `"0"`. Omitted when none of those fields is present on the
//!   record.
//! - Lines that have expired (per-PGN-class TTL — 120 s for
//!   sensors, 1 h for AIS-shaped records) are pruned before each
//!   snapshot.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use canboat_core::{DecodedField, DecodedPgn, FieldValue};

/// TTL for non-AIS PGNs — matches canboat's `SENSOR_TIMEOUT`.
pub const SENSOR_TTL: Duration = Duration::from_secs(120);

/// TTL for AIS-like PGNs — matches canboat's `AIS_TIMEOUT`. AIS
/// targets seen recently are still considered "near" for an hour.
pub const AIS_TTL: Duration = Duration::from_secs(3600);

/// Ordered list of secondary-discriminator field names. The first
/// matching field on a decoded record becomes the suffix; the bool
/// flag marks fields that identify AIS records (which get the
/// longer TTL).
const SECONDARY_FIELDS: &[(&str, bool)] = &[
    ("Instance", false),
    ("Reference", false),
    ("User ID", true),
    ("Message ID", true),
    ("Proprietary ID", false),
];

struct CacheEntry {
    /// The analyzer JSON line for this record (no trailing newline).
    line: String,
    /// Truncated-at-first-`:` description used as the `"description"`
    /// field of the per-PGN wrapper object.
    pgn_description: String,
    expires_at: Instant,
}

/// `(pgn, src, secondary_text)` — the secondary text is the
/// readable value of the discriminating field (Instance / Reference
/// / User ID / …), `None` when none of the discriminator fields is
/// present.
type CacheKey = (u32, u8, Option<String>);

pub struct SnapshotStore {
    /// Keyed on [`CacheKey`] so the same PGN / source pair with
    /// different sub-targets (multiple AIS ships, multiple sensor
    /// instances, ...) coexist.
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Stash the analyzer JSON `line` (no trailing newline) for this
    /// decoded record.
    pub fn store(&self, decoded: &DecodedPgn, line: String) {
        let (secondary_text, is_ais) = classify(decoded);
        let ttl = if is_ais { AIS_TTL } else { SENSOR_TTL };
        let entry = CacheEntry {
            line,
            pgn_description: short_description(&decoded.description),
            expires_at: Instant::now() + ttl,
        };
        let key = (decoded.pgn, decoded.src, secondary_text);
        self.cache
            .lock()
            .expect("snapshot cache poisoned")
            .insert(key, entry);
    }

    /// Build the canboat-C-compatible nested JSON dump of every live
    /// entry. Expired entries are pruned in-place under the same
    /// lock. Returns the document as one big `String` ending in `}\n`
    /// (or `\n` if the cache is empty).
    pub fn snapshot(&self) -> String {
        let now = Instant::now();
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");
        guard.retain(|_, v| v.expires_at > now);

        // Group live entries by PGN, preserving per-PGN order by src
        // for readability.
        type GroupKey<'a> = (u8, &'a Option<String>);
        let mut by_pgn: HashMap<u32, Vec<(GroupKey<'_>, &CacheEntry)>> = HashMap::new();
        for ((pgn, src, sec), entry) in guard.iter() {
            by_pgn.entry(*pgn).or_default().push(((*src, sec), entry));
        }

        let mut out = String::with_capacity(8192);
        let mut first_pgn = true;
        for (pgn, entries) in by_pgn.iter() {
            // Use the first entry's pgn_description as the family
            // name — all entries under the same PGN share it.
            let desc = &entries[0].1.pgn_description;
            if first_pgn {
                out.push_str("{\"");
                first_pgn = false;
            } else {
                out.push_str("\n,\"");
            }
            let _ = write!(out, "{pgn}\":\n  {{\"description\":");
            write_json_string(&mut out, desc);
            for ((src, sec), entry) in entries {
                out.push_str("\n  ,\"");
                let _ = write!(out, "{src}");
                if let Some(s) = sec.as_deref() {
                    out.push('_');
                    out.push_str(s);
                }
                out.push_str("\":");
                out.push_str(&entry.line);
            }
            out.push_str("\n  }");
        }
        if first_pgn {
            // No entries at all — emit just a blank line so the
            // client gets something well-defined.
            out.push('\n');
        } else {
            out.push_str("\n}\n");
        }
        out
    }

    /// Number of live entries (no pruning). For tests / future
    /// `--status` endpoint.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.lock().expect("snapshot cache poisoned").len()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Truncate `desc` at the first `:` to produce the PGN-family name
/// canboat C uses for the snapshot's `"description"` header. Mirrors
/// the extractor in `n2kd/main.c`.
fn short_description(desc: &str) -> String {
    match desc.find(':') {
        Some(idx) => desc[..idx].to_string(),
        None => desc.to_string(),
    }
}

/// Find the secondary key value (as text) for `decoded`. Returns
/// `(maybe_text, is_ais)`:
///
/// * `maybe_text` is `Some` when one of `SECONDARY_FIELDS` matched.
/// * `is_ais` is true when any AIS-marker field name appears on the
///   record (separate from which one produced the text).
fn classify(decoded: &DecodedPgn) -> (Option<String>, bool) {
    let mut text: Option<String> = None;
    let mut is_ais = false;
    for (name, ais) in SECONDARY_FIELDS {
        if let Some(field) = decoded.field_by_name(name) {
            if *ais {
                is_ais = true;
            }
            if text.is_none() {
                text = field_value_text(field);
            }
        }
    }
    (text, is_ais)
}

/// Render the discriminating value as the bare text canboat C would
/// produce by scanning the JSON line. Lookups prefer the name (e.g.
/// `"True"`); plain integers stringify; non-discriminator variants
/// return `None`.
fn field_value_text(field: &DecodedField) -> Option<String> {
    match &field.value {
        FieldValue::Lookup { name: Some(n), .. } => Some(n.clone()),
        FieldValue::Lookup { value, name: None } => Some(value.to_string()),
        FieldValue::Integer(v) => Some(v.to_string()),
        FieldValue::Number(v) | FieldValue::Float(v) => Some(format!("{v}")),
        FieldValue::String(s) => Some(s.clone()),
        FieldValue::Mmsi(v) => Some(v.to_string()),
        FieldValue::Pgn { value, .. } => Some(value.to_string()),
        FieldValue::Date(d) => Some(d.to_string()),
        FieldValue::Time { raw, .. } => Some(raw.to_string()),
        _ => None,
    }
}

/// Write `s` as a JSON string literal (just the bits we need: `"`,
/// `\`, and control chars get escaped; the rest goes verbatim).
fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_description_trims_at_colon() {
        assert_eq!(short_description("Simnet: Device Status"), "Simnet");
        assert_eq!(short_description("Navico: Unknown 1"), "Navico");
        assert_eq!(short_description("Rudder"), "Rudder");
        assert_eq!(short_description("ISO Address Claim"), "ISO Address Claim");
    }
}
