//! Shared snapshot cache for the canboat C-compatible base-port output.
//!
//! Both the standalone `n2kd` binary and the combined `canboat-pipeline`
//! expose a "full state on connect" TCP port: on a new connection they
//! dump the latest analyzer-JSON line per `(pgn, src, secondary)` tuple
//! and close. canboat C does this in `n2kd/main.c` and the dump shape
//! is:
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
//! - `<secondary>` is the readable value of the first discriminating
//!   field on the record (Instance / Reference / User ID / Message ID
//!   / Proprietary ID) — omitted when none is present.
//! - Lines that have expired (per-PGN-class TTL, see [`ttl_for_pgn`])
//!   are pruned before each snapshot.
//!
//! This module owns the cache, TTL policy, and the nested-JSON
//! emitter. The two binaries differ only in how they classify their
//! input — n2kd scans the analyzer-JSON line as text; canboat-pipeline
//! walks the `DecodedPgn` struct — and they each build a
//! [`SnapshotInput`] from it before calling [`SnapshotStore::store`].

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// TTL for ordinary sensor PGNs — matches canboat C's `SENSOR_TIMEOUT`.
pub const SENSOR_TTL: Duration = Duration::from_secs(120);

/// TTL for AIS-shaped PGNs — matches canboat C's `AIS_TIMEOUT`. AIS
/// targets seen recently are still considered "near" for an hour.
pub const AIS_TTL: Duration = Duration::from_secs(3600);

/// TTL for ISO Address Claim (PGN 60928). Renamed from canboat C's
/// `CLAIM_TIMEOUT` and bumped from 120 s to 3600 s — once a device has
/// claimed an address it should stay in the snapshot for the same
/// duration we trust AIS targets, even on a quiet bus.
pub const DEVICE_CLAIM_TTL: Duration = Duration::from_secs(3600);

/// PGNs that describe a device's identity and never need to expire
/// from the snapshot: Product Information (126996) and Configuration
/// Information (126998). Entries for these stay live until the
/// process restarts. The corresponding `DEVICE_INFO_TIMEOUT` is
/// represented by [`ttl_for_pgn`] returning `None`.
pub const DEVICE_INFO_PGNS: &[u32] = &[126996, 126998];

/// PGN that triggers [`DEVICE_CLAIM_TTL`].
pub const ISO_ADDRESS_CLAIM_PGN: u32 = 60928;

/// Pick the snapshot TTL for `pgn`. Returns `None` for PGNs in
/// [`DEVICE_INFO_PGNS`] — they never expire.
pub fn ttl_for_pgn(pgn: u32, is_ais: bool) -> Option<Duration> {
    if DEVICE_INFO_PGNS.contains(&pgn) {
        None
    } else if pgn == ISO_ADDRESS_CLAIM_PGN {
        Some(DEVICE_CLAIM_TTL)
    } else if is_ais {
        Some(AIS_TTL)
    } else {
        Some(SENSOR_TTL)
    }
}

/// Ordered list of secondary-discriminator field names. The first
/// matching field becomes the suffix on the `<src>_<secondary>` key
/// in the snapshot output; the bool flag marks fields that identify
/// AIS records (which get [`AIS_TTL`]).
///
/// Both binaries iterate this list with their own matching mechanism
/// (n2kd does substring scan over the JSON line; canboat-pipeline
/// reads `decoded.field_by_name`) so the *content* stays in lock-step
/// even when the extraction differs.
pub const SECONDARY_FIELDS: &[(&str, bool)] = &[
    ("Instance", false),
    ("Reference", false),
    ("User ID", true),
    ("Message ID", true),
    ("Proprietary ID", false),
];

/// One record to be stashed in the snapshot cache. The caller is
/// responsible for classifying its input (analyzer-JSON line or
/// `DecodedPgn`) and producing this struct.
#[derive(Debug, Clone)]
pub struct SnapshotInput {
    /// PGN number.
    pub pgn: u32,
    /// Source address on the N2K bus.
    pub src: u8,
    /// Readable value of the first matching [`SECONDARY_FIELDS`] entry,
    /// or `None` if no discriminator field was present.
    pub secondary: Option<String>,
    /// `true` when an AIS-marker secondary field was seen on this
    /// record (separate from which discriminator produced the
    /// `secondary` text).
    pub is_ais: bool,
    /// The PGN's full description, e.g. `"Simnet: Device Status"`.
    /// The store truncates at the first `:` for the snapshot wrapper.
    pub pgn_description: String,
    /// The analyzer-JSON line for this record (no trailing newline).
    pub line: String,
}

struct CacheEntry {
    line: String,
    /// `pgn_description` truncated at the first `:`.
    pgn_short_description: String,
    /// `None` means "never expires" — set for PGNs in
    /// [`DEVICE_INFO_PGNS`].
    expires_at: Option<Instant>,
}

/// `(pgn, src, secondary_text)`.
type CacheKey = (u32, u8, Option<String>);

/// Shared snapshot cache. Thread-safe (interior `Mutex`).
pub struct SnapshotStore {
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Stash one classified record. Overwrites any prior entry with
    /// the same `(pgn, src, secondary)` key.
    pub fn store(&self, input: SnapshotInput) {
        let expires_at = ttl_for_pgn(input.pgn, input.is_ais).map(|ttl| Instant::now() + ttl);
        let entry = CacheEntry {
            line: input.line,
            pgn_short_description: short_description(&input.pgn_description),
            expires_at,
        };
        self.cache
            .lock()
            .expect("snapshot cache poisoned")
            .insert((input.pgn, input.src, input.secondary), entry);
    }

    /// Build the canboat-C-compatible nested JSON dump of every live
    /// entry. Expired entries are pruned in-place under the same
    /// lock. Returns the document as one big `String` ending in `}\n`
    /// (or `\n` if the cache is empty).
    pub fn snapshot(&self) -> String {
        let now = Instant::now();
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");
        guard.retain(|_, v| v.expires_at.is_none_or(|t| t > now));

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
            let desc = &entries[0].1.pgn_short_description;
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
            out.push('\n');
        } else {
            out.push_str("\n}\n");
        }
        out
    }

    /// Number of live entries (no pruning).
    pub fn len(&self) -> usize {
        self.cache.lock().expect("snapshot cache poisoned").len()
    }

    /// `true` when the cache contains no live entries (no pruning).
    pub fn is_empty(&self) -> bool {
        self.cache.lock().expect("snapshot cache poisoned").is_empty()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Truncate `desc` at the first `:` to produce the PGN-family name
/// canboat C uses for the snapshot's `"description"` field.
pub fn short_description(desc: &str) -> String {
    match desc.find(':') {
        Some(idx) => desc[..idx].to_string(),
        None => desc.to_string(),
    }
}

/// Write `s` as a JSON string literal (`"`, `\`, and control chars
/// escaped; the rest goes verbatim).
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
    fn ttl_for_device_info_pgns_is_none() {
        assert!(ttl_for_pgn(126996, false).is_none());
        assert!(ttl_for_pgn(126998, false).is_none());
        // is_ais flag is ignored for device-info PGNs.
        assert!(ttl_for_pgn(126996, true).is_none());
    }

    #[test]
    fn ttl_for_iso_address_claim_is_device_claim() {
        assert_eq!(ttl_for_pgn(60928, false), Some(DEVICE_CLAIM_TTL));
        // The device-info override beats DEVICE_CLAIM but isn't
        // reachable for PGN 60928 — sanity-check the dispatch order
        // stays deterministic.
        assert_eq!(ttl_for_pgn(60928, true), Some(DEVICE_CLAIM_TTL));
    }

    #[test]
    fn ttl_for_ais_record_is_ais_ttl() {
        assert_eq!(ttl_for_pgn(129038, true), Some(AIS_TTL));
        assert_eq!(ttl_for_pgn(129039, true), Some(AIS_TTL));
    }

    #[test]
    fn ttl_for_anything_else_is_sensor_ttl() {
        assert_eq!(ttl_for_pgn(127251, false), Some(SENSOR_TTL));
        assert_eq!(ttl_for_pgn(127257, false), Some(SENSOR_TTL));
    }

    #[test]
    fn device_claim_ttl_is_3600s() {
        assert_eq!(DEVICE_CLAIM_TTL.as_secs(), 3600);
    }

    #[test]
    fn short_description_trims_at_colon() {
        assert_eq!(short_description("Simnet: Device Status"), "Simnet");
        assert_eq!(short_description("Navico: Unknown 1"), "Navico");
        assert_eq!(short_description("Rudder"), "Rudder");
        assert_eq!(short_description("ISO Address Claim"), "ISO Address Claim");
    }

    #[test]
    fn snapshot_empty_returns_blank_line() {
        let s = SnapshotStore::new();
        assert_eq!(s.snapshot(), "\n");
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn snapshot_wraps_one_entry_in_nested_object() {
        let s = SnapshotStore::new();
        s.store(SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: r#"{"pgn":127251,"src":7,"fields":{"Rate":0}}"#.to_string(),
        });
        let dump = s.snapshot();
        assert!(dump.starts_with("{\"127251\":\n  {\"description\":\"Rate of Turn\""));
        assert!(dump.contains("\"7\":{\"pgn\":127251,\"src\":7,\"fields\":{\"Rate\":0}}"));
        assert!(dump.ends_with("}\n"));
    }

    #[test]
    fn snapshot_keys_src_with_secondary_when_present() {
        let s = SnapshotStore::new();
        s.store(SnapshotInput {
            pgn: 129039,
            src: 23,
            secondary: Some("244180106".to_string()),
            is_ais: true,
            pgn_description: "AIS Class B Position Report".to_string(),
            line: "{...}".to_string(),
        });
        let dump = s.snapshot();
        assert!(
            dump.contains("\"23_244180106\":"),
            "expected src_secondary key, got:\n{dump}"
        );
        assert!(
            dump.contains("\"description\":\"AIS Class B Position Report\""),
            "AIS description has no colon — should not be truncated"
        );
    }

    #[test]
    fn store_overwrites_same_key() {
        let s = SnapshotStore::new();
        let mut input = SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: "old".to_string(),
        };
        s.store(input.clone());
        input.line = "new".to_string();
        s.store(input);
        assert_eq!(s.len(), 1);
        assert!(s.snapshot().contains("new"));
        assert!(!s.snapshot().contains("old"));
    }
}
