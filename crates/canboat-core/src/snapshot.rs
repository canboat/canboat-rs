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

use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

use crate::startup::format_iso_ms;

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
    /// Most recent record's `"timestamp":` field — emitted verbatim
    /// as `"last":` in the status port output.
    last_timestamp: Option<String>,
    /// Number of records stashed under this key so far.
    count: u64,
    /// Monotonic `Instant` of the previous [`SnapshotStore::store`]
    /// call for this key. Used to compute [`Self::interval_ms`] when
    /// the next record arrives.
    previous_store_at: Option<Instant>,
    /// Milliseconds between the two most recent records under this
    /// key (i.e. `now - previous_store_at` evaluated at the last
    /// `store` call). `0` until the second record arrives — matches
    /// canboat C n2kd, where `m_interval` starts at 0 and updates on
    /// each subsequent store.
    interval_ms: u64,
}

/// `(pgn, src, secondary_text)`.
type CacheKey = (u32, u8, Option<String>);

/// Shared snapshot cache. Thread-safe (interior `Mutex`).
///
/// Uses [`IndexMap`] so the snapshot emitter walks entries in
/// insertion order — matching canboat C n2kd's `pgnList[]` first-seen
/// ordering. The first record for a given PGN fixes its position;
/// subsequent records under that key update the value in place.
pub struct SnapshotStore {
    cache: Mutex<IndexMap<CacheKey, CacheEntry>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(IndexMap::new()),
        }
    }

    /// Stash one classified record. Overwrites any prior entry with
    /// the same `(pgn, src, secondary)` key in place — the entry's
    /// insertion order is preserved. Status fields (`count`,
    /// `interval_ms`) accumulate across stores for the same key.
    pub fn store(&self, input: SnapshotInput) {
        let now = Instant::now();
        let expires_at = ttl_for_pgn(input.pgn, input.is_ais).map(|ttl| now + ttl);
        let key = (input.pgn, input.src, input.secondary);
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");

        // Carry count + previous_store_at forward across overwrites
        // so the status port's count/interval reflect the full history
        // for this (pgn, src, secondary) — not just the latest record.
        let prev_count = guard.get(&key).map(|e| e.count).unwrap_or(0);
        let prev_store_at = guard.get(&key).and_then(|e| e.previous_store_at);
        let interval_ms = match prev_store_at {
            Some(t) => now.saturating_duration_since(t).as_millis() as u64,
            None => 0,
        };

        // canboat C uses the wall-clock time of store as the status
        // port's `"last":` field (`m->m_last = now`), not the
        // record's analyzer-JSON timestamp. Mirror that so the status
        // emitter stays byte-comparable with canboat C.
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let entry = CacheEntry {
            line: input.line,
            pgn_short_description: short_description(&input.pgn_description),
            expires_at,
            last_timestamp: Some(format_iso_ms(wall_ms)),
            count: prev_count + 1,
            previous_store_at: Some(now),
            interval_ms,
        };
        guard.insert(key, entry);
    }

    /// Build the canboat-C-compatible nested JSON dump of every live
    /// entry. Expired entries are pruned in-place under the same
    /// lock. Returns the document as one big `String` ending in `}\n`
    /// (or `\n` if the cache is empty).
    pub fn snapshot(&self) -> String {
        self.filtered_snapshot(|_, _| true)
    }

    /// Build the canboat-C-compatible AIS snapshot dump: same shape
    /// as [`Self::snapshot`] but filtered to AIS records.
    ///
    /// canboat C n2kd routes a PGN to the AIS port when:
    ///
    /// * its description starts with `"AIS"`, OR
    /// * the PGN is 129026 (COG & SOG, Rapid Update), OR
    /// * the PGN is 129029 (Position, Rapid Update).
    ///
    /// (See the `(stream == CLIENT_AIS) == (strncmp(desc,"AIS",3)==0)
    /// || pgn == 129026 || pgn == 129029` predicate in
    /// `n2kd/main.c:458`.)
    pub fn ais_snapshot(&self) -> String {
        self.filtered_snapshot(|pgn, entry| {
            *pgn == 129026
                || *pgn == 129029
                || entry.pgn_short_description.starts_with("AIS")
        })
    }

    /// Internal helper: nested-JSON dump like [`Self::snapshot`] but
    /// only emits entries whose `(pgn, entry)` passes `keep`.
    fn filtered_snapshot<F>(&self, keep: F) -> String
    where
        F: Fn(&u32, &CacheEntry) -> bool,
    {
        let now = Instant::now();
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");
        guard.retain(|_, v| v.expires_at.is_none_or(|t| t > now));

        type GroupKey<'a> = (u8, &'a Option<String>);
        let mut by_pgn: IndexMap<u32, Vec<(GroupKey<'_>, &CacheEntry)>> = IndexMap::new();
        for ((pgn, src, sec), entry) in guard.iter() {
            if !keep(pgn, entry) {
                continue;
            }
            by_pgn.entry(*pgn).or_default().push(((*src, sec), entry));
        }

        let mut out = String::with_capacity(2048);
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

    /// Build the canboat-C-compatible status dump: same per-PGN
    /// nested wrapper as [`Self::snapshot`], but each `<src>[_<sec>]`
    /// value is `{"last":..,"interval":..,"count":..}` describing the
    /// receive cadence rather than the latest line. Mirrors canboat
    /// C n2kd's `CLIENT_STATUS_STREAM` path in
    /// `n2kd/main.c:424-447`.
    ///
    /// Like [`Self::snapshot`], expired entries are pruned in-place
    /// and the document ends in `}\n` (or `\n` when the cache is
    /// empty).
    pub fn status_snapshot(&self) -> String {
        let now = Instant::now();
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");
        guard.retain(|_, v| v.expires_at.is_none_or(|t| t > now));

        type GroupKey<'a> = (u8, &'a Option<String>);
        let mut by_pgn: IndexMap<u32, Vec<(GroupKey<'_>, &CacheEntry)>> = IndexMap::new();
        for ((pgn, src, sec), entry) in guard.iter() {
            by_pgn.entry(*pgn).or_default().push(((*src, sec), entry));
        }

        let mut out = String::with_capacity(4096);
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
                out.push_str("\":{\"last\":");
                // canboat C always emits "last" as a quoted string,
                // even when the source line had no timestamp — it
                // falls back to "" in that case (a stored record
                // would always have one in practice).
                write_json_string(&mut out, entry.last_timestamp.as_deref().unwrap_or(""));
                let _ = write!(
                    out,
                    ",\"interval\":{},\"count\":{}}}",
                    entry.interval_ms, entry.count
                );
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
    fn snapshot_walks_pgns_in_insertion_order() {
        let s = SnapshotStore::new();
        let inputs = [
            (65305, 21, "Simnet"),
            (60928, 7, "ISO Address Claim"),
            (127251, 27, "Rate of Turn"),
        ];
        for (pgn, src, desc) in inputs {
            s.store(SnapshotInput {
                pgn,
                src,
                secondary: None,
                is_ais: false,
                pgn_description: desc.to_string(),
                line: format!(r#"{{"pgn":{pgn},"src":{src}}}"#),
            });
        }
        let dump = s.snapshot();
        // First PGN inserted appears first; subsequent PGNs follow in
        // first-seen order. Matches canboat C's pgnList[] ordering.
        let pos_first = dump.find("65305").expect("first pgn present");
        let pos_second = dump.find("60928").expect("second pgn present");
        let pos_third = dump.find("127251").expect("third pgn present");
        assert!(
            pos_first < pos_second && pos_second < pos_third,
            "expected insertion order 65305 < 60928 < 127251, got dump:\n{dump}"
        );
    }

    #[test]
    fn snapshot_preserves_position_when_existing_key_updated() {
        let s = SnapshotStore::new();
        // Insert two PGNs, then update the first with a new line —
        // its position must not move to the end.
        for (pgn, line) in [(65305u32, "first-line"), (127251, "second-line")] {
            s.store(SnapshotInput {
                pgn,
                src: 7,
                secondary: None,
                is_ais: false,
                pgn_description: "x".to_string(),
                line: line.to_string(),
            });
        }
        s.store(SnapshotInput {
            pgn: 65305,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "x".to_string(),
            line: "first-line-updated".to_string(),
        });
        let dump = s.snapshot();
        let pos_first = dump.find("65305").expect("first pgn present");
        let pos_second = dump.find("127251").expect("second pgn present");
        assert!(
            pos_first < pos_second,
            "65305 must still precede 127251 after update; dump:\n{dump}"
        );
        assert!(dump.contains("first-line-updated"));
        assert!(!dump.contains("\"first-line\""));
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

    #[test]
    fn status_snapshot_emits_canboat_c_shape() {
        let s = SnapshotStore::new();
        s.store(SnapshotInput {
            pgn: 65305,
            src: 21,
            secondary: None,
            is_ais: false,
            pgn_description: "Simnet: Device Mode Request".to_string(),
            line: r#"{"pgn":65305}"#.to_string(),
        });
        let status = s.status_snapshot();
        // PGN-family header.
        assert!(status.starts_with("{\"65305\":\n  {\"description\":\"Simnet\""));
        // Per-(src,secondary) entry carries last/interval/count
        // exactly in canboat C's order. `last` is a wall-clock ISO
        // timestamp emitted at store time so we don't assert its
        // exact value; the interval/count fields are deterministic
        // for a first record (0, 1).
        assert!(
            status.contains("\"21\":{\"last\":\""),
            "missing src key with last field: {status}"
        );
        assert!(
            status.contains(",\"interval\":0,\"count\":1}"),
            "missing interval/count tail: {status}"
        );
        assert!(status.ends_with("}\n"));
    }

    #[test]
    fn status_snapshot_count_increments_across_stores() {
        let s = SnapshotStore::new();
        let template = SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: "ignored".to_string(),
        };
        for _ in 0..5 {
            s.store(template.clone());
        }
        assert!(s.status_snapshot().contains("\"count\":5"));
    }

    #[test]
    fn status_snapshot_uses_secondary_in_key() {
        let s = SnapshotStore::new();
        s.store(SnapshotInput {
            pgn: 129039,
            src: 23,
            secondary: Some("244180106".to_string()),
            is_ais: true,
            pgn_description: "AIS Class B Position Report".to_string(),
            line: "{}".to_string(),
        });
        let status = s.status_snapshot();
        assert!(status.contains("\"23_244180106\":{\"last\":"));
    }

    #[test]
    fn ais_snapshot_includes_ais_described_pgns_and_special_pgns() {
        let s = SnapshotStore::new();
        // Non-AIS sensor record — must not appear in the AIS dump.
        s.store(SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: r#"{"pgn":127251}"#.to_string(),
        });
        // AIS-described record (description starts with "AIS").
        s.store(SnapshotInput {
            pgn: 129039,
            src: 23,
            secondary: Some("244180106".to_string()),
            is_ais: true,
            pgn_description: "AIS Class B Position Report".to_string(),
            line: r#"{"pgn":129039}"#.to_string(),
        });
        // PGN 129026 (COG & SOG) — description doesn't start with
        // "AIS" but C still routes it to the AIS port.
        s.store(SnapshotInput {
            pgn: 129026,
            src: 52,
            secondary: None,
            is_ais: false,
            pgn_description: "COG & SOG, Rapid Update".to_string(),
            line: r#"{"pgn":129026}"#.to_string(),
        });
        // PGN 129029 (Position) — same special case.
        s.store(SnapshotInput {
            pgn: 129029,
            src: 52,
            secondary: None,
            is_ais: false,
            pgn_description: "Position, Rapid Update".to_string(),
            line: r#"{"pgn":129029}"#.to_string(),
        });

        let dump = s.ais_snapshot();
        assert!(
            dump.contains("\"129039\""),
            "AIS-described PGN missing:\n{dump}"
        );
        assert!(
            dump.contains("\"129026\""),
            "special-cased PGN 129026 missing:\n{dump}"
        );
        assert!(
            dump.contains("\"129029\""),
            "special-cased PGN 129029 missing:\n{dump}"
        );
        assert!(
            !dump.contains("\"127251\""),
            "non-AIS sensor PGN leaked into ais dump:\n{dump}"
        );
    }

    #[test]
    fn ais_snapshot_empty_returns_blank_line() {
        let s = SnapshotStore::new();
        // Empty cache.
        assert_eq!(s.ais_snapshot(), "\n");
        // Cache has only non-AIS entries — still empty after filter.
        s.store(SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: "{}".to_string(),
        });
        assert_eq!(s.ais_snapshot(), "\n");
    }

    #[test]
    fn status_snapshot_empty_is_blank_line() {
        assert_eq!(SnapshotStore::new().status_snapshot(), "\n");
    }

    /// Helper: realistic 4-record corpus covering the three port
    /// emitters' interesting shapes — multi-PGN, `<src>_<sec>` keys,
    /// AIS-described and special-cased PGNs, mixed timestamps.
    fn fill_canon_corpus(s: &SnapshotStore) {
        s.store(SnapshotInput {
            pgn: 127251,
            src: 7,
            secondary: None,
            is_ais: false,
            pgn_description: "Rate of Turn".to_string(),
            line: r#"{"pgn":127251,"src":7,"fields":{"Rate":0}}"#.to_string(),
        });
        s.store(SnapshotInput {
            pgn: 65305,
            src: 17,
            secondary: None,
            is_ais: false,
            pgn_description: "Simnet: Device Status".to_string(),
            line: r#"{"pgn":65305,"src":17,"fields":{"x":1}}"#.to_string(),
        });
        s.store(SnapshotInput {
            pgn: 129039,
            src: 23,
            secondary: Some("244180106".to_string()),
            is_ais: true,
            pgn_description: "AIS Class B Position Report".to_string(),
            line: r#"{"pgn":129039,"src":23,"fields":{"User ID":"244180106"}}"#.to_string(),
        });
        s.store(SnapshotInput {
            pgn: 129026,
            src: 52,
            secondary: None,
            is_ais: false,
            pgn_description: "COG & SOG, Rapid Update".to_string(),
            line: r#"{"pgn":129026,"src":52,"fields":{"COG":239.6}}"#.to_string(),
        });
    }

    /// Byte-exact lock against canboat C n2kd's JSON snapshot port
    /// output. Any change to the wrapper format, ordering, separators,
    /// or key shape will fail loudly here.
    #[test]
    fn snapshot_byte_exact_canboat_c_layout() {
        let s = SnapshotStore::new();
        fill_canon_corpus(&s);
        let expected = r#"{"127251":
  {"description":"Rate of Turn"
  ,"7":{"pgn":127251,"src":7,"fields":{"Rate":0}}
  }
,"65305":
  {"description":"Simnet"
  ,"17":{"pgn":65305,"src":17,"fields":{"x":1}}
  }
,"129039":
  {"description":"AIS Class B Position Report"
  ,"23_244180106":{"pgn":129039,"src":23,"fields":{"User ID":"244180106"}}
  }
,"129026":
  {"description":"COG & SOG, Rapid Update"
  ,"52":{"pgn":129026,"src":52,"fields":{"COG":239.6}}
  }
}
"#;
        assert_eq!(s.snapshot(), expected);
    }

    /// Byte-exact lock against canboat C n2kd's AIS port output:
    /// AIS-described PGNs + 129026/129029 only, otherwise identical
    /// to the snapshot wrapper.
    #[test]
    fn ais_snapshot_byte_exact_canboat_c_layout() {
        let s = SnapshotStore::new();
        fill_canon_corpus(&s);
        // 127251 and 65305 must be filtered out; 129039 (AIS-prefix)
        // and 129026 (special-case) stay, in first-seen order.
        let expected = r#"{"129039":
  {"description":"AIS Class B Position Report"
  ,"23_244180106":{"pgn":129039,"src":23,"fields":{"User ID":"244180106"}}
  }
,"129026":
  {"description":"COG & SOG, Rapid Update"
  ,"52":{"pgn":129026,"src":52,"fields":{"COG":239.6}}
  }
}
"#;
        assert_eq!(s.ais_snapshot(), expected);
    }

    /// Byte-exact lock for the status port. `last` is wall-clock at
    /// store time (matches canboat C); redact every `"last":"<iso>"`
    /// to a stable placeholder before comparing so the test stays
    /// deterministic. `interval` is 0 for first-record entries —
    /// each key here is stored exactly once.
    #[test]
    fn status_snapshot_byte_exact_canboat_c_layout() {
        let s = SnapshotStore::new();
        fill_canon_corpus(&s);
        let actual = redact_iso_last(&s.status_snapshot());
        let expected = r#"{"127251":
  {"description":"Rate of Turn"
  ,"7":{"last":"<ts>","interval":0,"count":1}
  }
,"65305":
  {"description":"Simnet"
  ,"17":{"last":"<ts>","interval":0,"count":1}
  }
,"129039":
  {"description":"AIS Class B Position Report"
  ,"23_244180106":{"last":"<ts>","interval":0,"count":1}
  }
,"129026":
  {"description":"COG & SOG, Rapid Update"
  ,"52":{"last":"<ts>","interval":0,"count":1}
  }
}
"#;
        assert_eq!(actual, expected);
    }

    /// Replace every `"last":"<24-char-ISO-timestamp>"` with
    /// `"last":"<ts>"` so the byte-exact status test stays stable.
    fn redact_iso_last(s: &str) -> String {
        // Cheap state machine — find `"last":"`, skip to the next
        // `"`, replace the body. No regex dep.
        let mut out = String::with_capacity(s.len());
        let needle = "\"last\":\"";
        let mut rest = s;
        while let Some(idx) = rest.find(needle) {
            out.push_str(&rest[..idx + needle.len()]);
            let after = &rest[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                out.push_str("<ts>");
                rest = &after[end..];
            } else {
                out.push_str(after);
                return out;
            }
        }
        out.push_str(rest);
        out
    }
}
