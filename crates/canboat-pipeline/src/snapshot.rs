//! Snapshot cache for the "full state on connect" TCP port.
//!
//! Mirrors canboat C `n2kd`'s base-port behaviour: keep the latest
//! analyzer JSON line per `(pgn, src, secondary)` tuple, expire stale
//! entries on a per-PGN-class TTL, and dump everything still alive
//! whenever a TCP client connects.
//!
//! The `secondary` discriminator lets the same PGN from the same
//! source produce multiple cache entries when the payload identifies
//! a sub-target — e.g. multiple AIS ships under PGN 129038, or
//! multiple sensor instances of PGN 130312 from the same MFD. The
//! key set + AIS-vs-sensor classification mirrors n2kd's
//! `SECONDARY_KEYS`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use canboat_core::{DecodedField, DecodedPgn, FieldValue};

/// TTL for non-AIS PGNs — matches canboat's `SENSOR_TIMEOUT`. After
/// this the entry is removed from the snapshot.
pub const SENSOR_TTL: Duration = Duration::from_secs(120);

/// TTL for AIS-like PGNs — matches canboat's `AIS_TIMEOUT`. AIS
/// targets seen recently are still considered "near" for an hour.
pub const AIS_TTL: Duration = Duration::from_secs(3600);

/// Ordered list of secondary-discriminator field names. The first
/// matching field on a decoded record is used; the boolean flag
/// marks fields that identify AIS records (which get the longer
/// TTL).
const SECONDARY_FIELDS: &[(&str, bool)] = &[
    ("Instance", false),
    ("Reference", false),
    ("User ID", true),
    ("Message ID", true),
    ("Proprietary ID", false),
];

#[derive(Clone)]
struct CacheEntry {
    line: String,
    expires_at: Instant,
}

pub struct SnapshotStore {
    cache: Mutex<HashMap<(u32, u8, u64), CacheEntry>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Stash the analyzer JSON `line` (already trailing-newline-
    /// terminated) for the given decoded record, using the canboat-
    /// style secondary key.
    pub fn store(&self, decoded: &DecodedPgn, line: String) {
        let (secondary, is_ais) = classify(decoded);
        let ttl = if is_ais { AIS_TTL } else { SENSOR_TTL };
        let entry = CacheEntry {
            line,
            expires_at: Instant::now() + ttl,
        };
        let key = (decoded.pgn, decoded.src, secondary);
        self.cache
            .lock()
            .expect("snapshot cache poisoned")
            .insert(key, entry);
    }

    /// Return every live (un-expired) cached line. Expired entries
    /// are pruned in-place. Order is unspecified (HashMap iteration);
    /// canboat C n2kd makes no guarantee here either.
    pub fn snapshot(&self) -> Vec<String> {
        let now = Instant::now();
        let mut guard = self.cache.lock().expect("snapshot cache poisoned");
        guard.retain(|_, v| v.expires_at > now);
        guard.values().map(|v| v.line.clone()).collect()
    }

    /// Number of live entries (no pruning). Convenient for tests
    /// and for a future `--status` endpoint that wants a quick count.
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

/// Find the secondary key for `decoded`. Returns `(hash, is_ais)`:
///
/// * `hash` is a djb2 hash of the discriminating field value (0 when
///   no discriminator field is present — most PGNs).
/// * `is_ais` is true when any AIS-marker field name appears on the
///   record (separate from which one produced the `hash`).
fn classify(decoded: &DecodedPgn) -> (u64, bool) {
    let mut hash = 0u64;
    let mut found_hash = false;
    let mut is_ais = false;
    for (name, ais) in SECONDARY_FIELDS {
        if let Some(field) = decoded.field_by_name(name) {
            if *ais {
                is_ais = true;
            }
            if !found_hash {
                hash = hash_field_value(field);
                found_hash = true;
            }
        }
    }
    (hash, is_ais)
}

/// djb2 hash of a field's value, picking whichever representation
/// the `FieldValue` carries. The point is *stability* — same field
/// value → same hash — not cryptographic strength.
fn hash_field_value(field: &DecodedField) -> u64 {
    let mut h: u64 = 5381;
    match &field.value {
        FieldValue::Lookup { value, .. } | FieldValue::BitField { value, .. } => {
            h = djb2_mix_u64(h, *value);
        }
        FieldValue::Integer(v) => h = djb2_mix_u64(h, *v as u64),
        FieldValue::Number(v) | FieldValue::Float(v) => h = djb2_mix_u64(h, v.to_bits()),
        FieldValue::String(s) => {
            for b in s.bytes() {
                h = (h.wrapping_shl(5)).wrapping_add(h).wrapping_add(b as u64);
            }
        }
        FieldValue::Mmsi(v) => h = djb2_mix_u64(h, *v as u64),
        FieldValue::Pgn { value, .. } => h = djb2_mix_u64(h, *value as u64),
        FieldValue::Date(d) => h = djb2_mix_u64(h, *d as u64),
        FieldValue::Time { raw, .. } => h = djb2_mix_u64(h, *raw as u64),
        // For variants without a useful scalar (Binary, IsoName,
        // Reserved, etc.) leave the hash at its seed — these don't
        // appear as discriminators in canboat's SECONDARY_KEYS set.
        _ => {}
    }
    h
}

#[inline]
fn djb2_mix_u64(mut h: u64, v: u64) -> u64 {
    for shift in (0..64).step_by(8) {
        let byte = (v >> shift) & 0xff;
        h = (h.wrapping_shl(5)).wrapping_add(h).wrapping_add(byte);
    }
    h
}
