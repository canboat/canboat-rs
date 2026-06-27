//! Pipeline-side snapshot adapter.
//!
//! The cache, TTL policy, and nested-JSON emitter all live in
//! [`canboat_core::snapshot`]. This module is the pipeline-flavoured
//! input shim: it walks a [`DecodedPgn`] to extract the discriminator
//! text and AIS flag, then hands a [`SnapshotInput`] to the shared
//! [`canboat_core::snapshot::SnapshotStore`].

use std::sync::Arc;

use canboat_core::snapshot::{SnapshotInput, SECONDARY_FIELDS};
use canboat_core::{DecodedField, DecodedPgn, FieldValue};

/// Thin wrapper that keeps the existing `SnapshotStore::store(decoded,
/// line)` API used by pipeline callers, while delegating the cache /
/// TTL / emit responsibilities to [`canboat_core::snapshot`].
pub struct SnapshotStore {
    inner: Arc<canboat_core::snapshot::SnapshotStore>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(canboat_core::snapshot::SnapshotStore::new()),
        }
    }

    /// Stash the analyzer JSON `line` (no trailing newline) for this
    /// decoded record.
    pub fn store(&self, decoded: &DecodedPgn, line: String) {
        let (secondary, is_ais) = classify(decoded);
        self.inner.store(SnapshotInput {
            pgn: decoded.pgn,
            src: decoded.src,
            secondary,
            is_ais,
            pgn_description: decoded.description.to_string(),
            line,
        });
    }

    /// Build the canboat-C-compatible nested JSON snapshot dump
    /// (non-AIS PGNs + the always-shared 129026 / 129029).
    pub fn snapshot(&self) -> String {
        self.inner.snapshot()
    }

    /// Build the AIS snapshot dump — same nested wrapper as
    /// [`Self::snapshot`] but filtered to AIS-described PGNs plus
    /// PGN 129026 / 129029. Matches canboat C `n2kd`'s `port+4`
    /// AIS port output.
    pub fn ais_snapshot(&self) -> String {
        self.inner.ais_snapshot()
    }

    /// Number of live entries (no pruning). For tests / future
    /// `--status` endpoint.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the secondary key value (as text) for `decoded`. Returns
/// `(maybe_text, is_ais)`:
///
/// * `maybe_text` is `Some` when one of [`SECONDARY_FIELDS`] matched.
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
