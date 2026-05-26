//! PGN database — loaded from `canboat.json` and indexed for lookup.
//!
//! The database is the static reference for decoding. It is read-only
//! after construction. Wrap in an `Arc` when sharing across stages.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use serde::Deserialize;

use crate::types::{BitLookupTable, LookupTable, PgnInfo};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("I/O error reading PGN database: {0}")]
    Io(#[from] io::Error),
    #[error("malformed PGN database JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Raw top-level shape of `canboat.json` — only the fields we currently
/// use. Unknown keys are silently ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CanboatJson {
    schema_version: String,
    version: String,
    #[serde(rename = "PGNs")]
    pgns: Vec<PgnInfo>,
    #[serde(default)]
    lookup_enumerations: Vec<LookupTable>,
    #[serde(default)]
    lookup_bit_enumerations: Vec<BitLookupTable>,
    /// Stored raw — these are decoded lazily by the field types that use
    /// them (deferred to v0.x).
    #[serde(default)]
    lookup_indirect_enumerations: Vec<serde_json::Value>,
    #[serde(default)]
    lookup_field_type_enumerations: Vec<serde_json::Value>,
}

/// The canboat PGN database.
pub struct PgnDatabase {
    /// canboat.json `SchemaVersion`.
    pub schema_version: String,
    /// canboat.json `Version` (the upstream canboat release).
    pub version: String,

    pgns: Vec<PgnInfo>,
    /// pgn number → indices into `pgns`. Some PGNs have multiple
    /// definitions disambiguated by `Match` field values.
    pgn_index: HashMap<u32, Vec<usize>>,

    /// name → enum table.
    lookups: HashMap<String, LookupTable>,
    /// name → bit-flag table.
    bit_lookups: HashMap<String, BitLookupTable>,

    /// Reserved for future use — not yet indexed.
    _indirect_raw: Vec<serde_json::Value>,
    _field_type_raw: Vec<serde_json::Value>,
}

impl PgnDatabase {
    /// Load and parse a canboat database JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }

    /// Load from any `Read` source (file, bytes, embedded blob).
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, LoadError> {
        let raw: CanboatJson = serde_json::from_reader(reader)?;
        Ok(Self::from_raw(raw))
    }

    /// Load from a JSON string in memory.
    pub fn from_json_str(json: &str) -> Result<Self, LoadError> {
        let raw: CanboatJson = serde_json::from_str(json)?;
        Ok(Self::from_raw(raw))
    }

    fn from_raw(raw: CanboatJson) -> Self {
        let mut pgn_index: HashMap<u32, Vec<usize>> = HashMap::new();
        for (idx, p) in raw.pgns.iter().enumerate() {
            pgn_index.entry(p.pgn).or_default().push(idx);
        }
        let lookups = raw
            .lookup_enumerations
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect();
        let bit_lookups = raw
            .lookup_bit_enumerations
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect();
        Self {
            schema_version: raw.schema_version,
            version: raw.version,
            pgns: raw.pgns,
            pgn_index,
            lookups,
            bit_lookups,
            _indirect_raw: raw.lookup_indirect_enumerations,
            _field_type_raw: raw.lookup_field_type_enumerations,
        }
    }

    /// Total number of PGN definitions (including manufacturer variants).
    pub fn pgn_count(&self) -> usize {
        self.pgns.len()
    }

    /// Iterate over every PGN definition in load order.
    pub fn pgns(&self) -> impl Iterator<Item = &PgnInfo> {
        self.pgns.iter()
    }

    /// Iterator over every definition for a given PGN number.
    /// PGNs may have multiple definitions disambiguated by `Match`
    /// field values (manufacturer variants).
    pub fn pgn_variants(&self, pgn: u32) -> impl Iterator<Item = &PgnInfo> {
        self.pgn_index
            .get(&pgn)
            .into_iter()
            .flatten()
            .map(move |&i| &self.pgns[i])
    }

    /// First definition for a PGN number, or `None`.
    pub fn first_pgn(&self, pgn: u32) -> Option<&PgnInfo> {
        self.pgn_index
            .get(&pgn)
            .and_then(|v| v.first())
            .map(|&i| &self.pgns[i])
    }

    /// Look up an enum table by name (e.g. `"MANUFACTURER_CODE"`).
    pub fn lookup(&self, name: &str) -> Option<&LookupTable> {
        self.lookups.get(name)
    }

    /// Look up a bit-flag table by name.
    pub fn bit_lookup(&self, name: &str) -> Option<&BitLookupTable> {
        self.bit_lookups.get(name)
    }
}
