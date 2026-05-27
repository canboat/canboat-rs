//! PGN database — loaded from `canboat.json` and indexed for lookup.
//!
//! The database is the static reference for decoding. It is read-only
//! after construction. Wrap in an `Arc` when sharing across stages.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use serde::Deserialize;

use crate::types::{BitLookupTable, FieldInfo, IndirectLookupTable, LookupTable, PgnInfo};

/// Multiplier to convert radians to degrees.
const RAD_TO_DEG: f64 = 180.0 / std::f64::consts::PI;

/// Apply canboat's non-SI display-time conversions to one field.
///
/// Matches the `fixupTypes` logic in `canboat/analyzer/fieldtype.c`:
///   - `rad`  → `deg`     (resolution × 180/π,    precision = 1)
///   - `rad/s` → `deg/s`  (resolution × 180/π)
///   - `K`    → `C`       (unit_offset = -273.15) for unsigned-K only
///   - `Pa`   → `bar`     (resolution / 100000,   precision = 3)
///   - `C`    → `Ah`      (resolution / 3600)     [coulomb → amp-hour]
fn apply_non_si_unit_fixup(f: &mut FieldInfo) {
    // Canboat hard-codes 7-decimal display precision for lat/lon
    // (analyzer/print.c::fieldPrintLatLon → `%10.7f`). Mirror that
    // here so the precision_for() fallback doesn't print 16 digits
    // for the 64-bit lat/lon resolution of 1e-16.
    if let Some(pq) = f.physical_quantity.as_deref() {
        if pq == "GEOGRAPHICAL_LATITUDE" || pq == "GEOGRAPHICAL_LONGITUDE" {
            f.precision = 7;
        }
    }

    let Some(unit) = f.unit.as_deref() else {
        return;
    };
    match unit {
        "rad" => {
            if let Some(r) = f.resolution.as_mut() {
                *r *= RAD_TO_DEG;
            }
            if let Some(v) = f.range_min.as_mut() {
                *v *= RAD_TO_DEG;
            }
            if let Some(v) = f.range_max.as_mut() {
                *v = (*v * RAD_TO_DEG).max(360.0);
            }
            f.unit = Some("deg".to_string());
            f.precision = 1;
        }
        "rad/s" => {
            if let Some(r) = f.resolution.as_mut() {
                *r *= RAD_TO_DEG;
            }
            if let Some(v) = f.range_min.as_mut() {
                *v *= RAD_TO_DEG;
            }
            if let Some(v) = f.range_max.as_mut() {
                *v *= RAD_TO_DEG;
            }
            f.unit = Some("deg/s".to_string());
        }
        "K" if !f.signed.unwrap_or(false) => {
            f.unit_offset = -273.15;
            if let Some(v) = f.range_min.as_mut() {
                *v += -273.15;
            }
            if let Some(v) = f.range_max.as_mut() {
                // Match the typo-faithful behaviour of canboat (it
                // subtracts 275.15 from rangeMax; harmless for our
                // purposes since the threshold check uses the wire-max
                // anyway).
                *v += -275.15;
            }
            f.unit = Some("C".to_string());
        }
        "Pa" => {
            if let Some(r) = f.resolution.as_mut() {
                *r /= 100_000.0;
            }
            if let Some(v) = f.range_min.as_mut() {
                *v /= 100_000.0;
            }
            if let Some(v) = f.range_max.as_mut() {
                *v /= 100_000.0;
            }
            f.unit = Some("bar".to_string());
            f.precision = 3;
        }
        "C" => {
            if let Some(r) = f.resolution.as_mut() {
                *r /= 3600.0;
            }
            if let Some(v) = f.range_min.as_mut() {
                *v /= 3600.0;
            }
            if let Some(v) = f.range_max.as_mut() {
                *v /= 3600.0;
            }
            f.unit = Some("Ah".to_string());
        }
        _ => {}
    }
}

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
    #[serde(default)]
    lookup_indirect_enumerations: Vec<IndirectLookupTable>,
    /// Stored raw — decoded when the FIELD_TYPE_ENUMERATION decoder
    /// arrives (deferred to v0.x).
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
    /// name → indirect (two-key) lookup table.
    indirect_lookups: HashMap<String, IndirectLookupTable>,

    /// Reserved for future use — not yet indexed.
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

    /// Merge additional PGN entries from a canboat-shaped JSON blob
    /// into the loaded database. Used for the synthetic PGN range
    /// (CANBOAT_BEM / ACTISENSE_BEM / IKONVERT_BEM, starting at
    /// 0x40000) that canboat's C analyzer defines in `analyzer/pgn.h`
    /// rather than `docs/canboat.json`. Each new PGN goes through the
    /// same non-SI unit fix-up the loader applies on first load, then
    /// is appended to the `pgns` list and indexed.
    pub fn merge_pgns_from_json(&mut self, json: &str) -> Result<(), LoadError> {
        #[derive(Deserialize)]
        struct PgnList {
            #[serde(rename = "PGNs")]
            pgns: Vec<PgnInfo>,
        }
        let mut list: PgnList = serde_json::from_str(json)?;
        for pgn in &mut list.pgns {
            for f in &mut pgn.fields {
                apply_non_si_unit_fixup(f);
            }
        }
        let base = self.pgns.len();
        for (offset, p) in list.pgns.iter().enumerate() {
            self.pgn_index.entry(p.pgn).or_default().push(base + offset);
        }
        self.pgns.extend(list.pgns);
        Ok(())
    }

    fn from_raw(mut raw: CanboatJson) -> Self {
        // Apply canboat's non-SI unit conversions to every field once
        // at load time (mirrors `fieldtype.c::fixupTypes` in canboat).
        // After this pass, decoders and formatters can use the field
        // metadata verbatim: resolution / unit / precision / unit_offset
        // all reflect the displayed value, not the wire value.
        for pgn in &mut raw.pgns {
            for f in &mut pgn.fields {
                apply_non_si_unit_fixup(f);
            }
        }
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
        let indirect_lookups = raw
            .lookup_indirect_enumerations
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
            indirect_lookups,
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

    /// Find a catch-all "fallback" PGN definition for an unknown
    /// `pgn`. Mirrors canboat's `searchForUnknownPgn` (analyzer/pgn.c):
    /// walk the load-ordered list, remember the most recent entry with
    /// `Fallback: true`, and stop once we pass `pgn`. The accumulated
    /// fallback is returned — these definitions describe the generic
    /// "0x1FF00-0x1FFFF: Manufacturer Specific fast-packet
    /// non-addressed"–style stubs.
    pub fn fallback_pgn(&self, pgn: u32) -> Option<&PgnInfo> {
        let mut fallback: Option<&PgnInfo> = None;
        for info in &self.pgns {
            if info.fallback == Some(true) {
                fallback = Some(info);
            }
            if info.pgn >= pgn {
                break;
            }
        }
        fallback
    }

    /// Look up an enum table by name (e.g. `"MANUFACTURER_CODE"`).
    pub fn lookup(&self, name: &str) -> Option<&LookupTable> {
        self.lookups.get(name)
    }

    /// Look up a bit-flag table by name.
    pub fn bit_lookup(&self, name: &str) -> Option<&BitLookupTable> {
        self.bit_lookups.get(name)
    }

    /// Resolve `(value1, value2)` through an INDIRECT_LOOKUP table.
    pub fn indirect_lookup(&self, name: &str, value1: u64, value2: u64) -> Option<&str> {
        self.indirect_lookups
            .get(name)?
            .values
            .iter()
            .find(|v| v.value1 == value1 && v.value2 == value2)
            .map(|v| v.name.as_str())
    }
}
