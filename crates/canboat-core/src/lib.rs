//! canboat-core: sans-I/O NMEA 2000 (canboat) PGN database, parsers,
//! decoder, and output formatters.
//!
//! This crate does no I/O. All functions are sync. Bytes go in, events
//! and bytes come out. The caller drives the I/O — see `canboat-io`
//! (sync) and `canboat-tokio` (async) for adapters.

pub mod db;
pub mod types;

pub use db::{LoadError, PgnDatabase};
pub use types::{
    BitLookupTable, BitLookupValue, FieldInfo, FieldType, LookupTable, LookupValue, PacketType,
    PgnInfo,
};

#[cfg(test)]
mod smoke {
    use super::*;
    use std::path::PathBuf;

    /// Path to the vendored canboat.json, relative to the workspace root.
    fn db_path() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // crates/canboat-core/ → workspace root → data/canboat.json
        manifest
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .join("data")
            .join("canboat.json")
    }

    #[test]
    fn loads_full_database() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        // The vendored database is canboat 6.1.9 / schema 2.3.0.
        assert!(!db.version.is_empty());
        assert!(!db.schema_version.is_empty());
        // Sanity check on PGN count — upstream had 543 in 6.1.9.
        assert!(
            db.pgn_count() >= 500,
            "expected >=500 PGNs, got {}",
            db.pgn_count()
        );
    }

    #[test]
    fn finds_iso_address_claim() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        let pgn = db.first_pgn(60928).expect("PGN 60928 must exist");
        assert_eq!(pgn.id, "isoAddressClaim");
        assert_eq!(pgn.packet_type, PacketType::Single);
        // 10 fields including Unique Number, Manufacturer Code, etc.
        assert_eq!(pgn.fields.len(), 10);
        // Field 2 should be a LOOKUP into MANUFACTURER_CODE.
        let mfr = &pgn.fields[1];
        assert_eq!(mfr.field_type, Some(FieldType::Lookup));
        assert_eq!(
            mfr.lookup_enumeration.as_deref(),
            Some("MANUFACTURER_CODE")
        );
    }

    #[test]
    fn resolves_manufacturer_lookup() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        let table = db.lookup("MANUFACTURER_CODE").expect("table present");
        assert!(table.values.iter().any(|v| v.name == "Navico"));
    }
}
