//! canboat-core: sans-I/O NMEA 2000 (canboat) PGN database, parsers,
//! decoder, and output formatters.
//!
//! This crate does no I/O. All functions are sync. Bytes go in, events
//! and bytes come out. The caller drives the I/O — see `canboat-io`
//! (sync) and `canboat-tokio` (async) for adapters.

pub mod bits;
pub mod db;
pub mod decode;
pub mod format;
pub mod frame;
pub mod output;
pub mod reassembly;
pub mod types;

pub use db::{FieldHandle, LoadError, LoadOptions, PgnDatabase};
pub use decode::{DecodeError, DecodedField, DecodedPgn, FieldValue};
pub use frame::{RawFrame, FASTPACKET_MAX_SIZE};
pub use reassembly::{FramePacketType, Reassembled, Reassembler, ReassemblyError};
pub use types::{
    BitLookupTable, BitLookupValue, FieldInfo, FieldType, IndirectLookupTable, IndirectLookupValue,
    LookupTable, LookupValue, PacketType, PgnInfo,
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
        assert_eq!(&*pgn.id, "isoAddressClaim");
        assert_eq!(pgn.packet_type, PacketType::Single);
        // 10 fields including Unique Number, Manufacturer Code, etc.
        assert_eq!(pgn.fields.len(), 10);
        // Field 2 should be a LOOKUP into MANUFACTURER_CODE.
        let mfr = &pgn.fields[1];
        assert_eq!(mfr.field_type, Some(FieldType::Lookup));
        assert_eq!(mfr.lookup_enumeration.as_deref(), Some("MANUFACTURER_CODE"));
    }

    #[test]
    fn resolves_manufacturer_lookup() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        let table = db.lookup("MANUFACTURER_CODE").expect("table present");
        assert!(table.values.iter().any(|v| v.name == "Navico"));
    }

    #[test]
    fn field_handle_resolves_and_finds() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        // PGN 60928 Unique Number is field order 1.
        let h = db
            .field("isoAddressClaim", "Unique Number")
            .expect("unique number handle");
        assert_eq!(h.field_order, 1);
        // Unknown field name is None.
        assert!(db.field("isoAddressClaim", "no such field").is_none());
        // Unknown PGN id is None.
        assert!(db.field("noSuchPgn", "Unique Number").is_none());
    }

    #[test]
    fn field_handle_indexes_decoded_record() {
        let db = PgnDatabase::load(db_path()).expect("load canboat.json");
        // From canboat/analyzer/tests/pgn-test.in — Unique Number =
        // 1088507, Manufacturer Code = 275 / Navico.
        let mut data: smallvec::SmallVec<[u8; 8]> = smallvec::SmallVec::new();
        for b in [0xfb, 0x9b, 0x70, 0x22, 0x00, 0x9b, 0x50, 0xc0] {
            data.push(b);
        }
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 5,
            dst: 255,
            data,
        };
        let dec = db.decode(&frame).expect("decode");
        // The same handle resolved at startup retrieves the
        // top-level Unique Number field at `O(1)`.
        let h = db
            .field("isoAddressClaim", "Unique Number")
            .expect("handle");
        let f = dec.field(&h).expect("field present");
        assert_eq!(f.value.as_i64(), Some(1_088_507));
    }
}
