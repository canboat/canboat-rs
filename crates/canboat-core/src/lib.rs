//! canboat-core: sans-I/O NMEA 2000 (canboat) PGN database, parsers,
//! decoder, and output formatters.
//!
//! This crate does no I/O. All functions are sync. Bytes go in, events
//! and bytes come out. The caller drives the I/O — see `canboat-io`
//! (sync) and `canboat-tokio` (async) for adapters.

pub mod analyzer_json;
pub mod bits;
pub mod db;
pub mod decode;
pub mod format;
pub mod frame;
pub mod os;
pub mod output;
pub mod reassembly;
mod schema_data;
pub mod snapshot;
pub mod startup;
pub mod types;

pub use db::{FieldHandle, PgnDatabase};
pub use decode::{DecodeError, DecodedField, DecodedPgn, FieldValue};
pub use frame::{FASTPACKET_MAX_SIZE, RawFrame};
pub use reassembly::{FramePacketType, Reassembled, Reassembler, ReassemblyError};
pub use startup::{CANBOAT_BEM, format_iso_ms, startup_record};
pub use types::{
    BitLookupTable, BitLookupValue, FieldInfo, FieldType, IndirectLookupTable, IndirectLookupValue,
    LookupTable, LookupValue, PacketType, PgnInfo,
};

#[cfg(test)]
mod smoke {
    use super::*;

    #[test]
    fn loads_full_database() {
        let db = PgnDatabase::embedded();
        assert!(!db.version.is_empty());
        assert!(!db.schema_version.is_empty());
        assert!(
            db.pgn_count() >= 500,
            "expected >=500 PGNs, got {}",
            db.pgn_count()
        );
    }

    #[test]
    fn finds_iso_address_claim() {
        let db = PgnDatabase::embedded();
        let pgn = db.first_pgn(60928).expect("PGN 60928 must exist");
        assert_eq!(pgn.id, "isoAddressClaim");
        assert_eq!(pgn.packet_type, PacketType::Single);
        assert_eq!(pgn.fields.len(), 10);
        let mfr = &pgn.fields[1];
        assert_eq!(mfr.field_type, Some(FieldType::Lookup));
        assert_eq!(mfr.lookup_enumeration, Some("MANUFACTURER_CODE"));
    }

    #[test]
    fn resolves_manufacturer_lookup() {
        let db = PgnDatabase::embedded();
        let table = db.lookup("MANUFACTURER_CODE").expect("table present");
        assert!(table.values.iter().any(|v| v.name == "Navico"));
    }

    #[test]
    fn field_handle_resolves_and_finds() {
        let db = PgnDatabase::embedded();
        let h = db
            .field("isoAddressClaim", "uniqueNumber")
            .expect("unique number handle");
        assert_eq!(h.field_order, 1);
        assert!(db.field("isoAddressClaim", "noSuchField").is_none());
        assert!(db.field("noSuchPgn", "uniqueNumber").is_none());
    }

    #[test]
    fn field_handle_indexes_decoded_record() {
        let db = PgnDatabase::embedded();
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
        let h = db.field("isoAddressClaim", "uniqueNumber").expect("handle");
        let f = dec.field(&h).expect("field present");
        assert_eq!(f.value.as_i64(), Some(1_088_507));
    }
}
