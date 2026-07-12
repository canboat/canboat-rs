// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat` — NMEA 2000 (canboat) decoding, encoding, and live-bus access.
//!
//! This is the single crate an external consumer depends on. Its public
//! surface is deliberately small and feature-gated; think in terms of
//! [`Frame`] ⇆ [`DecodedPgn`] (decode) and [`PgnBuilder`] → [`Frame`]
//! (encode). See `docs/library-api-plan.md` for the full design.
//!
//! # Quick start
//!
//! Everything below is in the baseline `decode` feature — no I/O, no threads.
//! The pivot is [`Frame`] (a raw PGN on the wire) and [`Database`] (the
//! compiled canboat schema). Fields are addressed by a generated **`FieldId`
//! constant** ([`ids::field`]) — the recommended path on both sides:
//! [`PgnBuilder::push`] to encode, [`DecodedPgn::field`] to read back. It is
//! `O(1)` (a single array index by the field's schema position) and
//! compile-checked: a typo, or a field from the wrong PGN, fails the build
//! instead of erroring at runtime.
//!
//! ```
//! use canboat::{Database, EncodeValue, FieldValue, Units};
//! use canboat::ids::field::wind_data as wd;
//!
//! let db = Database::embedded(Units::Metric);
//!
//! // Encode PGN 130306 "Wind Data": 5.23 m/s at 1.5 rad, apparent wind.
//! // Unset fields (and proprietary manufacturer/industry selectors) fall
//! // back to their schema defaults.
//! let frame: canboat::Frame = db
//!     .encode("windData")?
//!     .push(wd::WIND_SPEED, 5.23)?
//!     .push(wd::WIND_ANGLE, 1.5)?
//!     .push(wd::REFERENCE, EncodeValue::Lookup("Apparent".into()))?
//!     .build()?;
//! assert_eq!(frame.pgn, 130306);
//!
//! // Decode it back — the read side mirrors the write side.
//! let decoded = db.decode(&frame).expect("valid frame decodes");
//! assert_eq!(decoded.id, "windData");
//! match &decoded.field(wd::REFERENCE).unwrap().value {
//!     FieldValue::Lookup { name, .. } => assert_eq!(*name, Some("Apparent")),
//!     other => panic!("unexpected: {other:?}"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! No constant to hand (the field is chosen at runtime — a config-driven
//! encoder, a CLI arg)? Use the `*_by_name` twins,
//! [`PgnBuilder::push_by_name`] and [`DecodedPgn::field_by_name`] — an `O(n)`
//! scan by schema name, resolved at runtime rather than compile time:
//!
//! ```
//! # use canboat::{Database, EncodeValue, Units};
//! # let db = Database::embedded(Units::Metric);
//! let frame = db
//!     .encode("windData")?
//!     .push_by_name("Wind Speed", 5.23)?
//!     .push_by_name("Reference", EncodeValue::Lookup("Apparent".into()))?
//!     .build()?;
//! assert_eq!(db.decode(&frame).unwrap().field_by_name("Wind Speed").is_some(), true);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Lookup (enum) fields
//!
//! A `LOOKUP` field carries a raw integer that maps to a label. Encode it by
//! **label** ([`EncodeValue::Lookup`], shown above) or by **raw value**
//! ([`EncodeValue::Int`]); on decode, [`FieldValue::Lookup`] gives you both
//! the number and its resolved name, so you can match on whichever you have:
//!
//! ```
//! # use canboat::{Database, EncodeValue, FieldValue, Units};
//! # use canboat::ids::field::wind_data as wd;
//! # let db = Database::embedded(Units::Metric);
//! // Reference = 2 is "Apparent" — set the enum's raw value directly.
//! let frame = db.encode("windData")?.push(wd::REFERENCE, EncodeValue::Int(2))?.build()?;
//!
//! let decoded = db.decode(&frame).unwrap();
//! match &decoded.field(wd::REFERENCE).unwrap().value {
//!     FieldValue::Lookup { value, name } => {
//!         assert_eq!(*value, 2);                 // the raw enum value
//!         assert_eq!(*name, Some("Apparent"));   // its schema label, if known
//!     }
//!     _ => unreachable!(),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! To read frames off a real transport, add the `io` feature and feed a
//! [`read::FrameSource`] into a [`read::Decoder`]; to own a live CAN bus with
//! the address-claim, quirks, and TCP serving layer already assembled, add the
//! `bridge` feature and drive a `bridge::Bridge`.
//!
//! # Features
//!
//! * `decode` (baseline) — sans-I/O core: schema, decode, encode, formatters.
//!   No threads, no async, no sockets.
//! * `io` — byte-source readers (`read::*Reader`) for serial / files / text.
//! * `wire` — cross-process `wire` transport (postcard `WirePgn` + `Hello`).
//! * `node` — `device`: be a compliant N2K node (address claim + responder).
//! * `bridge` — `bridge`: the live CAN bus, fully assembled.
//! * `nmea0183`, `ais` — output-formatter sub-features.
//!
//! The `cli` feature (the package default) builds the `canboat` binary and is
//! not part of this library's public contract. Library consumers select
//! `default-features = false` plus the features they need.
#![cfg_attr(feature = "decode", deny(missing_docs))]

// ─────────────────────────── decode (baseline) ───────────────────────────
// Core types, re-exported at the crate root under their locked public names.
// The internal canboat-core names (PgnDatabase, RawFrame, FieldRef) are mapped
// to the public names here; FieldHandle was collapsed into FieldId in Phase 1.

#[cfg(feature = "decode")]
pub use canboat_core::{
    ADDR_GLOBAL,
    ADDR_NULL,
    CANBOAT_JSON_VERSION as CANBOAT_VERSION,
    DecodeError,
    DecodedField,
    // decode (inbound)
    DecodedPgn,
    EncodeError,
    EncodeValue,
    FASTPACKET_MAX_SIZE,
    // the single field-addressing type (FieldHandle was removed in Phase 1)
    FieldRef as FieldId,
    FieldValue,
    FramePacketType,
    // encode (outbound)
    PgnBuilder,
    // schema & database
    PgnDatabase as Database,
    RAWFRAME_MAX_SIZE as FRAME_MAX_SIZE,
    // frames — the wire-side pivot
    RawFrame as Frame,
    Reassembled,
    // fast-packet reassembly
    Reassembler,
    ReassemblyError,
    // versions / identity
    SCHEMA_HASH,
    Units,
};

/// Schema introspection: the read-facing shape of the PGN/field definitions,
/// for consumers that treat the database as metadata (codegen, UI forms).
#[cfg(feature = "decode")]
pub mod schema {
    pub use canboat_core::{
        BitLookupTable, BitLookupValue, FieldInfo, FieldType, IndirectLookupTable,
        IndirectLookupValue, LookupTable, LookupValue, PacketType, PgnInfo,
    };
}

/// Generated compile-time identity constants: `ids::pgn::WIND_DATA`,
/// `ids::field::wind_data::WIND_ANGLE`. Resolve a field once, at build time.
#[cfg(feature = "decode")]
pub mod ids {
    pub use canboat_core::{field, pgn};
}

/// Turn a [`DecodedPgn`] back into bytes/text. `write_nmea0183` / `write_ais`
/// land here when the `nmea0183` / `ais` features are wired.
#[cfg(feature = "decode")]
pub mod output {
    pub use canboat_core::output::{CamelCase, JsonOptions, write_json};
}

/// Inbound: turn a byte source into a stream of [`DecodedPgn`].
///
/// [`FrameSource`](read::FrameSource) is the bring-your-own-transport seam —
/// implement it over your own CAN driver, then feed it to
/// [`Decoder`](read::Decoder) to get decoded records. Ready-made readers for
/// ASCII line formats, `.ebl` logs, and `.pcap`/`.nif` captures arrive with the
/// `io` feature. [`from_analyzer_json`](read::from_analyzer_json) rehydrates an
/// already-decoded analyzer-JSON line.
#[cfg(feature = "decode")]
pub mod read {
    pub use canboat_core::json_to_decoded as from_analyzer_json;
    pub use canboat_core::{Decoder, FrameSource};

    /// A [`FrameSource`] over an Actisense `.ebl` binary log.
    #[cfg(feature = "io")]
    pub use canboat_io::EblReader;
    /// A [`FrameSource`] over any canboat ASCII line format (PLAIN / FAST /
    /// Actisense / YDWG-02 / iKonvert): honours `# format=` headers, otherwise
    /// autodetects. Wrap a file, a stdin lock, or [`open_capture`].
    #[cfg(feature = "io")]
    pub use canboat_io::LineFrameReader as PlainReader;

    /// Open a capture as a [`PlainReader`] ready for a [`Decoder`]: a plain
    /// PLAIN/FAST text log, or a `.pcap` / `.pcap.gz` / `.nif` container
    /// (auto-detected and unwrapped to its PLAIN payload).
    #[cfg(feature = "io")]
    pub fn open_capture(
        path: &std::path::Path,
    ) -> std::io::Result<PlainReader<Box<dyn std::io::BufRead>>> {
        let br: Box<dyn std::io::BufRead> = if canboat_io::container::is_container(path) {
            canboat_io::container::plain_reader(path, canboat_io::container::Options::default())?
        } else {
            Box::new(std::io::BufReader::new(std::fs::File::open(path)?))
        };
        Ok(PlainReader::new(br))
    }
}

// ─────────────────────────────── wire ────────────────────────────────────

/// Cross-process transport: send decoded records between processes that link
/// a byte-identical schema, guarded by the [`Hello`](wire::Hello) handshake.
#[cfg(feature = "wire")]
pub mod wire {
    pub use canboat_wire::{
        FrameError, Hello, HelloError, MAX_FRAME_LEN, PgnIndex, WirePgn, append_frame,
        decode_frame, pgn_id_hash, try_read_frame,
    };
}

// ─────────────────────────────── device ──────────────────────────────────

/// Be a compliant N2K node without owning a transport, all [`Frame`]-in /
/// [`Frame`]-out — the caller owns the bus.
///
/// [`Name`](device::Name) builds the 64-bit ISO NAME; [`Claimer`](device::Claimer)
/// is the address-claim state machine (NAME arbitration). The response builders —
/// [`ProductInfo`](device::ProductInfo) (PGN 126996) and the
/// [`pgn_list_frames`](device::pgn_list_frames) /
/// [`iso_ack_frame`](device::iso_ack_frame) /
/// [`heartbeat_frame`](device::heartbeat_frame) helpers — emit the frames a node
/// answers discovery with; the caller drives them from its own event loop (as the
/// socketcan gateway and the motion quirk both do).
#[cfg(feature = "node")]
pub mod device {
    pub use canboat_io::address_claim::{AddressClaim as Claimer, ClaimState};
    pub use canboat_io::name::Name;
    pub use canboat_io::nmea_responder::{
        ProductInfo, heartbeat_frame, iso_ack_frame, pgn_list_frames,
    };
}

// ─────────────────────────────── bridge ──────────────────────────────────

/// The live CAN bus, fully assembled: own a socketcan interface (or another
/// [`FrameSource`](read) via a device backend), claim an address, apply
/// quirks, and expose an in-process [`DecodedPgn`] stream plus an optional
/// TCP serving layer (the 2597–2606 ports the `canboat server` daemon opens).
///
/// [`Bridge::new`](bridge::Bridge::new) builds the core;
/// [`Bridge::decoded`](bridge::Bridge::decoded) taps the decoded stream,
/// [`Bridge::serve`](bridge::Bridge::serve) opens the TCP ports, and
/// [`Bridge::spawn`](bridge::Bridge::spawn) (or the blocking
/// [`Bridge::run`](bridge::Bridge::run)) starts the bus.
/// [`BridgeConfig`](bridge::BridgeConfig) is the plain, clap-free config;
/// [`Quirk`](bridge::Quirk) selects a bus value-add.
///
/// ```no_run
/// use canboat::bridge::{Bridge, BridgeConfig};
///
/// # fn main() -> anyhow::Result<()> {
/// // Own a SocketCAN interface, tap the decoded stream, and re-serve the
/// // 2597–2606 TCP ports so other LAN consumers keep working.
/// let mut config = BridgeConfig::default();
/// config.socketcan = Some("can0".into());
///
/// let mut bridge = Bridge::new(config)?;
/// let decoded = bridge.decoded(); // Receiver<Arc<DecodedPgn>>
/// bridge.serve()?;
/// bridge.spawn()?; // pipeline runs on a background thread
///
/// for pgn in decoded.iter() {
///     println!("{} from {}", pgn.pgn, pgn.src);
/// }
/// bridge.wait();
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "bridge")]
pub mod bridge {
    pub use canboat_bridge::server::{Bridge, BridgeConfig, QuirkKind as Quirk, Transmitter};
}

// ─────────────────────────────── prelude ─────────────────────────────────

/// The 90% path in one glob import: `use canboat::prelude::*;`.
#[cfg(feature = "decode")]
pub mod prelude {
    pub use crate::{
        Database, DecodeError, DecodedField, DecodedPgn, FieldId, FieldValue, Frame, Units,
    };
}
