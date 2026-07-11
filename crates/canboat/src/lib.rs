// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat` — NMEA 2000 (canboat) decoding, encoding, and live-bus access.
//!
//! This is the single crate an external consumer depends on. Its public
//! surface is deliberately small and feature-gated; think in terms of
//! [`Frame`] ⇆ [`DecodedPgn`] (decode) and [`MessageBuilder`] → [`Frame`]
//! (encode). See `docs/library-api-plan.md` for the full design.
//!
//! # Features
//!
//! * `decode` (baseline) — sans-I/O core: schema, decode, encode, formatters.
//!   No threads, no async, no sockets.
//! * `io` — byte-source readers (`read::*Reader`) for serial / files / text.
//! * `wire` — cross-process [`wire`] transport (postcard `WirePgn` + `Hello`).
//! * `node` — [`device`]: be a compliant N2K node (address claim + responder).
//! * `bridge` — [`bridge`]: the live CAN bus, fully assembled.
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
    MessageBuilder,
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
/// arrive with the `nmea0183` / `ais` features in Phase 2.
#[cfg(feature = "decode")]
pub mod output {
    pub use canboat_core::output::{CamelCase, JsonOptions, write_json};
}

/// Inbound: turn a byte source into a stream of [`DecodedPgn`].
///
/// The [`from_analyzer_json`] entry (already-decoded analyzer JSON → record)
/// is available under `decode`. The `FrameSource` trait and the concrete
/// `*Reader` byte-source implementations arrive with the `io` feature in
/// Phase 2.
#[cfg(feature = "decode")]
pub mod read {
    pub use canboat_core::json_to_decoded as from_analyzer_json;
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

/// Be a compliant N2K node without owning a transport: NAME arbitration and
/// the ISO/product/config responder, all [`Frame`]-in/[`Frame`]-out.
///
/// Populated in Phase 4 from the extracted `address_claim` + `nmea_responder`
/// components as `device::{Name, Claimer, Responder}`.
#[cfg(feature = "node")]
pub mod device {}

// ─────────────────────────────── bridge ──────────────────────────────────

/// The live CAN bus, fully assembled: own a socketcan interface (or a custom
/// [`FrameSource`](read)), claim an address, apply quirks, and expose an
/// in-process [`DecodedPgn`] stream plus an optional TCP serving layer.
///
/// Populated in Phase 5 by lifting `server` + `n2kd` into `canboat-bridge`.
#[cfg(feature = "bridge")]
pub mod bridge {}

// ─────────────────────────────── prelude ─────────────────────────────────

/// The 90% path in one glob import: `use canboat::prelude::*;`.
#[cfg(feature = "decode")]
pub mod prelude {
    pub use crate::{
        Database, DecodeError, DecodedField, DecodedPgn, FieldId, FieldValue, Frame, Units,
    };
}
