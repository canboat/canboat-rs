//! Static schema tables, generated at build time from
//! `data/canboat.json` plus `data/synthetic-pgns.json` by
//! `canboat-core/build.rs`.
//!
//! Exposes:
//! - [`PGNS`] — `&[PgnInfo]` in JSON declaration order.
//! - [`PGN_INDEX`] — `&[(u32, &[u32])]`, sorted by PGN number, value
//!   is a slice of indices into [`PGNS`] (variants in declaration order).
//! - [`LOOKUPS`], [`BIT_LOOKUPS`], [`INDIRECT_LOOKUPS`],
//!   [`FIELD_TYPE_LOOKUPS`] — sorted alphabetically by name for
//!   binary-search lookup.
//! - [`SCHEMA_VERSION`], [`VERSION`] — strings from canboat.json.

include!(concat!(env!("OUT_DIR"), "/schema_generated.rs"));
