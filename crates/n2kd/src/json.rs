//! Compatibility shim — the analyzer-JSON value extractor lives in
//! `canboat_core::analyzer_json` so the snapshot ingest path and the
//! TUI viewer can share it. `crate::json::*` calls inside this crate
//! keep working unchanged via this re-export.

pub use canboat_core::analyzer_json::*;
