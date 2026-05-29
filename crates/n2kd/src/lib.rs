//! n2kd library — exposes the conversion modules used by the
//! `n2kd` binary and any in-process pipeline experiments.
//!
//! The public surface here is intentionally narrow: just the modules
//! that convert analyzer-shaped JSON into NMEA 0183 sentences. Server
//! plumbing (TCP listeners, the `Hub`, the stdin pump) stays in the
//! binary's `main.rs`.

pub mod ais;
pub mod ais_decoded;
pub mod decoded;
pub mod json;
pub mod nmea0183;
