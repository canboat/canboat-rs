//! In-process entry points to the canboat-rs analyzer pipeline.
//!
//! [`replay::decode_stream`] (and the [`replay::decode_file`]
//! convenience wrapper) feed an analyzer-shaped input file through
//! exactly the same parse / reassemble / decode path the `analyzer`
//! binary uses — auto-detecting the input format, honouring
//! `# format=<NAME>` headers, locking into "coalesced" once any
//! line carries > 8 payload bytes, and emitting a fully-decoded
//! [`canboat_core::DecodedPgn`] via a sink callback per record.
//!
//! Callers that want JSON / text output can run
//! [`canboat_core::output::write_json`] /
//! [`canboat_core::output::write_text`] on the decoded record inside
//! the sink. The `analyzer` binary does exactly this — and so does
//! `canboat-tui`'s log-replay mode, so the two paths share the same
//! reassembly + decode behaviour without spawning a subprocess.

pub mod replay;
