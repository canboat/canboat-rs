//! Drives the analyzer → n2kd conversion stage.
//!
//! Consumes `RawFrame`s off an `mpsc::Receiver`, runs them through
//! the reassembler + PGN decoder, dispatches to the struct-based
//! converters in `n2kd::decoded` / `n2kd::ais_decoded` (with a JSON
//! fallback for the long tail of PGNs the struct path hasn't covered
//! yet), and writes NMEA 0183 sentences to stdout. Three side
//! branches feed the optional TCP servers:
//!
//! * `csv_hub` — every `RawFrame` rendered as a PLAIN/FAST line.
//! * `nmea_hub` — every NMEA 0183 sentence (one or more per record).
//! * `analyzer_hub` — every decoded record rendered as analyzer JSON.
//! * `snapshot` — analyzer JSON stashed per `(pgn, src, secondary)`
//!   for the n2kd-compatible full-state-on-connect port.
//!
//! Each side branch is gated. The hub-broadcast paths skip the
//! formatter when no one is subscribed (atomic load). The snapshot
//! cache, when present, always wants its JSON line, so JSON
//! serialization runs whenever either the analyzer hub has
//! subscribers OR the snapshot store is configured.

use std::cell::RefCell;
use std::io::{self, LineWriter, Write};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use canboat_core::format::write_plain;
use canboat_core::output::{write_json, JsonOptions};
use canboat_core::{FramePacketType, PgnDatabase, RawFrame, Reassembled, Reassembler};

use crate::hub::Hub;
use crate::snapshot::SnapshotStore;

thread_local! {
    static JSON_BUF: RefCell<String> = const { RefCell::new(String::new()) };
}

fn is_ais_pgn(pgn: u32) -> bool {
    matches!(
        pgn,
        129038
            | 129039
            | 129040
            | 129041
            | 129793
            | 129794
            | 129798
            | 129801
            | 129802
            | 129809
            | 129810
    )
}

/// Bundle of broadcast hubs the pipeline writes into.
pub struct Hubs {
    pub csv: Arc<Hub>,
    pub nmea: Arc<Hub>,
    pub analyzer: Arc<Hub>,
    /// Optional cache for the snapshot port. When `Some`, every
    /// decoded record's analyzer JSON line lands in the cache; the
    /// snapshot TCP listener dumps the live entries on each connect.
    pub snapshot: Option<Arc<SnapshotStore>>,
}

/// Pipeline entry point. Returns when `frames_rx` is closed.
///
/// `emit_nmea_stdout` mirrors canboat C `n2kd`'s `--nmea0183` flag:
/// when `true`, NMEA 0183 sentences are also written to stdout (in
/// addition to the optional TCP NMEA-0183 broadcast). Off by default
/// — long-running deployments use the TCP port and don't want their
/// service log spammed.
pub fn run(db: PgnDatabase, frames_rx: Receiver<RawFrame>, hubs: Hubs, emit_nmea_stdout: bool) {
    // LineWriter (rather than BufWriter) so each NMEA 0183 sentence
    // is flushed as soon as its trailing newline arrives. Long-
    // running deployments observe stdout for the latest state, not
    // a batched dump; canboat C n2kd flushes per line too.
    let stdout = io::stdout();
    let mut out = LineWriter::new(stdout.lock());

    let mut reasm = Reassembler::new();
    let mut nmea_buf = String::with_capacity(256);
    let mut csv_line = String::with_capacity(256);
    let mut json_line = String::with_capacity(1024);
    let mut rl = n2kd::nmea0183::RateLimiter::new(false);
    let mut ais_seq: u8 = 0;
    let handles = n2kd::decoded::Handles::new(&db);

    let json_opts = JsonOptions {
        include_empty: false,
        name_value: true,
        debug: false,
    };

    while let Ok(frame) = frames_rx.recv() {
        // Lazy CSV broadcast — one PLAIN/FAST line per RawFrame.
        if hubs.csv.has_subscribers() {
            csv_line.clear();
            if write_plain(&mut csv_line, &frame).is_ok() {
                csv_line.push('\n');
                hubs.csv.broadcast(&csv_line);
            }
        }

        let packet_type = db
            .first_pgn(frame.pgn)
            .or_else(|| db.fallback_pgn(frame.pgn))
            .map(|p| match p.packet_type {
                canboat_core::PacketType::Fast => FramePacketType::Fast,
                canboat_core::PacketType::Single => FramePacketType::Single,
                _ => FramePacketType::Other,
            })
            .unwrap_or(FramePacketType::Other);

        let assembled = match reasm.push(frame, packet_type) {
            Reassembled::PassThrough(f) | Reassembled::Complete(f) => f,
            _ => continue,
        };
        let Ok(decoded) = db.decode(&assembled) else {
            continue;
        };

        // Lazy analyzer JSON broadcast / snapshot stash — one JSON
        // line per decoded record. Serialization runs when either
        // the analyzer hub has subscribers OR the snapshot store is
        // configured. The JSON serializer walks every decoded field,
        // so skipping when no one needs the line actually buys
        // something on a high-rate input stream.
        let want_json = hubs.analyzer.has_subscribers() || hubs.snapshot.is_some();
        if want_json {
            json_line.clear();
            if write_json(&mut json_line, &decoded, &json_opts).is_ok() {
                // Snapshot wants the bare JSON (it embeds the line as
                // a value inside its own nested wrapper). The
                // analyzer port wants one-record-per-line, so we tack
                // the newline on for that path only.
                if let Some(snap) = hubs.snapshot.as_ref() {
                    snap.store(&decoded, json_line.clone());
                }
                if hubs.analyzer.has_subscribers() {
                    json_line.push('\n');
                    hubs.analyzer.broadcast(&json_line);
                }
            }
        }

        nmea_buf.clear();
        let pgn = decoded.pgn;
        let n_emitted = if n2kd::decoded::Handles::supports(pgn) {
            n2kd::decoded::convert_nmea0183(&mut nmea_buf, &decoded, &mut rl, &handles)
        } else if is_ais_pgn(pgn) {
            n2kd::ais_decoded::convert(&mut nmea_buf, &decoded, &mut ais_seq)
        } else {
            JSON_BUF.with(|c| {
                let mut buf = c.borrow_mut();
                buf.clear();
                let _ = write_json(&mut *buf, &decoded, &json_opts);
                n2kd::nmea0183::convert(&mut nmea_buf, &buf, &mut rl)
            })
        };
        if n_emitted > 0 {
            if emit_nmea_stdout {
                let _ = out.write_all(nmea_buf.as_bytes());
            }
            if hubs.nmea.has_subscribers() {
                hubs.nmea.broadcast(&nmea_buf);
            }
        }
    }
    out.flush().ok();
}
