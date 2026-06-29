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
use std::collections::VecDeque;
use std::io::{self, LineWriter, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;

use canboat_core::format::write_plain;
use canboat_core::output::{CamelCase, JsonOptions, write_json};
use canboat_core::{FramePacketType, PgnDatabase, RawFrame, Reassembled, Reassembler};
use canboat_io::device::FrameSender;
use n2kd::request_engine::RequestEngine;

use crate::hub::Hub;
use crate::quirks::Quirks;
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
    /// Raw N2K input/output: every coalesced frame goes out as a
    /// `# format=FAST` PLAIN line; clients can write PLAIN/FAST back
    /// to inject onto the bus. Previously named `csv`.
    pub raw: Arc<Hub>,
    pub nmea: Arc<Hub>,
    pub analyzer: Arc<Hub>,
    /// Optional cache for the snapshot port. When `Some`, every
    /// decoded record's analyzer JSON line lands in the cache; the
    /// snapshot TCP listener dumps the live entries on each connect.
    pub snapshot: Option<Arc<SnapshotStore>>,
    /// Per-device tracker for the periodic ISO claim / product-info
    /// auto-request engine. The pipeline updates it from every
    /// decoded frame; `main.rs` separately spawns the request loop
    /// when there's a device writer to send the resulting PGN 59904
    /// requests to.
    pub engine: Arc<RequestEngine>,
    /// Device-quirk workarounds. Inspects every inbound frame and
    /// optionally emits synthetic responses (e.g. PGN 126996 on
    /// behalf of an SCX-20 that's "forgotten" how to answer). Empty
    /// kinds = no-op; the per-frame call short-circuits.
    pub quirks: Quirks,
    /// Outbound frame sender into the device writer. Used by quirk
    /// synthesisers to land their impersonation on the wire so
    /// external consumers (e.g. an NGT-1 on the same bus) see it.
    /// `None` in stdin-only mode where there's no device writer.
    pub device_sender: Option<FrameSender>,
}

/// Pipeline entry point. Returns when `frames_rx` is closed.
///
/// * `emit_nmea_stdout` mirrors canboat C `n2kd`'s `--nmea0183` flag.
///   When `true`, NMEA 0183 sentences are also written to stdout (in
///   addition to the optional TCP NMEA-0183 broadcast). Off by
///   default — long-running deployments use the TCP port and don't
///   want their service log spammed.
/// * `pre_coalesced` is the shared "are frames already coalesced
///   PGN payloads?" flag. Set up-front to `true` for sources known
///   to coalesce on the wire (NGT-1, iKonvert, Maretron); the
///   pipeline will additionally flip it to `true` the first time it
///   sees a frame with `data.len() > 8` (matching canboat's
///   `RAWFORMAT_PLAIN_OR_FAST` → `FAST` lock-in). Once true it
///   stays true. The stdin pump also flips it when it sees a
///   `# format=<NAME>` header declaring a coalesced format.
/// * `camel_case` selects field-key + PGN-description style for
///   the analyzer JSON / snapshot output — `Off` / `Lower` (matches
///   canboat C `-camel`) / `Upper` (matches `-upper-camel`).
pub fn run(
    db: &'static PgnDatabase,
    frames_rx: Receiver<RawFrame>,
    mut hubs: Hubs,
    emit_nmea_stdout: bool,
    pre_coalesced: Arc<AtomicBool>,
    camel_case: CamelCase,
) {
    // LineWriter (rather than BufWriter) so each NMEA 0183 sentence
    // is flushed as soon as its trailing newline arrives. Long-
    // running deployments observe stdout for the latest state, not
    // a batched dump; canboat C n2kd flushes per line too.
    let stdout = io::stdout();
    let mut out = LineWriter::new(stdout.lock());

    let mut reasm = Reassembler::new();
    let mut nmea_buf = String::with_capacity(256);
    let mut raw_line = String::with_capacity(256);
    let mut json_line = String::with_capacity(1024);
    let mut rl = n2kd::nmea0183::RateLimiter::new(false);
    let mut ais_seq: u8 = 0;
    let handles = n2kd::decoded::Handles::new(db);

    let json_opts = JsonOptions {
        include_empty: false,
        name_value: true,
        debug: false,
        camel_case,
    };

    // Quirk synthesisers can produce extra `RawFrame`s in response to
    // an inbound bus frame. We re-feed them through this same loop so
    // they pass through reassembly, decode and broadcast just like a
    // real bus frame would. A synthetic frame can't re-trigger a
    // quirk (its PGN is always a *response*, never the trigger PGN),
    // so there's no risk of an infinite synthesis loop.
    let mut pending_synth: VecDeque<RawFrame> = VecDeque::new();

    loop {
        let frame = if let Some(synth) = pending_synth.pop_front() {
            synth
        } else {
            match frames_rx.recv() {
                Ok(f) => f,
                Err(_) => break,
            }
        };

        // Quirk shim: inspect the inbound bus frame, maybe synthesise.
        // Each synthetic is written to the bus (so external consumers
        // see it with the impersonated src) and queued back into this
        // loop (so the local pipeline indexes / broadcasts it too).
        if hubs.quirks.is_enabled() {
            for synth in hubs.quirks.process_inbound(&frame) {
                if let Some(sender) = hubs.device_sender.as_ref() {
                    let _ = sender.send_frame(synth.clone());
                }
                pending_synth.push_back(synth);
            }
        }

        // Lazy raw broadcast — one `# format=FAST` PLAIN line
        // per coalesced `RawFrame`.
        if hubs.raw.has_subscribers() {
            raw_line.clear();
            if write_plain(&mut raw_line, &frame).is_ok() {
                raw_line.push('\n');
                hubs.raw.broadcast(&raw_line);
            }
        }

        // When the source already coalesces fast-packets (NGT-1,
        // iKonvert, Maretron, FAST-format stdin), the reassembler
        // must be skipped entirely. A coalesced fast-packet whose
        // payload is ≤8 bytes would otherwise have its first byte
        // misread as a sequence / frame-index header.
        //
        // Sticky lock-in: once we see ANY frame with more than 8
        // payload bytes, the upstream is definitely emitting
        // coalesced PGNs, so flip the shared flag for all
        // subsequent frames (and any other subscriber that reads
        // it). Matches canboat's `RAWFORMAT_PLAIN_OR_FAST` → `FAST`
        // promotion in analyzer.c.
        if !pre_coalesced.load(Ordering::Relaxed) && frame.data.len() > 8 {
            log::debug!(
                "frame with {} payload bytes seen; locking pipeline into coalesced mode",
                frame.data.len()
            );
            pre_coalesced.store(true, Ordering::Relaxed);
        }
        let assembled = if pre_coalesced.load(Ordering::Relaxed) {
            frame
        } else {
            let packet_type = db
                .first_pgn(frame.pgn)
                .or_else(|| db.fallback_pgn(frame.pgn))
                .map(|p| match p.packet_type {
                    canboat_core::PacketType::Fast => FramePacketType::Fast,
                    canboat_core::PacketType::Single => FramePacketType::Single,
                    _ => FramePacketType::Other,
                })
                .unwrap_or(FramePacketType::Other);
            match reasm.push(frame, packet_type) {
                Reassembled::PassThrough(f) | Reassembled::Complete(f) => f,
                _ => continue,
            }
        };
        let Ok(decoded) = db.decode(&assembled) else {
            continue;
        };

        // Feed the periodic claim/product-info request engine.
        // Updates "last received" stamps for PGN 60928 and 126996.
        hubs.engine.note_device_seen(decoded.pgn, decoded.src);

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
