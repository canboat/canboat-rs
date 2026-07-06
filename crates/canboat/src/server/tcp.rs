// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Device-pipeline-specific TCP listeners.
//!
//! The read-only broadcast + snapshot ports are shared with `n2kd` and
//! live in [`n2kd::serving::tcp`]. What stays here needs the device
//! writer and the wire protocol, so only the `server` pipeline uses it:
//!
//! * **Write server** (WO) — accepts PLAIN/FAST lines and injects them
//!   onto the bus via an [`InjectPoint`] (device writer + pipeline
//!   loopback). This is also where the BEM NMEA-0183-filter control
//!   channel lands.
//!
//! * **Binary analyzer server** (RO) — the `canboat_wire` handshake
//!   plus length-prefixed postcard `WirePgn` frames from a [`BinHub`].

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};

use canboat_core::RawFrame;
use canboat_core::format::{PlainError, parse_plain};
use canboat_io::device::FrameSender;

/// Where a client-written frame goes. In device mode, we forward to
/// the device *and* loop it back into the pipeline source so it
/// appears in NMEA 0183 / snapshot / read-side TCP output, mirroring
/// the stdin-pump behaviour. In stdin mode there's no device and no
/// loopback channel, so writes are dropped on the floor.
#[derive(Clone)]
pub struct InjectPoint {
    pub device: FrameSender,
    pub loopback: mpsc::Sender<RawFrame>,
    /// Live claim address from the underlying device adapter, when
    /// known (today only `--socketcan` exposes it). Used to rewrite a
    /// client-supplied `src == 0` (PC-gateway default) or `src == 255`
    /// (broadcast — never a valid source) to the gateway's address on
    /// the loopback side, so the in-process pipeline sees the same
    /// `src` the rewritten frame will reach the bus with. `None`
    /// disables the rewrite (other device backends; stdin mode).
    pub claim_addr: Option<Arc<AtomicU8>>,
}

use n2kd::serving::BinHub;

// Nagle's algorithm is deliberately left ENABLED on every client
// socket (no `set_nodelay`). These are telemetry streams, not
// request/response protocols: at bus rates (hundreds of lines/s)
// the kernel coalescing consecutive small writes into full segments
// is pure win — fewer packets, fewer syscall-sized wakeups on the
// receiver — and the added latency is bounded by the ACK round-trip
// (sub-millisecond on loopback / LAN). The write loops below batch
// at the application level too; Nagle mops up whatever still goes
// out small.

/// Bind a **write-only** TCP input server: clients connect and write
/// PLAIN/FAST lines that are parsed and injected onto the bus via
/// `inject`. Nothing is streamed back — this is the canonical
/// `SERVER_INPUT_STREAM` slot (canboat C n2kd `port+3`). Unlike the
/// broadcast ports it never subscribes to a hub, so it adds no
/// serialization pressure; that's what makes it the cheap write path
/// for a consumer that reads its data elsewhere (e.g. the binary
/// port). `inject: None` (stdin mode, no device) still accepts and
/// drains client writes, logging them at debug.
pub fn spawn_input_server(
    name: &'static str,
    bind: Ipv4Addr,
    port: u16,
    inject: Option<InjectPoint>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} TCP port {}:{}", bind, port))?;
    let mode = if inject.is_some() {
        "write-only"
    } else {
        "write-only (writes dropped)"
    };
    log::info!("{name} server listening on {}:{} ({mode})", bind, port);
    Ok(thread::Builder::new()
        .name(format!("{name}-accept"))
        .spawn(move || input_accept(name, listener, inject))
        .expect("spawn input accept"))
}

fn input_accept(name: &'static str, listener: TcpListener, inject: Option<InjectPoint>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("{name} accept failed: {e}");
                return;
            }
        };
        log::info!("{name} client connected: {peer}");
        let inj = inject.clone();
        thread::Builder::new()
            .name(format!("{name}-client"))
            .spawn(move || {
                // We never broadcast to this client; FIN our write
                // direction so a client that tries to read sees EOF.
                if let Err(e) = stream.shutdown(Shutdown::Write) {
                    log::debug!("{name}: shutdown(write) failed: {e}");
                }
                run_inbound_reader(name, stream, inj);
            })
            .ok();
    }
}

fn run_inbound_reader(name: &'static str, stream: TcpStream, inject: Option<InjectPoint>) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return,
        };
        match &inject {
            // Device wired up: forward the line. Stop when the writer
            // (or pipeline) has gone away.
            Some(i) => {
                if !forward_plain_line(&line, i) {
                    return;
                }
            }
            // Stdin-mode pipeline: no device to forward to. Drain the
            // line so the client keeps making progress, but log at
            // debug so a stray write doesn't disappear without a
            // trace.
            None => {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if !trimmed.is_empty() {
                    log::debug!("{name}: no device wired up, dropping client line: {trimmed}");
                }
            }
        }
    }
}

/// Parse one PLAIN/FAST line, send to the device, AND loop it back
/// into the pipeline source so it appears in the pipeline's output
/// streams. Returns `false` when either the device writer or the
/// pipeline has gone away (caller should stop).
fn forward_plain_line(line: &str, inject: &InjectPoint) -> bool {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return true;
    }
    // Silently skip iKonvert-style control / data sentences that
    // sometimes leak in from clients that were originally talking
    // to a Digital Yacht iKonvert (`$PDGY,N2NET_OFFLINE`,
    // `!PDGY,…`). They're not PLAIN/FAST. We could route them
    // through to an iKonvert-typed device but that's a feature for
    // another day; for now they're not "malformed", just not for
    // us.
    if trimmed.starts_with('$') || trimmed.starts_with('!') {
        log::debug!("skipping non-PLAIN/FAST line: {trimmed}");
        return true;
    }
    match parse_plain(trimmed) {
        Ok(mut frame) => {
            // The NMEA 0183 filter control PGN is a pipeline-local
            // message, never a bus frame: loop it into the pipeline
            // (which owns the filter state) but do not transmit it on
            // the N2K bus or rewrite its source.
            if frame.pgn == n2kd::nmea_filter::PGN_NMEA0183_FILTER {
                return inject.loopback.send(frame).is_ok();
            }
            // Rewrite a default / broadcast `src` to our gateway's
            // live claim address on BOTH paths. The device adapter
            // does the same rewrite internally for the bus side, but
            // the loopback bypasses that — so without this, the
            // in-process pipeline (n2kd snapshot / analyzer-port JSON
            // / NMEA 0183) shows the original `src=0` or `src=255`
            // even though the on-wire frame has the gateway's src.
            // `CLAIM_UNCLAIMED` (254) means we haven't claimed yet —
            // leave src as-is rather than guess.
            if matches!(frame.src, 0 | 255)
                && let Some(claim) = inject.claim_addr.as_deref()
            {
                let live = claim.load(Ordering::Relaxed);
                if live != canboat_io::device::socketcan::CLAIM_UNCLAIMED {
                    frame.src = live;
                }
            }
            if inject.device.send_frame(frame.clone()).is_err() {
                return false;
            }
            inject.loopback.send(frame).is_ok()
        }
        Err(PlainError::Empty) => true,
        Err(e) => {
            log_bad_plain_line(trimmed, &e);
            true
        }
    }
}

/// Render the malformed-line warning with the offending line and a
/// caret pointing at the byte offset where parsing failed. Helps
/// the user see *what* came in over the wire that the parser
/// didn't like.
fn log_bad_plain_line(line: &str, err: &PlainError) {
    match err.byte_offset() {
        Some(offset) => {
            // Cap the offset at the line length so we always render
            // a sane pointer even if the source counted past EOL.
            let pointer_col = offset.min(line.len());
            let pointer = format!("{:width$}^", "", width = pointer_col);
            log::warn!(
                "ignoring malformed PLAIN/FAST line: {err}\n  line:    {line}\n  pointer: {pointer}"
            );
        }
        None => {
            log::warn!("ignoring malformed PLAIN/FAST line: {err}\n  line: {line}");
        }
    }
}

/// Bind the binary analyzer server (`--analyzer-binary-port`).
///
/// Strictly read-only. On connect it writes the canboat-wire
/// [`canboat_wire::Hello`] handshake — magic, wire-protocol version, and
/// the [`canboat_core::SCHEMA_HASH`] — then streams length-prefixed
/// postcard `WirePgn` frames from `hub` for the life of the connection.
/// A client MUST read and verify the `Hello` first: the schema hash is
/// what proves both ends share byte-identical field indices, without
/// which the per-field `order` numbers on the wire are meaningless.
pub fn spawn_binary_stream(bind: Ipv4Addr, port: u16, hub: Arc<BinHub>) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding binary TCP port {}:{}", bind, port))?;
    log::info!("binary analyzer server listening on {}:{} (RO)", bind, port);
    Ok(thread::Builder::new()
        .name("binary-accept".into())
        .spawn(move || binary_accept(listener, hub))
        .expect("spawn binary accept"))
}

fn binary_accept(listener: TcpListener, hub: Arc<BinHub>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("binary accept failed: {e}");
                return;
            }
        };
        log::info!("binary client connected: {peer}");
        let h = hub.clone();
        thread::Builder::new()
            .name("binary-client".into())
            .spawn(move || run_binary_client(stream, h))
            .ok();
    }
}

fn run_binary_client(mut stream: TcpStream, hub: Arc<BinHub>) {
    // Read-only: FIN the read direction so client writes get
    // ECONNRESET / EPIPE rather than piling up unread.
    if let Err(e) = stream.shutdown(Shutdown::Read) {
        log::debug!("binary: shutdown(read) failed: {e}");
    }
    // Handshake first — a client can reject a schema/version mismatch
    // before decoding a single record.
    let mut hello = Vec::with_capacity(64);
    if canboat_wire::append_frame(&mut hello, &canboat_wire::Hello::current()).is_err() {
        return;
    }
    if stream.write_all(&hello).is_err() {
        return;
    }
    // Each `Arc<[u8]>` chunk from the hub is already a run of whole
    // frames (the pipeline's BinBatcher coalesces them), so forward it
    // verbatim. Nagle — left enabled like the text ports — mops up the
    // small writes into full segments.
    let rx = hub.subscribe();
    while let Ok(chunk) = rx.recv() {
        if stream.write_all(&chunk).is_err() {
            break;
        }
    }
    drop(stream);
}
