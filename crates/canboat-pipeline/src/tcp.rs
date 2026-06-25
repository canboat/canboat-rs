//! TCP listeners attached to the pipeline.
//!
//! Five endpoints:
//!
//! * **Snapshot server** (RO, one-shot) — on connect, dumps every
//!   live `(pgn, src, secondary)` cache entry as analyzer JSON, then
//!   closes. Mirrors canboat C `n2kd`'s base port (2597 by default).
//!
//! * **CSV server** (R/W) — clients receive the PLAIN/FAST text
//!   rendering of every frame received from the device, *and* lines
//!   they send back are parsed as PLAIN/FAST and queued for the
//!   device writer. This is the canboat-style "one socket, both
//!   directions" port.
//!
//! * **NMEA 0183 server** (RO) — clients receive every NMEA 0183
//!   sentence the pipeline emits, including AIVDM.
//!
//! * **Analyzer server** (RO) — clients receive analyzer JSON, one
//!   record per line.
//!
//! * **Write server** (WO) — accepts PLAIN/FAST lines and sends them
//!   to the device writer. No data flows back. Cheaper for clients
//!   that only need to inject N2K traffic.
//!
//! All read-side streams are lazy: the pipeline only formats data
//! when at least one client is subscribed (see [`crate::hub::Hub`]).
//! The snapshot port pulls from a cache populated by the pipeline.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};

use canboat_core::format::{parse_plain, PlainError};
use canboat_core::RawFrame;
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

/// One-shot header sent to every CSV (R/W) client on connect.
/// Matches the line the canboat C reader binaries
/// (`actisense-serial`, `ikonvert-serial`, `maretron-ipg`) emit on
/// stdout to declare "frames are already coalesced FAST". A
/// downstream canboat `analyzer` or canboatjs's `Liner +
/// parseActisense` use this to skip per-CAN-frame reassembly.
pub const CANBOAT_FORMAT_FAST_HEADER: &[u8] = b"# format=FAST\n";

use crate::hub::Hub;
use crate::snapshot::SnapshotStore;

/// Disable Nagle's algorithm on a freshly-accepted client socket.
/// Without this, the kernel batches small writes for up to ~40 ms
/// looking for more data to coalesce — fine for bulk transfers,
/// terrible for the per-sentence streams this binary produces.
/// Logged at debug level if setsockopt fails so the failure is
/// noticed but doesn't take the client connection down.
fn set_nodelay(stream: &TcpStream, name: &str) {
    if let Err(e) = stream.set_nodelay(true) {
        log::debug!("{name}: set_nodelay failed: {e}");
    }
}

/// Bind the snapshot server. Each accepted client gets one dump of
/// every live `(pgn, src, secondary)` cache entry then the connection
/// closes — same shape as canboat C `n2kd`'s base port.
pub fn spawn_snapshot(
    bind: Ipv4Addr,
    port: u16,
    store: Arc<SnapshotStore>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding snapshot TCP port {}:{}", bind, port))?;
    log::info!("snapshot server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name("snapshot-accept".into())
        .spawn(move || snapshot_accept(listener, store))
        .expect("spawn snapshot accept"))
}

fn snapshot_accept(listener: TcpListener, store: Arc<SnapshotStore>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("snapshot accept failed: {e}");
                return;
            }
        };
        log::info!("snapshot client connected: {peer}");
        let s = store.clone();
        thread::Builder::new()
            .name("snapshot-client".into())
            .spawn(move || run_snapshot_client(stream, s))
            .ok();
    }
}

fn run_snapshot_client(mut stream: TcpStream, store: Arc<SnapshotStore>) {
    set_nodelay(&stream, "snapshot");
    // Snapshot is a strictly read-only one-shot: FIN the read
    // direction immediately so any client writes during the brief
    // window before the dump completes get ECONNRESET / EPIPE
    // instead of piling up in the kernel's receive buffer.
    if let Err(e) = stream.shutdown(Shutdown::Read) {
        log::debug!("snapshot: shutdown(read) failed: {e}");
    }
    // Snapshot is a one-shot dump — build the JSON document under
    // the cache lock, then drop the lock before sending so a slow
    // client can't stall the pipeline's `store()` calls.
    let doc = store.snapshot();
    let _ = stream.write_all(doc.as_bytes());
    let _ = stream.flush();
    // Explicit shutdown to signal end-of-stream to the client — TCP
    // close-after-flush is the canonical "one-shot snapshot done"
    // signal. The implicit drop would do the same, but being
    // explicit makes the intent obvious.
    let _ = stream.shutdown(Shutdown::Both);
}

/// Direction policy for [`spawn_stream_server`]. Mode `ReadOnly`
/// shuts down the TCP read direction on every accept; `ReadWrite`
/// spawns an inbound reader subthread that parses PLAIN/FAST lines
/// and forwards `RawFrame`s through `inject` if one is configured
/// (silently drops them when `None`, e.g. stdin-mode pipeline with
/// no device behind it).
pub enum Direction {
    ReadOnly,
    ReadWrite { inject: Option<InjectPoint> },
}

/// Bind a TCP server that streams `hub` broadcast lines out to every
/// connected client and — depending on [`Direction`] — optionally
/// accepts PLAIN/FAST lines back from those clients.
///
/// `header` is optional bytes written to the client immediately on
/// connect, before the first broadcast line. Used by the CSV port
/// to emit canboat's `# format=FAST\n` so downstream PLAIN/FAST
/// parsers know the stream is pre-coalesced.
pub fn spawn_stream_server(
    name: &'static str,
    bind: Ipv4Addr,
    port: u16,
    hub: Arc<Hub>,
    direction: Direction,
    header: Option<&'static [u8]>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} TCP port {}:{}", bind, port))?;
    let mode = match (&direction, header.is_some()) {
        (Direction::ReadWrite { inject: Some(_) }, true) => "R/W + header",
        (Direction::ReadWrite { inject: Some(_) }, false) => "R/W",
        (Direction::ReadWrite { inject: None }, true) => "R/W (writes dropped) + header",
        (Direction::ReadWrite { inject: None }, false) => "R/W (writes dropped)",
        (Direction::ReadOnly, _) => "RO",
    };
    log::info!("{name} server listening on {}:{} ({mode})", bind, port);
    Ok(thread::Builder::new()
        .name(format!("{name}-accept"))
        .spawn(move || stream_accept(name, listener, hub, direction, header))
        .expect("spawn stream accept"))
}

fn stream_accept(
    name: &'static str,
    listener: TcpListener,
    hub: Arc<Hub>,
    direction: Direction,
    header: Option<&'static [u8]>,
) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("{name} accept failed: {e}");
                return;
            }
        };
        log::info!("{name} client connected: {peer}");
        let h = hub.clone();
        let d = match &direction {
            Direction::ReadOnly => Direction::ReadOnly,
            Direction::ReadWrite { inject } => Direction::ReadWrite {
                inject: inject.clone(),
            },
        };
        thread::Builder::new()
            .name(format!("{name}-client"))
            .spawn(move || run_stream_client(name, stream, h, d, header))
            .ok();
    }
}

fn run_stream_client(
    name: &'static str,
    stream: TcpStream,
    hub: Arc<Hub>,
    direction: Direction,
    header: Option<&'static [u8]>,
) {
    set_nodelay(&stream, name);

    let read_handle = match direction {
        // Strictly read-only: FIN the read direction so any client
        // write attempts get ECONNRESET / EPIPE instead of silently
        // piling up in the kernel's receive buffer.
        Direction::ReadOnly => {
            if let Err(e) = stream.shutdown(Shutdown::Read) {
                log::debug!("{name}: shutdown(read) failed: {e}");
            }
            None
        }
        // R/W: spawn a reader subthread on its own socket clone.
        // When no inject point is configured (stdin mode) the reader
        // silently drops inbound lines — we still accept the writes
        // (no FIN), we just have nowhere to forward them.
        Direction::ReadWrite { inject } => match stream.try_clone() {
            Ok(read_stream) => Some(
                thread::Builder::new()
                    .name(format!("{name}-client-read"))
                    .spawn(move || run_inbound_reader(name, read_stream, inject))
                    .expect("spawn inbound reader"),
            ),
            Err(e) => {
                log::warn!("{name}: cannot clone client stream: {e}");
                None
            }
        },
    };

    // Main: drain the subscription and write to the socket.
    let rx = hub.subscribe();
    let mut stream = stream;
    if let Some(bytes) = header {
        if stream.write_all(bytes).is_err() {
            return;
        }
    }
    while let Ok(line) = rx.recv() {
        if stream.write_all(line.as_bytes()).is_err() {
            break;
        }
    }
    // Closing the write side drops the fd; the inbound reader (if
    // any) exits on its next read.
    drop(stream);
    if let Some(j) = read_handle {
        let _ = j.join();
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

/// Bind a write-only TCP server. Each client's lines are parsed as
/// PLAIN/FAST and sent to the device writer. Useful for clients that
/// just want to inject N2K traffic without reading anything back.
pub fn spawn_writeonly(bind: Ipv4Addr, port: u16, inject: InjectPoint) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding write-only TCP port {}:{}", bind, port))?;
    log::info!("write-only server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name("write-accept".into())
        .spawn(move || writeonly_accept(listener, inject))
        .expect("spawn write-only accept"))
}

fn writeonly_accept(listener: TcpListener, inject: InjectPoint) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("write-only accept failed: {e}");
                return;
            }
        };
        log::info!("write-only client connected: {peer}");
        let i = inject.clone();
        thread::Builder::new()
            .name("write-client".into())
            .spawn(move || run_writeonly_client(stream, i))
            .ok();
    }
}

fn run_writeonly_client(stream: TcpStream, inject: InjectPoint) {
    set_nodelay(&stream, "write-only");
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                log::debug!("write-only client read error: {e}");
                return;
            }
        };
        if !forward_plain_line(&line, &inject) {
            return;
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
            // Rewrite a default / broadcast `src` to our gateway's
            // live claim address on BOTH paths. The device adapter
            // does the same rewrite internally for the bus side, but
            // the loopback bypasses that — so without this, the
            // in-process pipeline (n2kd snapshot / analyzer-port JSON
            // / NMEA 0183) shows the original `src=0` or `src=255`
            // even though the on-wire frame has the gateway's src.
            // `CLAIM_UNCLAIMED` (254) means we haven't claimed yet —
            // leave src as-is rather than guess.
            if matches!(frame.src, 0 | 255) {
                if let Some(claim) = inject.claim_addr.as_deref() {
                    let live = claim.load(Ordering::Relaxed);
                    if live != canboat_io::device::socketcan::CLAIM_UNCLAIMED {
                        frame.src = live;
                    }
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
