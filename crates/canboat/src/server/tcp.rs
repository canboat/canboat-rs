// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

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
//! when at least one client is subscribed (see [`n2kd::serving::Hub`]).
//! The snapshot port pulls from a cache populated by the pipeline.

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

/// One-shot header sent to every CSV (R/W) client on connect.
/// Matches the line the canboat C reader binaries
/// (`actisense-serial`, `ikonvert-serial`, `maretron-ipg`) emit on
/// stdout to declare "frames are already coalesced FAST". A
/// downstream canboat `analyzer` or canboatjs's `Liner +
/// parseActisense` use this to skip per-CAN-frame reassembly.
pub const CANBOAT_FORMAT_FAST_HEADER: &[u8] = b"# format=FAST\n";

use crate::server::snapshot::SnapshotStore;
use n2kd::serving::{BinHub, Hub};

// Nagle's algorithm is deliberately left ENABLED on every client
// socket (no `set_nodelay`). These are telemetry streams, not
// request/response protocols: at bus rates (hundreds of lines/s)
// the kernel coalescing consecutive small writes into full segments
// is pure win — fewer packets, fewer syscall-sized wakeups on the
// receiver — and the added latency is bounded by the ACK round-trip
// (sub-millisecond on loopback / LAN). The write loops below batch
// at the application level too; Nagle mops up whatever still goes
// out small.

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

/// Bind the AIS-snapshot server. Same connect-and-dump behaviour as
/// [`spawn_snapshot`], but the dump is filtered to AIS-described
/// PGNs plus PGN 129026 / 129029 — matches canboat C `n2kd`'s
/// `port+4` AIS port.
pub fn spawn_ais_snapshot(
    bind: Ipv4Addr,
    port: u16,
    store: Arc<SnapshotStore>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding ais TCP port {}:{}", bind, port))?;
    log::info!("ais server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name("ais-accept".into())
        .spawn(move || ais_snapshot_accept(listener, store))
        .expect("spawn ais accept"))
}

fn ais_snapshot_accept(listener: TcpListener, store: Arc<SnapshotStore>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("ais accept failed: {e}");
                return;
            }
        };
        log::info!("ais client connected: {peer}");
        let s = store.clone();
        thread::Builder::new()
            .name("ais-client".into())
            .spawn(move || run_ais_snapshot_client(stream, s))
            .ok();
    }
}

fn run_ais_snapshot_client(mut stream: TcpStream, store: Arc<SnapshotStore>) {
    if let Err(e) = stream.shutdown(Shutdown::Read) {
        log::debug!("ais: shutdown(read) failed: {e}");
    }
    let doc = store.ais_snapshot();
    let _ = stream.write_all(doc.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Bind a read-only TCP server that streams `hub` broadcast lines out
/// to every connected client. The read direction is FIN'd on accept —
/// all injection goes through the dedicated write-only input port
/// ([`spawn_input_server`]), so no broadcast stream is bidirectional.
///
/// `header` is optional bytes written to the client immediately on
/// connect, before the first broadcast line. Used by the raw output
/// port to emit canboat's `# format=FAST\n` so downstream PLAIN/FAST
/// parsers know the stream is pre-coalesced.
pub fn spawn_stream_server(
    name: &'static str,
    bind: Ipv4Addr,
    port: u16,
    hub: Arc<Hub>,
    header: Option<&'static [u8]>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} TCP port {}:{}", bind, port))?;
    log::info!("{name} server listening on {}:{} (RO)", bind, port);
    Ok(thread::Builder::new()
        .name(format!("{name}-accept"))
        .spawn(move || stream_accept(name, listener, hub, header))
        .expect("spawn stream accept"))
}

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

fn stream_accept(
    name: &'static str,
    listener: TcpListener,
    hub: Arc<Hub>,
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
        thread::Builder::new()
            .name(format!("{name}-client"))
            .spawn(move || run_stream_client(name, stream, h, header))
            .ok();
    }
}

fn run_stream_client(
    name: &'static str,
    stream: TcpStream,
    hub: Arc<Hub>,
    header: Option<&'static [u8]>,
) {
    // FIN the read direction so any client write attempts get
    // ECONNRESET / EPIPE instead of silently piling up in the kernel's
    // receive buffer — these broadcast ports are strictly read-only.
    if let Err(e) = stream.shutdown(Shutdown::Read) {
        log::debug!("{name}: shutdown(read) failed: {e}");
    }

    // Main: drain the subscription and write to the socket.
    let rx = hub.subscribe();
    let mut stream = stream;
    if let Some(bytes) = header
        && stream.write_all(bytes).is_err()
    {
        return;
    }
    // Batch: block for the first line, then greedily drain whatever
    // is already queued and push it all out with a single write.
    // A burst (one fast-packet flurry decoding into many lines, or a
    // slow client catching up) collapses into one syscall; a quiet
    // stream still sends each line immediately — `try_recv` comes
    // back `Empty` and the single-line batch goes straight out. The
    // cap only bounds memory; a burst larger than it simply takes
    // more than one write.
    const MAX_BATCH: usize = 64 * 1024;
    let mut batch: Vec<u8> = Vec::with_capacity(4096);
    while let Ok(line) = rx.recv() {
        batch.clear();
        batch.extend_from_slice(line.as_bytes());
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(line) => batch.extend_from_slice(line.as_bytes()),
                Err(_) => break,
            }
        }
        if stream.write_all(&batch).is_err() {
            break;
        }
    }
    // Closing the write side drops the fd and ends the client.
    drop(stream);
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
            if frame.pgn == crate::server::pipeline::PGN_NMEA0183_FILTER {
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
