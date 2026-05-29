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
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};

use canboat_core::format::{parse_plain, PlainError};
use canboat_io::device::FrameSender;

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
    use std::net::Shutdown;
    set_nodelay(&stream, "snapshot");
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

/// Bind a read-only TCP server. Each client subscribes to `hub` and
/// is forwarded broadcast lines until either side disconnects.
pub fn spawn_readonly(
    name: &'static str,
    bind: Ipv4Addr,
    port: u16,
    hub: Arc<Hub>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} TCP port {}:{}", bind, port))?;
    log::info!("{name} server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name(format!("{name}-accept"))
        .spawn(move || readonly_accept(name, listener, hub))
        .expect("spawn read-only accept"))
}

fn readonly_accept(name: &'static str, listener: TcpListener, hub: Arc<Hub>) {
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
            .spawn(move || run_readonly_client(stream, h))
            .ok();
    }
}

fn run_readonly_client(mut stream: TcpStream, hub: Arc<Hub>) {
    set_nodelay(&stream, "readonly");
    let rx = hub.subscribe();
    while let Ok(line) = rx.recv() {
        if stream.write_all(line.as_bytes()).is_err() {
            return;
        }
    }
}

/// Bind a write-only TCP server. Each client's lines are parsed as
/// PLAIN/FAST and sent to the device writer. Useful for clients that
/// just want to inject N2K traffic without reading anything back.
pub fn spawn_writeonly(bind: Ipv4Addr, port: u16, sender: FrameSender) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding write-only TCP port {}:{}", bind, port))?;
    log::info!("write-only server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name("write-accept".into())
        .spawn(move || writeonly_accept(listener, sender))
        .expect("spawn write-only accept"))
}

fn writeonly_accept(listener: TcpListener, sender: FrameSender) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("write-only accept failed: {e}");
                return;
            }
        };
        log::info!("write-only client connected: {peer}");
        let s = sender.clone();
        thread::Builder::new()
            .name("write-client".into())
            .spawn(move || run_writeonly_client(stream, s))
            .ok();
    }
}

fn run_writeonly_client(stream: TcpStream, sender: FrameSender) {
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
        if !forward_plain_line(&line, &sender) {
            return;
        }
    }
}

/// Bind the bidirectional CSV server. Each client thread spawns a
/// reader sub-thread (parses incoming PLAIN/FAST lines and queues
/// them for the device writer) and runs the read-out loop in the
/// caller thread (drains the CsvHub subscription and writes to the
/// socket).
///
/// `sender` is optional: when running in stdin mode there's no
/// device to forward to, so incoming writes are silently dropped.
pub fn spawn_csv_rw(
    bind: Ipv4Addr,
    port: u16,
    hub: Arc<Hub>,
    sender: Option<FrameSender>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding CSV TCP port {}:{}", bind, port))?;
    log::info!("CSV R/W server listening on {}:{}", bind, port);
    Ok(thread::Builder::new()
        .name("csv-accept".into())
        .spawn(move || csv_accept(listener, hub, sender))
        .expect("spawn CSV accept"))
}

fn csv_accept(listener: TcpListener, hub: Arc<Hub>, sender: Option<FrameSender>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                log::error!("csv accept failed: {e}");
                return;
            }
        };
        log::info!("csv client connected: {peer}");
        let h = hub.clone();
        let s = sender.clone();
        thread::Builder::new()
            .name("csv-client".into())
            .spawn(move || run_csv_client(stream, h, s))
            .ok();
    }
}

fn run_csv_client(stream: TcpStream, hub: Arc<Hub>, sender: Option<FrameSender>) {
    set_nodelay(&stream, "csv");
    // Split the stream so the read side can run on its own thread.
    // `TcpStream::try_clone` shares the underlying socket between
    // the two handles; closing either side closes the connection.
    // (set_nodelay above is a socket-level option, so it applies
    // to both halves.)
    let write_stream = stream;
    let read_stream = match write_stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("csv: cannot clone client stream: {e}");
            return;
        }
    };

    // Reader subthread — parse incoming PLAIN/FAST lines and forward
    // them to the device writer.
    let read_handle = thread::Builder::new()
        .name("csv-client-read".into())
        .spawn(move || {
            let reader = BufReader::new(read_stream);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => return,
                };
                match sender.as_ref() {
                    Some(sender) => {
                        if !forward_plain_line(&line, sender) {
                            return;
                        }
                    }
                    None => {
                        // Stdin mode: silently swallow lines.
                        log::debug!("csv (no device): dropping client line");
                    }
                }
            }
        })
        .expect("spawn csv reader subthread");

    // Main thread — drain the subscription, write to the socket.
    let rx = hub.subscribe();
    let mut stream = write_stream;
    while let Ok(line) = rx.recv() {
        if stream.write_all(line.as_bytes()).is_err() {
            break;
        }
    }
    // Closing the write side via drop will also close the read side
    // (shared socket fd), which lets the reader thread exit on its
    // next read.
    drop(stream);
    let _ = read_handle.join();
}

/// Parse one PLAIN/FAST line and forward to the device writer.
/// Returns `false` when the writer has gone away (caller should stop).
fn forward_plain_line(line: &str, sender: &FrameSender) -> bool {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return true;
    }
    match parse_plain(trimmed) {
        Ok(frame) => sender.send_frame(frame).is_ok(),
        Err(PlainError::Empty) => true,
        Err(e) => {
            log::warn!("ignoring malformed PLAIN/FAST line: {e}");
            true
        }
    }
}
