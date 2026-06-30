//! TCP client to either `n2kd` or `canboat-pipeline`.
//!
//! On startup the client opens the snapshot port (default 2597),
//! drains the one-shot JSON blob, and seeds [`crate::state::AppState`]
//! with everything currently in the cache. Then it opens the
//! analyzer/stream port (default 2598) and stays subscribed for the
//! lifetime of the process — each incoming line goes through
//! [`canboat_core::snapshot::classify_json_line`] so the keys we
//! produce are byte-identical to the ones the snapshot port stores.
//!
//! The stream port is RW on canboat-pipeline (`--analyzer-port` is
//! deliberately bidirectional, see project memory) so the same socket
//! is used to push outgoing PLAIN lines back upstream — ISO Requests
//! and PGN 126208 transmission-interval commands.
//!
//! n2kd's stream port is read-only; writes from the TUI to n2kd are
//! silently ignored by the daemon, and the ISO-Request / override
//! features will appear to do nothing. The status bar makes this
//! explicit by labelling the endpoint as `n2kd` when the snapshot
//! port responds with the n2kd-shaped status header (a heuristic, not
//! a contract) — for now we just surface the IP/port and document the
//! limitation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

use crate::state::AppState;

/// Per-connection timeout for the initial TCP connect + first read.
/// Without this the TUI sits black forever when the endpoint isn't
/// reachable (the OS default connect timeout is ~75 s on Linux,
/// longer on macOS).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on the snapshot read. canboat-pipeline / n2kd both write the
/// whole dump and close, so this only fires when the peer is
/// pathological (open socket, no FIN). Generous so a large cache
/// fits.
const SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Handle to the writer half of the live stream connection. The UI
/// pushes outgoing canboat PLAIN lines (without the trailing newline)
/// onto this channel; a background task tacks on `\n` and writes
/// them to the socket. The channel is created upfront — sends queue
/// here until the stream task connects, so the UI is usable from the
/// first frame.
#[derive(Clone)]
pub struct Writer {
    tx: mpsc::UnboundedSender<String>,
}

impl Writer {
    pub fn send(&self, line: String) -> bool {
        self.tx.send(line).is_ok()
    }
}

/// Build the writer channel and return both halves — the `Writer`
/// for the UI, and the receiver for the stream task to drain once
/// the connection comes up.
pub fn make_writer() -> (Writer, mpsc::UnboundedReceiver<String>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Writer { tx }, rx)
}

/// Spawn the background snapshot-load task. Failures are surfaced
/// via [`AppState::status`] (`snapshot_loaded` + `last_error`); the
/// caller is not blocked.
pub fn spawn_snapshot_load(host: String, port: u16, state: Arc<Mutex<AppState>>) {
    tokio::spawn(async move {
        if let Err(e) = load_snapshot(&host, port, state.clone()).await {
            let mut s = state.lock().await;
            s.status.last_error = Some(format!("snapshot: {e:#}"));
        }
    });
}

/// Spawn the background stream-connection task — connects to the
/// live-JSON port, then runs the reader (decoding into `state`) and
/// writer (draining `rx` to the socket) until the connection
/// drops. Failures are surfaced via [`AppState::status`].
pub fn spawn_stream_connection(
    host: String,
    port: u16,
    state: Arc<Mutex<AppState>>,
    rx: mpsc::UnboundedReceiver<String>,
) {
    tokio::spawn(async move {
        if let Err(e) = connect_stream(&host, port, state.clone(), rx).await {
            let mut s = state.lock().await;
            s.status.last_error = Some(format!("stream: {e:#}"));
        }
    });
}

/// Pull the entire snapshot blob from `host:port` and seed `state`
/// with it. Connection is closed by the server when the dump
/// completes; both the connect and the read are bounded by
/// [`CONNECT_TIMEOUT`] / [`SNAPSHOT_READ_TIMEOUT`] so a black-hole
/// peer can't hang the UI.
async fn load_snapshot(host: &str, port: u16, state: Arc<Mutex<AppState>>) -> Result<()> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect snapshot port {host}:{port} timed out"))?
        .with_context(|| format!("connecting snapshot port {host}:{port}"))?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::with_capacity(64 * 1024);
    timeout(SNAPSHOT_READ_TIMEOUT, reader.read_to_string(&mut buf))
        .await
        .context("reading snapshot blob timed out (peer did not close)")?
        .context("reading snapshot blob")?;

    let trimmed = buf.trim();
    if trimmed.is_empty() {
        let mut s = state.lock().await;
        s.status.snapshot_loaded = true;
        return Ok(());
    }
    let root: Value = serde_json::from_str(trimmed).context("parsing snapshot JSON")?;
    let Some(by_pgn) = root.as_object() else {
        anyhow::bail!("snapshot top-level is not a JSON object");
    };

    let mut guard = state.lock().await;
    for (pgn_str, group) in by_pgn {
        let Ok(pgn) = pgn_str.parse::<u32>() else {
            continue;
        };
        let Some(group_obj) = group.as_object() else {
            continue;
        };
        for (key, line_val) in group_obj {
            if key == "description" {
                continue;
            }
            // `<src>` or `<src>_<secondary>` — split on the first `_`.
            let (src_str, secondary) = match key.split_once('_') {
                Some((s, sec)) => (s, Some(sec.to_string())),
                None => (key.as_str(), None),
            };
            let Ok(src) = src_str.parse::<u8>() else {
                continue;
            };
            let description = line_val
                .pointer("/description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            guard.upsert(pgn, src, secondary, description, line_val.clone());
        }
    }
    guard.status.snapshot_loaded = true;
    Ok(())
}

/// Open the live stream socket and run reader + writer concurrently
/// on the current task. Returns when either half ends (peer closed,
/// I/O error). The Writer channel's `rx` is owned by this task — any
/// queued sends drain to the socket as soon as the connection is up.
async fn connect_stream(
    host: &str,
    port: u16,
    state: Arc<Mutex<AppState>>,
    rx: mpsc::UnboundedReceiver<String>,
) -> Result<()> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect stream port {host}:{port} timed out"))?
        .with_context(|| format!("connecting stream port {host}:{port}"))?;
    stream.set_nodelay(true).ok();
    let (read_half, write_half) = stream.into_split();

    {
        let mut s = state.lock().await;
        s.status.stream_connected = true;
    }

    // Run both halves; first to finish unblocks the other (because the
    // socket halves share a Drop tree once the task exits).
    tokio::select! {
        _ = reader_task(read_half, state.clone()) => {}
        _ = writer_task(write_half, rx, state.clone()) => {}
    }
    let mut s = state.lock().await;
    s.status.stream_connected = false;
    Ok(())
}

async fn reader_task(reader: tokio::net::tcp::OwnedReadHalf, state: Arc<Mutex<AppState>>) {
    let mut br = BufReader::new(reader);
    let mut line = String::with_capacity(4096);
    loop {
        line.clear();
        match br.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                let mut s = state.lock().await;
                s.status.last_error = Some(format!("stream read: {e}"));
                break;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        // Banner from analyzer-style emitters — skip without poisoning
        // the cache.
        if trimmed.starts_with("{\"version\"") {
            continue;
        }
        // canboat C / our n2kd require `}}` to filter out fieldless
        // records; mirror that so we never insert empty entries.
        if !trimmed.ends_with("}}") {
            continue;
        }
        let mut inputs = Vec::new();
        canboat_core::snapshot::classify_json_line(trimmed, |i| inputs.push(i));
        if inputs.is_empty() {
            continue;
        }
        let mut s = state.lock().await;
        for input in inputs {
            // Re-parse the (possibly spliced) line so the entry
            // carries a structured Value the UI can pointer-walk.
            let value: Value = match serde_json::from_str(&input.line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            s.upsert(
                input.pgn,
                input.src,
                input.secondary,
                input.pgn_description,
                value,
            );
        }
    }
    let mut s = state.lock().await;
    s.status.stream_connected = false;
}

async fn writer_task(
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<String>,
    state: Arc<Mutex<AppState>>,
) {
    while let Some(mut line) = rx.recv().await {
        if !line.ends_with('\n') {
            line.push('\n');
        }
        if let Err(e) = writer.write_all(line.as_bytes()).await {
            let mut s = state.lock().await;
            s.status.last_error = Some(format!("stream write: {e}"));
            break;
        }
    }
}
