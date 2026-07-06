// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::state::{AppState, Progress};

/// Per-connection timeout for the initial TCP connect. Without this
/// the TUI sits black forever when the endpoint isn't reachable (the
/// OS default connect timeout is ~75 s on Linux, longer on macOS).
/// 10 s is a tight upper bound that still survives a slow link and a
/// busy peer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

/// One message from the log-decode thread to the apply task. A `Frame`
/// carries the coalesced PLAIN/FAST line for a whole decoded frame
/// (once, for the Raw-export buffer); the following `Record`(s) are the
/// per-classifier splits of that same frame applied to the model.
enum LoadItem {
    Frame(String),
    Record(canboat_core::snapshot::SnapshotInput),
}

/// Does the file look like analyzer JSON output (our own "Analysed"
/// export) rather than a raw wire capture? Peeks the first non-blank,
/// non-`#` line and checks for a leading `{`.
fn looks_like_json_capture(path: &Path) -> bool {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        return t.starts_with('{');
    }
    false
}

/// Ingest a raw wire capture (PLAIN/FAST/Actisense/…) via the analyzer
/// decode pipeline, emitting a `Frame` (coalesced bytes, for Raw
/// re-export) plus the classifier `Record`s for each decoded message.
fn ingest_raw_capture(path: &Path, tx: &mpsc::UnboundedSender<LoadItem>) -> anyhow::Result<()> {
    use canboat_core::format::write_plain;
    use canboat_core::frame::RawFrame;
    use canboat_core::output::{JsonOptions, write_json};
    use canboat_core::snapshot::classify_json_line;
    let cfg = analyzer::replay::Config::default();
    let json_opts = JsonOptions::default();
    let mut buf = String::with_capacity(512);
    let mut raw = String::with_capacity(128);
    analyzer::replay::decode_file(path, &cfg, |decoded| {
        // Re-emit the wire bytes as one coalesced PLAIN/FAST line so a
        // later "Save ▸ Raw" can round-trip the capture. Sent once per
        // frame, ahead of its classifier splits.
        raw.clear();
        let frame = RawFrame::new(
            decoded.timestamp.clone(),
            decoded.prio,
            decoded.pgn,
            decoded.src,
            decoded.dst,
            decoded.data.iter().copied(),
        );
        if write_plain(&mut raw, &frame).is_ok() {
            let _ = tx.send(LoadItem::Frame(raw.clone()));
        }
        buf.clear();
        // Re-render to JSON so the per-line classifier path here is
        // identical to the live-stream one — same composite keys, same
        // per-iteration splits for repeating-PK PGNs.
        if write_json(&mut buf, decoded, &json_opts).is_err() {
            return;
        }
        classify_json_line(&buf, |input| {
            let _ = tx.send(LoadItem::Record(input));
        });
    })?;
    Ok(())
}

/// Ingest an analyzer-JSON capture (our "Analysed" export): one JSON
/// record per line, applied through the same `classify_json_line` path
/// as the live stream. There are no wire bytes to re-emit, so no
/// `Frame`s are sent (a later Raw save of a JSON-loaded capture is
/// empty, same as live mode).
fn ingest_json_capture(path: &Path, tx: &mpsc::UnboundedSender<LoadItem>) -> anyhow::Result<()> {
    use canboat_core::snapshot::classify_json_line;
    use std::io::BufRead;
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.context("reading JSON capture")?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        classify_json_line(t, |input| {
            let _ = tx.send(LoadItem::Record(input));
        });
    }
    Ok(())
}

/// Spawn the background log-replay task. Sniffs `path` for analyzer
/// JSON (our own "Analysed" export) vs a raw wire capture and ingests
/// it accordingly in a blocking thread, shipping records through an
/// unbounded channel to a sibling async apply task. Errors land in
/// `AppState::status.last_error` so the fatal-error modal surfaces them.
pub fn spawn_log_load(path: PathBuf, state: Arc<Mutex<AppState>>) -> Vec<JoinHandle<()>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<LoadItem>();

    // CPU-bound: run the decode in a blocking thread so the tokio
    // reactor isn't starved on big captures.
    let path_for_blocker = path.clone();
    let state_for_err = state.clone();
    let decode = tokio::task::spawn_blocking(move || {
        let result = if canboat_io::container::is_container(&path_for_blocker) {
            // Binary `.pcap` / `.pcap.gz` / `.nif` — unwrapped to PLAIN
            // by the analyzer's container-aware `decode_file`.
            ingest_raw_capture(&path_for_blocker, &tx)
        } else if looks_like_json_capture(&path_for_blocker) {
            ingest_json_capture(&path_for_blocker, &tx)
        } else {
            ingest_raw_capture(&path_for_blocker, &tx)
        };
        if let Err(e) = result {
            // Lock briefly to surface the read / parse failure to the UI.
            tokio::runtime::Handle::current().block_on(async {
                let mut s = state_for_err.lock().await;
                s.status.last_error = Some(format!("log: {e:#}"));
            });
        }
    });

    // Drain the channel on the tokio runtime — applies one record at
    // a time, so a long-running ingest doesn't lock the UI out.
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let apply = tokio::spawn(async move {
        let mut count = 0usize;
        while let Some(item) = rx.recv().await {
            match item {
                LoadItem::Frame(line) => {
                    let mut s = state.lock().await;
                    s.raw_lines.push(line);
                }
                LoadItem::Record(input) => {
                    let value: Value = match serde_json::from_str(&input.line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let mut s = state.lock().await;
                    s.upsert(
                        input.pgn,
                        input.src,
                        input.secondary,
                        input.pgn_description,
                        value,
                    );
                    count += 1;
                }
            }
        }
        // Channel closed → analyzer pipeline finished. Confirm to the
        // user that the (asynchronous) load is done.
        let mut s = state.lock().await;
        s.status.snapshot_loaded = true;
        s.notice = Some(format!("✓ Loaded {count} records — {name}"));
    });
    vec![decode, apply]
}

/// Output format for a capture save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveFormat {
    /// Decoded canboat analyzer JSON, one object per line (`.json`).
    Analysed,
    /// Coalesced canboat PLAIN/FAST text with a `# format=FAST` header
    /// (`.raw`) — re-loadable via File ▸ Load. Only carries frames
    /// captured in log-replay mode; the live JSON stream has no wire
    /// bytes to re-emit.
    Raw,
}

impl SaveFormat {
    /// File extension for this format (no dot).
    pub fn extension(self) -> &'static str {
        match self {
            SaveFormat::Analysed => "json",
            SaveFormat::Raw => "raw",
        }
    }
}

/// Write the current capture to `path` in `format`. Returns the number
/// of records / frames written.
///
/// * [`SaveFormat::Analysed`] serialises the observation history as one
///   JSON object per line.
/// * [`SaveFormat::Raw`] writes a `# format=FAST` header followed by the
///   coalesced PLAIN/FAST line for every captured frame (empty in live
///   mode, where no wire bytes are retained).
///
/// The interactive path uses [`spawn_save`] (chunked, off the UI lock);
/// this single-shot writer backs the format-correctness tests, which
/// need a synchronous result to assert against.
#[cfg(test)]
pub fn save_capture(path: &Path, state: &AppState, format: SaveFormat) -> Result<usize> {
    use std::fs::File;
    use std::io::{BufWriter, Write};
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    let mut n = 0usize;
    match format {
        SaveFormat::Analysed => {
            for rec in &state.history {
                serde_json::to_writer(&mut w, &rec.line).context("serialising record")?;
                w.write_all(b"\n").context("writing capture")?;
                n += 1;
            }
        }
        SaveFormat::Raw => {
            // The coalesced-payload header canboat's reader recognises.
            w.write_all(b"# format=FAST\n").context("writing header")?;
            for line in &state.raw_lines {
                w.write_all(line.as_bytes()).context("writing frame")?;
                w.write_all(b"\n").context("writing frame")?;
                n += 1;
            }
        }
    }
    w.flush().context("flushing capture")?;
    Ok(n)
}

/// Spawn a background capture save. A big (700 MB+) export must not run
/// under the state lock — that would freeze the UI for the whole write —
/// so this writes in chunks, releasing the lock between them and
/// reporting progress via [`AppState::save_progress`]. `history` /
/// `raw_lines` are append-only, so snapshotting the length up front and
/// only writing indices `0..total` is race-free even in live mode; the
/// bounds are re-checked with `get` in case Load/Connect replaced the
/// state mid-write (both are disabled while a save runs).
pub fn spawn_save(
    path: PathBuf,
    format: SaveFormat,
    state: Arc<Mutex<AppState>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_save(&path, format, &state).await {
            let mut s = state.lock().await;
            s.save_progress = None;
            s.status.last_error = Some(format!("save: {e:#}"));
        }
    })
}

async fn run_save(path: &Path, format: SaveFormat, state: &Arc<Mutex<AppState>>) -> Result<()> {
    use tokio::io::BufWriter;

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture")
        .to_string();
    let total = {
        let mut s = state.lock().await;
        let total = match format {
            SaveFormat::Analysed => s.history.len(),
            SaveFormat::Raw => s.raw_lines.len(),
        };
        s.save_progress = Some(Progress {
            label: format!("Saving {name}"),
            done: 0,
            total,
        });
        total
    };

    let file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    if matches!(format, SaveFormat::Raw) {
        w.write_all(b"# format=FAST\n")
            .await
            .context("writing header")?;
    }

    // Serialise a slice of records under the lock, then release it while
    // the (potentially slow) disk write runs.
    const CHUNK: usize = 2000;
    let mut done = 0usize;
    let mut buf = String::with_capacity(64 * 1024);
    while done < total {
        let end = (done + CHUNK).min(total);
        buf.clear();
        {
            let s = state.lock().await;
            match format {
                SaveFormat::Analysed => {
                    for i in done..end {
                        let Some(rec) = s.history.get(i) else { break };
                        buf.push_str(&serde_json::to_string(&rec.line).unwrap_or_default());
                        buf.push('\n');
                    }
                }
                SaveFormat::Raw => {
                    for i in done..end {
                        let Some(line) = s.raw_lines.get(i) else {
                            break;
                        };
                        buf.push_str(line);
                        buf.push('\n');
                    }
                }
            }
        }
        w.write_all(buf.as_bytes())
            .await
            .context("writing capture")?;
        done = end;
        {
            let mut s = state.lock().await;
            if let Some(p) = &mut s.save_progress {
                p.done = done;
            }
        }
        // Yield so the UI can grab the lock and repaint the bar.
        tokio::task::yield_now().await;
    }
    w.flush().await.context("flushing capture")?;

    let mut s = state.lock().await;
    s.save_progress = None;
    s.notice = Some(if done == 0 && format == SaveFormat::Raw {
        "Saved 0 raw frames — live JSON has no wire bytes; load a capture to export raw".to_string()
    } else {
        format!("✓ Saved {done} records → {}", path.display())
    });
    Ok(())
}

/// Spawn the background snapshot-load task. Failures are surfaced
/// via [`AppState::status`] (`snapshot_loaded` + `last_error`); the
/// caller is not blocked.
pub fn spawn_snapshot_load(host: String, port: u16, state: Arc<Mutex<AppState>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = load_snapshot(&host, port, state.clone()).await {
            let mut s = state.lock().await;
            s.status.last_error = Some(format!("snapshot: {e:#}"));
        }
    })
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
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = connect_stream(&host, port, state.clone(), rx).await {
            let mut s = state.lock().await;
            s.status.last_error = Some(format!("stream: {e:#}"));
        }
    })
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
            // Surface every non-OK PGN 126208 Acknowledge as a
            // user-visible alert. Devices that accept a Request
            // typically stay silent (the SCX-20 only ACKs failures
            // — see device-scx20 memory) so reacting only to
            // failures is the right signal.
            if input.pgn == 126208
                && let Some(alert) = nak_alert(input.src, &value)
            {
                s.push_alert(alert);
            }
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

/// If `line` is a PGN 126208 Acknowledge (Function Code = 2) carrying
/// at least one non-zero error code, format a one-line summary
/// suitable for the UI toast slot. Returns `None` for non-ACKs and
/// for ACKs whose error codes are all zero ("Acknowledge" — no
/// error). The summary names both the acknowledging device
/// (`src` of the inbound record) and the PGN the ACK references, so
/// the user can match it back to whichever Request they just sent.
fn nak_alert(ack_src: u8, line: &Value) -> Option<String> {
    let function_code = read_lookup_int(line.pointer("/fields/Function Code"))?;
    if function_code != 2 {
        return None;
    }
    let pgn_field = line.pointer("/fields/PGN");
    let acked_pgn = read_lookup_int(pgn_field).unwrap_or(0);
    let acked_pgn_name = pgn_field
        .and_then(|v| v.pointer("/name").and_then(Value::as_str))
        .unwrap_or("");
    let pgn_err = read_lookup_int(line.pointer("/fields/PGN error code")).unwrap_or(0);
    let pgn_err_name = read_lookup_name(line.pointer("/fields/PGN error code")).unwrap_or_default();
    let interval_err =
        read_lookup_int(line.pointer("/fields/Transmission interval/Priority error code"))
            .unwrap_or(0);
    let interval_err_name =
        read_lookup_name(line.pointer("/fields/Transmission interval/Priority error code"))
            .unwrap_or_default();
    if pgn_err == 0 && interval_err == 0 {
        return None;
    }
    let pgn_label = if acked_pgn_name.is_empty() {
        format!("PGN {acked_pgn}")
    } else {
        format!("PGN {acked_pgn} ({acked_pgn_name})")
    };
    Some(format!(
        "⚠ src {ack_src} NAK {pgn_label} — PGN err {pgn_err} {pgn_err_name} / interval err {interval_err} {interval_err_name}"
    ))
}

/// Pull a numeric value out of a canboat lookup field — handles both
/// the bare integer shape and the `-nv` `{value, name, key}` object.
fn read_lookup_int(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    v.pointer("/value").and_then(Value::as_i64)
}

/// Pull the display name from a canboat lookup field (the `-nv`
/// object's `.name`). Returns `None` for plain-integer shapes.
fn read_lookup_name(v: Option<&Value>) -> Option<String> {
    v?.pointer("/name")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Status;
    use serde_json::json;
    use std::collections::HashMap;

    fn seeded() -> AppState {
        let mut s = AppState::new(Status::new_log("x".into()), HashMap::new());
        s.upsert(
            129025,
            10,
            None,
            "Position".into(),
            json!({"pgn": 129025, "fields": {"Latitude": 1.0}}),
        );
        s.upsert(127250, 10, None, "Heading".into(), json!({"pgn": 127250}));
        s
    }

    #[test]
    fn save_analysed_writes_one_json_line_per_record() {
        let s = seeded();
        let path =
            std::env::temp_dir().join(format!("canboat-tui-json-{}.json", std::process::id()));
        let n = save_capture(&path, &s, SaveFormat::Analysed).unwrap();
        assert_eq!(n, 2);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("129025"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_raw_writes_header_and_captured_frames() {
        let mut s = seeded();
        // Simulate what the log path captures.
        s.raw_lines
            .push("2024-01-01T00:00:00.000,2,129025,10,255,8,01,02,03,04,05,06,07,08".into());
        let path = std::env::temp_dir().join(format!("canboat-tui-raw-{}.raw", std::process::id()));
        let n = save_capture(&path, &s, SaveFormat::Raw).unwrap();
        assert_eq!(n, 1);
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some("# format=FAST"));
        assert!(lines.next().unwrap().contains(",129025,"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn analysed_export_is_detected_and_reingestible() {
        // Two field-bearing records so the classifier yields inputs.
        let mut s = AppState::new(Status::new_log("x".into()), HashMap::new());
        s.upsert(
            129025,
            10,
            None,
            "Position".into(),
            json!({"pgn": 129025, "src": 10, "fields": {"Latitude": 1.0}}),
        );
        s.upsert(
            127250,
            10,
            None,
            "Heading".into(),
            json!({"pgn": 127250, "src": 10, "fields": {"Heading": 2.0}}),
        );
        let path = std::env::temp_dir().join(format!("canboat-tui-rt-{}.json", std::process::id()));
        save_capture(&path, &s, SaveFormat::Analysed).unwrap();

        // Our export sniffs as JSON, a raw header does not.
        assert!(looks_like_json_capture(&path));

        // Re-ingesting yields the records back through the channel.
        let (tx, mut rx) = mpsc::unbounded_channel::<LoadItem>();
        ingest_json_capture(&path, &tx).unwrap();
        drop(tx);
        let mut records = 0;
        while let Ok(item) = rx.try_recv() {
            if matches!(item, LoadItem::Record(_)) {
                records += 1;
            }
        }
        assert_eq!(records, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn raw_capture_is_not_mistaken_for_json() {
        let path =
            std::env::temp_dir().join(format!("canboat-tui-rawsniff-{}.raw", std::process::id()));
        std::fs::write(
            &path,
            "# format=FAST\n2024-01-01T00:00:00.000,2,129025,10,255,8,01,02,03,04,05,06,07,08\n",
        )
        .unwrap();
        assert!(!looks_like_json_capture(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn spawn_save_writes_records_and_clears_progress() {
        let state = Arc::new(Mutex::new(seeded()));
        let path =
            std::env::temp_dir().join(format!("canboat-tui-async-{}.json", std::process::id()));
        spawn_save(path.clone(), SaveFormat::Analysed, state.clone())
            .await
            .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("129025"));

        let s = state.lock().await;
        assert!(s.save_progress.is_none(), "progress cleared when done");
        assert!(
            s.notice.as_deref().unwrap().contains("Saved 2 records"),
            "completion notice raised"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_raw_empty_in_live_mode_still_writes_header() {
        let s = AppState::new(Status::new_live("h".into(), 1, 2), HashMap::new());
        let path =
            std::env::temp_dir().join(format!("canboat-tui-raw-empty-{}.raw", std::process::id()));
        let n = save_capture(&path, &s, SaveFormat::Raw).unwrap();
        assert_eq!(n, 0);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "# format=FAST\n");
        let _ = std::fs::remove_file(&path);
    }
}
