//! `n2kd`: TCP multiplexer for an analyzer JSON stream.
//!
//! Mirrors the most-used surface of `canboat/n2kd/main.c`. The
//! analyzer feeds us JSON-per-line on stdin; we fan that out to TCP
//! clients on three ports:
//!
//! | Port (default)       | Behaviour                                                                  |
//! |----------------------|----------------------------------------------------------------------------|
//! | `port + 1` (2598)    | **JSON stream** — each connected client receives every line as it arrives. |
//! | `port`     (2597)    | **JSON snapshot** — on connect, send the latest-known JSON for every       |
//! |                      | `(pgn, src)` we've seen, then close.                                       |
//! | `port + 5` (2602)    | **Raw input** — clients write canboat PLAIN/FAST lines; we forward them    |
//! |                      | to stdout (so a pipeline like `n2kd | actisense-serial ttyUSB0` can write  |
//! |                      | back to the bus).                                                          |
//!
//! Deferred from canboat's `main.c`: NMEA 0183 conversion stream
//! (port + 2), AIS-only port (port + 3), status port (port + 4),
//! UDP broadcast, and the device-claim / product-info auto-request
//! state machine. The JSON stream + snapshot is what the vast
//! majority of n2kd consumers use.
//!
//! Architecture: three std threads — the stdin pump (also drives
//! the cache + broadcasts), the TCP accept loops (one per port),
//! and per-client writer threads. Subscriber registration goes via
//! `mpsc::Sender<String>` channels; cache state lives behind an
//! `Arc<Mutex<…>>`.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

/// Default TCP base port. Stream is `+1`, raw-input is `+5`.
const DEFAULT_PORT: u16 = 2597;
/// How long a cached `(pgn, src)` entry stays valid before we drop
/// it from snapshots. Matches `SENSOR_TIMEOUT` in `main.c`.
const SENSOR_TIMEOUT: Duration = Duration::from_secs(120);
/// Longer timeout for AIS-shaped messages (User ID / Message ID
/// secondary keys). Matches `AIS_TIMEOUT` in `main.c`.
const AIS_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Debug, Parser)]
#[command(
    name = "n2kd",
    about = "Multiplex analyzer JSON stdin to JSON snapshot / stream / raw-input TCP clients",
    version
)]
struct Cli {
    /// Base TCP port. `port` is JSON snapshot, `port+1` is JSON
    /// stream, `port+5` is raw input.
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Filter incoming JSON to PGNs whose `src` matches this
    /// comma-separated list (e.g. `1,2,127`). Matches canboat's
    /// `srcFilter`.
    #[arg(long)]
    src_filter: Option<String>,

    /// Bind on `0.0.0.0` instead of `127.0.0.1`.
    #[arg(long)]
    public: bool,

    /// Verbose / debug logging — alias of `-d`.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Quiet — only show errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("n2kd: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let level = if cli.quiet {
        "error"
    } else if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let src_filter = parse_src_filter(cli.src_filter.as_deref())?;
    let bind_addr: Ipv4Addr = if cli.public {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };

    let hub = Arc::new(Hub::new(src_filter));

    // Spawn the three TCP listeners.
    spawn_listener(
        bind_addr,
        cli.port + 1,
        "json-stream",
        Arc::clone(&hub),
        run_stream_client,
    )?;
    spawn_listener(
        bind_addr,
        cli.port,
        "json-snapshot",
        Arc::clone(&hub),
        run_snapshot_client,
    )?;
    spawn_listener(
        bind_addr,
        cli.port + 5,
        "raw-input",
        Arc::clone(&hub),
        run_raw_input_client,
    )?;

    // Main thread: stdin pump.
    run_stdin_pump(&hub)
}

fn parse_src_filter(arg: Option<&str>) -> Result<Option<Vec<u8>>> {
    let Some(s) = arg else { return Ok(None) };
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let v: u8 = tok
            .parse()
            .with_context(|| format!("--src-filter token {tok:?}"))?;
        out.push(v);
    }
    Ok(Some(out))
}

/// Spawn a TCP listener on `port`. Each accepted connection is
/// handed to `handler` on its own thread.
fn spawn_listener<F>(
    bind: Ipv4Addr,
    port: u16,
    name: &'static str,
    hub: Arc<Hub>,
    handler: F,
) -> Result<()>
where
    F: Fn(TcpStream, Arc<Hub>) + Send + Copy + 'static,
{
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} ({name})");
    thread::Builder::new()
        .name(format!("n2kd-{name}"))
        .spawn(move || {
            for incoming in listener.incoming() {
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("accept on {name}: {e}");
                        continue;
                    }
                };
                let peer = stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|_| "?".into());
                log::info!("{name} client connected from {peer}");
                let hub2 = Arc::clone(&hub);
                thread::Builder::new()
                    .name(format!("n2kd-{name}-{peer}"))
                    .spawn(move || handler(stream, hub2))
                    .ok();
            }
        })
        .context("spawning listener")?;
    Ok(())
}

/// Per-stream-client handler: register as a subscriber, drain the
/// channel writing each frame to the socket. The hub holds the
/// `Sender<String>`; when the client disconnects, the writer thread
/// drops it and the hub purges it on the next broadcast.
fn run_stream_client(mut stream: TcpStream, hub: Arc<Hub>) {
    let (tx, rx) = mpsc::channel::<String>();
    hub.subscribe(tx);
    while let Ok(line) = rx.recv() {
        if stream.write_all(line.as_bytes()).is_err() {
            return;
        }
        // Each line in the channel already has its `\n`.
    }
}

/// Per-snapshot-client handler: write every cached line, close.
fn run_snapshot_client(mut stream: TcpStream, hub: Arc<Hub>) {
    let snapshot = hub.snapshot();
    for line in snapshot {
        if stream.write_all(line.as_bytes()).is_err() {
            return;
        }
    }
    // Closing the stream prompts the client to read EOF.
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Per-raw-input-client handler: read lines, forward to stdout.
fn run_raw_input_client(stream: TcpStream, hub: Arc<Hub>) {
    let reader = BufReader::new(stream);
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    for line in reader.lines().map_while(|r| r.ok()) {
        let mut line = line;
        line.push('\n');
        if lock.write_all(line.as_bytes()).is_err() {
            return;
        }
        let _ = lock.flush();
        let _ = hub; // Reserved — future versions may want to push raw input through the broadcast too.
    }
}

/// Read JSON-per-line from stdin, update the cache, broadcast each
/// line to stream subscribers.
fn run_stdin_pump(hub: &Hub) -> Result<()> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::with_capacity(4096);
    loop {
        line.clear();
        let n = lock.read_line(&mut line).context("reading stdin")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        // The analyzer banner ({"version":…,"units":…}) carries no
        // PGN — broadcast it but skip the cache.
        if trimmed.starts_with("{\"version\"") {
            hub.broadcast(&line);
            continue;
        }
        if !trimmed.starts_with("{\"timestamp\"") {
            log::debug!("ignoring non-JSON-PGN line: {trimmed:.80}");
            continue;
        }
        let Some(meta) = extract_meta(trimmed) else {
            log::debug!("could not parse pgn/src from {trimmed:.80}");
            hub.broadcast(&line);
            continue;
        };
        if !hub.src_allowed(meta.src) {
            continue;
        }
        hub.store(meta, line.clone());
        hub.broadcast(&line);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    pgn: u32,
    src: u8,
    /// Optional secondary key — collapses messages from the same
    /// (pgn, src) but with a distinguishing field like `Instance` or
    /// `User ID`. Mirrors canboat's `secondaryKeyList`. We hash the
    /// value into a u64 so the cache key stays Copy / fixed-size.
    secondary: u64,
    is_ais_like: bool,
}

/// Extract (pgn, src, secondary-key-hash) from a JSON line. Cheap:
/// substring scans, not real JSON parsing — same approach canboat C
/// uses in `getJSONValue`.
fn extract_meta(line: &str) -> Option<Meta> {
    let pgn = find_int_field(line, "\"pgn\":")?;
    let src = find_int_field(line, "\"src\":")? as u8;
    let secondary = SECONDARY_KEYS
        .iter()
        .find_map(|(k, _)| {
            let idx = line.find(k)?;
            let after = &line[idx + k.len()..];
            // Read until the next `,` or `}`. Hash the bytes — we
            // only need a stable key, not the value itself.
            let end = after.find([',', '}']).unwrap_or(after.len());
            Some(djb2_hash(after[..end].trim_matches(['"', ' ', ':'])))
        })
        .unwrap_or(0);
    let is_ais_like = SECONDARY_KEYS
        .iter()
        .any(|(k, ais)| *ais && line.contains(k));
    Some(Meta {
        pgn: pgn as u32,
        src,
        secondary,
        is_ais_like,
    })
}

/// Parse `"<field>":NUM` out of a JSON line. Returns the integer
/// value, or `None` if not found / not numeric.
fn find_int_field(line: &str, key: &str) -> Option<i64> {
    let idx = line.find(key)?;
    let after = &line[idx + key.len()..];
    let after = after.trim_start_matches([' ', ':']);
    let end = after
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .unwrap_or(after.len());
    after[..end].parse().ok()
}

fn djb2_hash(s: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = (h.wrapping_shl(5)).wrapping_add(h).wrapping_add(b as u64);
    }
    h
}

/// Secondary-key field name fragments and whether they indicate an
/// AIS-shaped message (which gets a longer cache TTL). Mirrors
/// `secondaryKeyList[]` in canboat main.c.
const SECONDARY_KEYS: &[(&str, bool)] = &[
    ("Instance\":", false),
    ("\"Reference\":", false),
    ("\"User ID\":", true),
    ("\"Message ID\":", true),
    ("\"Proprietary ID\":", false),
];

/// The shared state every part of the daemon reads or writes.
struct Hub {
    cache: Mutex<HashMap<(u32, u8, u64), CacheEntry>>,
    subscribers: Mutex<Vec<Sender<String>>>,
    src_filter: Option<Vec<u8>>,
}

struct CacheEntry {
    line: String,
    expires_at: Instant,
}

impl Hub {
    fn new(src_filter: Option<Vec<u8>>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(Vec::new()),
            src_filter,
        }
    }

    fn src_allowed(&self, src: u8) -> bool {
        match &self.src_filter {
            None => true,
            Some(list) => list.contains(&src),
        }
    }

    /// Replace the cached value for `(pgn, src, secondary)`.
    fn store(&self, meta: Meta, line: String) {
        let ttl = if meta.is_ais_like {
            AIS_TIMEOUT
        } else {
            SENSOR_TIMEOUT
        };
        let entry = CacheEntry {
            line,
            expires_at: Instant::now() + ttl,
        };
        self.cache
            .lock()
            .unwrap()
            .insert((meta.pgn, meta.src, meta.secondary), entry);
    }

    /// Snapshot of every cached entry that hasn't expired yet.
    fn snapshot(&self) -> Vec<String> {
        let now = Instant::now();
        let mut guard = self.cache.lock().unwrap();
        guard.retain(|_, v| v.expires_at > now);
        guard.values().map(|v| v.line.clone()).collect()
    }

    fn subscribe(&self, tx: Sender<String>) {
        self.subscribers.lock().unwrap().push(tx);
    }

    /// Push `line` to every subscriber. Drops senders whose receiver
    /// has disconnected. The line is expected to already end with a
    /// newline — callers pass through what they read from stdin.
    fn broadcast(&self, line: &str) {
        let mut subs = self.subscribers.lock().unwrap();
        subs.retain(|tx| tx.send(line.to_string()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pgn_src() {
        let line = r#"{"timestamp":"2026-01-01T00:00:00","prio":2,"src":7,"dst":255,"pgn":127251,"fields":{"Rate":0}}"#;
        let meta = extract_meta(line).unwrap();
        assert_eq!(meta.pgn, 127251);
        assert_eq!(meta.src, 7);
        // No secondary-key field → hash is 0.
        assert_eq!(meta.secondary, 0);
        assert!(!meta.is_ais_like);
    }

    #[test]
    fn extracts_secondary_key_for_ais() {
        let line = r#"{"timestamp":"…","src":23,"pgn":129039,"fields":{"Message ID":18,"User ID":"244180106"}}"#;
        let meta = extract_meta(line).unwrap();
        assert_eq!(meta.pgn, 129039);
        assert!(meta.is_ais_like);
        assert!(meta.secondary != 0, "secondary should hash to non-zero");
    }

    #[test]
    fn snapshot_returns_cached_lines() {
        let hub = Hub::new(None);
        let line = r#"{"timestamp":"…","src":7,"pgn":127251,"fields":{"Rate":0}}"#.to_string();
        let meta = extract_meta(&line).unwrap();
        hub.store(meta, line.clone() + "\n");
        let snap = hub.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].contains("127251"));
    }

    #[test]
    fn src_filter_accepts_listed() {
        let hub = Hub::new(Some(vec![1, 7]));
        assert!(hub.src_allowed(1));
        assert!(hub.src_allowed(7));
        assert!(!hub.src_allowed(8));
    }
}
