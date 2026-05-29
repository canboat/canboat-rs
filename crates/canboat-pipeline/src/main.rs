//! `canboat-pipeline` — single-process N2K → NMEA 0183 pipeline.
//!
//! Combines the work that the C canboat stack normally splits across
//! three processes (a device reader like `actisense-serial`, the
//! `analyzer`, and `n2kd`) into one binary. `RawFrame`s flow between
//! stages as structs over mpsc channels — no PLAIN/FAST text
//! serialization between stages — so the formatter/parser tax pays
//! out only at the human-readable boundaries (NMEA 0183 stdout and
//! the optional CSV TCP server).
//!
//! Input modes:
//!
//! * **stdin** (no `--actisense` / `--ikonvert` / `--maretron`): the
//!   binary parses PLAIN/FAST lines off stdin. Compatible with
//!   `analyzer < file.raw | canboat-pipeline` style pipelines that used
//!   to exist with `n2kd-inproc`.
//! * **device**: a [`canboat_io::device`] reader stage opens the
//!   chosen serial port / TCP socket and emits `RawFrame`s
//!   directly. In this mode, the raw-input TCP port (write-N2K) and
//!   the lazy CSV TCP server are also wired up.
//!
//! Output: NMEA 0183 sentences on stdout.

mod hub;
mod pipeline;
mod snapshot;
mod tcp;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};
use clap::Parser;

use canboat_core::format::{
    detect, header_implies_coalesced, parse_format_header, parse_with, InputFormat,
};
use canboat_core::{LoadOptions, PgnDatabase, RawFrame};
use canboat_io::device::{self, Supervisor};
use canboat_io::open_serial_rw;

use crate::hub::Hub;
use crate::pipeline::Hubs;
use crate::snapshot::SnapshotStore;

const SYNTHETIC_PGNS_JSON: &str = include_str!("../../../data/synthetic-pgns.json");

#[derive(Debug, Parser)]
#[command(
    name = "canboat-pipeline",
    about = "Single-process device-reader \u{2192} analyzer \u{2192} n2kd pipeline",
    version
)]
struct Cli {
    /// Path to canboat.json. Falls back to CANBOAT_JSON env, then
    /// to the workspace-vendored copy at data/canboat.json.
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,

    /// Read frames from an Actisense NGT-1 / W2K-1 on this serial
    /// device path (e.g. `/dev/ttyUSB0`).
    #[arg(
        long,
        value_name = "DEVICE",
        conflicts_with_all = ["ikonvert", "maretron"]
    )]
    actisense: Option<String>,

    /// Read frames from a Digital Yacht iKonvert on this serial
    /// device path.
    #[arg(
        long,
        value_name = "DEVICE",
        conflicts_with_all = ["actisense", "maretron"]
    )]
    ikonvert: Option<String>,

    /// Read frames from a Maretron IPG100/200 over TCP. Accepts either
    /// `host:port` or `tcp://host[:port]`. Default port 6543 (bus 0).
    #[arg(
        long,
        value_name = "URL",
        conflicts_with_all = ["actisense", "ikonvert"]
    )]
    maretron: Option<String>,

    /// Baud rate for serial devices. Defaults: 115200 for NGT-1,
    /// 230400 for iKonvert. Ignored for Maretron.
    #[arg(long, value_name = "BAUD")]
    baud: Option<u32>,

    /// Maretron login password (default: empty).
    #[arg(long, default_value = "")]
    maretron_password: String,

    /// iKonvert RX filter list (`<pgn>,<pgn>,...`). When set, init
    /// brings the device online in `NORMAL` mode and runs the
    /// `N2NET_RESET` + `RX_LIST` handshake steps.
    #[arg(long, value_name = "PGN,PGN,...")]
    ikonvert_rx: Option<String>,

    /// iKonvert TX filter list (`<pgn>,<pgn>,...`). Triggers the
    /// `N2NET_RESET` + `TX_LIST` handshake steps.
    #[arg(long, value_name = "PGN,PGN,...")]
    ikonvert_tx: Option<String>,

    /// Disable the iKonvert TX rate limit. Use at your own risk.
    #[arg(long)]
    ikonvert_rate_limit_off: bool,

    /// Bind address for all TCP listeners. Defaults to `0.0.0.0` so
    /// clients on the LAN (chartplotters, OpenCPN, etc.) can
    /// connect. Pass `127.0.0.1` to restrict access to the local
    /// host.
    #[arg(long, default_value = "0.0.0.0")]
    bind: Ipv4Addr,

    /// Port for the snapshot server — on connect, dumps the latest
    /// analyzer JSON line per `(pgn, src, secondary)` then closes.
    /// Matches canboat C `n2kd`'s base port (`-p`). Enabling this
    /// forces JSON serialization for every decoded record so the
    /// cache stays current; disable with `0` if you don't need it.
    #[arg(long, default_value_t = 2597)]
    snapshot_port: u16,

    /// Port for the read-only analyzer JSON server — one decoded PGN
    /// per line. Matches canboat C `n2kd`'s `port+1` stream port.
    /// Lazy: skipped when no client is subscribed. `0` disables.
    #[arg(long, default_value_t = 2598)]
    analyzer_port: u16,

    /// Port for the read-only NMEA 0183 server (includes AIVDM).
    /// Matches canboat C `n2kd`'s `port+2` NMEA 0183 port. `0`
    /// disables.
    #[arg(long, default_value_t = 2599)]
    nmea0183_port: u16,

    /// Port for the write-only N2K injection server. PLAIN/FAST lines
    /// from clients are encoded and pushed to the device. Matches
    /// canboat C `n2kd`'s `port+5` raw-input port. `0` disables.
    /// Only active in device mode (otherwise there is no device to
    /// send to).
    #[arg(long, default_value_t = 2602)]
    write_port: u16,

    /// Port for the bidirectional CSV (PLAIN/FAST) server. Clients
    /// receive every frame as a PLAIN/FAST line and can send
    /// PLAIN/FAST lines back to inject into the N2K bus. New in
    /// `canboat-pipeline`; no direct canboat C equivalent. Formatting
    /// is lazy (skipped when no client is subscribed). `0` disables.
    #[arg(long, default_value_t = 2603)]
    csv_port: u16,

    /// Also write NMEA 0183 sentences (including AIVDM) to stdout —
    /// mirrors canboat C `n2kd`'s `--nmea0183` flag. Off by default,
    /// matching n2kd's TCP-multiplex behaviour; subscribers should
    /// connect to `--nmea0183-port` (2599) instead.
    #[arg(long)]
    nmea0183_stdout: bool,

    /// Keep fields in their canboat-declared SI base units (rad,
    /// Pa, K, C, …). Without this flag the pipeline applies
    /// canboat's user-friendly fix-ups — Pa→bar, K→°C, C→Ah,
    /// rad→deg — matching the canboat C analyzer's default. The
    /// flag affects the analyzer JSON / snapshot ports and any
    /// NMEA 0183 conversion that consumes raw field values.
    #[arg(long)]
    si: bool,

    /// Verbose logging.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Quiet — only errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn default_db_path() -> Option<PathBuf> {
    let here = std::env::current_exe().ok()?;
    let workspace = here.ancestors().nth(3)?;
    let candidate = workspace.join("data").join("canboat.json");
    candidate.exists().then_some(candidate)
}

fn main() -> Result<()> {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    let level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let db_path = cli
        .db
        .clone()
        .or_else(|| std::env::var_os("CANBOAT_JSON").map(PathBuf::from))
        .or_else(default_db_path)
        .context("no canboat.json path supplied (pass --db or set CANBOAT_JSON)")?;
    let load_opts = LoadOptions { si: cli.si };
    let mut db = PgnDatabase::load_with(&db_path, load_opts)
        .with_context(|| format!("loading PGN database {}", db_path.display()))?;
    db.merge_pgns_from_json_with(SYNTHETIC_PGNS_JSON, load_opts)
        .context("merging synthetic PGN definitions")?;

    let snapshot = if cli.snapshot_port != 0 {
        Some(Arc::new(SnapshotStore::new()))
    } else {
        None
    };
    let hubs = Hubs {
        csv: Arc::new(Hub::new()),
        nmea: Arc::new(Hub::new()),
        analyzer: Arc::new(Hub::new()),
        snapshot: snapshot.clone(),
    };

    // Pick the frame source and (if a device) its writer handle. In
    // device mode the source is a Supervisor that survives serial /
    // TCP disconnects with exponential backoff.
    //
    // `pre_coalesced` is true when each `RawFrame` from this source
    // is already a complete PGN payload (iKonvert / Maretron). In
    // that case the pipeline skips the fast-packet reassembler —
    // those gateways have already done the coalescing on the wire.
    let (frames_rx, supervisor, pre_coalesced) = open_source(&cli)?;
    let device_sender = supervisor.as_ref().map(|s| s.frame_sender());

    let mut tcp_joins: Vec<thread::JoinHandle<()>> = Vec::new();
    if let Some(store) = snapshot.as_ref() {
        tcp_joins.push(tcp::spawn_snapshot(
            cli.bind,
            cli.snapshot_port,
            store.clone(),
        )?);
    }
    if cli.csv_port != 0 {
        tcp_joins.push(tcp::spawn_csv_rw(
            cli.bind,
            cli.csv_port,
            hubs.csv.clone(),
            device_sender.clone(),
        )?);
    }
    if cli.nmea0183_port != 0 {
        tcp_joins.push(tcp::spawn_readonly(
            "nmea0183",
            cli.bind,
            cli.nmea0183_port,
            hubs.nmea.clone(),
        )?);
    }
    if cli.analyzer_port != 0 {
        tcp_joins.push(tcp::spawn_readonly(
            "analyzer",
            cli.bind,
            cli.analyzer_port,
            hubs.analyzer.clone(),
        )?);
    }
    if let (Some(sender), true) = (device_sender, cli.write_port != 0) {
        tcp_joins.push(tcp::spawn_writeonly(cli.bind, cli.write_port, sender)?);
    }

    pipeline::run(db, frames_rx, hubs, cli.nmea0183_stdout, pre_coalesced);

    // After the pipeline drains, signal the supervisor to stop
    // reconnecting. The TCP accept threads run forever — leak them;
    // process exit will reap them.
    if let Some(s) = supervisor {
        s.shutdown();
    }
    Ok(())
}

/// Open whichever input source the CLI selected. Returns
/// `(frames_rx, optional_supervisor, pre_coalesced)`.
///
/// * `pre_coalesced` is `true` when each `RawFrame` produced by the
///   source is already a complete PGN payload — the iKonvert and the
///   Maretron IPG do their own fast-packet coalescing on the wire,
///   so the pipeline must skip the reassembler for them. Sending
///   small coalesced payloads through the reassembler causes their
///   leading bytes to be misread as fast-packet headers.
/// * `supervisor` is `None` only in stdin mode; the caller skips
///   wiring the write-only TCP port and the supervisor shutdown.
///
/// In device mode the supervisor's manager thread handles reconnect
/// on disconnect/EOF with exponential backoff up to 30 s, so a flaky
/// serial port or TCP gateway doesn't take the pipeline down.
fn open_source(
    cli: &Cli,
) -> Result<(
    mpsc::Receiver<RawFrame>,
    Option<Supervisor>,
    Arc<AtomicBool>,
)> {
    if let Some(path) = cli.actisense.as_deref() {
        let baud = cli.baud.unwrap_or(115_200);
        let path = path.to_string();
        let factory = NamedFactory::new("ngt1", move || {
            let (reader, writer) = open_serial_rw(&path, baud)?;
            Ok(device::ngt1::run(reader, writer))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // NGT-1's `N2K_MSG_RECEIVED` (0x93) frames carry full PGN
        // payloads — fast-packet coalescing happens inside the
        // device, not on the wire we receive. Skip the reassembler.
        return Ok((rx, Some(sup), Arc::new(AtomicBool::new(true))));
    }
    if let Some(path) = cli.ikonvert.as_deref() {
        let baud = cli.baud.unwrap_or(230_400);
        let path = path.to_string();
        let rx_list = cli.ikonvert_rx.clone();
        let tx_list = cli.ikonvert_tx.clone();
        let rate_limit_off = cli.ikonvert_rate_limit_off;
        let factory = NamedFactory::new("ikonvert", move || {
            let (reader, writer) = open_serial_rw(&path, baud)?;
            let config = device::ikonvert::Config {
                rx_list: rx_list.clone(),
                tx_list: tx_list.clone(),
                rate_limit_off,
                ..Default::default()
            };
            Ok(device::ikonvert::run(reader, writer, config))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // iKonvert coalesces fast-packets internally; skip the
        // reassembler entirely.
        return Ok((rx, Some(sup), Arc::new(AtomicBool::new(true))));
    }
    if let Some(url) = cli.maretron.as_deref() {
        let url = url.to_string();
        let password = cli.maretron_password.clone();
        let factory = NamedFactory::new("maretron", move || {
            let (reader, writer) = open_maretron_pair(&url)?;
            let cfg = device::maretron::Config {
                password: password.clone(),
                fixtime: None,
            };
            Ok(device::maretron::run(reader, writer, cfg))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // Maretron IPG ships full PGN payloads per 0xA5 frame.
        return Ok((rx, Some(sup), Arc::new(AtomicBool::new(true))));
    }
    // stdin fallback — no device, no reconnect logic needed. We
    // can't know in advance whether the upstream uses PLAIN
    // (per-CAN-frame, needs reassembly) or FAST (already coalesced).
    // The stdin pump watches for `# format=<NAME>` headers and flips
    // the flag when it sees one declaring a coalesced format; the
    // pipeline itself also flips it on the first >8-byte payload.
    let pre_coalesced = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<RawFrame>();
    let coalesced_for_pump = pre_coalesced.clone();
    thread::Builder::new()
        .name("stdin-pump".into())
        .spawn(move || stdin_pump(tx, coalesced_for_pump))
        .expect("spawn stdin-pump");
    Ok((rx, None, pre_coalesced))
}

/// Swap the `Supervisor::frames_rx` out so the pipeline can own it
/// while we keep the supervisor for shutdown / frame_sender access.
fn split_supervisor(mut sup: Supervisor) -> (mpsc::Receiver<RawFrame>, Supervisor) {
    let (_dummy_tx, dummy_rx) = mpsc::channel::<RawFrame>();
    let rx = std::mem::replace(&mut sup.frames_rx, dummy_rx);
    (rx, sup)
}

/// A [`device::DeviceFactory`] that carries a static name and a
/// closure. We can't `impl DeviceFactory for FnMut()` directly because
/// the blanket name() default returns `"device"`; this wrapper plumbs
/// the device-kind label through to the supervisor's log lines.
struct NamedFactory<F> {
    name: &'static str,
    open: F,
}

impl<F> NamedFactory<F>
where
    F: FnMut() -> io::Result<device::DeviceHandle> + Send + 'static,
{
    fn new(name: &'static str, open: F) -> Self {
        Self { name, open }
    }
}

impl<F> device::DeviceFactory for NamedFactory<F>
where
    F: FnMut() -> io::Result<device::DeviceHandle> + Send + 'static,
{
    fn open(&mut self) -> io::Result<device::DeviceHandle> {
        (self.open)()
    }
    fn name(&self) -> &str {
        self.name
    }
}

fn open_maretron_pair(url: &str) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let raw = url.strip_prefix("tcp://").unwrap_or(url);
    let with_port = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:6543")
    };
    let resolved = with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other(format!("no addresses for {with_port}")))?;
    log::info!("maretron: connecting to {resolved}");
    let stream = TcpStream::connect_timeout(&resolved, Duration::from_secs(10))?;
    let read_clone = stream.try_clone()?;
    Ok((Box::new(read_clone), Box::new(stream)))
}

/// Read PLAIN/FAST lines off stdin, parse to `RawFrame`, push onto
/// `tx`. Auto-detects between PLAIN and FAST on the first non-empty
/// line.
fn stdin_pump(tx: mpsc::Sender<RawFrame>, pre_coalesced: Arc<AtomicBool>) {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::with_capacity(1024);
    let mut active_format: Option<InputFormat> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                log::error!("stdin read: {e}");
                return;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            // `# format=<NAME>` headers — emitted by the canboat C
            // reader binaries — pin both the parser format and (for
            // any coalesced format) the pipeline's reassembly bypass.
            if let Some(fmt) = parse_format_header(trimmed) {
                if active_format.is_none() {
                    active_format = Some(fmt);
                    log::info!("input format set by header: {:?}", fmt);
                }
                if header_implies_coalesced(trimmed) && !pre_coalesced.swap(true, Ordering::Relaxed)
                {
                    log::debug!(
                        "stdin header declares coalesced format; \
                         pipeline will skip reassembly"
                    );
                }
            }
            continue;
        }
        if active_format.is_none() {
            active_format = detect(trimmed).or(Some(InputFormat::Plain));
        }
        let Ok(Some(frame)) = parse_with(active_format.unwrap(), trimmed) else {
            continue;
        };
        if tx.send(frame).is_err() {
            return;
        }
    }
}

// Suppress an unused-import warning when no device flag is built (we
// rely on `bail!` for the future "no source AND not interactive"
// branch — keeping the import wired up here documents the intent).
#[allow(dead_code)]
fn _no_source() -> Result<()> {
    bail!("no input source");
}
