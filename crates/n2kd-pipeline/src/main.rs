//! `n2kd-pipeline` — single-process N2K → NMEA 0183 pipeline.
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
//!   `analyzer < file.raw | n2kd-pipeline` style pipelines that used
//!   to exist with `n2kd-inproc`.
//! * **device**: a [`canboat_io::device`] reader stage opens the
//!   chosen serial port / TCP socket and emits `RawFrame`s
//!   directly. In this mode, the raw-input TCP port (write-N2K) and
//!   the lazy CSV TCP server are also wired up.
//!
//! Output: NMEA 0183 sentences on stdout.

mod hub;
mod pipeline;
mod tcp;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use canboat_core::format::{detect, parse_with, InputFormat};
use canboat_core::{PgnDatabase, RawFrame};
use canboat_io::device::{self, DeviceHandle};
use canboat_io::open_serial_rw;

use crate::hub::Hub;
use crate::pipeline::Hubs;

const SYNTHETIC_PGNS_JSON: &str = include_str!("../../../data/synthetic-pgns.json");

#[derive(Debug, Parser)]
#[command(
    name = "n2kd-pipeline",
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

    /// Bind address for all TCP listeners.
    #[arg(long, default_value = "127.0.0.1")]
    bind: Ipv4Addr,

    /// Port for the bidirectional CSV (PLAIN/FAST) server. Clients
    /// receive every frame as a PLAIN/FAST line and can send
    /// PLAIN/FAST lines back to inject into the N2K bus. Formatting
    /// is lazy (skipped when no client is subscribed). `0` disables.
    #[arg(long, default_value_t = 2598)]
    csv_port: u16,

    /// Port for the read-only NMEA 0183 server (includes AIVDM).
    /// Formatting goes to stdout regardless; this server just
    /// re-broadcasts. `0` disables.
    #[arg(long, default_value_t = 2599)]
    nmea0183_port: u16,

    /// Port for the read-only analyzer JSON server — one decoded PGN
    /// per line. Lazy: skipped when no client is subscribed. `0`
    /// disables.
    #[arg(long, default_value_t = 2600)]
    analyzer_port: u16,

    /// Port for the write-only N2K injection server. PLAIN/FAST lines
    /// from clients are encoded and pushed to the device. `0`
    /// disables. Only active in device mode (otherwise there is no
    /// device to send to).
    #[arg(long, default_value_t = 2601)]
    write_port: u16,

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
    let mut db = PgnDatabase::load(&db_path)
        .with_context(|| format!("loading PGN database {}", db_path.display()))?;
    db.merge_pgns_from_json(SYNTHETIC_PGNS_JSON)
        .context("merging synthetic PGN definitions")?;

    let hubs = Hubs {
        csv: Arc::new(Hub::new()),
        nmea: Arc::new(Hub::new()),
        analyzer: Arc::new(Hub::new()),
    };

    // Pick the frame source and (if a device) its writer handle.
    let (frames_rx, device_handle) = open_source(&cli)?;
    let device_sender = device_handle.as_ref().map(|h| h.frame_sender());

    let mut tcp_joins: Vec<thread::JoinHandle<()>> = Vec::new();
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

    pipeline::run(db, frames_rx, hubs);

    // After the pipeline drains, tell the device threads to wind
    // down. The TCP accept threads run forever — leak them; process
    // exit will reap them.
    if let Some(h) = device_handle {
        h.join();
    }
    Ok(())
}

/// Open whichever input source the CLI selected. Returns
/// `(frames_rx, optional_device_handle)`. In stdin mode the second
/// element is `None`; the caller skips wiring TCP servers.
fn open_source(cli: &Cli) -> Result<(mpsc::Receiver<RawFrame>, Option<DeviceHandle>)> {
    if let Some(path) = cli.actisense.as_deref() {
        let baud = cli.baud.unwrap_or(115_200);
        let (reader, writer) = open_serial_pair(path, baud)?;
        let handle = device::ngt1::run(reader, writer);
        // We move handle.frames_rx out — but `DeviceHandle`'s field is
        // public and the helpers go through `frame_sender()`, so we
        // build the rest of the handle minus the receiver below.
        let (rx, handle) = split_device_handle(handle);
        return Ok((rx, Some(handle)));
    }
    if let Some(path) = cli.ikonvert.as_deref() {
        let baud = cli.baud.unwrap_or(230_400);
        let (reader, writer) = open_serial_pair(path, baud)?;
        let handle = device::ikonvert::run(reader, writer, device::ikonvert::Config::default());
        let (rx, handle) = split_device_handle(handle);
        return Ok((rx, Some(handle)));
    }
    if let Some(url) = cli.maretron.as_deref() {
        let (reader, writer) = open_maretron_pair(url)?;
        let cfg = device::maretron::Config {
            password: cli.maretron_password.clone(),
            fixtime: None,
        };
        let handle = device::maretron::run(reader, writer, cfg);
        let (rx, handle) = split_device_handle(handle);
        return Ok((rx, Some(handle)));
    }
    // stdin fallback.
    let (tx, rx) = mpsc::channel::<RawFrame>();
    thread::Builder::new()
        .name("stdin-pump".into())
        .spawn(move || stdin_pump(tx))
        .expect("spawn stdin-pump");
    Ok((rx, None))
}

/// Split the device handle into the frame receiver + the rest of the
/// handle (kept around so the writer/reader threads stay alive). The
/// `DeviceHandle::frames_rx` field is public so we just move it out.
fn split_device_handle(mut h: DeviceHandle) -> (mpsc::Receiver<RawFrame>, DeviceHandle) {
    // Swap in a dummy receiver — its sender is dropped immediately so
    // the channel is closed; the new handle never delivers frames
    // (it's only held for shutdown / frame_sender() purposes).
    let (_dummy_tx, dummy_rx) = mpsc::channel::<RawFrame>();
    let rx = std::mem::replace(&mut h.frames_rx, dummy_rx);
    (rx, h)
}

fn open_serial_pair(
    path: &str,
    baud: u32,
) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    open_serial_rw(path, baud).with_context(|| format!("opening {} at {} bps", path, baud))
}

fn open_maretron_pair(url: &str) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let raw = url.strip_prefix("tcp://").unwrap_or(url);
    let with_port = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:6543")
    };
    let resolved = with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving {with_port}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {with_port}"))?;
    log::info!("maretron: connecting to {resolved}");
    let stream = TcpStream::connect_timeout(&resolved, Duration::from_secs(10))
        .with_context(|| format!("connecting to {with_port}"))?;
    let read_clone = stream.try_clone().context("cloning TCP stream")?;
    Ok((Box::new(read_clone), Box::new(stream)))
}

/// Read PLAIN/FAST lines off stdin, parse to `RawFrame`, push onto
/// `tx`. Auto-detects between PLAIN and FAST on the first non-empty
/// line.
fn stdin_pump(tx: mpsc::Sender<RawFrame>) {
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
        if trimmed.is_empty() || trimmed.starts_with('#') {
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
