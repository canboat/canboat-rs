//! `maretron-ipg`: bridge a Maretron IPG100/200 over TCP to a canboat
//! PLAIN/FAST byte stream on stdout.
//!
//! Mirrors `canboat/maretron-ipg/maretron-ipg.c`. The session:
//!
//!   1. Open a TCP connection to `tcp://<host>[:<port>]` (default
//!      port 6543, "bus 0"). Use `:6553` for bus 1 on a dual-bus
//!      IPG.
//!   2. Send a `CONNECT\t"<password>"\t\tMOBILE\0` text frame.
//!   3. Wait for `CONNECTED\t<serial>\0` (or `NO\0` on auth fail).
//!   4. Send `SET_MODE\tBINARY\0` to flip the stream to binary.
//!   5. Loop: parse binary frames + interleaved text messages off the
//!      socket; emit each binary frame as a canboat PLAIN/FAST line.
//!   6. On stdin lines that look like PLAIN/FAST, encode them as
//!      Maretron 0xA5 frames and push them back to the IPG.
//!
//! Mode flags mirror canboat v6.2.0:
//!
//! ```text
//!   (none)  bidirectional
//!   -r      read-only — skip stdin entirely
//!   -w      write-only — drain IPG frames but don't emit them
//!   -p      passthru — send stdin to IPG AND echo it to stdout
//! ```

use std::io::{self, BufRead, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::{
    maretron_ipg::{
        build_connect, build_frame, build_set_mode_binary, ensure_default_port, parse,
        MaretronFrame, ParseOutcome, SessionState, RX_CONNECTED, RX_DETAILED_LICENSES_USED,
        RX_INSTANCE_DATA, RX_LICENSES_USED, RX_NO, RX_SERVER_VERSION,
    },
    parse_plain,
    plain::ParseError,
    write_plain,
};
use canboat_core::RawFrame;

/// Synthetic-PGN marker; canboat skips these on tx (they're fake
/// internal PGNs the analyzer emits, never meant to hit the bus).
const CANBOAT_PGN_START: u32 = 0x40000;

/// Canboat downstream tools look for this header to know the stream
/// is in FAST format.
const CANBOAT_FORMAT_FAST_HEADER: &str = "# format=FAST\n";

#[derive(Debug, Parser)]
#[command(
    name = "maretron-ipg",
    about = "Bridge a Maretron IPG100/200 (TCP) to canboat PLAIN/FAST",
    version
)]
struct Cli {
    /// IPG URL: `tcp://<host>[:<port>]`. Default port 6543 (bus 0);
    /// use `:6553` for bus 1 on a dual-bus IPG.
    device: Option<String>,

    /// Read-only mode — never forward stdin to the IPG.
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// Write-only mode — read stdin and send to IPG; drain IPG frames
    /// but don't emit them on stdout.
    #[arg(short = 'w', long = "write-only")]
    write_only: bool,

    /// Passthru mode — send stdin to the IPG AND echo each line to
    /// stdout. To suppress device writes use `-r`.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Exit if no IPG frame has been received in N seconds. `0`
    /// disables the timeout.
    #[arg(short = 't', long, default_value_t = 0u64)]
    timeout: u64,

    /// IPG login password. Default: empty (most stock units accept
    /// an empty password).
    #[arg(long, default_value = "")]
    password: String,

    /// Verbose logging — alias of `-d`. Matches canboat's C tool.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Quiet — only show errors.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Override the timestamp emitted on every line (canboat
    /// `-fixtime`). Useful for deterministic tests.
    #[arg(long, value_name = "STRING")]
    fixtime: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("maretron-ipg: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    if cli.read_only && cli.write_only {
        anyhow::bail!("-r and -w are mutually exclusive");
    }
    let level = if cli.quiet {
        "error"
    } else if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let device = cli
        .device
        .as_deref()
        .context("specify the IPG TCP URL, e.g. tcp://ipg.local")?;
    if !device.starts_with("tcp:") {
        anyhow::bail!("only tcp:// URLs are supported (got {device:?})");
    }
    let addr = ensure_default_port(device);
    log::info!("connecting to {addr}");

    let resolved = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .next()
        .with_context(|| format!("no addresses for {addr}"))?;
    let stream = TcpStream::connect_timeout(&resolved, Duration::from_secs(10))
        .with_context(|| format!("connecting to {addr}"))?;
    if cli.timeout > 0 {
        stream
            .set_read_timeout(Some(Duration::from_secs(cli.timeout)))
            .ok();
    }

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    out.write_all(CANBOAT_FORMAT_FAST_HEADER.as_bytes())?;
    out.flush()?;

    let read_stream = stream.try_clone().context("cloning TCP stream")?;
    let write_stream = stream;

    // Writer thread — owns the TCP write side, gates on an mpsc
    // channel of outbound items.
    let (tx, rx) = mpsc::channel::<TxItem>();
    // CONNECT goes out before anything else, then we wait for the
    // CONNECTED reply before flipping to binary.
    tx.send(TxItem::Raw(build_connect(&cli.password))).ok();

    let writer_join = thread::Builder::new()
        .name("maretron-writer".into())
        .spawn(move || writer_thread(write_stream, rx))
        .expect("spawn writer");

    // Stdin pump — only when we'll write to the device. Send None to
    // the channel as a "writer is detached" signal; the writer
    // ignores frames received before it has flipped to binary, which
    // is fine because we only flip after CONNECTED arrives.
    let stdin_join = if !cli.read_only {
        let stdin_tx = tx.clone();
        let pass = cli.passthru;
        let join = thread::Builder::new()
            .name("maretron-stdin".into())
            .spawn(move || stdin_pump_thread(stdin_tx, pass))
            .expect("spawn stdin");
        Some(join)
    } else {
        None
    };

    // Main thread: drive the read loop, emit PLAIN/FAST.
    let res = run_read_loop(
        read_stream,
        &mut out,
        cli.timeout,
        &tx,
        cli.write_only,
        cli.fixtime.clone(),
    );

    // Drop our sender so the writer wakes up on `recv()` returning Err.
    drop(tx);
    let _ = writer_join.join();
    if let Some(j) = stdin_join {
        let _ = j.join();
    }
    res
}

enum TxItem {
    /// Verbatim bytes to forward to the IPG.
    Raw(Vec<u8>),
    /// Outbound N2K frame to encode as a 0xA5 Maretron frame.
    Frame(RawFrame),
}

fn writer_thread<W: Write>(mut device: W, rx: mpsc::Receiver<TxItem>) {
    while let Ok(item) = rx.recv() {
        let bytes = match item {
            TxItem::Raw(b) => b,
            TxItem::Frame(frame) => {
                if frame.pgn >= CANBOAT_PGN_START {
                    log::debug!("skipping synthetic PGN {}", frame.pgn);
                    continue;
                }
                match build_frame(frame.pgn, frame.prio, frame.dst, &frame.data) {
                    Some(b) => b,
                    None => {
                        log::warn!("cannot encode PGN {} (payload too large)", frame.pgn);
                        continue;
                    }
                }
            }
        };
        if let Err(e) = device.write_all(&bytes) {
            log::error!("write failed: {e}");
            return;
        }
        let _ = device.flush();
    }
}

fn stdin_pump_thread(tx: mpsc::Sender<TxItem>, passthru: bool) {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::with_capacity(512);
    let mut stdout = io::stdout().lock();
    loop {
        line.clear();
        match lock.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                log::error!("stdin read error: {e}");
                return;
            }
        }
        if passthru {
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.flush();
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let frame = match parse_plain(trimmed) {
            Ok(f) => f,
            Err(ParseError::Empty) => continue,
            Err(e) => {
                log::warn!("skipping malformed stdin line: {e}");
                continue;
            }
        };
        if tx.send(TxItem::Frame(frame)).is_err() {
            return;
        }
    }
}

fn run_read_loop<R: Read, W: Write>(
    mut stream: R,
    out: &mut W,
    timeout_secs: u64,
    tx: &mpsc::Sender<TxItem>,
    write_only: bool,
    fixtime: Option<String>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut acc: Vec<u8> = Vec::with_capacity(4096);
    let mut state = SessionState::AwaitHandshake;
    let mut line_buf = String::with_capacity(256);
    let timeout = (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs));
    let mut last_rx = std::time::Instant::now();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("EOF on device");
                return Ok(());
            }
            Ok(n) => {
                last_rx = std::time::Instant::now();
                acc.extend_from_slice(&buf[..n]);
                loop {
                    let outcome = parse(&acc, state);
                    match outcome {
                        ParseOutcome::NeedMore => break,
                        ParseOutcome::Drop { consumed } => {
                            acc.drain(..consumed);
                        }
                        ParseOutcome::Text { line, consumed } => {
                            acc.drain(..consumed);
                            state = handle_text(&line, state, tx);
                        }
                        ParseOutcome::Frame { frame, consumed } => {
                            acc.drain(..consumed);
                            if !write_only {
                                emit_frame(out, &frame, &mut line_buf, fixtime.as_deref())?;
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                if let Some(t) = timeout {
                    if last_rx.elapsed() > t {
                        log::warn!("no frame for {} s; exiting", t.as_secs());
                        return Ok(());
                    }
                }
                continue;
            }
            Err(e) => return Err(e).context("reading device"),
        }
    }
}

fn handle_text(line: &str, state: SessionState, tx: &mpsc::Sender<TxItem>) -> SessionState {
    let (head, rest) = line.split_once('\t').unwrap_or((line, ""));
    match head {
        RX_CONNECTED => {
            log::info!("connected to IPG (serial {rest})");
            let _ = tx.send(TxItem::Raw(build_set_mode_binary()));
            SessionState::Streaming
        }
        RX_NO => {
            log::error!("authentication rejected by IPG");
            // Falling through to keep the read loop running so we
            // surface the EOF that the IPG normally sends next.
            state
        }
        RX_SERVER_VERSION => {
            log::info!("IPG server version {rest}");
            state
        }
        RX_INSTANCE_DATA => {
            log::info!("IPG instance data {rest}");
            state
        }
        RX_LICENSES_USED | RX_DETAILED_LICENSES_USED => {
            log::debug!("{head}\t{rest}");
            state
        }
        _ => {
            log::debug!("unhandled IPG control: {head} {rest}");
            state
        }
    }
}

fn emit_frame<W: Write>(
    out: &mut W,
    frame: &MaretronFrame,
    buf: &mut String,
    fixtime: Option<&str>,
) -> Result<()> {
    let ts = match fixtime {
        Some(s) => s.to_string(),
        None => now_iso_ms(),
    };
    let raw = frame.to_raw(Some(ts));
    buf.clear();
    write_plain(buf, &raw).context("writing plain line")?;
    out.write_all(buf.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SS.mmm` from the host clock in UTC.
fn now_iso_ms() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let ms = dur.subsec_millis();
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400) as u32;
    let h = day_secs / 3600;
    let m = (day_secs / 60) % 60;
    let s = day_secs % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}")
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
