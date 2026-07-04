// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `ikonvert-serial`: bidirectional bridge between a Digital Yacht
//! iKonvert and a canboat PLAIN/FAST byte stream.
//!
//! Mirrors the canboat C tool's behaviour, including the ACK-driven
//! init handshake (see [`canboat_io::device::ikonvert`]). The
//! tool-specific shape — three threads (device read/write managed by
//! the codec runner, plus a stdin pump for outbound traffic) — is
//! delegated to `canboat-io::device`, so this binary is mostly CLI
//! plumbing.
//!
//! Modes mirror canboat v6.2.0:
//!
//! ```text
//!     (none)  bidirectional
//!     -r      read-only — skip stdin entirely (init handshake still runs)
//!     -w      write-only — drain device frames but don't emit them
//!     -p      passthru — send stdin to device AND echo it to stdout
//! ```
//!
//! The iKonvert boots into `N2NET_OFFLINE` and emits nothing until the
//! host sends `N2NET_INIT`, so the init handshake runs in `-r` too;
//! `-r` is implemented at the parse layer (no stdin pump), not by
//! disabling writes.

use std::fs::File;
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::{parse_plain, plain::ParseError, write_plain};
use canboat_io::device::{DeviceHandle, FrameSender, ikonvert};
use canboat_io::open_serial_rw;

/// Default baud rate of the Digital Yacht iKonvert.
const DEFAULT_BAUD: u32 = 230_400;

/// `# format=FAST\n` — header tag the analyzer recognises.
const CANBOAT_FORMAT_FAST_HEADER: &str = "# format=FAST\n";

#[derive(Debug, Parser)]
#[command(
    name = "ikonvert-serial",
    about = "Bridge a Digital Yacht iKonvert to canboat PLAIN/FAST format",
    version,
    after_help = canboat_cli::help_footer()
)]
struct Cli {
    /// Path to the serial device (e.g. /dev/ttyUSB0). Use `-` to read
    /// iKonvert ASCII bytes from stdin instead. Required unless
    /// `--file` is set.
    device: Option<String>,

    /// Replay iKonvert ASCII bytes from a captured file. Implies `-r`.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Baud rate. iKonvert's default is 230400.
    #[arg(short = 'b', long = "baud", alias = "speed", short_alias = 's', default_value_t = DEFAULT_BAUD)]
    baud: u32,

    /// Read-only mode — never read stdin; device init handshake still runs.
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// Write-only mode — read stdin and write to device; drain device
    /// frames but don't emit them on stdout.
    #[arg(short = 'w', long = "write-only")]
    write_only: bool,

    /// Passthru mode — send stdin to the device AND echo each line to
    /// stdout. To suppress device writes use `-r`.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Optional comma-separated RX filter list. If set, brings the
    /// device online in NORMAL mode rather than ALL.
    #[arg(long, value_name = "PGN,PGN,...")]
    rx: Option<String>,

    /// Optional comma-separated TX filter list. Canboat C also
    /// accepts this and sends `$PDGY,TX_LIST,...` during init.
    #[arg(long, value_name = "PGN,PGN,...")]
    tx: Option<String>,

    /// Disable the iKonvert TX rate limit (use at own risk).
    #[arg(short = 'l', long = "rate-limit-off")]
    rate_limit_off: bool,

    /// Verbose logging — alias of `-d`. Matches canboat's C tool.
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
        eprintln!("ikonvert-serial: {e:#}");
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
    canboat_cli::log_startup(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    out.write_all(CANBOAT_FORMAT_FAST_HEADER.as_bytes())?;
    // Synthetic startup record, like canboat's emitCanboatStartupRecord.
    let rec = canboat_core::startup_record(
        env!("CARGO_PKG_VERSION"),
        "ikonvert-serial",
        cli.device.as_deref().unwrap_or("-"),
    );
    let mut prologue = String::with_capacity(160);
    canboat_core::format::plain::write_line(&mut prologue, &rec).ok();
    out.write_all(prologue.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;

    // Open the underlying byte stream — either a real serial device,
    // a captured replay file, or stdin (`-`). Replay mode is
    // implicitly read-only; the codec writer thread still runs but
    // its bytes go to a sink.
    let (reader, writer, do_init): (Box<dyn Read + Send>, Box<dyn Write + Send>, bool) =
        match (cli.device.as_deref(), cli.file.as_deref()) {
            (None, None) => anyhow::bail!("specify a serial device or --file"),
            (Some(_), Some(_)) => anyhow::bail!("specify either a device or --file, not both"),
            (None, Some(path)) => {
                let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
                (Box::new(f), Box::new(io::sink()), false)
            }
            (Some("-"), None) => {
                let stdin = io::stdin();
                (Box::new(StdinReader(stdin)), Box::new(io::sink()), false)
            }
            (Some(dev), None) => {
                let (r, w) = open_serial_rw(dev, cli.baud)
                    .with_context(|| format!("opening {} at {} bps", dev, cli.baud))?;
                (r, w, true)
            }
        };

    // Replay / read-from-stdin mode skips the init handshake; with no
    // real device behind the writer side there's nothing to ACK.
    // Note: -r still runs init against a real device — the iKonvert
    // boots OFFLINE and emits nothing until N2NET_INIT lands.
    let config = if do_init {
        ikonvert::Config {
            rx_list: cli.rx.clone(),
            tx_list: cli.tx.clone(),
            rate_limit_off: cli.rate_limit_off,
            ..Default::default()
        }
    } else {
        ikonvert::Config::skip_init()
    };

    let handle = ikonvert::run(reader, writer, config);

    // Stdin pump — only when we'll actually forward to a real device.
    // In -w we still read stdin (and write to device), we just
    // suppress the stdout emit downstream; only -r skips stdin
    // entirely. For replay / read-from-stdin sources there's no
    // writable device behind us, so don't block on stdin. Only
    // materialize the FrameSender if we're using it — otherwise the
    // extra cmd_tx clone keeps the writer thread alive forever and
    // handle.join() hangs after the reader hits EOF.
    let do_read_stdin = !cli.read_only && do_init;
    let stdin_join = if do_read_stdin {
        Some(spawn_stdin_pump(handle.frame_sender(), cli.passthru))
    } else {
        None
    };

    // Drain the codec's frames into stdout as PLAIN/FAST lines.
    drain_frames_to_stdout(&handle, &mut out, cli.write_only)?;

    // Frames receiver closed (EOF on device / writer gone) — wait
    // for the codec threads and the stdin pump (if any) to wind down.
    handle.join();
    if let Some(j) = stdin_join {
        let _ = j.join();
    }
    Ok(())
}

fn drain_frames_to_stdout<W: Write>(
    handle: &DeviceHandle,
    out: &mut W,
    write_only: bool,
) -> Result<()> {
    let mut line_buf = String::with_capacity(256);
    let mut frames_emitted: u64 = 0;
    while let Ok(frame) = handle.frames_rx.recv() {
        if write_only {
            continue;
        }
        line_buf.clear();
        write_plain(&mut line_buf, &frame).context("write to String")?;
        out.write_all(line_buf.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;
        frames_emitted += 1;
    }
    log::info!("emitted {frames_emitted} N2K frames");
    Ok(())
}

fn spawn_stdin_pump(sender: FrameSender, passthru: bool) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("stdin-pump".into())
        .spawn(move || stdin_pump_thread(sender, passthru))
        .expect("spawn stdin pump")
}

fn stdin_pump_thread(sender: FrameSender, passthru: bool) {
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
        if sender.send_frame(frame).is_err() {
            return;
        }
    }
}

struct StdinReader(io::Stdin);
impl Read for StdinReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buf)
    }
}
