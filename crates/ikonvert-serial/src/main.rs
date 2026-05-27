//! `ikonvert-serial`: bidirectional bridge between a Digital Yacht
//! iKonvert and a canboat PLAIN/FAST byte stream.
//!
//! Behaves like `actisense-serial` but speaks the iKonvert ASCII
//! protocol (`!PDGY,...` frames + `$PDGY,...` control sentences).
//!
//! Modes (combinable, mirror canboat's C tool):
//!
//! ```text
//!     (none)  bidirectional
//!     -r      read-only — never read stdin, never write device
//!     -w      write-only — never read device
//!     -p      passthru — read stdin but discard it
//!     -o      output-commands — echo each stdin line to stdout
//! ```
//!
//! Architecture: same three-thread shape as `actisense-serial`. A
//! cloned `SerialPort` handle is shared between a read thread and a
//! write thread; a stdin pump parses canboat PLAIN/FAST lines and
//! sends `RawFrame`s on an mpsc channel.
//!
//! On a serial device the writer thread also performs the iKonvert
//! init handshake: `$PDGY,N2NET_OFFLINE` followed by
//! `$PDGY,N2NET_INIT,ALL` (or `NORMAL` if an RX list is set).
//! The full multi-step ACK-driven state machine the C code runs is
//! deferred — for v0.1 we send the commands without waiting for ACK,
//! which works in practice for the read+write use case.

use std::fs::File;
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::{
    ikonvert::{self, IkonvertLine, TX_LIMIT_OFF, TX_OFFLINE, TX_ONLINE_ALL, TX_ONLINE_NORMAL},
    parse_plain,
    plain::ParseError,
    write_plain,
};
use canboat_core::RawFrame;
use canboat_io::open_serial;

/// Default baud rate of the Digital Yacht iKonvert.
const DEFAULT_BAUD: u32 = 230_400;
/// Synthetic-PGN marker; skip these on the write path.
const CANBOAT_PGN_START: u32 = 0x40000;

/// `# format=FAST\n` — header tag the analyzer recognises.
const CANBOAT_FORMAT_FAST_HEADER: &str = "# format=FAST\n";

#[derive(Debug, Parser)]
#[command(
    name = "ikonvert-serial",
    about = "Bridge a Digital Yacht iKonvert to canboat PLAIN/FAST format",
    version
)]
struct Cli {
    /// Path to the serial device (e.g. /dev/ttyUSB0). Required unless
    /// `--file` is set.
    device: Option<String>,

    /// Replay iKonvert ASCII bytes from a captured file. Implies `-r`.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Baud rate. iKonvert's default is 230400.
    #[arg(short = 'b', long, default_value_t = DEFAULT_BAUD)]
    baud: u32,

    /// Read-only mode.
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// Write-only mode.
    #[arg(short = 'w', long = "write-only")]
    write_only: bool,

    /// Passthru mode — read stdin but don't forward to device.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Echo each stdin line back to stdout.
    #[arg(short = 'o', long = "output-commands")]
    output_commands: bool,

    /// Exit if no frame for N seconds (0 disables).
    #[arg(short = 't', long, default_value_t = 0u64)]
    timeout: u64,

    /// Optional comma-separated RX filter list. If set, brings the
    /// device online in NORMAL mode rather than ALL.
    #[arg(long, value_name = "PGN,PGN,...")]
    rx: Option<String>,

    /// Disable the iKonvert TX rate limit (use at own risk).
    #[arg(short = 'l', long = "rate-limit-off")]
    rate_limit_off: bool,

    /// Verbose / debug logging.
    #[arg(short = 'd', long)]
    debug: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if cli.debug {
        "debug"
    } else {
        "info"
    }))
    .init();

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    out.write_all(CANBOAT_FORMAT_FAST_HEADER.as_bytes())?;
    out.flush()?;

    let read_source = match (cli.device.as_deref(), cli.file.as_deref()) {
        (None, None) => anyhow::bail!("specify a serial device or --file"),
        (Some(_), Some(_)) => anyhow::bail!("specify either a device or --file, not both"),
        (None, Some(path)) => InputSource::File(path.to_path_buf()),
        (Some(dev), None) => InputSource::Serial(dev.to_string()),
    };

    let do_write = !cli.read_only && matches!(read_source, InputSource::Serial(_));
    // Same caveat as actisense-serial: only consume stdin when a
    // writer thread is alive — otherwise the read_line() call blocks
    // forever and the binary never exits after a `--file` replay.
    let do_read_stdin = do_write;
    let do_read_device = !cli.write_only;

    let (mut read_handle, write_handle_opt): (
        Box<dyn Read + Send>,
        Option<Box<dyn Write + Send>>,
    ) = match &read_source {
        InputSource::Serial(path) => {
            let read_port = open_serial(path, cli.baud)
                .with_context(|| format!("opening {} at {} bps", path, cli.baud))?;
            let write_handle: Option<Box<dyn Write + Send>> = if do_write {
                let wp = read_port
                    .try_clone()
                    .with_context(|| format!("cloning {}", path))?;
                Some(Box::new(SerialWriter(wp)))
            } else {
                None
            };
            (Box::new(SerialReader(read_port)), write_handle)
        }
        InputSource::File(path) => (
            Box::new(
                File::open(path).with_context(|| format!("opening file {}", path.display()))?,
            ),
            None,
        ),
    };

    let (write_tx, writer_join) = if let Some(handle) = write_handle_opt {
        let (tx, rx) = mpsc::channel::<TxItem>();
        let rx_list = cli.rx.clone();
        let rate_off = cli.rate_limit_off;
        let join = thread::Builder::new()
            .name("ikonvert-writer".into())
            .spawn(move || writer_thread(handle, rx, rx_list, rate_off))
            .expect("spawn writer");
        (Some(tx), Some(join))
    } else {
        (None, None)
    };

    let stdin_join = if do_read_stdin {
        let tx_for_writer = write_tx.clone();
        let echo = cli.output_commands;
        let pass = cli.passthru;
        let join = thread::Builder::new()
            .name("stdin-pump".into())
            .spawn(move || stdin_pump_thread(tx_for_writer, pass, echo))
            .expect("spawn stdin pump");
        Some(join)
    } else {
        None
    };

    if do_read_device {
        run_read_loop(&mut read_handle, &mut out, cli.timeout)?;
    }

    drop(write_tx);
    if let Some(j) = writer_join {
        let _ = j.join();
    }
    if let Some(j) = stdin_join {
        let _ = j.join();
    }
    Ok(())
}

enum InputSource {
    Serial(String),
    File(PathBuf),
}

/// What the stdin pump pushes onto the writer's channel.
enum TxItem {
    /// A canboat-format N2K frame — writer encodes as `!PDGY,...`.
    Frame(RawFrame),
    /// A literal `$PDGY,...` control sentence from stdin to forward.
    Raw(String),
}

struct SerialReader(Box<dyn serialport::SerialPort>);
impl Read for SerialReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

struct SerialWriter(Box<dyn serialport::SerialPort>);
impl Write for SerialWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn run_read_loop<R: Read>(
    reader: &mut R,
    out: &mut impl Write,
    timeout_secs: u64,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let mut acc = String::with_capacity(1024);
    let mut line_buf = String::with_capacity(256);
    let mut frames_emitted: u64 = 0;
    let mut last_rx = std::time::Instant::now();
    let timeout = (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs));

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                last_rx = std::time::Instant::now();
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(eol) = acc.find('\n') {
                    let line: String = acc.drain(..=eol).collect();
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        continue;
                    }
                    let parsed = match ikonvert::parse_line(trimmed) {
                        Ok(p) => p,
                        Err(e) => {
                            log::warn!("iKonvert parse error on {trimmed:?}: {e}");
                            continue;
                        }
                    };
                    let frame = match parsed {
                        IkonvertLine::Frame(f) => f,
                        IkonvertLine::Control(c) => {
                            log::debug!("iKonvert control: {c}");
                            continue;
                        }
                        IkonvertLine::Other => continue,
                    };
                    line_buf.clear();
                    write_plain(&mut line_buf, &frame).expect("write to String");
                    out.write_all(line_buf.as_bytes())?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    frames_emitted += 1;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                if let Some(t) = timeout {
                    if last_rx.elapsed() > t {
                        log::warn!("no message received for {} s; exiting", t.as_secs());
                        return Ok(());
                    }
                }
                continue;
            }
            Err(e) => return Err(e).context("reading device"),
        }
    }
    log::info!("emitted {frames_emitted} N2K frames");
    Ok(())
}

fn writer_thread<W: Write>(
    mut device: W,
    rx: mpsc::Receiver<TxItem>,
    rx_list: Option<String>,
    rate_limit_off: bool,
) {
    // Best-effort init handshake. The C tool runs a multi-step state
    // machine that waits for each ACK; we send fire-and-forget which
    // is enough for read+write to work in practice.
    let mut init = String::new();
    init.push_str(TX_OFFLINE);
    if let Some(list) = rx_list.as_deref() {
        // $PDGY,RX_LIST,<pgn>,<pgn>,...
        init.push_str("$PDGY,RX_LIST,");
        init.push_str(list);
        init.push_str("\r\n");
        init.push_str(TX_ONLINE_NORMAL);
    } else {
        init.push_str(TX_ONLINE_ALL);
    }
    if rate_limit_off {
        init.push_str(TX_LIMIT_OFF);
    }
    if let Err(e) = device.write_all(init.as_bytes()) {
        log::error!("iKonvert init write failed: {e}");
        return;
    }
    let _ = device.flush();

    while let Ok(item) = rx.recv() {
        let bytes = match item {
            TxItem::Frame(frame) => {
                if frame.pgn >= CANBOAT_PGN_START {
                    log::debug!("skipping synthetic PGN {}", frame.pgn);
                    continue;
                }
                ikonvert::encode_tx_frame(&frame).into_bytes()
            }
            TxItem::Raw(s) => {
                let mut buf = s.into_bytes();
                if !buf.ends_with(b"\n") {
                    buf.extend_from_slice(b"\r\n");
                }
                buf
            }
        };
        if let Err(e) = device.write_all(&bytes) {
            log::error!("iKonvert write failed: {e}");
            return;
        }
        let _ = device.flush();
    }
}

fn stdin_pump_thread(
    write_tx: Option<mpsc::Sender<TxItem>>,
    passthru: bool,
    output_commands: bool,
) {
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
        if output_commands {
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.flush();
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if passthru {
            continue;
        }
        let Some(tx) = write_tx.as_ref() else {
            continue;
        };
        // Allow stdin lines that are literal $PDGY control sentences
        // through verbatim (the C tool does this).
        if trimmed.starts_with("$PDGY") {
            if tx.send(TxItem::Raw(trimmed.to_string())).is_err() {
                return;
            }
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
