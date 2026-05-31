//! `actisense-serial`: bidirectional bridge between an Actisense NGT-1
//! and a canboat PLAIN/FAST byte stream.
//!
//! - Reads binary NGT-1 bytes off a serial port (or replay file) and
//!   prints each frame as a canboat PLAIN/FAST line on stdout.
//! - Reads PLAIN/FAST lines from stdin, encodes them as NGT-1
//!   `N2K_MSG_SEND` (0x94) frames, and writes them to the serial port
//!   so they appear on the NMEA 2000 bus.
//!
//! Mode flags mirror the C `actisense-serial` (canboat v6.2.0):
//!
//! ```text
//!     (none)  bidirectional
//!     -r      read-only — skip stdin entirely
//!     -w      write-only — drain device output but don't emit it
//!     -p      passthru — send stdin to device AND echo it to stdout
//! ```
//!
//! The architecture is three sync threads:
//!   1. **Read** thread: drives [`Ngt1Decoder`], writes each completed
//!      frame as PLAIN/FAST to stdout.
//!   2. **Write** thread: pulls [`canboat_core::RawFrame`]s off an
//!      mpsc channel, encodes them, and writes the bytes to a cloned
//!      handle of the serial port. Also emits the NGT-1 startup
//!      sequence on entry and re-pings every 20 s.
//!   3. **Stdin pump** thread: reads stdin lines, parses each via
//!      `parse_plain`, sends the resulting `RawFrame` on the channel
//!      (and optionally tees the original line to stdout).
//!
//! `SerialPort::try_clone` produces an independent fd-sharing handle
//! so the read and write threads operate on the same port without a
//! Mutex.

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
    encode_n2k_send_frame, encode_startup_ping, ngt1::NgtEvent, parse_plain, plain::ParseError,
    write_plain, Ngt1Decoder,
};
use canboat_core::RawFrame;
use canboat_io::{open_serial, BytePump};

/// Default baud rate of the Actisense NGT-1.
const DEFAULT_BAUD: u32 = 115_200;
/// Re-send the startup sequence every N seconds (matches canboat).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// Synthetic-PGN marker. Canboat sets the high nibble to 4 to mark
/// fake PGNs that should never hit the bus; we skip them on the
/// write path.
const ACTISENSE_BEM: u32 = 0x40000;

/// `# format=FAST` header line + a "we just started" virtual PGN that
/// downstream tools (the analyzer) can pick up. Matches the prologue
/// emitted by canboat's actisense-serial.
const CANBOAT_FORMAT_FAST_HEADER: &str = "# format=FAST\n";

#[derive(Debug, Parser)]
#[command(
    name = "actisense-serial",
    about = "Bridge an Actisense NGT-1 to canboat PLAIN/FAST format",
    version
)]
struct Cli {
    /// Path to the serial device (e.g. /dev/ttyUSB0). Use `-` to read
    /// raw NGT-1 bytes from stdin instead. Required unless `--file`
    /// is set.
    device: Option<String>,

    /// Replay raw NGT-1 bytes from a captured file instead of a
    /// serial port. Implies `-r` (read-only).
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Baud rate. NGT-1's default is 115200; W2K-1 USB is similar.
    #[arg(short = 'b', long = "baud", alias = "speed", short_alias = 's', default_value_t = DEFAULT_BAUD)]
    baud: u32,

    /// Read-only mode — never read stdin, never write to device.
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// Write-only mode — read stdin and write to device; drain device
    /// output but don't emit it on stdout.
    #[arg(short = 'w', long = "write-only")]
    write_only: bool,

    /// Passthru mode — send stdin to the device AND echo each line to
    /// stdout. To suppress device writes use `-r`.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Exit if no frame has been read in this many seconds (0 disables).
    #[arg(short = 't', long, default_value_t = 0u64)]
    timeout: u64,

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
        eprintln!("actisense-serial: {e:#}");
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

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    // Emit the prologue that downstream tools key on.
    out.write_all(CANBOAT_FORMAT_FAST_HEADER.as_bytes())?;
    out.flush()?;

    // Decide what kind of input we're reading. A `--file` always
    // forces read-only. The literal `-` is treated as stdin (Unix
    // convention) — read-only.
    let read_source = match (cli.device.as_deref(), cli.file.as_deref()) {
        (None, None) => anyhow::bail!("specify a serial device or --file"),
        (Some(_), Some(_)) => anyhow::bail!("specify either a device or --file, not both"),
        (None, Some(path)) => InputSource::File(path.to_path_buf()),
        (Some("-"), None) => InputSource::Stdin,
        (Some(dev), None) => InputSource::Serial(dev.to_string()),
    };

    let do_write = !cli.read_only && matches!(read_source, InputSource::Serial(_));
    // Only consume stdin when there's actually a writer to forward to;
    // otherwise the stdin-pump thread would block on read_line forever
    // and prevent clean shutdown when the device read loop ends (e.g.
    // when replaying from `--file`).
    let do_read_stdin = do_write;
    // In -w mode against a serial device we still poll & discard the
    // device's bytes (kernel buffer hygiene); for non-serial sources
    // -w just skips the read entirely.
    let do_read_device = !cli.write_only || matches!(read_source, InputSource::Serial(_));

    // --- Open the input source. For a serial device that we'll also
    // be writing to, we clone the handle so the writer thread has its
    // own fd.
    let (mut read_handle, write_handle_opt): (Box<dyn Read + Send>, Option<Box<dyn Write + Send>>) =
        match &read_source {
            InputSource::Serial(path) => {
                let read_port = open_serial(path, cli.baud)
                    .with_context(|| format!("opening {} at {} bps", path, cli.baud))?;
                let write_handle: Option<Box<dyn Write + Send>> = if do_write {
                    let wp = read_port
                        .try_clone()
                        .with_context(|| format!("cloning {}", path))?;
                    Some(Box::new(SerialWriter::new(wp)))
                } else {
                    None
                };
                (Box::new(SerialReader::new(read_port)), write_handle)
            }
            InputSource::File(path) => (
                Box::new(
                    File::open(path).with_context(|| format!("opening file {}", path.display()))?,
                ),
                None,
            ),
            InputSource::Stdin => {
                let stdin = io::stdin();
                let reader: Box<dyn Read + Send> = Box::new(StdinReader(stdin));
                (reader, None)
            }
        };

    // --- Spawn the writer thread if we're going to transmit.
    let (write_tx, writer_join) = if let Some(handle) = write_handle_opt {
        let (tx, rx) = mpsc::channel::<RawFrame>();
        let join = thread::Builder::new()
            .name("ngt1-writer".into())
            .spawn(move || writer_thread(handle, rx))
            .expect("spawn writer");
        (Some(tx), Some(join))
    } else {
        (None, None)
    };

    // --- Spawn the stdin pump if we're going to consume stdin.
    let stdin_join = if do_read_stdin {
        let tx_for_writer = write_tx.clone();
        let pass = cli.passthru;
        let join = thread::Builder::new()
            .name("stdin-pump".into())
            .spawn(move || stdin_pump_thread(tx_for_writer, pass))
            .expect("spawn stdin pump");
        Some(join)
    } else {
        None
    };

    // --- Main thread: read device bytes and emit PLAIN/FAST. In -w
    // mode against a serial device we still read but suppress the
    // emit, so the kernel RX buffer doesn't back up.
    if do_read_device {
        run_read_loop(&mut read_handle, &mut out, cli.timeout, cli.write_only)?;
    }

    // Drop the writer's sender first so the writer thread sees EOF on
    // its channel and exits cleanly.
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
    /// `-` on the command line — read NGT-1 bytes from stdin.
    Stdin,
}

/// `io::Stdin` exposes `Read` but the call holds a lock per `read`;
/// wrap it in a struct so we can drop it into a `Box<dyn Read + Send>`
/// without per-call locking ceremony at the call site.
struct StdinReader(io::Stdin);
impl Read for StdinReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buf)
    }
}

/// Wrapper that gives `Box<dyn serialport::SerialPort>` a `Read` impl
/// directly (it already implements it, but the trait objects need a
/// concrete type to box into `Box<dyn Read + Send>`).
struct SerialReader(Box<dyn serialport::SerialPort>);
impl SerialReader {
    fn new(p: Box<dyn serialport::SerialPort>) -> Self {
        Self(p)
    }
}
impl Read for SerialReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

struct SerialWriter(Box<dyn serialport::SerialPort>);
impl SerialWriter {
    fn new(p: Box<dyn serialport::SerialPort>) -> Self {
        Self(p)
    }
}
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
    suppress_output: bool,
) -> Result<()> {
    let mut pump = BytePump::new(reader);
    let mut decoder = Ngt1Decoder::new();
    let mut line = String::with_capacity(256);
    let mut frames_emitted: u64 = 0;
    let mut last_rx = std::time::Instant::now();
    let timeout = (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs));

    loop {
        match pump.read_chunk() {
            Ok(None) => break,
            Ok(Some(chunk)) => {
                last_rx = std::time::Instant::now();
                if suppress_output {
                    continue;
                }
                for ev in decoder.push_bytes(chunk) {
                    if let NgtEvent::Message(msg) = ev {
                        if let Some(frame) = msg.to_raw_frame() {
                            line.clear();
                            write_plain(&mut line, &frame).expect("write to String");
                            out.write_all(line.as_bytes())?;
                            out.write_all(b"\n")?;
                            out.flush()?;
                            frames_emitted += 1;
                        }
                    } else if let NgtEvent::Error(e) = ev {
                        log::warn!("NGT-1 framing error: {e}");
                    }
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

fn writer_thread<W: Write>(mut device: W, rx: mpsc::Receiver<RawFrame>) {
    // Send the NGT-1 startup sequence on entry so the device unlocks
    // its TX queue.
    if let Err(e) = device.write_all(&encode_startup_ping()) {
        log::error!("NGT-1 startup write failed: {e}");
        return;
    }
    if let Err(e) = device.flush() {
        log::warn!("NGT-1 startup flush failed: {e}");
    }
    let mut next_ping = std::time::Instant::now() + KEEPALIVE_INTERVAL;
    loop {
        let now = std::time::Instant::now();
        let until_ping = next_ping.saturating_duration_since(now);
        match rx.recv_timeout(until_ping) {
            Ok(frame) => {
                if frame.pgn >= ACTISENSE_BEM {
                    log::debug!("skipping synthetic PGN {}", frame.pgn);
                    continue;
                }
                let bytes = encode_n2k_send_frame(&frame);
                if let Err(e) = device.write_all(&bytes) {
                    log::error!("write to NGT-1 failed: {e}");
                    return;
                }
                let _ = device.flush();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(e) = device.write_all(&encode_startup_ping()) {
                    log::warn!("NGT-1 keepalive ping failed: {e}");
                    return;
                }
                let _ = device.flush();
                next_ping = std::time::Instant::now() + KEEPALIVE_INTERVAL;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn stdin_pump_thread(write_tx: Option<mpsc::Sender<RawFrame>>, passthru: bool) {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::with_capacity(512);
    let mut stdout = io::stdout().lock();
    loop {
        line.clear();
        match lock.read_line(&mut line) {
            Ok(0) => return, // EOF
            Ok(_) => {}
            Err(e) => {
                log::error!("stdin read error: {e}");
                return;
            }
        }
        if passthru {
            // Echo verbatim (line already has trailing newline) in
            // addition to forwarding the parsed frame to the device.
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.flush();
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(tx) = write_tx.as_ref() else {
            continue;
        };
        let frame = match parse_plain(trimmed) {
            Ok(f) => f,
            Err(ParseError::Empty) => continue,
            Err(e) => {
                log::warn!("skipping malformed stdin line: {e}");
                continue;
            }
        };
        if tx.send(frame).is_err() {
            // Writer thread is gone.
            return;
        }
    }
}
