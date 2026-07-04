// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

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

use canboat_core::RawFrame;
use canboat_core::format::{
    N2K_MSG_RECEIVED, Ngt1Decoder, NgtMessage, encode_n2k_send_frame, encode_startup_ping,
    ngt1::{EblHeader, NgtEvent},
    parse_plain,
    plain::ParseError,
    write_plain,
};
use canboat_io::{BytePump, open_serial};

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
    version,
    after_help = canboat_cli::help_footer()
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
    canboat_cli::log_startup(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    // Emit the prologue that downstream tools key on: the FAST header
    // and the synthetic startup record (like canboat's
    // emitCanboatStartupRecord).
    out.write_all(CANBOAT_FORMAT_FAST_HEADER.as_bytes())?;
    let rec = canboat_core::startup_record(
        env!("CARGO_PKG_VERSION"),
        "actisense-serial",
        cli.device.as_deref().unwrap_or("-"),
    );
    let mut prologue = String::with_capacity(160);
    canboat_core::format::plain::write_line(&mut prologue, &rec).ok();
    out.write_all(prologue.as_bytes())?;
    out.write_all(b"\n")?;
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
    // own fd. For a regular file we also sniff the first byte to spot
    // a W2K-1 / OpenCPN JSON capture so we can switch to the line-
    // oriented reader.
    let (mut read_handle, write_handle_opt, read_kind): (
        Box<dyn Read + Send>,
        Option<Box<dyn Write + Send>>,
        ReadKind,
    ) = match &read_source {
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
            (
                Box::new(SerialReader::new(read_port)),
                write_handle,
                ReadKind::Ngt1,
            )
        }
        InputSource::File(path) => {
            let mut file =
                File::open(path).with_context(|| format!("opening file {}", path.display()))?;
            // Decide which framing the file carries. EBL is the only
            // format keyed on extension — its bytes start with `ESC SOH`
            // (0x1b 0x01), which makes for a fragile sniff signal vs.
            // raw NGT-1 byte streams that begin with random data, so the
            // canboat C tool also uses the `.ebl` suffix. JSON captures
            // (`{"pgn":..,"payload":[..]}` per line, W2K-1 / OpenCPN) are
            // sniffed from a leading `{` so they need no flag. The
            // peeked byte is prepended back via `Read::chain`.
            let is_ebl = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("ebl"))
                .unwrap_or(false);
            let mut first = [0u8; 1];
            let n = file
                .read(&mut first)
                .with_context(|| format!("sniffing {}", path.display()))?;
            let kind = if is_ebl {
                log::debug!("EBL mode selected for {}", path.display());
                ReadKind::Ebl
            } else if n == 1 && first[0] == b'{' {
                log::debug!("W2K JSON mode selected for {}", path.display());
                ReadKind::W2KJson
            } else {
                ReadKind::Ngt1
            };
            let prefix = io::Cursor::new(first[..n].to_vec());
            let handle: Box<dyn Read + Send> = Box::new(prefix.chain(file));
            (handle, None, kind)
        }
        InputSource::Stdin => {
            let stdin = io::stdin();
            let reader: Box<dyn Read + Send> = Box::new(StdinReader(stdin));
            (reader, None, ReadKind::Ngt1)
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
        match read_kind {
            ReadKind::Ngt1 => {
                run_read_loop(&mut read_handle, &mut out, cli.timeout, cli.write_only)?
            }
            ReadKind::W2KJson => run_w2k_read_loop(&mut read_handle, &mut out, cli.write_only)?,
            ReadKind::Ebl => run_ebl_read_loop(&mut read_handle, &mut out, cli.write_only)?,
        }
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

/// Which device-side wire format we'll decode. NGT-1 byte stream is the
/// default for serial / stdin / raw files; W2K-1 / OpenCPN JSON capture
/// is auto-detected from a leading `{` and parsed line-at-a-time; EBL
/// (Actisense `.ebl` logs) is selected by file extension because its
/// `ESC SOH …` header bytes aren't reliably distinct from raw NGT-1
/// preamble noise.
enum ReadKind {
    Ngt1,
    W2KJson,
    Ebl,
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
                if let Some(t) = timeout
                    && last_rx.elapsed() > t
                {
                    log::warn!("no message received for {} s; exiting", t.as_secs());
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e).context("reading device"),
        }
    }
    log::info!("emitted {frames_emitted} N2K frames");
    Ok(())
}

/// Read an Actisense `.ebl` log file: an interleave of `ESC SOH … ESC LF`
/// timestamp records and `DLE STX … DLE ETX` NGT-1 frames. Drives the
/// EBL-aware variant of [`Ngt1Decoder`]. Each NGT-1 N2K message is
/// stamped with the most recent EBL header timestamp before emission, so
/// the captured wall-clock time replays accurately.
fn run_ebl_read_loop<R: Read>(
    reader: &mut R,
    out: &mut impl Write,
    suppress_output: bool,
) -> Result<()> {
    let mut decoder = Ngt1Decoder::with_ebl();
    let mut buf = [0u8; 4096];
    let mut line = String::with_capacity(256);
    let mut current_ts_ms: Option<u64> = None;
    let mut frames_emitted: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e).context("reading EBL file"),
        };
        for ev in decoder.push_bytes(&buf[..n]) {
            match ev {
                NgtEvent::Header(EblHeader::Timestamp(ms)) => {
                    current_ts_ms = Some(ms);
                }
                NgtEvent::Header(EblHeader::Unknown { kind, .. }) => {
                    log::debug!("unknown EBL header type 0x{kind:02x}");
                }
                NgtEvent::Message(msg) => {
                    if suppress_output {
                        continue;
                    }
                    // Replay captures interleave receive- and send-
                    // direction N2K frames plus Actisense system-status
                    // messages; `to_raw_frame_any_dir` handles all
                    // three. The internal NGT-1 timestamp is a 32-bit
                    // ms counter since device boot (meaningless for
                    // replay), so override with the most recent EBL
                    // header timestamp.
                    let Some(mut frame) = msg.to_raw_frame_any_dir() else {
                        continue;
                    };
                    if let Some(ms) = current_ts_ms {
                        frame.timestamp = Some(canboat_core::format_iso_ms(ms));
                    }
                    line.clear();
                    write_plain(&mut line, &frame).expect("write to String");
                    out.write_all(line.as_bytes())?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    frames_emitted += 1;
                }
                NgtEvent::Error(e) => {
                    log::warn!("EBL framing error: {e}");
                }
            }
        }
    }
    log::info!("emitted {frames_emitted} N2K frames (EBL)");
    Ok(())
}

/// Read a W2K-1 / OpenCPN JSON capture: one `{"pgn":..,"payload":[..]}`
/// object per line, where the payload array is a de-framed Actisense
/// N2K message — `command(1) length(1) prio(1) pgn(3 LE) dst(1) src(1)
/// ts(4 LE) dlen(1) data(dlen)`. The DLE framing and checksum a serial
/// NGT-1 would add are absent, so we hand the body straight to
/// `NgtMessage::to_raw_frame` after stripping the command + stale
/// length bytes. Mirrors `w2kMessageReceived` in canboat's
/// `actisense-serial.c`.
fn run_w2k_read_loop<R: Read>(
    reader: &mut R,
    out: &mut impl Write,
    suppress_output: bool,
) -> Result<()> {
    let mut reader = io::BufReader::new(reader);
    let mut line = String::with_capacity(2048);
    let mut payload = Vec::with_capacity(256);
    let mut text = String::with_capacity(256);
    let mut frames_emitted: u64 = 0;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(e).context("reading W2K JSON line"),
        }
        if suppress_output {
            continue;
        }
        if !parse_w2k_payload(&line, &mut payload) {
            continue;
        }
        if payload.len() < 13 || payload[0] != N2K_MSG_RECEIVED {
            log::warn!(
                "ignoring W2K payload ({} bytes, command {:02x})",
                payload.len(),
                payload.first().copied().unwrap_or(0)
            );
            continue;
        }
        // Skip command byte + stale BST length byte; the rest is what
        // NgtMessage::to_raw_frame expects (prio + pgn + dst + src +
        // ts + dlen + data).
        let msg = NgtMessage {
            command: N2K_MSG_RECEIVED,
            payload: payload[2..].to_vec(),
        };
        if let Some(frame) = msg.to_raw_frame() {
            text.clear();
            write_plain(&mut text, &frame).expect("write to String");
            out.write_all(text.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
            frames_emitted += 1;
        }
    }
    log::info!("emitted {frames_emitted} N2K frames (W2K JSON)");
    Ok(())
}

/// Pull the integer bytes out of a W2K-1 line's `"payload":[..]` array.
/// Returns `false` and leaves `out` empty if the line doesn't carry a
/// well-formed payload array. Doesn't try to be a real JSON parser —
/// the C tool does the same lightweight scan.
fn parse_w2k_payload(line: &str, out: &mut Vec<u8>) -> bool {
    out.clear();
    let Some(start) = line.find("\"payload\"") else {
        return false;
    };
    let after_key = &line[start..];
    let Some(bracket) = after_key.find('[') else {
        return false;
    };
    let rest = &after_key[bracket + 1..];
    let end = rest.find(']').unwrap_or(rest.len());
    for tok in rest[..end].split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<u16>() {
            Ok(v) if v <= 255 => out.push(v as u8),
            _ => {
                out.clear();
                return false;
            }
        }
    }
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_w2k_payload_array() {
        let line = r#"{"pgn":60928,"payload":[147,19,6,0,238,0,255,0,255,255,255,255,8,163,195,33,34,0,130,50,192]}"#;
        let mut out = Vec::new();
        assert!(parse_w2k_payload(line, &mut out));
        assert_eq!(out.len(), 21);
        assert_eq!(out[0], N2K_MSG_RECEIVED);
        assert_eq!(out[2], 6); // prio
    }

    #[test]
    fn parse_w2k_payload_rejects_line_without_payload_key() {
        let line = r#"{"pgn":60928,"data":[1,2,3]}"#;
        let mut out = Vec::new();
        assert!(!parse_w2k_payload(line, &mut out));
        assert!(out.is_empty());
    }

    #[test]
    fn parse_w2k_payload_handles_spaces_and_trailing_newline() {
        let line =
            "{\"payload\":[ 147 , 19 ,6,0,238,0,255,0,255,255,255,255,8,1,2,3,4,5,6,7,8 ]}\n";
        let mut out = Vec::new();
        assert!(parse_w2k_payload(line, &mut out));
        assert_eq!(out[0], 147);
        assert_eq!(out.last(), Some(&8));
    }

    #[test]
    fn parse_w2k_payload_rejects_out_of_range_value() {
        let line = r#"{"payload":[256,0,0]}"#;
        let mut out = Vec::new();
        assert!(!parse_w2k_payload(line, &mut out));
        assert!(out.is_empty());
    }

    /// One full W2K line should decode through `NgtMessage::to_raw_frame`
    /// to the same prio/pgn/src/dst we hand-derived from the payload.
    #[test]
    fn w2k_payload_to_raw_frame_round_trip() {
        let line = r#"{"pgn":127245,"payload":[147,19,2,13,241,1,255,5,255,255,255,255,8,0,255,255,127,27,0,255,255]}"#;
        let mut payload = Vec::new();
        assert!(parse_w2k_payload(line, &mut payload));
        let msg = NgtMessage {
            command: N2K_MSG_RECEIVED,
            payload: payload[2..].to_vec(),
        };
        let frame = msg.to_raw_frame().expect("decodes");
        assert_eq!(frame.prio, 2);
        assert_eq!(frame.pgn, 127245);
        assert_eq!(frame.src, 5);
        assert_eq!(frame.dst, 255);
        assert_eq!(frame.data.len(), 8);
    }
}
