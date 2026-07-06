// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat interface` — bridge a live NMEA 2000 gateway to/from stdout.
//!
//! Supersedes the standalone `actisense-serial`, `ikonvert-serial`,
//! `maretron-ipg` and `socketcan-serial` binaries. Each spoke shares
//! one shape: a device codec from [`canboat_io::device`] turns the wire
//! protocol into a [`DeviceHandle`], whose `frames_rx` is a
//! [`FrameReader`] and whose `FrameSender` is a [`FrameWriter`]. So both
//! directions are a single [`canboat_io::copy`]:
//!
//! - **read**  device `frames_rx` → PLAIN on stdout
//! - **write** PLAIN on stdin → device `FrameSender`
//!
//! Output leads with the canboat `# format=FAST` header and a synthetic
//! startup record, matching the retired binaries byte for byte (the
//! per-kind producer name is preserved so the n2kd parity harness keeps
//! comparing like with like).

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::thread;

use anyhow::{Context, Result, bail};

use canboat_core::RawFrame;
use canboat_io::device::{self, DeviceHandle};
use canboat_io::{FrameWriter, LineFrameReader, PlainWriter, copy, open_serial_rw};

/// `# format=FAST` tag every canboat reader prepends to its PLAIN
/// stream so a downstream analyzer knows the frames are coalesced.
const FORMAT_FAST_HEADER: &[u8] = b"# format=FAST\n";

/// Which gateway to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Kind {
    /// Actisense NGT-1 (binary), over a serial port.
    Ngt1,
    /// Digital Yacht iKonvert (ASCII), over a serial port.
    Ikonvert,
    /// Maretron IPG100/200, over TCP.
    Maretron,
    /// Linux SocketCAN interface (e.g. `can0`).
    Socketcan,
}

impl Kind {
    /// Producer name stamped into the startup record. Kept identical
    /// to the retired standalone binary so parity output is unchanged.
    fn producer(self) -> &'static str {
        match self {
            Kind::Ngt1 => "actisense-serial",
            Kind::Ikonvert => "ikonvert-serial",
            Kind::Maretron => "maretron-ipg",
            Kind::Socketcan => "socketcan-serial",
        }
    }

    /// Default serial baud (0 for non-serial transports).
    fn default_baud(self) -> u32 {
        match self {
            Kind::Ngt1 => 115_200,
            Kind::Ikonvert => 230_400,
            Kind::Maretron | Kind::Socketcan => 0,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Gateway type.
    #[arg(long, value_enum)]
    kind: Kind,

    /// Endpoint: serial path (ngt1/ikonvert), `host:port` (maretron),
    /// or CAN interface name such as `can0` (socketcan).
    #[arg(value_name = "DEVICE")]
    device: String,

    /// Replay from a captured device byte stream instead of opening a
    /// live serial port (ngt1/ikonvert only).
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Serial baud rate. Defaults to 115200 (ngt1) / 230400 (ikonvert).
    #[arg(short = 'b', long)]
    baud: Option<u32>,

    /// Read-only: emit received frames, ignore stdin.
    #[arg(short = 'r', long = "read-only", conflicts_with = "write_only")]
    read_only: bool,

    /// Write-only: send stdin frames to the device, drop received ones.
    #[arg(short = 'w', long = "write-only")]
    write_only: bool,

    /// iKonvert: comma-separated receive PGN allow-list.
    #[arg(long, value_name = "PGN,...")]
    rx: Option<String>,

    /// iKonvert: comma-separated transmit PGN allow-list.
    #[arg(long, value_name = "PGN,...")]
    tx: Option<String>,

    /// iKonvert: disable the device's TX rate limit.
    #[arg(long)]
    rate_limit_off: bool,

    /// Maretron: IPG login password (default: empty).
    #[arg(long, value_name = "PASSWORD")]
    password: Option<String>,

    /// SocketCAN: preferred source address to claim (default 0).
    #[arg(long, value_name = "N")]
    address: Option<u8>,

    /// SocketCAN: passive sniff — skip the ISO address-claim handshake.
    #[arg(long)]
    no_claim: bool,
}

pub fn run(args: Args) -> Result<()> {
    let mut handle = open_device(&args)?;

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    write_prologue(&mut out, &args).context("writing prologue")?;

    match (args.read_only, args.write_only) {
        // Read-only: device → PLAIN stdout, ignore stdin.
        (true, _) => {
            let mut writer = PlainWriter::new(&mut out);
            copy(&mut handle.frames_rx, &mut writer).context("reading from device")?;
        }
        // Write-only: stdin PLAIN → device on the main thread (so we
        // exit when stdin ends); received frames are drained and
        // discarded so the channel can't back up.
        (false, true) => {
            let mut sender = handle.frame_sender();
            let mut rx = handle.frames_rx;
            let drain = thread::Builder::new()
                .name("frame-drain".into())
                .spawn(move || {
                    let _ = copy(&mut rx, &mut DiscardWriter);
                })
                .expect("spawn frame drain");
            pump_stdin(&mut sender).context("sending stdin frames")?;
            drop(drain);
        }
        // Bidirectional (default): stdin → device on a background
        // thread, device → PLAIN stdout on the main thread.
        (false, false) => {
            let mut sender = handle.frame_sender();
            let pump = thread::Builder::new()
                .name("stdin-pump".into())
                .spawn(move || {
                    if let Err(e) = pump_stdin(&mut sender) {
                        log::warn!("stdin pump stopped: {e}");
                    }
                })
                .expect("spawn stdin pump");
            let mut writer = PlainWriter::new(&mut out);
            copy(&mut handle.frames_rx, &mut writer).context("reading from device")?;
            drop(pump); // device closed; don't wait on a blocked stdin read
        }
    }
    Ok(())
}

/// Pump PLAIN frames from stdin into `sender` until stdin ends.
fn pump_stdin(sender: &mut device::FrameSender) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = LineFrameReader::new(stdin.lock());
    copy(&mut reader, sender).map(|_| ())
}

/// A [`FrameWriter`] that throws frames away — used to keep a device's
/// receive channel drained in write-only mode.
struct DiscardWriter;

impl FrameWriter for DiscardWriter {
    fn write_frame(&mut self, _frame: &RawFrame) -> io::Result<()> {
        Ok(())
    }
}

/// Emit the `# format=FAST` header + the synthetic startup record.
fn write_prologue<W: Write>(out: &mut W, args: &Args) -> io::Result<()> {
    out.write_all(FORMAT_FAST_HEADER)?;
    let rec = canboat_core::startup_record(
        env!("CARGO_PKG_VERSION"),
        args.kind.producer(),
        &args.device,
    );
    let mut line = String::with_capacity(160);
    canboat_core::format::plain::write_line(&mut line, &rec).ok();
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Open the selected transport and start its device codec.
fn open_device(args: &Args) -> Result<DeviceHandle> {
    match args.kind {
        Kind::Ngt1 => {
            let (r, w) = open_stream(args)?;
            Ok(device::ngt1::run(r, w))
        }
        Kind::Ikonvert => {
            let (r, w) = open_stream(args)?;
            let config = device::ikonvert::Config {
                rx_list: args.rx.clone(),
                tx_list: args.tx.clone(),
                rate_limit_off: args.rate_limit_off,
                // No device on the far end of a file replay to ACK the
                // init handshake, so skip it.
                skip_init: args.file.is_some(),
            };
            Ok(device::ikonvert::run(r, w, config))
        }
        Kind::Maretron => {
            if args.file.is_some() {
                bail!("--file replay is not supported for the maretron transport");
            }
            let stream = TcpStream::connect(&args.device)
                .with_context(|| format!("connecting to {}", args.device))?;
            let reader: Box<dyn Read + Send> =
                Box::new(stream.try_clone().context("cloning TCP stream")?);
            let writer: Box<dyn Write + Send> = Box::new(stream);
            let config = device::maretron::Config {
                password: args.password.clone().unwrap_or_default(),
                fixtime: None,
            };
            Ok(device::maretron::run(reader, writer, config))
        }
        Kind::Socketcan => {
            if args.file.is_some() {
                bail!("--file replay is not supported for the socketcan transport");
            }
            let mut config = device::socketcan::Config::default();
            if let Some(addr) = args.address {
                config.address = addr;
            }
            config.no_claim = args.no_claim;
            let claim = Arc::new(AtomicU8::new(config.address));
            // On non-Linux this returns ErrorKind::Unsupported.
            device::socketcan::run(&args.device, config, claim)
                .with_context(|| format!("opening SocketCAN interface {}", args.device))
        }
    }
}

/// Byte-stream transport (serial device or `--file` replay) as an
/// independent `(reader, writer)` pair.
fn open_stream(args: &Args) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    if let Some(path) = &args.file {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        // Nothing to write to on replay — swallow the write side.
        Ok((Box::new(file), Box::new(io::sink())))
    } else {
        let baud = args.baud.unwrap_or_else(|| args.kind.default_baud());
        open_serial_rw(&args.device, baud)
            .with_context(|| format!("opening serial port {}", args.device))
    }
}
