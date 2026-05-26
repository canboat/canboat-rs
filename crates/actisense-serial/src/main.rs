//! `actisense-serial`: read N2K frames from an Actisense NGT-1 over a
//! serial port (or a captured byte stream) and emit each frame on
//! stdout in the canboat PLAIN/FAST line format.
//!
//! This binary is the v0 integration test for the sans-I/O
//! architecture: every interesting decision (frame parsing, DLE
//! unstuffing, header layout, output formatting) lives in
//! `canboat-core`. The binary itself only owns the I/O loop and the
//! exit conditions.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::{ngt1::NgtEvent, write_plain, Ngt1Decoder};
use canboat_io::{open_serial, BytePump};

/// Default baud rate of the Actisense NGT-1.
const DEFAULT_BAUD: u32 = 115_200;

#[derive(Debug, Parser)]
#[command(
    name = "actisense-serial",
    about = "Read N2K frames from an Actisense NGT-1 and emit canboat PLAIN/FAST lines",
    version
)]
struct Cli {
    /// Path to the serial device (e.g. /dev/ttyUSB0). Required unless
    /// `--file` is set.
    device: Option<String>,

    /// Read NGT-1 raw bytes from a captured file instead of a serial
    /// port. Useful for replaying captures without hardware.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Baud rate when reading from a serial device.
    #[arg(short = 'b', long, default_value_t = DEFAULT_BAUD)]
    baud: u32,

    /// Enable debug logging on stderr.
    #[arg(short = 'd', long)]
    debug: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("actisense-serial: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    let reader: Box<dyn Read> = match (cli.device.as_deref(), cli.file.as_deref()) {
        (Some(path), None) => Box::new(open_serial(path, cli.baud).with_context(|| {
            format!("opening serial device {path} at {} bps", cli.baud)
        })?),
        (None, Some(file)) => {
            Box::new(File::open(file).with_context(|| format!("opening file {}", file.display()))?)
        }
        (Some(_), Some(_)) => anyhow::bail!("specify either a device or --file, not both"),
        (None, None) => anyhow::bail!("specify a serial device or --file"),
    };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut pump = BytePump::new(reader);
    let mut decoder = Ngt1Decoder::new();
    let mut line = String::with_capacity(256);
    let mut frames_emitted: u64 = 0;

    loop {
        match pump.read_chunk() {
            Ok(None) => break, // EOF — file replay completed
            Ok(Some(chunk)) => {
                for ev in decoder.push_bytes(chunk) {
                    handle_event(&ev, &mut line, &mut out, &mut frames_emitted)?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                // Serial read timeout: nothing to do, loop and try again.
                continue;
            }
            Err(e) => return Err(e).context("reading input"),
        }
    }

    log::info!("emitted {frames_emitted} N2K frames");
    Ok(())
}

fn handle_event(
    ev: &NgtEvent,
    line: &mut String,
    out: &mut impl Write,
    counter: &mut u64,
) -> Result<()> {
    match ev {
        NgtEvent::Message(msg) => {
            let Some(frame) = msg.to_raw_frame() else {
                log::debug!(
                    "skipping non-N2K NGT message cmd=0x{:02x} ({} bytes)",
                    msg.command,
                    msg.payload.len()
                );
                return Ok(());
            };
            line.clear();
            write_plain(line, &frame).expect("write to String");
            out.write_all(line.as_bytes()).context("writing line")?;
            out.write_all(b"\n").context("writing newline")?;
            *counter += 1;
        }
        NgtEvent::Error(e) => {
            log::warn!("NGT-1 framing error: {e}");
        }
    }
    Ok(())
}
