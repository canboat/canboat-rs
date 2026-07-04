// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `socketcan-serial`: bridge a Linux SocketCAN interface to/from
//! canboat FAST format, behaving as much like `actisense-serial` and
//! `ikonvert-serial` as possible.
//!
//!   - received CAN frames are reassembled into whole PGNs and written
//!     to stdout in canboat FAST format (one line per PGN, preceded by
//!     a `# format=FAST` header), using [`canboat_core::Reassembler`];
//!   - canboat lines read from stdin are split into CAN frames and sent
//!     to the bus, with the source address forced to our claimed one;
//!   - the program is a real node on the bus: it claims an ISO source
//!     address (PGN 60928), backs off / re-claims on conflict, and
//!     answers ISO Requests (PGN 59904) for its address claim.
//!
//! The bus-protocol layer (socket open, address claim, heartbeat, ISO
//! Request / Group Function responders, buffered POLLOUT-driven TX)
//! lives in [`canboat_io::device::socketcan`]. This binary is the thin
//! CLI wrapper: parse args, build a [`Config`], emit the canboat FAST
//! header + startup record, drain received `RawFrame`s onto stdout (with
//! fast-packet reassembly), and pipe stdin PLAIN lines back through the
//! library for transmission.
//!
//! Which PGNs are fast-packet for stdout reassembly is decided by range,
//! except for the mixed 0x1F000..0x1FFFF range, for which a table
//! generated from `crates/canboat-core/data/canboat.json` at build time (see `build.rs`) is
//! consulted.
//!
//! Mirrors `canboat/socketcan-serial/socketcan-serial.c`.

use std::process::ExitCode;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "socketcan-serial",
    about = "Bridge a Linux SocketCAN interface to/from canboat FAST format",
    version,
    after_help = canboat_cli::help_footer()
)]
struct Cli {
    /// SocketCAN interface name, e.g. can0 or nmea2000.
    device: String,

    /// Writeonly: received frames are not written to stdout.
    #[arg(short = 'w', long = "write-only")]
    writeonly: bool,

    /// Readonly: data from stdin is not sent to the device.
    #[arg(short = 'r', long = "read-only")]
    readonly: bool,

    /// Passthru: data from stdin is also echoed to stdout.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Verbose / debug logging.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Do not claim an address (passive bridge only).
    #[arg(short = 'n', long = "no-claim")]
    no_claim: bool,

    /// Timeout: quit if no frame is received for <n> seconds.
    #[arg(short = 't', long, value_name = "SECONDS", default_value_t = 0)]
    timeout: u64,

    /// Preferred source address to claim.
    #[arg(
        short = 'a',
        long = "address",
        value_name = "ADDR",
        default_value_t = 0
    )]
    address: u8,

    /// Unique number for the ISO NAME (default derived from the pid).
    #[arg(short = 'u', long = "unique", value_name = "N", default_value_t = 0)]
    unique: u32,

    /// Manufacturer code for the ISO NAME (999 = Signal K).
    #[arg(
        short = 'm',
        long = "manufacturer",
        value_name = "N",
        default_value_t = 999
    )]
    manufacturer: u16,

    /// Heartbeat (PGN 126993) interval in ms; 0 disables.
    #[arg(
        long = "heartbeat",
        alias = "hb",
        value_name = "MS",
        default_value_t = 60000
    )]
    heartbeat: u64,

    /// ISO NAME System Instance, 0..15. Real sensors leave this at 0,
    /// so the default of 15 (max) pushes our NAME up in the lower-NAME-
    /// wins arbitration order — we yield to any well-behaved device on
    /// the bus rather than steal addresses from real hardware.
    #[arg(
        long = "system-instance",
        alias = "si",
        value_name = "N",
        default_value_t = 15
    )]
    system_instance: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    let level = if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
    canboat_cli::log_startup(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    if let Err(e) = run(cli) {
        eprintln!("socketcan-serial: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn run(_cli: Cli) -> anyhow::Result<()> {
    anyhow::bail!("SocketCAN is Linux-only");
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> anyhow::Result<()> {
    linux::run(cli)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufWriter, Write};
    use std::thread;

    use anyhow::{Context, Result};
    use canboat_core::format::plain::{parse_line, write_line};
    use canboat_core::frame::RawFrame;
    use canboat_io::device::socketcan::{self, Config};

    use super::*;

    pub fn run(cli: Cli) -> Result<()> {
        // --- Open the SocketCAN bus participant in canboat-io.
        let config = Config {
            address: cli.address,
            unique: cli.unique,
            manufacturer: cli.manufacturer,
            system_instance: cli.system_instance,
            heartbeat_ms: cli.heartbeat,
            no_claim: cli.no_claim,
            timeout_secs: cli.timeout,
            model_version: None,
        };
        // Binary doesn't surface the claim address externally — pass
        // a fresh atom and discard the handle to it.
        let claim_addr =
            std::sync::Arc::new(std::sync::atomic::AtomicU8::new(socketcan::CLAIM_UNCLAIMED));
        let handle = socketcan::run(&cli.device, config, claim_addr)
            .with_context(|| format!("opening SocketCAN {}", cli.device))?;

        // --- Emit the canboat prologue: FAST format header + synthetic
        // startup record so downstream tools know which producer and
        // device this stream came from.
        let stdout = std::io::stdout();
        let mut out = BufWriter::new(stdout.lock());
        writeln!(out, "# format=FAST")?;
        let rec = canboat_core::startup_record(
            env!("CARGO_PKG_VERSION"),
            "socketcan-serial",
            &cli.device,
        );
        let mut line = String::with_capacity(160);
        write_line(&mut line, &rec).ok();
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;

        // --- Spawn the stdin pump if we'll forward to the device. In
        // readonly mode the pump is skipped; if stdin EOFs later, the
        // pump thread just exits.
        let stdin_join = if !cli.readonly {
            let sender = handle.frame_sender();
            let passthru = cli.passthru;
            Some(
                thread::Builder::new()
                    .name("stdin-pump".into())
                    .spawn(move || stdin_pump_thread(sender, passthru))
                    .context("spawning stdin pump")?,
            )
        } else {
            None
        };

        // --- Drain RX frames from the library and emit one PLAIN/FAST
        // line per PGN to stdout (unless writeonly). The library
        // reassembles internally and hands us coalesced `RawFrame`s,
        // so we just format and write.
        let writeonly = cli.writeonly;
        while let Ok(frame) = handle.frames_rx.recv() {
            if writeonly {
                continue;
            }
            line.clear();
            if write_line(&mut line, &frame).is_err() {
                continue;
            }
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
        }

        // Library closed the frames channel; wait for the stdin pump
        // to wind down too.
        if let Some(j) = stdin_join {
            let _ = j.join();
        }
        Ok(())
    }

    /// Read PLAIN lines from stdin, parse them, and hand each frame to
    /// the library for transmission. The library treats `src == 0` as
    /// "rewrite to my claim address", so we leave the parsed `src`
    /// alone — the line's author either sets it explicitly (e.g. to
    /// impersonate, like a quirk would) or leaves it at 0 to let the
    /// library substitute.
    fn stdin_pump_thread(sender: canboat_io::device::FrameSender, passthru: bool) {
        use std::io::{self, BufRead};
        let stdin = io::stdin();
        let mut buf = String::with_capacity(512);
        let mut stdout = io::stdout().lock();
        loop {
            buf.clear();
            let mut lock = stdin.lock();
            let n = match lock.read_line(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) => {
                    log::error!("stdin read: {e}");
                    return;
                }
            };
            let _ = n;
            let trimmed = buf.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if passthru {
                let _ = stdout.write_all(buf.as_bytes());
                let _ = stdout.flush();
            }
            let frame: RawFrame = match parse_line(trimmed) {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("skipping malformed line: {e}");
                    continue;
                }
            };
            if sender.send_frame(frame).is_err() {
                return; // library shut down
            }
        }
    }
}
