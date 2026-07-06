// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `nif2analyzer`: unpack a Navico `.nif` diagnostic export (or a plain
//! `.pcap` / `.pcap.gz` SocketCAN capture) and emit the CAN frames it
//! contains as canboat analyzer `RAWFORMAT_PLAIN` lines.
//!
//! A `.nif` ("Navico Information File", the diag bundle a Zeus/NSO MFD
//! writes to USB) is gzip(GNU tar); inside, the on-board NetLogger
//! service keeps rolling SocketCAN captures under two directories:
//!
//! ```text
//!   …/NetLogger/dumps/filtered/deviceInfo/can0/<ts>.pcap.gz   device roster
//!   …/NetLogger/dumps/raw/can0/<ts>.pcap.gz                   full bus traffic
//! ```
//!
//! The captures are concatenated **filtered-first** (so a downstream
//! decode opens with a concrete view of who is on the bus) then **raw**,
//! each group chronological by filename. The heavy lifting lives in
//! [`canboat_io::container`], shared with the analyzer and the TUI.
//!
//! Output (one line per CAN frame):
//!
//! ```text
//!   YYYY-MM-DD-HH:MM:SS.mmm,<prio>,<pgn>,<src>,<dst>,<size>,<hex>...
//! ```

use std::io::{self, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;

use canboat_io::container::{Options, plain_reader};

#[derive(Debug, Parser)]
#[command(
    name = "nif2analyzer",
    about = "Unpack a Navico .nif (or .pcap) and emit its CAN captures as canboat PLAIN",
    version,
    after_help = canboat_cli::help_footer()
)]
struct Cli {
    /// One or more `.nif` / `.pcap` / `.pcap.gz` files. For a `.nif` the
    /// `filtered` captures are emitted first, then the `raw` captures.
    /// Output is to stdout.
    files: Vec<PathBuf>,

    /// Emit only the `raw` captures (skip the filtered device roster).
    /// `.nif` only.
    #[arg(long, conflicts_with = "filtered_only")]
    raw_only: bool,

    /// Emit only the `filtered` device-roster captures. `.nif` only.
    #[arg(long)]
    filtered_only: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("nif2analyzer: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    if cli.files.is_empty() {
        bail!("at least one .nif / .pcap file is required");
    }
    let opts = Options {
        filtered: !cli.raw_only,
        raw: !cli.filtered_only,
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for path in &cli.files {
        let mut reader =
            plain_reader(path, opts).with_context(|| format!("opening {}", path.display()))?;
        io::copy(&mut reader, &mut out).with_context(|| format!("reading {}", path.display()))?;
    }
    Ok(())
}
