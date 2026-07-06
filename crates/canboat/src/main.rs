// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat`: the single-binary front end to the canboat-rs toolkit.
//!
//! Subcommands replace the historical scatter of standalone binaries:
//!
//! - `convert` — translate a capture between any supported formats
//!   (subsumes `analyzer`, `nif2analyzer`, the various `*2*` shunts).
//!   Ported.
//! - `interface` — bridge a live gateway (NGT-1, iKonvert, SocketCAN,
//!   Maretron IPG) to/from stdout. (to be ported)
//! - `server` — the n2kd/pipeline daemon. (to be ported)
//! - `tui` — the terminal browser. (to be ported)
//!
//! Old tool names keep working via argv[0] multiplexing (added with
//! the retirement of the standalone crates).

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod convert;

#[derive(Debug, Parser)]
#[command(
    name = "canboat",
    about = "The canboat NMEA 2000 toolkit",
    version,
    after_help = canboat_cli::help_footer()
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Convert a capture between formats (any input → PLAIN / JSON / text).
    Convert(convert::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    let result = match cli.command {
        Command::Convert(args) => convert::run(args),
    };
    if let Err(e) = result {
        eprintln!("canboat: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
