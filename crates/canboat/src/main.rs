// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat`: the single-binary front end to the canboat-rs toolkit.
//!
//! Subcommands replace the historical scatter of standalone binaries:
//!
//! - `convert` — translate a capture between any supported formats
//!   (subsumes `analyzer`, `nif2analyzer`, the various `*2*` shunts).
//! - `interface` — bridge a live gateway (NGT-1, iKonvert, SocketCAN,
//!   Maretron IPG) to/from stdout.
//! - `server` — the device → analyzer → n2kd pipeline daemon.
//! - `tui` — the terminal browser.
//!
//! Retired tool names keep working via argv[0] multiplexing — see
//! [`legacy`]. `canboat install-shims` creates the symlinks.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod convert;
mod interface;
mod legacy;
mod server;
mod tui;

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

    /// Bridge a live gateway (NGT-1 / iKonvert / Maretron / SocketCAN) to/from stdout.
    Interface(interface::Args),

    /// Run the single-process device → analyzer → n2kd pipeline server.
    Server(Box<server::Args>),

    /// Interactive terminal browser for a live n2kd/server stream or a capture.
    Tui(tui::Args),

    /// Install symlinks for the retired tool names (analyzer, *-serial, …).
    InstallShims {
        /// Directory to create the symlinks in. Defaults to the
        /// directory containing the `canboat` executable.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    // argv[0] multiplexing: a legacy name either runs its own
    // alias-module or rewrites into a `canboat <subcommand>` invocation.
    let argv = match legacy::route(canboat_cli::canboat_argv()) {
        legacy::Route::Alias(result) => return finish(result),
        legacy::Route::Canboat(argv) => argv,
    };
    let cli = Cli::parse_from(argv);
    let result = match cli.command {
        Command::Convert(args) => convert::run(args),
        Command::Interface(args) => interface::run(args),
        Command::Server(args) => server::run(*args),
        Command::Tui(args) => run_tui(args),
        Command::InstallShims { dir } => install_shims(dir),
    };
    finish(result)
}

/// Print any error and translate to a process exit code.
fn finish(result: anyhow::Result<()>) -> ExitCode {
    if let Err(e) = result {
        eprintln!("canboat: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Resolve the shim install directory (default: the binary's own dir)
/// and create the symlinks.
fn install_shims(dir: Option<PathBuf>) -> anyhow::Result<()> {
    use anyhow::Context;
    let dir = match dir {
        Some(d) => d,
        None => std::env::current_exe()
            .context("locating the canboat executable")?
            .parent()
            .context("canboat executable has no parent directory")?
            .to_path_buf(),
    };
    legacy::install_shims(&dir)
}

/// The TUI is async; the rest of `canboat` is not. Spin up a dedicated
/// multi-threaded runtime (matching the old `#[tokio::main]` shape) just
/// for this subcommand rather than making the whole binary async.
fn run_tui(args: tui::Args) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(tui::run(args))
}
