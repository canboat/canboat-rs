//! Read N2K traffic off an Actisense NGT-1 over a serial port and
//! print one line per decoded PGN as canboat-style text. The
//! interesting part is what isn't here: zero protocol code lives in
//! this file — Ngt1Stream wraps the same sans-I/O state machine the
//! sync actisense-serial binary uses.
//!
//! Usage:
//!
//! ```sh
//!   cargo run -p canboat-tokio --example ngt1_demo -- \
//!       --serial /dev/ttyUSB0 [--baud 115200] [--db data/canboat.json]
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use canboat_core::{
    output::{write_text, TextOptions},
    PgnDatabase,
};
use canboat_tokio::Ngt1Stream;
use clap::Parser;
use futures::StreamExt;
use tokio_serial::SerialPortBuilderExt;

#[derive(Parser, Debug)]
#[command(name = "ngt1_demo")]
struct Cli {
    /// Serial device path.
    #[arg(long)]
    serial: String,
    /// Baud rate (NGT-1's default is 115200).
    #[arg(long, default_value_t = 115_200)]
    baud: u32,
    /// PGN database path. Defaults to ../../data/canboat.json relative
    /// to the crate manifest.
    #[arg(long)]
    db: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let db_path = cli.db.unwrap_or_else(default_db_path);
    let db = Arc::new(
        PgnDatabase::load(&db_path)
            .with_context(|| format!("loading {}", db_path.display()))?,
    );

    let port = tokio_serial::new(&cli.serial, cli.baud)
        .timeout(Duration::from_millis(250))
        .open_native_async()
        .with_context(|| format!("opening {}", cli.serial))?;

    let mut stream = Ngt1Stream::new(port, db);
    let opts = TextOptions::default();
    let mut buf = String::with_capacity(256);
    while let Some(decoded) = stream.next().await {
        buf.clear();
        write_text(&mut buf, &decoded, &opts).expect("write to String");
        println!("{buf}");
    }
    Ok(())
}

fn default_db_path() -> PathBuf {
    let manifest: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("data").join("canboat.json"))
        .unwrap_or_else(|| PathBuf::from("data/canboat.json"))
}
