//! Read N2K traffic off a Digital Yacht iKonvert over a serial port
//! and consume `DecodedPgn` events directly (no JSON middleman). This
//! mirrors how merrimac-rs is expected to embed the canboat stack.
//!
//! Usage:
//!
//! ```sh
//!   cargo run -p canboat-tokio --example merrimac_demo -- \
//!       --serial /dev/ttyUSB0 [--baud 230400] [--db data/canboat.json]
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use canboat_core::PgnDatabase;
use canboat_tokio::IkonvertStream;
use clap::Parser;
use futures::StreamExt;
use tokio_serial::SerialPortBuilderExt;

#[derive(Parser, Debug)]
#[command(name = "merrimac_demo")]
struct Cli {
    #[arg(long)]
    serial: String,
    /// Baud rate (iKonvert's default is 230400).
    #[arg(long, default_value_t = 230_400)]
    baud: u32,
    #[arg(long)]
    db: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let db_path = cli.db.unwrap_or_else(default_db_path);
    let db = Arc::new(
        PgnDatabase::load(&db_path).with_context(|| format!("loading {}", db_path.display()))?,
    );

    let port = tokio_serial::new(&cli.serial, cli.baud)
        .timeout(Duration::from_millis(250))
        .open_native_async()
        .with_context(|| format!("opening {}", cli.serial))?;

    let mut stream = IkonvertStream::new(port, db);
    while let Some(decoded) = stream.next().await {
        // This is what merrimac sees: typed DecodedPgn events with raw
        // structured FieldValues — no parsing back from JSON required.
        println!(
            "[pgn {:>6} src {:>3}] {} ({} fields)",
            decoded.pgn,
            decoded.src,
            decoded.description,
            decoded.fields.len(),
        );
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
