//! Benchmark scaffolding — runs the analyzer → n2kd pipeline in a
//! single process, without pipes or syscalls between the two stages.
//!
//! For each line of PLAIN/FAST input:
//!
//!   line → RawFrame → reassembly → DecodedPgn
//!        → JSON text (in a thread-local buffer)
//!        → n2kd::nmea0183::convert or n2kd::ais::convert
//!        → NMEA 0183 sentence on stdout
//!
//! Drops every other n2kd surface (TCP listeners, UDP broadcast,
//! claim-request engine, status emitter) — only the JSON-to-NMEA
//! conversion remains. The point is to measure how much of the
//! piped `analyzer | n2kd` runtime is the pipe / IO overhead vs. the
//! work each stage actually does.

use std::cell::RefCell;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::{detect, parse_with, InputFormat};
use canboat_core::output::{write_json, JsonOptions};
use canboat_core::{FramePacketType, PgnDatabase, Reassembled, Reassembler};

const SYNTHETIC_PGNS_JSON: &str = include_str!("../../../data/synthetic-pgns.json");

const AIS_PGNS: &[u32] = &[
    129038, 129039, 129040, 129041, 129793, 129794, 129798, 129801, 129802, 129809, 129810,
];

#[derive(Debug, Parser)]
#[command(
    name = "n2kd-inproc",
    about = "In-process analyzer→n2kd benchmark scaffolding",
    version
)]
struct Cli {
    /// Path to canboat.json. Falls back to CANBOAT_JSON env, then
    /// to the workspace-vendored copy at data/canboat.json.
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,
}

fn default_db_path() -> Option<PathBuf> {
    let here = std::env::current_exe().ok()?;
    let workspace = here.ancestors().nth(3)?;
    let candidate = workspace.join("data").join("canboat.json");
    candidate.exists().then_some(candidate)
}

thread_local! {
    static JSON_BUF: RefCell<String> = const { RefCell::new(String::new()) };
}

fn main() -> Result<()> {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    let db_path = cli
        .db
        .clone()
        .or_else(|| std::env::var_os("CANBOAT_JSON").map(PathBuf::from))
        .or_else(default_db_path)
        .context("no canboat.json path supplied (pass --db or set CANBOAT_JSON)")?;
    let mut db = PgnDatabase::load(&db_path)
        .with_context(|| format!("loading PGN database {}", db_path.display()))?;
    db.merge_pgns_from_json(SYNTHETIC_PGNS_JSON)
        .context("merging synthetic PGN definitions")?;

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock());

    let mut reasm = Reassembler::new();
    let mut active_format = None;
    let mut coalesced_mode = false;
    let mut nmea_buf = String::with_capacity(256);
    let mut rl = n2kd::nmea0183::RateLimiter::new(false);
    let mut ais_seq: u8 = 0;

    // Match canboat's analyzer `-json -nv` defaults — `-nv` turns
    // every LOOKUP into `{value,name}` (which is what n2kd's
    // converters parse), but `-empty` is off so missing fields
    // disappear from the JSON instead of becoming `null`.
    let json_opts = JsonOptions {
        include_empty: false,
        name_value: true,
        debug: false,
    };

    let mut line = String::with_capacity(1024);
    loop {
        line.clear();
        let n = reader.read_line(&mut line).context("read stdin")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if active_format.is_none() {
            active_format = detect(trimmed).or(Some(InputFormat::Plain));
        }
        let frame = match parse_with(active_format.unwrap(), trimmed) {
            Ok(Some(f)) => f,
            _ => continue,
        };
        if frame.data.len() > 8 {
            coalesced_mode = true;
        }
        let packet_type = if coalesced_mode {
            FramePacketType::Other
        } else {
            db.first_pgn(frame.pgn)
                .or_else(|| db.fallback_pgn(frame.pgn))
                .map(|p| match p.packet_type {
                    canboat_core::PacketType::Fast => FramePacketType::Fast,
                    canboat_core::PacketType::Single => FramePacketType::Single,
                    _ => FramePacketType::Other,
                })
                .unwrap_or(FramePacketType::Other)
        };
        let assembled = match reasm.push(frame, packet_type) {
            Reassembled::PassThrough(f) | Reassembled::Complete(f) => f,
            _ => continue,
        };
        let Ok(decoded) = db.decode(&assembled) else {
            continue;
        };

        // Stage 2 — serialize to the thread-local JSON buffer that
        // n2kd's conversion API consumes. This buffer is reused so
        // the per-record alloc is amortised.
        JSON_BUF.with(|c| {
            let mut buf = c.borrow_mut();
            buf.clear();
            // write_json returns fmt::Result; we ignore it because a
            // &mut String fmt sink can't actually fail.
            let _ = write_json(&mut *buf, &decoded, &json_opts);

            // Stage 3 — convert to NMEA 0183. n2kd takes `&str` JSON.
            nmea_buf.clear();
            let pgn = decoded.pgn;
            let n_emitted = if AIS_PGNS.contains(&pgn) {
                n2kd::ais::convert(&mut nmea_buf, &buf, &mut ais_seq)
            } else {
                n2kd::nmea0183::convert(&mut nmea_buf, &buf, &mut rl)
            };
            if n_emitted > 0 {
                // Stage 4 — write to stdout.
                let _ = out.write_all(nmea_buf.as_bytes());
            }
        });
    }
    out.flush().ok();
    Ok(())
}
