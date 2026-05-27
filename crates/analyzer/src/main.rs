//! `analyzer`: read canboat PLAIN/FAST lines from stdin (or a file),
//! decode each PGN against the canboat database, and emit text or
//! JSON on stdout.
//!
//! v0 supports the bare-essential CLI surface; flags map 1:1 onto the
//! C analyzer's behavior. The single-dash spellings the C analyzer
//! uses (`-json`, `-nv`, …) are accepted as Rust long flags (`--json`,
//! `--nv`, …) so the golden test harness can drive both.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::{
    format::{detect, parse_with, plain::ParseError, InputFormat},
    output::{write_json, write_text, JsonOptions, TextOptions},
    FramePacketType, PacketType, PgnDatabase, Reassembled, Reassembler,
};
use canboat_io::LineReader;

#[derive(Debug, Parser)]
#[command(
    name = "analyzer",
    about = "Decode canboat PLAIN/FAST lines from stdin into text or JSON",
    version
)]
struct Cli {
    /// Path to the canboat PGN database. Defaults to the workspace's
    /// vendored `data/canboat.json`. Set the `CANBOAT_JSON` env var
    /// to override.
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,

    /// Read input from this file instead of stdin.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Emit JSON instead of canboat text.
    #[arg(long)]
    json: bool,

    /// JSON: include `null` for unavailable fields (`-empty`).
    #[arg(long)]
    empty: bool,

    /// JSON: emit lookup values as `{"value":N,"name":"..."}` (`-nv`).
    #[arg(long)]
    nv: bool,

    /// JSON: wrap every field with byte/bit diagnostics — adds
    /// `"bytes":"FF FF"` and `"bits":"..."` to each field's object
    /// form (`-debug`).
    #[arg(long)]
    debug: bool,

    /// Use the given string in place of any analyzer-generated
    /// timestamps (matches canboat's `-fixtime`). Inputs that carry
    /// their own timestamps (PLAIN/FAST, Actisense ASCII) pass them
    /// through verbatim — only formats that fabricate a date (YDWG02,
    /// etc.) are affected. Accepted unconditionally for CLI
    /// compatibility with the canboat C analyzer.
    #[arg(long, value_name = "STRING")]
    fixtime: Option<String>,

    /// Filter: only process frames with this source address.
    #[arg(long, value_name = "N")]
    src: Option<u8>,

    /// Filter: only process frames with this destination address.
    #[arg(long, value_name = "N")]
    dst: Option<u8>,

    /// Force a specific input format instead of auto-detecting.
    /// Accepted values: plain, actisense, ydwg02, ikonvert.
    #[arg(long, value_name = "NAME")]
    format: Option<String>,

    /// Filter: only process frames with this PGN number.
    #[arg(value_name = "PGN")]
    pgn: Option<u32>,
}

fn parse_format_flag(name: &str) -> Result<InputFormat> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "plain" | "fast" => InputFormat::Plain,
        "actisense" | "actisense-ascii" => InputFormat::ActisenseAscii,
        "ydwg02" | "yden" => InputFormat::Ydwg02,
        "ikonvert" => InputFormat::Ikonvert,
        "airmar" => InputFormat::Airmar,
        "chetco" => InputFormat::Chetco,
        "garmin" | "garmin-csv" => InputFormat::GarminCsv,
        other => anyhow::bail!("unknown --format {other:?}"),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("analyzer: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let db_path = cli
        .db
        .clone()
        .or_else(|| std::env::var_os("CANBOAT_JSON").map(PathBuf::from))
        .or_else(default_db_path)
        .context("no canboat.json path supplied (pass --db or set CANBOAT_JSON)")?;
    let db = PgnDatabase::load(&db_path)
        .with_context(|| format!("loading PGN database {}", db_path.display()))?;

    let json_opts = JsonOptions {
        include_empty: cli.empty,
        name_value: cli.nv,
        debug: cli.debug,
    };
    let text_opts = TextOptions {
        show_unavailable: cli.empty,
        debug: cli.debug,
    };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut line_buf = String::with_capacity(512);
    let mut reasm = Reassembler::new();

    let forced_format = cli.format.as_deref().map(parse_format_flag).transpose()?;

    // Two distinct input shapes — stdin vs a regular file — but the
    // line-handling is identical. Box one and roll.
    if let Some(path) = cli.file.as_deref() {
        let file =
            File::open(path).with_context(|| format!("opening input file {}", path.display()))?;
        run_loop(
            LineReader::new(BufReader::new(file)),
            &db,
            &cli,
            &json_opts,
            &text_opts,
            forced_format,
            &mut reasm,
            &mut out,
            &mut line_buf,
        )?;
    } else {
        let stdin = io::stdin();
        run_loop(
            LineReader::new(stdin.lock()),
            &db,
            &cli,
            &json_opts,
            &text_opts,
            forced_format,
            &mut reasm,
            &mut out,
            &mut line_buf,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_loop<R: BufRead, W: Write>(
    mut reader: LineReader<R>,
    db: &PgnDatabase,
    cli: &Cli,
    json_opts: &JsonOptions,
    text_opts: &TextOptions,
    forced_format: Option<InputFormat>,
    reasm: &mut Reassembler,
    out: &mut W,
    line_buf: &mut String,
) -> Result<()> {
    let mut active_format = forced_format;
    // Canboat's PLAIN_OR_FAST mode locks into "coalesced" once any
    // line carries more than 8 payload bytes — from then on every
    // frame is assumed to be pre-assembled and the reassembler is
    // skipped. We do the same so single-line FAST captures (e.g.
    // pgn-test.in's mix of 8-byte and 43-byte payloads) decode
    // identically to the C analyzer.
    let mut coalesced_mode = false;
    while let Some(line) = reader.next_line().context("reading input line")? {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Auto-detect on the first content line if the user didn't
        // force a format.
        if active_format.is_none() {
            active_format = detect(line).or(Some(InputFormat::Plain));
            log::debug!("input format: {:?}", active_format);
        }
        let format = active_format.expect("active_format set above");
        let frame = match parse_with(format, line) {
            Ok(Some(f)) => f,
            Ok(None) => continue, // iKonvert control sentences etc.
            Err(ParseError::Empty) => continue,
            Err(e) => {
                log::warn!("skipping malformed input line: {e}");
                continue;
            }
        };

        if let Some(want) = cli.pgn {
            if frame.pgn != want {
                continue;
            }
        }
        if let Some(want) = cli.src {
            if frame.src != want {
                continue;
            }
        }
        if let Some(want) = cli.dst {
            if frame.dst != want {
                continue;
            }
        }

        // Once any line has > 8 payload bytes, assume the rest of
        // the stream is also pre-assembled FAST and skip reassembly
        // for everything that follows. Matches canboat's
        // RAWFORMAT_PLAIN_OR_FAST → RAWFORMAT_FAST lock-in
        // (analyzer.c:431) which also flips multiPackets to
        // COALESCED.
        if frame.data.len() > 8 {
            coalesced_mode = true;
        }

        // Fast-packet reassembly: single-frame PGNs and already-
        // coalesced frames (len > 8) pass through immediately;
        // fast-packet PGNs accumulate until complete. Unknown PGNs
        // fall through to a `Fallback: true` catch-all (e.g. the
        // `0x1FF00-0x1FFFF: Manufacturer Specific fast-packet
        // non-addressed` stub) so proprietary PGNs that aren't in
        // canboat.json still reassemble correctly.
        let packet_type = if coalesced_mode {
            FramePacketType::Other
        } else {
            db.first_pgn(frame.pgn)
                .or_else(|| db.fallback_pgn(frame.pgn))
                .map(|p| match p.packet_type {
                    PacketType::Fast => FramePacketType::Fast,
                    PacketType::Single => FramePacketType::Single,
                    _ => FramePacketType::Other,
                })
                .unwrap_or(FramePacketType::Other)
        };
        let assembled = match reasm.push(frame, packet_type) {
            Reassembled::PassThrough(f) | Reassembled::Complete(f) => f,
            Reassembled::Partial => continue,
            Reassembled::Error(e) => {
                log::warn!("reassembly error: {e}");
                continue;
            }
        };

        let decoded = match db.decode(&assembled) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("decode error: {e}");
                continue;
            }
        };

        line_buf.clear();
        if cli.json {
            write_json(line_buf, &decoded, json_opts).expect("write to String");
        } else {
            write_text(line_buf, &decoded, text_opts).expect("write to String");
        }
        out.write_all(line_buf.as_bytes()).context("writing line")?;
        out.write_all(b"\n").context("writing newline")?;
    }
    Ok(())
}

/// Try to find the workspace's vendored `data/canboat.json` next to
/// the binary or relative to `CARGO_MANIFEST_DIR` in dev builds.
fn default_db_path() -> Option<PathBuf> {
    // In a cargo-built dev binary, the workspace root is two levels up
    // from the crate's manifest.
    let manifest_dir: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let candidate = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("data").join("canboat.json"));
    candidate.filter(|p| p.exists())
}
