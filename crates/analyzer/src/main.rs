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
    CANBOAT_BEM, FramePacketType, PacketType, PgnDatabase, Reassembled, Reassembler,
    format::{
        InputFormat, detect, header_implies_coalesced, parse_format_header, parse_with,
        plain::ParseError,
    },
    output::{CamelCase, GeoFormat, JsonOptions, TextOptions, write_json, write_text},
};
use canboat_io::LineReader;

#[derive(Debug, Parser)]
#[command(
    name = "analyzer",
    about = "Decode canboat PLAIN/FAST lines from stdin into text or JSON",
    version
)]
struct Cli {
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

    /// Lat/lon display format — `dd` (decimal degrees, default),
    /// `dm` (degrees + decimal minutes), `dms` (degrees + minutes +
    /// decimal seconds). Matches canboat's `-geo {dd|dm|dms}`.
    #[arg(long, value_name = "FMT", default_value = "dd")]
    geo: String,

    /// Emit field keys + PGN descriptions as camelCase identifiers
    /// (e.g. `"uniqueNumber"` instead of `"Unique Number"`). Matches
    /// canboat C's `-camel`.
    #[arg(long, conflicts_with = "upper_camel")]
    camel: bool,

    /// Same as `--camel` but UpperCamelCase (`"UniqueNumber"`).
    /// Matches canboat C's `-upper-camel`.
    #[arg(long = "upper-camel")]
    upper_camel: bool,

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
        "plain" | "fast" | "plain_or_fast" => InputFormat::Plain,
        "plain_mix_fast" | "plain-mix-fast" => InputFormat::PlainMixFast,
        "actisense" | "actisense-ascii" | "actisense_n2k_ascii" => InputFormat::ActisenseAscii,
        "ydwg02" | "yden" => InputFormat::Ydwg02,
        "ikonvert" => InputFormat::Ikonvert,
        "airmar" => InputFormat::Airmar,
        "chetco" => InputFormat::Chetco,
        "garmin" | "garmin-csv" | "garmin_csv1" => InputFormat::GarminCsv,
        "garmin-csv2" | "garmin_csv2" => InputFormat::GarminCsv2,
        other => anyhow::bail!("unknown --format {other:?}"),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("analyzer: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    // The schema is compiled into the binary; no JSON loading, no
    // path discovery, no synthetic-PGN merge step — the build script
    // already folded `data/synthetic-pgns.json` into the static
    // tables. See `canboat-core/build.rs`.
    let db = PgnDatabase::embedded();

    let camel_case = if cli.upper_camel {
        CamelCase::Upper
    } else if cli.camel {
        CamelCase::Lower
    } else {
        CamelCase::Off
    };
    let json_opts = JsonOptions {
        include_empty: cli.empty,
        name_value: cli.nv,
        debug: cli.debug,
        camel_case,
    };
    let geo = match cli.geo.as_str() {
        "dd" => GeoFormat::Dd,
        "dm" => GeoFormat::Dm,
        "dms" => GeoFormat::Dms,
        other => anyhow::bail!("--geo must be one of dd, dm, dms (got {other:?})"),
    };
    let text_opts = TextOptions {
        show_unavailable: cli.empty,
        debug: cli.debug,
        geo,
    };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut line_buf = String::with_capacity(512);
    let mut reasm = Reassembler::new();

    // canboat's analyzer leads with a one-line JSON banner declaring
    // the database version and the active output knobs (see
    // analyzer.c:354-365). `-fixtime` suppresses it — *unless* the
    // fixed timestamp string contains "n2kd", in which case n2kd
    // still wants the banner upstream of the PGN stream.
    let suppress_banner = cli.fixtime.as_deref().is_some_and(|s| !s.contains("n2kd"));
    if cli.json && !suppress_banner {
        writeln!(
            out,
            "{{\"version\":\"{}\",\"units\":\"std\",\"showLookupValues\":{}}}",
            db.version,
            if cli.nv { "true" } else { "false" },
        )
        .context("writing JSON banner")?;
    }

    let forced_format = cli.format.as_deref().map(parse_format_flag).transpose()?;

    // Two distinct input shapes — stdin vs a regular file — but the
    // line-handling is identical. Box one and roll.
    if let Some(path) = cli.file.as_deref() {
        let file =
            File::open(path).with_context(|| format!("opening input file {}", path.display()))?;
        run_loop(
            LineReader::new(BufReader::new(file)),
            db,
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
            db,
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
    // Under -fixtime, suppress the incoming CANboat startup record
    // (CANBOAT_BEM) that producer tools emit at the head of every
    // stream. Its payload embeds the producer's build version, which
    // otherwise leaks into -fixtime output and breaks version-agnostic
    // golden tests. Mirrors the banner suppression above; same "n2kd"
    // carve-out so n2kd's own pipeline is unchanged.
    let suppress_startup_record = cli.fixtime.as_deref().is_some_and(|s| !s.contains("n2kd"));
    while let Some(line) = reader.next_line().context("reading input line")? {
        if line.is_empty() {
            continue;
        }
        // Honor `# format=<NAME>` headers emitted by the canboat
        // reader binaries (actisense-serial, ikonvert-serial,
        // maretron-ipg). Matches analyzer.c:383 — the header pins
        // the input format and, for any non-{PLAIN, PLAIN_OR_FAST,
        // PLAIN_MIX_FAST, YDWG02} format, flips multiPackets into
        // COALESCED mode (skip reassembly).
        if line.starts_with('#') {
            if let Some(fmt) = parse_format_header(line) {
                if active_format.is_none() {
                    active_format = Some(fmt);
                    log::info!("input format set by header: {:?}", fmt);
                }
                if header_implies_coalesced(line) {
                    coalesced_mode = true;
                    log::debug!("header declares coalesced format; skipping reassembly");
                }
            }
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

        if suppress_startup_record && frame.pgn == CANBOAT_BEM {
            continue;
        }

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
        //
        // PLAIN_MIX_FAST opts out — that format intentionally
        // interleaves coalesced FAST records with raw 8-byte
        // continuation frames, so we route per-frame instead.
        if frame.data.len() > 8 && format != InputFormat::PlainMixFast {
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
