// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `analyzer`: read canboat PLAIN/FAST lines from stdin (or a file),
//! decode each PGN against the canboat database, and emit text or
//! JSON on stdout.
//!
//! v0 supports the bare-essential CLI surface; flags map 1:1 onto the
//! C analyzer's behavior. The single-dash spellings the C analyzer
//! uses (`-json`, `-nv`, …) are accepted as Rust long flags (`--json`,
//! `--nv`, …) so the golden test harness can drive both.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::{
    PgnDatabase,
    format::InputFormat,
    output::{CamelCase, GeoFormat, JsonOptions, TextOptions, write_json, write_text},
};
use canboat_io::LineReader;

use analyzer::replay::{self, Config};

#[derive(Debug, Parser)]
#[command(
    name = "analyzer",
    about = "Decode canboat PLAIN/FAST lines from stdin into text or JSON",
    version,
    after_help = canboat_cli::help_footer()
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
    // The schema is compiled into the binary by `canboat-core/build.rs`;
    // we touch the embedded database here only to print the version in
    // the JSON banner below.
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

    // Suppress the CANBOAT_BEM startup record when `--fixtime` is
    // active so the producer's build version doesn't leak into
    // golden-test output. n2kd's own pipeline keeps the record (it
    // uses `--fixtime "<n2kd-…>"`).
    let cfg = Config {
        forced_format,
        pgn_filter: cli.pgn,
        src_filter: cli.src,
        dst_filter: cli.dst,
        suppress_startup_record: cli.fixtime.as_deref().is_some_and(|s| !s.contains("n2kd")),
    };

    // Sink: render each decoded record through write_json / write_text
    // and push the result to stdout. The library function feeds us
    // schema-static `DecodedPgn` borrows directly — no JSON
    // round-trip, no Vec<u8> allocation per record.
    let mut sink_err: Option<anyhow::Error> = None;
    let sink = |decoded: &canboat_core::DecodedPgn| {
        if sink_err.is_some() {
            return;
        }
        line_buf.clear();
        if cli.json {
            write_json(&mut line_buf, decoded, &json_opts).expect("write to String");
        } else {
            write_text(&mut line_buf, decoded, &text_opts).expect("write to String");
        }
        if let Err(e) = out
            .write_all(line_buf.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
        {
            sink_err = Some(anyhow::Error::new(e).context("writing line"));
        }
    };
    let result = if let Some(path) = cli.file.as_deref() {
        replay::decode_file(path, &cfg, sink)
    } else {
        let stdin = io::stdin();
        replay::decode_stream(LineReader::new(stdin.lock()), &cfg, sink)
    };
    if let Some(e) = sink_err {
        return Err(e);
    }
    result
}
