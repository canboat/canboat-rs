// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat convert` — translate a capture between formats.
//!
//! Every supported input (the canboat ASCII line formats, plus the
//! binary `.pcap`/`.pcap.gz`/`.nif` capture containers) is normalised
//! to a [`RawFrame`](canboat_core::RawFrame) stream, then emitted as:
//!
//! - `plain` — canboat PLAIN/FAST lines (a pure frame→frame shunt via
//!   [`canboat_io::copy`]); subsumes `nif2analyzer` and format
//!   normalisation.
//! - `json` / `text` — fully decoded records via the analyzer decode
//!   pipeline; this is what the `analyzer` binary does.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use canboat_core::RawFrame;
use canboat_core::format::InputFormat;
use canboat_core::output::{GeoFormat, JsonOptions, TextOptions, write_json, write_text};
use canboat_io::{
    FrameReader, FrameWriter, LineFrameReader, PlainWriter, analyze, container, copy,
};

/// Output format for `convert --to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutFormat {
    /// canboat PLAIN/FAST lines (raw frames, no decode).
    Plain,
    /// One decoded JSON object per record.
    Json,
    /// canboat human-readable text, one line per record.
    Text,
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Input file. A `.pcap` / `.pcap.gz` / `.nif` container is
    /// unwrapped automatically. Omit (or pass `-`) to read stdin.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Force the input format instead of auto-detecting it. One of:
    /// plain, plain-mix-fast, actisense, ydwg02, ikonvert, airmar,
    /// chetco, garmin, garmin-csv2.
    #[arg(long, value_name = "NAME")]
    from: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutFormat::Plain)]
    to: OutFormat,

    /// Filter: only emit frames with this source address.
    #[arg(long, value_name = "N")]
    src: Option<u8>,

    /// Filter: only emit frames with this destination address.
    #[arg(long, value_name = "N")]
    dst: Option<u8>,

    /// Filter: only emit frames with this PGN.
    #[arg(long, value_name = "PGN")]
    pgn: Option<u32>,
}

pub fn run(args: Args) -> Result<()> {
    let forced = args.from.as_deref().map(parse_format).transpose()?;
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    match args.to {
        OutFormat::Plain => convert_raw(&args, forced, &mut out),
        OutFormat::Json | OutFormat::Text => convert_decoded(&args, forced, &mut out),
    }
}

/// Raw path: input frames → PLAIN lines, no decode. The no-filter
/// case is exactly [`canboat_io::copy`]; with filters we run the same
/// pull loop with a per-frame predicate.
fn convert_raw<W: Write>(args: &Args, forced: Option<InputFormat>, out: &mut W) -> Result<()> {
    let source = open_source(args.file.as_deref())?;
    let mut reader = match forced {
        Some(fmt) => LineFrameReader::with_format(source, fmt),
        None => LineFrameReader::new(source),
    };
    let mut writer = PlainWriter::new(out);

    if !args.has_filter() {
        copy(&mut reader, &mut writer).context("converting to PLAIN")?;
        return Ok(());
    }
    while let Some(frame) = reader.read_frame().context("reading input")? {
        if args.keep(&frame) {
            writer.write_frame(&frame).context("writing PLAIN")?;
        }
    }
    writer.flush().context("flushing output")?;
    Ok(())
}

/// Decoded path: drive the analyzer pipeline and render each record as
/// JSON or text. Filters are pushed into the pipeline's `Config`.
fn convert_decoded<W: Write>(args: &Args, forced: Option<InputFormat>, out: &mut W) -> Result<()> {
    let json_opts = JsonOptions::default();
    let text_opts = TextOptions {
        show_unavailable: false,
        debug: false,
        geo: GeoFormat::Dd,
    };
    let as_json = args.to == OutFormat::Json;
    let cfg = analyze::Config {
        forced_format: forced,
        pgn_filter: args.pgn,
        src_filter: args.src,
        dst_filter: args.dst,
        suppress_startup_record: false,
    };

    let mut line = String::with_capacity(512);
    let mut sink_err: Option<io::Error> = None;
    let sink = |decoded: &canboat_core::DecodedPgn| {
        if sink_err.is_some() {
            return;
        }
        line.clear();
        if as_json {
            write_json(&mut line, decoded, &json_opts).expect("write to String");
        } else {
            write_text(&mut line, decoded, &text_opts).expect("write to String");
        }
        if let Err(e) = out
            .write_all(line.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
        {
            sink_err = Some(e);
        }
    };

    let source = open_source(args.file.as_deref())?;
    analyze::decode_stream(source, &cfg, sink).context("decoding input")?;
    if let Some(e) = sink_err {
        return Err(e).context("writing output");
    }
    Ok(())
}

/// Open the input as a canboat PLAIN-capable [`BufRead`]. A `.nif` /
/// `.pcap` container is unwrapped on the fly; `None` or `-` is stdin.
fn open_source(file: Option<&Path>) -> Result<Box<dyn BufRead>> {
    match file {
        Some(path) if path.as_os_str() != "-" => {
            if container::is_container(path) {
                container::plain_reader(path, Default::default())
                    .with_context(|| format!("opening {}", path.display()))
            } else {
                let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
                Ok(Box::new(BufReader::new(f)))
            }
        }
        // `Stdin::lock` yields a `'static` guard, so this is owned.
        _ => Ok(Box::new(io::stdin().lock())),
    }
}

impl Args {
    fn has_filter(&self) -> bool {
        self.src.is_some() || self.dst.is_some() || self.pgn.is_some()
    }

    /// True when `frame` passes the src/dst/pgn filters.
    fn keep(&self, frame: &RawFrame) -> bool {
        self.src.is_none_or(|s| frame.src == s)
            && self.dst.is_none_or(|d| frame.dst == d)
            && self.pgn.is_none_or(|p| frame.pgn == p)
    }
}

/// Map a `--from` name to an [`InputFormat`]. Mirrors the analyzer
/// binary's `--format` spellings.
fn parse_format(name: &str) -> Result<InputFormat> {
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
        other => anyhow::bail!("unknown --from format {other:?}"),
    })
}
