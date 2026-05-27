//! `candump2analyzer`: convert can-utils / candump output into the
//! canboat analyzer's `RAWFORMAT_PLAIN` lines.
//!
//! Five candump-ish input shapes are recognised (mirrors the C
//! tool's `FMT_1..FMT_5`):
//!
//! ```text
//!   FMT_1 Angstrom        : <0x18eeff01> [8] 05 a0 be 1c 00 a0 a0 c0
//!   FMT_2 Debian/can-utils:   can0  09F8027F   [8]  00 FC FF FF 00 00 FF FF
//!   FMT_3 candump -l      : (1502979132.106111) slcan0 09F50374#000A00FFFF00FFFF
//!   FMT_4 tshark pcap     : 10131  29.555750  ?  CAN 16 XTD: 0x09fd0223   00 49 02 1c a7 fa ff ff
//!   FMT_5 Navico TCP 8086 : 0021200 0e 1d ff 9d 08 00 00 00 80 df 3f 9f 34 12 ff 0d
//! ```
//!
//! Output:
//!
//! ```text
//!   YYYY-MM-DD-HH:MM:SS.mmm,<prio>,<pgn>,<src>,<dst>,<size>,<hex>...
//! ```
//!
//! The format is sniffed from the first non-empty / non-comment
//! line of input and locked in — same as canboat's C tool.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::ydwg02::iso11783_decompose;

#[derive(Debug, Parser)]
#[command(
    name = "candump2analyzer",
    about = "Convert can-utils candump lines to canboat PLAIN format",
    version
)]
struct Cli {
    /// Optional input file (defaults to stdin).
    input: Option<PathBuf>,

    /// Verbose / debug logging — alias of `-d`. Matches canboat C.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Quiet — only show errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Angstrom: `<0x09F8027F> [8] AA BB ...`
    Angstrom,
    /// can-utils on Debian: `  can0  09F8027F   [8]  AA BB ...`
    Debian,
    /// `candump -l`: `(1502979132.106111) slcan0 09F50374#AABB...`
    Log,
    /// tshark of pcap: `10131  29.555750  ?  CAN 16 XTD: 0x09fd0223   AA BB ...`
    Tshark,
    /// Navico TCP 8086: `0021200 0e 1d ff 9d 08 00 00 00 80 df 3f 9f 34 12 ff 0d`
    Navico,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("candump2analyzer: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let level = if cli.quiet {
        "error"
    } else if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let reader: Box<dyn BufRead> = match &cli.input {
        Some(path) => Box::new(BufReader::new(
            File::open(path).with_context(|| format!("opening {}", path.display()))?,
        )),
        None => Box::new(io::stdin().lock()),
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut format: Option<Format> = None;
    for line_res in reader.lines() {
        let line = line_res.context("reading input")?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Sniff the format from the first content line, then lock in.
        let fmt = match format {
            Some(f) => f,
            None => match sniff(trimmed) {
                Some(f) => {
                    log::info!("detected candump format: {f:?}");
                    format = Some(f);
                    f
                }
                None => {
                    log::warn!("could not detect format from line: {trimmed:?}");
                    continue;
                }
            },
        };
        match parse(fmt, trimmed) {
            Some(record) => {
                emit(&mut out, &record)?;
            }
            None => {
                log::debug!("skipping unparseable line: {trimmed:?}");
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Record {
    timestamp_ms: u64,
    /// `None` → no timestamp on the line, use the host clock.
    timestamp_from_line: bool,
    canid: u32,
    data: Vec<u8>,
}

fn sniff(line: &str) -> Option<Format> {
    if line.starts_with('<') {
        return Some(Format::Angstrom);
    }
    if line.starts_with('(') {
        return Some(Format::Log);
    }
    if line.contains("CAN 16 XTD:") {
        return Some(Format::Tshark);
    }
    let bytes = line.as_bytes();
    // Debian: starts with whitespace OR an interface name like `can0`,
    // followed by a hex CAN-id and `[N]`.
    if line.contains('[') && line.contains(']') {
        return Some(Format::Debian);
    }
    // Navico: 7-hex-digit timestamp at start, no other punctuation.
    if bytes.len() > 7 && bytes[..7].iter().all(|b| b.is_ascii_hexdigit()) && bytes[7] == b' ' {
        return Some(Format::Navico);
    }
    None
}

fn parse(fmt: Format, line: &str) -> Option<Record> {
    match fmt {
        Format::Angstrom => parse_angstrom(line),
        Format::Debian => parse_debian(line),
        Format::Log => parse_log(line),
        Format::Tshark => parse_tshark(line),
        Format::Navico => parse_navico(line),
    }
}

/// `<0xCANID> [N] AA BB ...`. The CAN id is hex; the `0x` prefix is
/// optional in some captures.
fn parse_angstrom(line: &str) -> Option<Record> {
    let rest = line.strip_prefix('<')?;
    let (id_tok, after) = rest.split_once('>')?;
    let id_tok = id_tok.trim_start_matches("0x").trim_start_matches("0X");
    let canid = u32::from_str_radix(id_tok, 16).ok()?;
    let (_count, rest) = bracketed_count_and_data(after)?;
    Some(Record {
        timestamp_ms: now_ms(),
        timestamp_from_line: false,
        canid,
        data: parse_hex_bytes(rest),
    })
}

/// `  can0  CANID   [N]  AA BB ...`. The interface column is
/// whitespace-separated and the bracket count carries the byte count.
fn parse_debian(line: &str) -> Option<Record> {
    let mut toks = line.split_whitespace();
    let _iface = toks.next()?;
    let id_tok = toks.next()?;
    let canid = u32::from_str_radix(id_tok, 16).ok()?;
    // The rest is `[N]  AA BB ...` — find the bracket and split there.
    let after_id = line.split_once(id_tok)?.1.trim_start();
    let (_count, rest) = bracketed_count_and_data(after_id)?;
    Some(Record {
        timestamp_ms: now_ms(),
        timestamp_from_line: false,
        canid,
        data: parse_hex_bytes(rest),
    })
}

/// `(unix_secs.usec) iface CANID#AABB...`. Data bytes are a single
/// run of hex digits after the `#`, no separators.
fn parse_log(line: &str) -> Option<Record> {
    let rest = line.strip_prefix('(')?;
    let (ts_tok, rest) = rest.split_once(')')?;
    let secs_f: f64 = ts_tok.trim().parse().ok()?;
    // Canboat C does `tv_sec = (time_t)sec; tv_usec = (sec - tv_sec)
    // * 1e6; msec = lrint(tv_usec / 1000.0)`. Mirror the rounding so
    // a captured `…421711` micro-timestamp rounds to `…422` ms, not
    // truncates to `…421`.
    // round_ties_even mirrors C's default `lrint` rounding (round-
    // half-to-even, aka banker's rounding) — without it,
    // `1502984881.6645 * 1000 = …664.5` would round away-from-zero
    // to 665 while canboat picks 664.
    let timestamp_ms = (secs_f * 1000.0).round_ties_even() as u64;
    let mut toks = rest.split_whitespace();
    let _iface = toks.next()?;
    let pair = toks.next()?;
    let (id_tok, data_tok) = pair.split_once('#')?;
    let canid = u32::from_str_radix(id_tok, 16).ok()?;
    let mut data = Vec::with_capacity(data_tok.len() / 2);
    for chunk in data_tok.as_bytes().chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        if let Ok(b) = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16) {
            data.push(b);
        } else {
            break;
        }
    }
    Some(Record {
        timestamp_ms,
        timestamp_from_line: true,
        canid,
        data,
    })
}

/// `<frame#> <secs.usec> <iface> CAN 16 XTD: 0xCANID   AA BB ...`.
fn parse_tshark(line: &str) -> Option<Record> {
    // Pull the seconds-float (second whitespace-separated token).
    let mut toks = line.split_whitespace();
    let _frame = toks.next()?;
    let secs_f: f64 = toks.next()?.parse().ok()?;
    // round_ties_even mirrors C's default `lrint` rounding (round-
    // half-to-even, aka banker's rounding) — without it,
    // `1502984881.6645 * 1000 = …664.5` would round away-from-zero
    // to 665 while canboat picks 664.
    let timestamp_ms = (secs_f * 1000.0).round_ties_even() as u64;
    let after_xtd = line.split_once("XTD:")?.1.trim_start();
    let id_end = after_xtd
        .find(char::is_whitespace)
        .unwrap_or(after_xtd.len());
    let id_tok = after_xtd[..id_end]
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let canid = u32::from_str_radix(id_tok, 16).ok()?;
    let rest = &after_xtd[id_end..];
    Some(Record {
        timestamp_ms,
        timestamp_from_line: true,
        canid,
        data: parse_hex_bytes(rest),
    })
}

/// Navico TCP 8086: 7-hex-digit timestamp then 16 single-byte hex
/// tokens. First 4 bytes are the CAN identifier (little-endian),
/// next 4 form something unused, then 8 data bytes.
fn parse_navico(line: &str) -> Option<Record> {
    let mut toks = line.split_whitespace();
    let ts_tok = toks.next()?;
    let timestamp_ms = u64::from_str_radix(ts_tok, 16).ok()?;
    let bytes: Vec<u8> = toks
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .collect();
    if bytes.len() < 8 {
        return None;
    }
    let canid = (bytes[0] as u32)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24);
    let data = bytes[8..bytes.len().min(8 + 8)].to_vec();
    Some(Record {
        timestamp_ms,
        timestamp_from_line: true,
        canid,
        data,
    })
}

/// `[N] AA BB ...` — return the count + the slice past the closing
/// bracket. Robust to whitespace before / after the brackets.
fn bracketed_count_and_data(s: &str) -> Option<(usize, &str)> {
    let s = s.trim_start();
    let rest = s.strip_prefix('[')?;
    let (count_tok, rest) = rest.split_once(']')?;
    let count: usize = count_tok.trim().parse().ok()?;
    Some((count, rest))
}

/// Parse space-separated hex bytes from `s`.
fn parse_hex_bytes(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map_while(|t| u8::from_str_radix(t.trim_start_matches("0x"), 16).ok())
        .collect()
}

fn emit<W: Write>(out: &mut W, r: &Record) -> Result<()> {
    let (prio, pgn, src, dst) = iso11783_decompose(r.canid);
    let ts = if r.timestamp_from_line {
        format_iso_ms(r.timestamp_ms)
    } else {
        format_iso_ms(now_ms())
    };
    write!(out, "{ts},{prio},{pgn},{src},{dst},{}", r.data.len())?;
    for b in &r.data {
        write!(out, ",{:02x}", b)?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD-HH:MM:SS.mmm` (canboat's `%F-%T.%03d`).
fn format_iso_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let frac = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400) as u32;
    let h = day_secs / 3600;
    let m = (day_secs / 60) % 60;
    let s = day_secs % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}-{h:02}:{m:02}:{s:02}.{frac:03}")
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_angstrom() {
        let line = "<0x09F8027F> [8] 00 FC FF FF 00 00 FF FF";
        let r = parse(Format::Angstrom, line).unwrap();
        assert_eq!(r.canid, 0x09F8027F);
        assert_eq!(r.data, vec![0x00, 0xFC, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF]);
        // No timestamp on the line — host clock used.
        assert!(!r.timestamp_from_line);
    }

    #[test]
    fn parses_debian() {
        let line = "   can0  09F8027F   [8]  00 FC FF FF 00 00 FF FF";
        let r = parse(Format::Debian, line.trim()).unwrap();
        assert_eq!(r.canid, 0x09F8027F);
        assert_eq!(r.data.len(), 8);
        assert!(!r.timestamp_from_line);
    }

    #[test]
    fn parses_log() {
        let line = "(1502979132.106111) slcan0 09F50374#000A00FFFF00FFFF";
        let r = parse(Format::Log, line).unwrap();
        assert_eq!(r.canid, 0x09F50374);
        assert_eq!(r.data, vec![0x00, 0x0A, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF]);
        assert!(r.timestamp_from_line);
        assert_eq!(r.timestamp_ms, 1_502_979_132_106);
    }

    #[test]
    fn parses_tshark() {
        let line = "10131  29.555750  ?  CAN 16 XTD: 0x09fd0223   00 49 02 1c a7 fa ff ff";
        let r = parse(Format::Tshark, line).unwrap();
        assert_eq!(r.canid, 0x09fd0223);
        assert_eq!(r.data, vec![0x00, 0x49, 0x02, 0x1c, 0xa7, 0xfa, 0xff, 0xff]);
        assert_eq!(r.timestamp_ms, 29_555); // 29.555750 s → 29555 ms
    }

    #[test]
    fn parses_navico() {
        // 7-hex tstamp, 4-byte canid LE, 4 unused, 8 data bytes.
        let line = "0021200 0e 1d ff 9d 08 00 00 00 80 df 3f 9f 34 12 ff 0d";
        let r = parse(Format::Navico, line).unwrap();
        assert_eq!(r.canid, 0x9DFF1D0E);
        assert_eq!(r.timestamp_ms, 0x21200);
        assert_eq!(r.data, vec![0x80, 0xdf, 0x3f, 0x9f, 0x34, 0x12, 0xff, 0x0d]);
    }

    #[test]
    fn sniffs_log_format() {
        assert_eq!(
            sniff("(1502979132.106111) slcan0 09F50374#001234"),
            Some(Format::Log)
        );
        assert_eq!(sniff("<0x09F8> [8] aa bb"), Some(Format::Angstrom));
        assert_eq!(sniff("  can0  09F8027F   [8]  00 FC"), Some(Format::Debian));
        assert_eq!(sniff("12 3.4 ? CAN 16 XTD: 0x09 aa"), Some(Format::Tshark));
        assert_eq!(sniff("0021200 0e 1d ff 9d"), Some(Format::Navico));
    }
}
