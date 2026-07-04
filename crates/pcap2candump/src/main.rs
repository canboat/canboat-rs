// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `pcap2candump`: convert a libpcap capture of SocketCAN frames into
//! `candump -l` log format (canboat's `FMT_3`). Mirrors
//! `canboat/pcap2candump/pcap2candump.py`.
//!
//! pcap file layout we accept:
//!
//! ```text
//!   global header (24 bytes), magic 0xa1b2c3d4 in little-endian
//!   for each record:
//!     ts_sec   : LE u32        — Unix-epoch seconds
//!     ts_usec  : LE u32        — microseconds (or nanoseconds if magic
//!                                were 0xa1b23c4d, which we reject)
//!     incl_len : LE u32        — captured length (unused, derived
//!                                from `datalen`)
//!     orig_len : LE u32        — original length (unused)
//!     can_id   : BE u32        — 29-bit ISO 11783 CAN identifier
//!     datalen  : u8
//!     pad      : 3 bytes
//!     data     : datalen bytes
//! ```
//!
//! Output: `(<sec>.<usec:06>) slcan0 <canid:x>#<hex bytes>`.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;

const PCAP_MAGIC_US: u32 = 0xa1b2c3d4;

#[derive(Debug, Parser)]
#[command(
    name = "pcap2candump",
    about = "Convert libpcap CAN captures to candump -l log lines",
    version,
    after_help = canboat_cli::help_footer()
)]
struct Cli {
    /// One or more pcap files. Output is to stdout.
    files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("pcap2candump: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    if cli.files.is_empty() {
        bail!("at least one pcap file is required");
    }
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for path in &cli.files {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        process_pcap(&bytes, &mut out).with_context(|| format!("processing {}", path.display()))?;
    }
    Ok(())
}

fn process_pcap<W: Write>(bytes: &[u8], out: &mut W) -> Result<()> {
    if bytes.len() < 24 {
        bail!("file too short to be a pcap (got {} bytes)", bytes.len());
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != PCAP_MAGIC_US {
        bail!("invalid pcap magic: 0x{magic:08x} (want 0xa1b2c3d4)");
    }
    let mut offset = 0x18;
    // Each CAN record is 16 (pcap rec hdr) + 8 (SocketCAN fixed) +
    // datalen (payload) = 24 + datalen bytes. The C++/Python tool
    // assumes that fixed shape.
    while offset + 24 <= bytes.len() {
        let ts_sec = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let canid = u32::from_be_bytes(bytes[offset + 16..offset + 20].try_into().unwrap());
        let datalen = bytes[offset + 20] as usize;
        let data_start = offset + 24;
        let data_end = data_start + datalen;
        if data_end > bytes.len() {
            // Truncated record — stop here, matching the Python's loop bounds.
            break;
        }
        write!(out, "({ts_sec}.{ts_usec:06}) slcan0 {canid:x}#")?;
        for b in &bytes[data_start..data_end] {
            write!(out, "{:02x}", b)?;
        }
        writeln!(out)?;
        offset = data_end;
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal one-record pcap in-memory and round-trip it.
    #[test]
    fn round_trips_one_record() {
        let mut buf = Vec::new();
        // Global header (24 bytes): magic + version + thiszone +
        // sigfigs + snaplen + network. Only magic matters for us.
        buf.extend_from_slice(&PCAP_MAGIC_US.to_le_bytes());
        buf.extend_from_slice(&[0u8; 20]);
        // Record header (16 bytes): ts_sec, ts_usec, incl_len, orig_len.
        buf.extend_from_slice(&1_502_984_881u32.to_le_bytes());
        buf.extend_from_slice(&664_500u32.to_le_bytes());
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&16u32.to_le_bytes());
        // CAN record: can_id BE, datalen, 3 pad, data.
        buf.extend_from_slice(&0x09F8027Fu32.to_be_bytes());
        buf.push(8); // datalen
        buf.extend_from_slice(&[0, 0, 0]); // pad
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);

        let mut out: Vec<u8> = Vec::new();
        process_pcap(&buf, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s.trim(),
            "(1502984881.664500) slcan0 9f8027f#aabbccddeeff1122"
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0xff; 24];
        let mut out = Vec::new();
        assert!(process_pcap(&buf, &mut out).is_err());
    }
}
