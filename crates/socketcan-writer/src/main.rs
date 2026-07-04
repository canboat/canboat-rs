// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `socketcan-writer`: read canboat PLAIN/FAST lines from stdin and
//! emit them as 29-bit CAN frames on a Linux SocketCAN interface
//! (or to stdout for testing). Mirrors
//! `canboat/socketcan-writer/socketcan-writer.c`.
//!
//! Single-frame PGNs (≤ 8 payload bytes) go out as one CAN frame;
//! longer payloads are split into NMEA 2000 fast-packet sequences
//! (frame 0 carries 6 payload bytes + a size byte; subsequent frames
//! carry 7 each). The CAN identifier is rebuilt from the PLAIN
//! line's (prio, pgn, src, dst) via the same bit-layout canboat C
//! uses in `getCanIdFromISO11783Bits`. The extended-frame flag
//! (`CAN_EFF_FLAG`, bit 31) is always set — NMEA 2000 only uses
//! 29-bit IDs.
//!
//! Outputs `linux/can/raw` `struct can_frame` (16 bytes: 4-byte
//! `can_id` + 1-byte `can_dlc` + 3 pad + 8 data) when writing to
//! stdout, so a downstream `cat | socketcan-writer can0` chain works.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

use canboat_core::format::parse_plain;
use canboat_core::frame::RawFrame;

/// `CAN_EFF_FLAG` from `linux/can.h`.
const CAN_EFF_FLAG: u32 = 0x8000_0000;
/// Synthetic-PGN range — never send these to the bus.
const CANBOAT_PGN_START: u32 = 0x40000;

#[derive(Debug, Parser)]
#[command(
    name = "socketcan-writer",
    about = "Forward canboat PLAIN/FAST stdin to a Linux SocketCAN device",
    version,
    after_help = canboat_cli::COPYRIGHT_ID
)]
struct Cli {
    /// Target device. Use `-` or `stdout` to write the raw 16-byte
    /// `can_frame` records to stdout instead of opening a SocketCAN
    /// interface — useful for offline pipelines.
    device: String,

    /// Honour the captured timestamps and pace each frame
    /// accordingly (similar to `replay`). Off by default to match
    /// canboat C, which only sleeps when frames are far apart.
    #[arg(long)]
    pace: bool,

    /// Verbose / debug logging — alias of `-d`. Matches canboat's
    /// C tool.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Quiet — only show errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("socketcan-writer: {e:#}");
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
    log::info!("{}", canboat_cli::COPYRIGHT_ID);

    let mut sink: Box<dyn FrameSink> = if cli.device == "-" || cli.device == "stdout" {
        Box::new(StdoutSink::new())
    } else {
        open_socketcan(&cli.device)?
    };

    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::with_capacity(2048);
    let mut prev_ts: Option<Instant> = None;
    let mut prev_wire_ms: Option<i64> = None;

    loop {
        line.clear();
        match lock.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(e).context("reading stdin"),
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let frame = match parse_plain(trimmed) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("skipping malformed line: {e}");
                continue;
            }
        };
        if frame.pgn >= CANBOAT_PGN_START {
            log::debug!("skipping synthetic PGN {}", frame.pgn);
            continue;
        }
        if cli.pace
            && let Some(now_ms) = frame.timestamp.as_deref().and_then(parse_iso_timestamp_ms)
        {
            if let (Some(prev_ms), Some(prev_inst)) = (prev_wire_ms, prev_ts) {
                let delta = now_ms - prev_ms;
                if (0..10_000).contains(&delta) {
                    let elapsed = prev_inst.elapsed();
                    let want = Duration::from_millis(delta as u64);
                    if want > elapsed {
                        std::thread::sleep(want - elapsed);
                    }
                }
            }
            prev_wire_ms = Some(now_ms);
            prev_ts = Some(Instant::now());
        }
        send_pgn(sink.as_mut(), &frame)?;
    }
    Ok(())
}

/// Build the 29-bit ISO 11783 CAN identifier from the PLAIN line's
/// (prio, pgn, src, dst). Mirrors `getCanIdFromISO11783Bits` in
/// canboat/common/common.c, including the `CAN_EFF_FLAG` high bit
/// (NMEA 2000 always uses extended frames).
fn build_canid(prio: u8, pgn: u32, src: u8, dst: u8) -> u32 {
    let mut can_id = (src as u32) | CAN_EFF_FLAG;
    let pf = (pgn >> 8) & 0xff;
    if pf < 240 {
        // PDU1: PS holds the destination address.
        can_id |= (dst as u32) << 8;
        can_id |= pgn << 8;
    } else {
        // PDU2: PS is part of the PGN itself.
        can_id |= pgn << 8;
    }
    can_id |= (prio as u32) << 26;
    can_id
}

/// Send one decoded PGN — splitting longer payloads into a sequence
/// of N2K fast-packet frames if needed.
fn send_pgn(sink: &mut dyn FrameSink, msg: &RawFrame) -> Result<()> {
    // PGNs can't exceed 18 bits; we'd overwrite priority otherwise.
    if msg.pgn >= (1 << 18) {
        log::warn!("invalid PGN {:#x} (>18 bits), skipping", msg.pgn);
        return Ok(());
    }
    let can_id = build_canid(msg.prio, msg.pgn, msg.src, msg.dst);
    if msg.data.len() <= 8 {
        let mut data = [0u8; 8];
        data[..msg.data.len()].copy_from_slice(&msg.data);
        return sink.write(can_id, msg.data.len() as u8, &data);
    }
    // Fast-packet: frame 0 has the size byte then 6 payload bytes;
    // each subsequent frame carries 7 more (the last one may be
    // short).
    let total = msg.data.len();
    let mut index: u8 = 0;
    let mut taken = 0usize;
    while taken < total {
        let mut data = [0u8; 8];
        data[0] = index;
        if index == 0 {
            data[1] = total as u8;
            let chunk = (total - taken).min(6);
            data[2..2 + chunk].copy_from_slice(&msg.data[taken..taken + chunk]);
            taken += chunk;
            sink.write(can_id, 8, &data)?;
        } else {
            let chunk = (total - taken).min(7);
            data[1..1 + chunk].copy_from_slice(&msg.data[taken..taken + chunk]);
            taken += chunk;
            sink.write(can_id, (1 + chunk) as u8, &data)?;
        }
        index = index.wrapping_add(1);
    }
    Ok(())
}

/// Tiny abstraction over the platform-specific CAN sink. Carries
/// the `can_id`, length code, and 8 data bytes — wider than the C
/// `can_frame` shape but matches what `socketcan` wants.
trait FrameSink {
    fn write(&mut self, can_id: u32, dlc: u8, data: &[u8; 8]) -> Result<()>;
}

/// Writes raw 16-byte `can_frame` records to stdout. Identical
/// byte layout to `<linux/can.h>::can_frame`.
struct StdoutSink {
    out: io::BufWriter<io::Stdout>,
}

impl StdoutSink {
    fn new() -> Self {
        Self {
            out: io::BufWriter::new(io::stdout()),
        }
    }
}

impl FrameSink for StdoutSink {
    fn write(&mut self, can_id: u32, dlc: u8, data: &[u8; 8]) -> Result<()> {
        // Layout: u32 can_id (native-endian) | u8 dlc | u8 __pad |
        // u8 __res0 | u8 __res1 | [u8; 8] data.
        self.out.write_all(&can_id.to_ne_bytes())?;
        self.out.write_all(&[dlc, 0, 0, 0])?;
        self.out.write_all(data)?;
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn open_socketcan(name: &str) -> Result<Box<dyn FrameSink>> {
    use socketcan::{CanSocket, EmbeddedFrame, ExtendedId, Socket, StandardId};
    let sock = CanSocket::open(name).with_context(|| format!("opening SocketCAN {name}"))?;
    struct LinuxSink {
        sock: CanSocket,
    }
    impl FrameSink for LinuxSink {
        fn write(&mut self, can_id: u32, dlc: u8, data: &[u8; 8]) -> Result<()> {
            let id = ExtendedId::new(can_id & 0x1FFF_FFFF)
                .map(socketcan::Id::Extended)
                .or_else(|| StandardId::new((can_id & 0x7FF) as u16).map(socketcan::Id::Standard))
                .context("encoding CAN id")?;
            let frame = socketcan::CanFrame::new(id, &data[..dlc as usize])
                .context("building CAN frame")?;
            self.sock.write_frame(&frame).context("write_frame")?;
            Ok(())
        }
    }
    Ok(Box::new(LinuxSink { sock }))
}

#[cfg(not(target_os = "linux"))]
fn open_socketcan(_name: &str) -> Result<Box<dyn FrameSink>> {
    anyhow::bail!(
        "SocketCAN is Linux-only; use `-` or `stdout` to emit raw can_frame bytes on this platform"
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.,]mmm` into Unix-epoch ms. Used only
/// by `--pace`; on a bad timestamp we fall back to no pacing.
fn parse_iso_timestamp_ms(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let take = |range: std::ops::Range<usize>| std::str::from_utf8(&bytes[range]).ok();
    let y: i64 = take(0..4)?.parse().ok()?;
    let mo: u32 = take(5..7)?.parse().ok()?;
    let d: u32 = take(8..10)?.parse().ok()?;
    let h: u32 = take(11..13)?.parse().ok()?;
    let m: u32 = take(14..16)?.parse().ok()?;
    let sec: u32 = take(17..19)?.parse().ok()?;
    let mut ms: i64 = 0;
    if bytes.len() >= 23
        && (bytes[19] == b'.' || bytes[19] == b',')
        && let Some(v) = take(20..23).and_then(|s| s.parse::<i64>().ok())
    {
        ms = v;
    }
    let days = days_since_epoch(y, mo as i64, d as i64)?;
    let secs = days * 86_400 + (h as i64) * 3600 + (m as i64) * 60 + sec as i64;
    Some(secs * 1000 + ms)
}

fn days_since_epoch(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe as i64 * 365 + (yoe as i64 / 4) - (yoe as i64 / 100) + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canid_for_pdu1_carries_dst() {
        // PGN 60928 (PDU1, PF=0xee), prio=6, src=0x07, dst=0xff.
        let id = build_canid(6, 60928, 0x07, 0xff);
        // CAN_EFF_FLAG | (prio << 26) | (pgn << 8) | (dst << 8) | src
        let want = CAN_EFF_FLAG | (6u32 << 26) | (60928u32 << 8) | (0xffu32 << 8) | 0x07;
        assert_eq!(id, want);
    }

    #[test]
    fn canid_for_pdu2_drops_dst() {
        // PGN 0xff18 (PF=0xff ≥ 240 → PDU2), prio=7, src=0x0d.
        let id = build_canid(7, 0xff18, 0x0d, 0xff);
        let want = CAN_EFF_FLAG | (7u32 << 26) | (0xff18u32 << 8) | 0x0d;
        assert_eq!(id, want);
    }

    #[test]
    fn single_frame_send() {
        struct Cap(Vec<(u32, u8, [u8; 8])>);
        impl FrameSink for Cap {
            fn write(&mut self, can_id: u32, dlc: u8, data: &[u8; 8]) -> Result<()> {
                self.0.push((can_id, dlc, *data));
                Ok(())
            }
        }
        let mut cap = Cap(Vec::new());
        let msg = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 7,
            dst: 255,
            data: smallvec::smallvec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        send_pgn(&mut cap, &msg).unwrap();
        assert_eq!(cap.0.len(), 1);
        assert_eq!(cap.0[0].1, 8);
        assert_eq!(&cap.0[0].2[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn fast_packet_split() {
        // 14-byte payload → frame 0 carries 6 bytes after size; frame 1
        // carries the remaining 8 bytes (dlc=1+7=8 actually no — 7+1
        // header byte, so the second frame holds 7 payload bytes,
        // leaving 14-6-7=1 byte for frame 2).
        struct Cap(Vec<(u8, u8, [u8; 8])>);
        impl FrameSink for Cap {
            fn write(&mut self, _can_id: u32, dlc: u8, data: &[u8; 8]) -> Result<()> {
                self.0.push((data[0], dlc, *data));
                Ok(())
            }
        }
        let mut cap = Cap(Vec::new());
        let payload: Vec<u8> = (0..14).collect();
        let msg = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 7,
            dst: 255,
            data: smallvec::SmallVec::from_vec(payload),
        };
        send_pgn(&mut cap, &msg).unwrap();
        // Expect frame 0 (index=0, size=14, +6 bytes), frame 1 (index=1, +7), frame 2 (index=2, +1).
        assert_eq!(cap.0.len(), 3);
        assert_eq!(cap.0[0].0, 0); // index 0
        assert_eq!(cap.0[0].2[1], 14); // total size
        assert_eq!(cap.0[1].0, 1); // index 1
        assert_eq!(cap.0[1].1, 8); // dlc full
        assert_eq!(cap.0[2].0, 2); // index 2
        assert_eq!(cap.0[2].1, 2); // dlc = 1 header + 1 payload
    }
}
