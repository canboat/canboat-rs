// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Library form of the analyzer's input → decode pipeline.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

use canboat_core::format::InputFormat;
use canboat_core::{
    CANBOAT_BEM, DecodedPgn, FramePacketType, PacketType, PgnDatabase, Reassembled, Reassembler,
};
use canboat_io::{FrameReader, LineFrameReader};

/// Per-call options for [`decode_stream`] / [`decode_file`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Config {
    /// Force a specific input format instead of auto-detecting from
    /// the first content line. Equivalent to the `--format` flag on
    /// the analyzer binary.
    pub forced_format: Option<InputFormat>,
    /// When set, drop frames whose PGN doesn't match (analyzer's
    /// positional `[PGN]` filter).
    pub pgn_filter: Option<u32>,
    /// When set, drop frames whose src doesn't match (analyzer's
    /// `--src` filter).
    pub src_filter: Option<u8>,
    /// When set, drop frames whose dst doesn't match (analyzer's
    /// `--dst` filter).
    pub dst_filter: Option<u8>,
    /// Drop the producer's `CANBOAT_BEM` startup record (`PGN
    /// 0x40010`). Set this when running under `--fixtime` so the
    /// producer's build version doesn't leak into version-agnostic
    /// output.
    pub suppress_startup_record: bool,
}

/// Open `path` and stream-decode it via [`decode_stream`]. Errors
/// from the parse / reassembly / decode steps are logged via the
/// `log` crate (matching the analyzer binary's behaviour) and the
/// stream continues; only a hard read error stops the loop.
pub fn decode_file<F: FnMut(&DecodedPgn)>(path: &Path, cfg: &Config, sink: F) -> Result<()> {
    // Binary capture containers (`.pcap`, `.pcap.gz`, `.nif`) are
    // unwrapped into PLAIN text on the fly, then fed through the same
    // line pipeline as any other input.
    if canboat_io::container::is_container(path) {
        let reader = canboat_io::container::plain_reader(path, Default::default())
            .with_context(|| format!("opening {}", path.display()))?;
        return decode_stream(reader, cfg, sink);
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    decode_stream(BufReader::new(file), cfg, sink)
}

/// Drive the analyzer pipeline over `source`. For each decoded
/// record, invoke `sink` with the resulting [`DecodedPgn`]. The
/// `DecodedPgn` borrows static schema data so callers can pass it
/// straight to `canboat_core::output::{write_json, write_text}`
/// without re-decoding.
///
/// The line parsing / format detection is delegated to
/// [`LineFrameReader`]; this function owns only the analyzer-specific
/// back half: filtering, fast-packet/TP reassembly, and schema decode.
pub fn decode_stream<R: BufRead, F: FnMut(&DecodedPgn)>(
    source: R,
    cfg: &Config,
    mut sink: F,
) -> Result<()> {
    let db = PgnDatabase::embedded();
    let mut reader = match cfg.forced_format {
        Some(fmt) => LineFrameReader::with_format(source, fmt),
        None => LineFrameReader::new(source),
    };
    // canboat's PLAIN_OR_FAST mode locks into "coalesced" once any
    // line carries more than 8 payload bytes — from then on every
    // frame is assumed to be pre-assembled and the reassembler is
    // skipped. Mirror the analyzer binary 1:1.
    let mut coalesced_mode = false;
    let mut reasm = Reassembler::new();

    while let Some(frame) = reader.read_frame().context("reading input line")? {
        // A `# format=<NAME>` header (consumed inside `read_frame`)
        // may have declared an already-coalesced format.
        coalesced_mode |= reader.header_coalesced();

        if cfg.suppress_startup_record && frame.pgn == CANBOAT_BEM {
            continue;
        }
        if let Some(want) = cfg.pgn_filter
            && frame.pgn != want
        {
            continue;
        }
        if let Some(want) = cfg.src_filter
            && frame.src != want
        {
            continue;
        }
        if let Some(want) = cfg.dst_filter
            && frame.dst != want
        {
            continue;
        }

        // Once any line carries > 8 payload bytes, assume FAST is
        // pre-coalesced and skip reassembly for the remainder of the
        // stream. PlainMixFast intentionally interleaves so opt out.
        if frame.data.len() > 8 && reader.active_format() != Some(InputFormat::PlainMixFast) {
            coalesced_mode = true;
        }
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
        sink(&decoded);
    }
    Ok(())
}
