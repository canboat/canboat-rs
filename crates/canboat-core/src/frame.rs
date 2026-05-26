//! `RawFrame` — a CAN/N2K frame that has been read off a wire or line.
//!
//! A `RawFrame` may represent either a single 8-byte CAN frame, or an
//! already-coalesced fast-packet payload of up to 223 bytes. The `data`
//! field's length distinguishes the two. The reassembly state machine
//! in [`crate::reassembly`] turns a stream of single-frame `RawFrame`s
//! into coalesced `RawFrame`s for fast-packet PGNs.

use smallvec::SmallVec;

/// Maximum payload size of a coalesced fast-packet PGN.
///
/// Frame 0 carries 6 payload bytes, frames 1..31 carry 7 bytes each:
/// `6 + 31 * 7 = 223`.
pub const FASTPACKET_MAX_SIZE: usize = 223;

/// A CAN/N2K frame.
///
/// Single-frame: `data.len() <= 8`. Coalesced fast-packet:
/// `data.len() <= FASTPACKET_MAX_SIZE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    /// Free-form timestamp string as captured on the input line (or `None`
    /// if the source did not carry one). Preserved verbatim so emitted
    /// output round-trips.
    pub timestamp: Option<String>,
    pub prio: u8,
    pub pgn: u32,
    pub src: u8,
    pub dst: u8,
    pub data: SmallVec<[u8; 8]>,
}

impl RawFrame {
    /// Construct a frame with the given header and payload. Does no
    /// validation beyond capping `data` at `FASTPACKET_MAX_SIZE`.
    pub fn new(
        timestamp: Option<String>,
        prio: u8,
        pgn: u32,
        src: u8,
        dst: u8,
        data: impl IntoIterator<Item = u8>,
    ) -> Self {
        let mut payload: SmallVec<[u8; 8]> = data.into_iter().collect();
        if payload.len() > FASTPACKET_MAX_SIZE {
            payload.truncate(FASTPACKET_MAX_SIZE);
        }
        Self {
            timestamp,
            prio,
            pgn,
            src,
            dst,
            data: payload,
        }
    }
}
