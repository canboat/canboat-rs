//! Fast-packet reassembly state machine (sans-I/O).
//!
//! NMEA 2000 fast-packet PGNs are split across up to 32 CAN frames.
//! The first byte of each frame's CAN payload is a header:
//!
//! ```text
//!   bits 7..5 : 3-bit sequence counter (rotates 0..7 per PGN/src)
//!   bits 4..0 : 5-bit frame index (0..31 within this sequence)
//! ```
//!
//! Frame 0 then carries one byte of total payload length and 6 bytes of
//! payload. Subsequent frames carry 7 bytes of payload each.
//!
//! The caller feeds raw CAN-sized frames (≤8 data bytes) along with
//! whether the PGN is fast-packet (looked up from the PGN database).
//! Single-frame PGNs and already-coalesced frames (`data.len() > 8`)
//! pass straight through.
//!
//! Slot eviction follows canboat: 64 slots, FIFO oldest-out on overflow.

use crate::frame::{RawFrame, FASTPACKET_MAX_SIZE};

const REASSEMBLY_BUFFER_SIZE: usize = 64;
const BUCKET_0_SIZE: usize = 6;
const BUCKET_N_SIZE: usize = 7;
const BUCKET_0_OFFSET: usize = 2;
const BUCKET_N_OFFSET: usize = 1;
const FASTPACKET_MAX_INDEX: u32 = 0x1f;

/// What the reassembler emitted in response to a `push` call.
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembled {
    /// PGN is not fast-packet, or the frame was already coalesced. The
    /// frame is returned unchanged.
    PassThrough(RawFrame),
    /// Fast-packet reassembly is complete; the coalesced payload is
    /// ready for decoding.
    Complete(RawFrame),
    /// More frames needed. The reassembler holds state internally.
    Partial,
    /// A protocol error was detected (sequence drift, missing frame 0,
    /// buffer overflow). The frame is dropped from the in-flight slot.
    Error(ReassemblyError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReassemblyError {
    #[error("fast-packet frame received with empty data")]
    EmptyData,
    #[error("duplicate frame index {frame} for pgn {pgn} src {src}")]
    DuplicateFrame { pgn: u32, src: u8, frame: u32 },
    #[error("no reassembly slot available; dropped pgn {pgn} src {src}")]
    OutOfSlots { pgn: u32, src: u8 },
}

/// Bare minimum slice of PGN-database state the reassembler needs.
/// Kept narrow so the reassembler doesn't link to the full database
/// and the caller can mock it freely in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramePacketType {
    /// Single-frame PGN — pass through unchanged.
    Single,
    /// Fast-packet PGN — reassemble across frames.
    Fast,
    /// Unknown PGN or anything else — pass through.
    Other,
}

#[derive(Debug, Clone)]
struct Slot {
    used: bool,
    pgn: u32,
    src: u8,
    seq: u8,
    /// Bitmask of frame indices received so far.
    frames: u32,
    /// Bitmask of frame indices required to complete.
    all_frames: u32,
    /// Total payload size from frame 0's length byte.
    size: usize,
    /// Sequence number in which the slot was claimed (monotonic). Used
    /// to evict the oldest slot when all slots are in use.
    age: u64,
    data: [u8; FASTPACKET_MAX_SIZE],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            used: false,
            pgn: 0,
            src: 0,
            seq: 0,
            frames: 0,
            all_frames: 0,
            size: 0,
            age: 0,
            data: [0u8; FASTPACKET_MAX_SIZE],
        }
    }
}

/// Fast-packet reassembler.
pub struct Reassembler {
    slots: Vec<Slot>,
    next_age: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            slots: vec![Slot::default(); REASSEMBLY_BUFFER_SIZE],
            next_age: 0,
        }
    }

    /// Push one CAN frame.
    ///
    /// `packet_type` should come from the PGN database. For unknown
    /// PGNs pass `FramePacketType::Other` — the frame will pass through
    /// untouched.
    pub fn push(&mut self, frame: RawFrame, packet_type: FramePacketType) -> Reassembled {
        // Coalesced payloads (len > 8) and non-fast-packet PGNs are
        // returned verbatim. This matches the C analyzer's gate.
        if frame.data.len() > 8 || packet_type != FramePacketType::Fast {
            return Reassembled::PassThrough(frame);
        }
        if frame.data.is_empty() {
            return Reassembled::Error(ReassemblyError::EmptyData);
        }

        let header = frame.data[0];
        let frame_index = (header & 0x1f) as u32;
        let seq = header & 0xe0;

        // Find an existing slot for (pgn, src, seq) — or claim a new one.
        let slot_idx = match self.find_slot(frame.pgn, frame.src, seq) {
            Some(i) => i,
            None => match self.claim_slot(frame.pgn, frame.src, seq) {
                Some(i) => i,
                None => {
                    return Reassembled::Error(ReassemblyError::OutOfSlots {
                        pgn: frame.pgn,
                        src: frame.src,
                    });
                }
            },
        };

        // Detect duplicate frame index within this sequence.
        if self.slots[slot_idx].frames & (1u32 << frame_index) != 0 {
            // Discard the existing partial assembly and start over.
            self.slots[slot_idx].frames = 0;
            self.slots[slot_idx].size = 0;
            return Reassembled::Error(ReassemblyError::DuplicateFrame {
                pgn: frame.pgn,
                src: frame.src,
                frame: frame_index,
            });
        }

        // Frame 0 carries the total payload size in data[1].
        if frame_index == 0 {
            let declared = frame.data.get(1).copied().unwrap_or(0) as usize;
            let size = declared.min(FASTPACKET_MAX_SIZE);
            self.slots[slot_idx].size = size;
            // canboat: number of frames needed = 1 + size/7 (integer
            // division). Frame 0 holds 6 bytes; each later frame holds
            // 7. The integer-truncated formula gives the right count
            // because frame 0's extra byte effectively borrows from the
            // first chunk of 7.
            let needed = (1 + size / BUCKET_N_SIZE).min((FASTPACKET_MAX_INDEX as usize) + 1);
            self.slots[slot_idx].all_frames = match needed {
                0 => 0,
                n if n >= 32 => u32::MAX,
                n => (1u32 << n) - 1,
            };
        }

        // Copy this frame's payload into the assembled buffer at the
        // correct offset. Missing trailing bytes are padded with 0xFF
        // to match what canboat does when a frame is truncated.
        let (dst_off, src_off, bucket_len) = if frame_index == 0 {
            (0usize, BUCKET_0_OFFSET, BUCKET_0_SIZE)
        } else {
            let idx = BUCKET_0_SIZE + (frame_index as usize - 1) * BUCKET_N_SIZE;
            (idx, BUCKET_N_OFFSET, BUCKET_N_SIZE)
        };

        let slot = &mut self.slots[slot_idx];
        // The bucket may run off the end of FASTPACKET_MAX_SIZE for
        // pathological inputs (frame index 31 on a small declared size).
        let end = (dst_off + bucket_len).min(FASTPACKET_MAX_SIZE);
        let bucket_capacity = end.saturating_sub(dst_off);

        let available = frame.data.len().saturating_sub(src_off);
        let copy_len = available.min(bucket_capacity);
        if copy_len > 0 {
            slot.data[dst_off..dst_off + copy_len]
                .copy_from_slice(&frame.data[src_off..src_off + copy_len]);
        }
        if copy_len < bucket_capacity {
            for byte in &mut slot.data[dst_off + copy_len..end] {
                *byte = 0xff;
            }
        }
        slot.frames |= 1u32 << frame_index;

        // Complete?
        if slot.all_frames != 0 && slot.frames == slot.all_frames {
            let size = slot.size;
            let mut data: smallvec::SmallVec<[u8; 8]> = smallvec::SmallVec::with_capacity(size);
            data.extend_from_slice(&slot.data[..size]);
            let reassembled = RawFrame {
                timestamp: frame.timestamp,
                prio: frame.prio,
                pgn: frame.pgn,
                src: frame.src,
                dst: frame.dst,
                data,
            };
            // Free the slot.
            slot.used = false;
            slot.frames = 0;
            slot.size = 0;
            return Reassembled::Complete(reassembled);
        }

        Reassembled::Partial
    }

    fn find_slot(&self, pgn: u32, src: u8, seq: u8) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.used && s.pgn == pgn && s.src == src && s.seq == seq)
    }

    fn claim_slot(&mut self, pgn: u32, src: u8, seq: u8) -> Option<usize> {
        // Prefer an unused slot.
        let free = self.slots.iter().position(|s| !s.used);
        let idx = match free {
            Some(i) => i,
            None => {
                // Evict the oldest in-use slot. (canboat just drops the
                // frame; we make best effort to keep going by reusing
                // the slot least-recently claimed.)
                self.slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.age)
                    .map(|(i, _)| i)?
            }
        };
        let age = self.next_age;
        self.next_age = self.next_age.wrapping_add(1);
        self.slots[idx] = Slot {
            used: true,
            pgn,
            src,
            seq,
            frames: 0,
            all_frames: 0,
            size: 0,
            age,
            data: [0u8; FASTPACKET_MAX_SIZE],
        };
        Some(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    fn frame(pgn: u32, src: u8, data: Vec<u8>) -> RawFrame {
        RawFrame {
            timestamp: None,
            prio: 3,
            pgn,
            src,
            dst: 255,
            data: data.into(),
        }
    }

    #[test]
    fn passes_through_single_frame_pgn() {
        let mut r = Reassembler::new();
        let f = frame(60928, 0, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        match r.push(f.clone(), FramePacketType::Single) {
            Reassembled::PassThrough(g) => assert_eq!(g, f),
            other => panic!("expected pass-through, got {other:?}"),
        }
    }

    #[test]
    fn passes_through_coalesced_payload() {
        let mut r = Reassembler::new();
        // Already-coalesced 14-byte payload: should pass through even
        // if the PGN is fast-packet.
        let f = frame(129029, 0, (0..14u8).collect());
        match r.push(f.clone(), FramePacketType::Fast) {
            Reassembled::PassThrough(g) => assert_eq!(g, f),
            other => panic!("expected pass-through, got {other:?}"),
        }
    }

    #[test]
    fn reassembles_two_frame_fast_packet() {
        let mut r = Reassembler::new();
        // Total payload 9 bytes: frame 0 carries 6, frame 1 carries 3.
        // Frame 0 header: seq=0, index=0 → 0x00; size byte = 9; then 6 payload bytes.
        let f0 = frame(129029, 0, vec![0x00, 9, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5]);
        match r.push(f0, FramePacketType::Fast) {
            Reassembled::Partial => (),
            other => panic!("expected partial, got {other:?}"),
        }
        // Frame 1 header: seq=0, index=1 → 0x01; then 7 payload bytes (last 4 padded FF).
        let f1 = frame(
            129029,
            0,
            vec![0x01, 0xa6, 0xa7, 0xa8, 0xff, 0xff, 0xff, 0xff],
        );
        let expected_payload: smallvec::SmallVec<[u8; 8]> =
            smallvec![0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
        match r.push(f1, FramePacketType::Fast) {
            Reassembled::Complete(g) => {
                assert_eq!(g.pgn, 129029);
                assert_eq!(g.data, expected_payload);
            }
            other => panic!("expected complete, got {other:?}"),
        }
    }

    #[test]
    fn separates_sequences_per_pgn_src_seq() {
        let mut r = Reassembler::new();
        // Two interleaved sequences with different seq numbers should
        // not corrupt each other.
        // Sequence A: seq=0x00
        let a0 = frame(129029, 0, vec![0x00, 7, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5]);
        // Sequence B: seq=0x20
        let b0 = frame(129029, 0, vec![0x20, 7, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5]);
        assert_eq!(r.push(a0, FramePacketType::Fast), Reassembled::Partial);
        assert_eq!(r.push(b0, FramePacketType::Fast), Reassembled::Partial);
        let a1 = frame(
            129029,
            0,
            vec![0x01, 0xa6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        let b1 = frame(
            129029,
            0,
            vec![0x21, 0xb6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        let a = match r.push(a1, FramePacketType::Fast) {
            Reassembled::Complete(g) => g,
            other => panic!("a: expected complete, got {other:?}"),
        };
        let b = match r.push(b1, FramePacketType::Fast) {
            Reassembled::Complete(g) => g,
            other => panic!("b: expected complete, got {other:?}"),
        };
        assert_eq!(&a.data[..], &[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6]);
        assert_eq!(&b.data[..], &[0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6]);
    }

    #[test]
    fn detects_duplicate_frame() {
        let mut r = Reassembler::new();
        let f0 = frame(129029, 0, vec![0x00, 14, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            r.push(f0.clone(), FramePacketType::Fast),
            Reassembled::Partial
        );
        // Same frame index again — should error and reset the slot.
        match r.push(f0, FramePacketType::Fast) {
            Reassembled::Error(ReassemblyError::DuplicateFrame { frame: 0, .. }) => (),
            other => panic!("expected duplicate-frame error, got {other:?}"),
        }
    }
}
