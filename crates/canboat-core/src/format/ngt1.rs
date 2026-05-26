//! Actisense NGT-1 binary protocol — sans-I/O byte framer.
//!
//! Frames on the wire look like:
//!
//! ```text
//!   DLE STX <cmd> <len> <payload...> <checksum> DLE ETX
//! ```
//!
//! Where:
//!   - DLE = 0x10, STX = 0x02, ETX = 0x03
//!   - Inside the framed region, every literal `DLE` is doubled
//!     (`DLE DLE`) so the receiver can unambiguously detect frame
//!     boundaries.
//!   - `len` is the unescaped payload length.
//!   - The 8-bit sum of cmd + len + payload + checksum is zero
//!     modulo 256.
//!
//! Commands we care about for v0:
//!   - `N2K_MSG_RECEIVED` (0x93) — an incoming N2K frame from the bus.
//!     The payload is:
//!     `prio(1) pgn(3, LE) dst(1) src(1) ts(4, LE ms) dlen(1) data(dlen)`.
//!
//! The framer emits [`NgtEvent`]s as soon as it finishes (or rejects)
//! a frame. It performs no I/O — the caller decides how bytes get fed
//! in (sync `Read::read`, tokio `AsyncReadExt::read_buf`, …).

use crate::frame::RawFrame;

const DLE: u8 = 0x10;
const STX: u8 = 0x02;
const ETX: u8 = 0x03;

/// Receive an N2K frame off the bus.
pub const N2K_MSG_RECEIVED: u8 = 0x93;
/// Send an N2K frame onto the bus.
pub const N2K_MSG_SEND: u8 = 0x94;
/// Receive an NGT-specific message.
pub const NGT_MSG_RECEIVED: u8 = 0xA0;
/// Send an NGT-specific message.
pub const NGT_MSG_SEND: u8 = 0xA1;

/// One fully-decoded NGT-1 protocol message (cmd + unescaped payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NgtMessage {
    pub command: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum NgtError {
    #[error("NGT message shorter than 3 bytes (cmd + len + checksum)")]
    ShortMessage,
    #[error("NGT checksum mismatch")]
    BadChecksum,
    #[error("NGT declared payload length {declared} does not match received {actual}")]
    LengthMismatch { declared: u8, actual: usize },
    #[error("NGT escape byte 0x{0:02x} not followed by STX/ETX/DLE")]
    BadEscape(u8),
}

/// Events emitted by [`Ngt1Decoder::push_byte`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NgtEvent {
    /// A complete NGT-1 message was decoded.
    Message(NgtMessage),
    /// The decoder rejected a frame (resync to next DLE STX).
    Error(NgtError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Outside any frame, looking for DLE.
    Idle,
    /// Saw DLE while idle — expecting STX to enter a frame.
    AwaitStx,
    /// Inside a frame, collecting bytes.
    InFrame,
    /// Saw DLE inside a frame; the next byte is either ETX (end of
    /// frame), DLE (escaped 0x10 literal), STX (resync to new frame),
    /// or something invalid.
    InEscape,
}

/// Streaming NGT-1 byte decoder. Feed bytes; pull events.
pub struct Ngt1Decoder {
    state: State,
    /// Accumulating frame payload (command + length + payload + checksum).
    buf: Vec<u8>,
}

impl Default for Ngt1Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ngt1Decoder {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            // Worst-case frame: 1 cmd + 1 len + 255 payload + 1 cksum.
            buf: Vec::with_capacity(258),
        }
    }

    /// Feed one byte. Returns `Some(event)` when a frame completes or
    /// fails; `None` while bytes are accumulating.
    pub fn push_byte(&mut self, b: u8) -> Option<NgtEvent> {
        match self.state {
            State::Idle => {
                if b == DLE {
                    self.state = State::AwaitStx;
                }
                None
            }
            State::AwaitStx => {
                match b {
                    STX => {
                        self.buf.clear();
                        self.state = State::InFrame;
                        None
                    }
                    DLE => {
                        // DLE DLE outside a frame — stay idle.
                        self.state = State::Idle;
                        None
                    }
                    _ => {
                        self.state = State::Idle;
                        None
                    }
                }
            }
            State::InFrame => {
                if b == DLE {
                    self.state = State::InEscape;
                } else {
                    self.buf.push(b);
                }
                None
            }
            State::InEscape => match b {
                ETX => self.finish_frame(),
                DLE => {
                    self.buf.push(DLE);
                    self.state = State::InFrame;
                    None
                }
                STX => {
                    // DLE STX inside a frame = resync to a new frame.
                    self.buf.clear();
                    self.state = State::InFrame;
                    None
                }
                other => {
                    self.state = State::Idle;
                    self.buf.clear();
                    Some(NgtEvent::Error(NgtError::BadEscape(other)))
                }
            },
        }
    }

    /// Convenience helper to feed a byte slice. Returns every event
    /// produced in order.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Vec<NgtEvent> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(ev) = self.push_byte(b) {
                out.push(ev);
            }
        }
        out
    }

    fn finish_frame(&mut self) -> Option<NgtEvent> {
        let raw = std::mem::take(&mut self.buf);
        self.state = State::Idle;
        if raw.len() < 3 {
            return Some(NgtEvent::Error(NgtError::ShortMessage));
        }
        let cksum: u8 = raw.iter().copied().fold(0u8, u8::wrapping_add);
        if cksum != 0 {
            return Some(NgtEvent::Error(NgtError::BadChecksum));
        }
        let command = raw[0];
        let declared = raw[1];
        let actual_payload_len = raw.len() - 3; // - cmd - len - checksum
        if declared as usize != actual_payload_len {
            return Some(NgtEvent::Error(NgtError::LengthMismatch {
                declared,
                actual: actual_payload_len,
            }));
        }
        let payload = raw[2..raw.len() - 1].to_vec();
        Some(NgtEvent::Message(NgtMessage { command, payload }))
    }
}

impl NgtMessage {
    /// Convert a `N2K_MSG_RECEIVED` (0x93) message into a [`RawFrame`].
    /// Other commands return `None` — they carry NGT-1-internal state,
    /// not N2K traffic.
    pub fn to_raw_frame(&self) -> Option<RawFrame> {
        if self.command != N2K_MSG_RECEIVED {
            return None;
        }
        // Header: prio(1) pgn(3 LE) dst(1) src(1) ts(4 LE) dlen(1)
        const HEADER: usize = 11;
        if self.payload.len() < HEADER {
            return None;
        }
        let prio = self.payload[0];
        let pgn = u32::from(self.payload[1])
            | (u32::from(self.payload[2]) << 8)
            | (u32::from(self.payload[3]) << 16);
        let dst = self.payload[4];
        let src = self.payload[5];
        // Bytes 6..10 = NGT-1 timestamp (ms since startup). We preserve
        // it as a string for downstream PLAIN/FAST emission.
        let ts_ms = u32::from(self.payload[6])
            | (u32::from(self.payload[7]) << 8)
            | (u32::from(self.payload[8]) << 16)
            | (u32::from(self.payload[9]) << 24);
        let dlen = self.payload[10] as usize;
        if HEADER + dlen > self.payload.len() {
            return None;
        }
        let data = self.payload[HEADER..HEADER + dlen]
            .iter()
            .copied()
            .collect::<smallvec::SmallVec<[u8; 8]>>();
        Some(RawFrame {
            timestamp: Some(ts_ms.to_string()),
            prio,
            pgn,
            src,
            dst,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid NGT-1 frame from command + payload, applying
    /// DLE-stuffing and computing the checksum.
    fn encode_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
        let mut inner = vec![cmd, payload.len() as u8];
        inner.extend_from_slice(payload);
        let cksum = inner.iter().copied().fold(0u8, u8::wrapping_add);
        inner.push(0u8.wrapping_sub(cksum));
        // Now DLE-stuff and wrap.
        let mut out = vec![DLE, STX];
        for b in &inner {
            out.push(*b);
            if *b == DLE {
                out.push(DLE);
            }
        }
        out.extend_from_slice(&[DLE, ETX]);
        out
    }

    #[test]
    fn decodes_a_simple_frame() {
        let frame = encode_frame(0x42, &[0x01, 0x02, 0x03]);
        let mut d = Ngt1Decoder::new();
        let events = d.push_bytes(&frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            NgtEvent::Message(m) => {
                assert_eq!(m.command, 0x42);
                assert_eq!(m.payload, vec![0x01, 0x02, 0x03]);
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn unescapes_dle_in_payload() {
        // Payload contains a literal DLE byte; it must be doubled on
        // the wire and surface as a single 0x10 in the decoded payload.
        let frame = encode_frame(0xA0, &[0xAA, DLE, 0xBB]);
        let mut d = Ngt1Decoder::new();
        let events = d.push_bytes(&frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            NgtEvent::Message(m) => assert_eq!(m.payload, vec![0xAA, DLE, 0xBB]),
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_checksum() {
        // Build a valid frame, then flip the checksum.
        let mut frame = encode_frame(0x42, &[0x01]);
        // Find the checksum byte (just before DLE ETX); flip a bit.
        let n = frame.len();
        frame[n - 3] = frame[n - 3].wrapping_add(1);
        let mut d = Ngt1Decoder::new();
        let events = d.push_bytes(&frame);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], NgtEvent::Error(NgtError::BadChecksum)));
    }

    #[test]
    fn split_across_pushes() {
        // Feed one byte at a time — must produce the same single event.
        let frame = encode_frame(0x42, &[0x01, 0x02]);
        let mut d = Ngt1Decoder::new();
        let mut total = Vec::new();
        for b in &frame {
            if let Some(ev) = d.push_byte(*b) {
                total.push(ev);
            }
        }
        assert_eq!(total.len(), 1);
        match &total[0] {
            NgtEvent::Message(m) => assert_eq!(m.command, 0x42),
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn ignores_garbage_before_frame() {
        // Pre- and post-amble noise must not trip the decoder.
        let mut bytes = vec![0xFF, 0xAA, 0x10, 0x99]; // bogus DLE-no-STX
        bytes.extend_from_slice(&encode_frame(0x42, &[0x01]));
        bytes.extend_from_slice(&[0x55, 0x66]);
        let mut d = Ngt1Decoder::new();
        let events = d.push_bytes(&bytes);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], NgtEvent::Message(_)));
    }

    #[test]
    fn n2k_msg_received_decodes_to_raw_frame() {
        // Header: prio=3, pgn=129025 (0x1F801), dst=0xFF, src=36,
        //         ts=0, dlen=8, data=[0xE6 .. 0xB3].
        let pgn = 129025u32;
        let mut payload = vec![
            3,                            // prio
            (pgn & 0xff) as u8,           // pgn LE
            ((pgn >> 8) & 0xff) as u8,
            ((pgn >> 16) & 0xff) as u8,
            0xff,                         // dst
            36,                           // src
            0, 0, 0, 0,                   // ts (4 bytes)
            8,                            // dlen
        ];
        payload.extend_from_slice(&[0xe6, 0xf1, 0x3a, 0x80, 0x9c, 0xc6, 0x0d, 0xb3]);
        let frame = encode_frame(N2K_MSG_RECEIVED, &payload);

        let mut d = Ngt1Decoder::new();
        let events = d.push_bytes(&frame);
        assert_eq!(events.len(), 1);
        let m = match &events[0] {
            NgtEvent::Message(m) => m,
            other => panic!("{other:?}"),
        };
        let raw = m.to_raw_frame().expect("convert");
        assert_eq!(raw.prio, 3);
        assert_eq!(raw.pgn, 129025);
        assert_eq!(raw.src, 36);
        assert_eq!(raw.dst, 0xff);
        assert_eq!(
            &raw.data[..],
            &[0xe6, 0xf1, 0x3a, 0x80, 0x9c, 0xc6, 0x0d, 0xb3]
        );
    }
}
