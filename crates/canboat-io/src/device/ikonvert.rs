//! Digital Yacht iKonvert codec adapter for [`super::run`].
//!
//! Wraps [`canboat_core::format::ikonvert`]. iKonvert is line-based
//! ASCII (`$PDGY,...` control sentences and `!PDGY,...` frame
//! sentences). The decoder buffers a partial line across reads, so
//! the partial-frame state lives in [`Decoder`].
//!
//! The init handshake is `N2NET_OFFLINE` → optional RX/TX filter
//! lists → `N2NET_INIT,ALL` (or `,NORMAL` when filters were set) →
//! optional `TX_LIMIT,OFF`. It's fire-and-forget; the ACK-driven
//! state machine the canboat C tool runs is not modelled here (it
//! works in practice for read+write without it).

use std::io::{Read, Write};

use canboat_core::format::ikonvert::{
    self, IkonvertLine, TX_LIMIT_OFF, TX_OFFLINE, TX_ONLINE_ALL, TX_ONLINE_NORMAL,
};
use canboat_core::RawFrame;

use super::{DeviceDecoder, DeviceEncoder, DeviceEvent, DeviceHandle};

/// Synthetic-PGN marker. iKonvert silently drops `>= 0x40000` PGNs
/// the same way actisense-serial does.
pub const IKONVERT_SYNTHETIC_PGN: u32 = 0x40000;

/// iKonvert initialisation parameters. All fields are optional —
/// `Config::default()` brings the bus online in `ALL` mode with no
/// rate-limit override.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Comma-separated PGN filter for receive. If set, init enters
    /// `NORMAL` mode instead of `ALL`.
    pub rx_list: Option<String>,
    /// Comma-separated PGN filter for transmit.
    pub tx_list: Option<String>,
    /// Disable the iKonvert TX rate limit. Off by default.
    pub rate_limit_off: bool,
}

/// Start the iKonvert reader/writer threads.
pub fn run(
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    config: Config,
) -> DeviceHandle {
    super::run(Decoder::new(), Encoder { config }, reader, writer)
}

/// Decoder buffers a partial line across reads.
pub struct Decoder {
    acc: String,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            acc: String::with_capacity(1024),
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceDecoder for Decoder {
    fn decode(&mut self, bytes: &[u8], events: &mut Vec<DeviceEvent>) {
        self.acc.push_str(&String::from_utf8_lossy(bytes));
        while let Some(eol) = self.acc.find('\n') {
            // `drain` to keep the buffer single-allocation.
            let line: String = self.acc.drain(..=eol).collect();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                continue;
            }
            match ikonvert::parse_line(trimmed) {
                Ok(IkonvertLine::Frame(f)) => events.push(DeviceEvent::Frame(f)),
                Ok(IkonvertLine::Control(c)) => log::debug!("ikonvert control: {c}"),
                Ok(IkonvertLine::Other) => {}
                Err(e) => events.push(DeviceEvent::Error(format!("ikonvert: {e}"))),
            }
        }
    }
}

pub struct Encoder {
    config: Config,
}

impl DeviceEncoder for Encoder {
    fn init_bytes(&self) -> Vec<u8> {
        let mut init = String::new();
        init.push_str(TX_OFFLINE);
        if let Some(list) = self.config.rx_list.as_deref() {
            init.push_str("$PDGY,RX_LIST,");
            init.push_str(list);
            init.push_str("\r\n");
        }
        if let Some(list) = self.config.tx_list.as_deref() {
            init.push_str("$PDGY,TX_LIST,");
            init.push_str(list);
            init.push_str("\r\n");
        }
        if self.config.rx_list.is_some() || self.config.tx_list.is_some() {
            init.push_str(TX_ONLINE_NORMAL);
        } else {
            init.push_str(TX_ONLINE_ALL);
        }
        if self.config.rate_limit_off {
            init.push_str(TX_LIMIT_OFF);
        }
        init.into_bytes()
    }

    fn encode_frame(&self, frame: &RawFrame) -> Option<Vec<u8>> {
        if frame.pgn >= IKONVERT_SYNTHETIC_PGN {
            log::debug!("ikonvert: skipping synthetic PGN {}", frame.pgn);
            return None;
        }
        Some(ikonvert::encode_tx_frame(frame).into_bytes())
    }
}
