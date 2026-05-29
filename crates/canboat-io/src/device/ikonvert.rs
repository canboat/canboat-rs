//! Digital Yacht iKonvert codec adapter for [`super::run`].
//!
//! Wraps [`canboat_core::format::ikonvert`]. iKonvert is line-based
//! ASCII (`$PDGY,...` control sentences and `!PDGY,...` frame
//! sentences). The decoder buffers a partial line across reads, so
//! the partial-frame state lives in [`Decoder`].
//!
//! Init handshake — mirrors `canboat/ikonvert-serial/ikonvert-serial.c`
//! exactly, because the iKonvert ignores commands that arrive while
//! it's still processing the previous one. The boot sequence is
//! **ACK-driven**: every command is followed by a `$PDGY,ACK,...`
//! confirmation, and the next command may only be written once the
//! previous one is acknowledged. Anything blasted as a single chunk
//! puts the device in a state where it stops emitting frames.
//!
//! Step-by-step (per canboat C `sendNextInitCommand`):
//!
//!   1. `$PDGY,N2NET_OFFLINE`         → wait ACK
//!   2. `$PDGY,N2NET_RESET`           → wait ACK   (only if rx/tx list set)
//!   3. `$PDGY,RX_LIST,<pgns>`        → wait ACK   (only if rx list set)
//!   4. `$PDGY,TX_LIST,<pgns>`        → wait ACK   (only if tx list set)
//!   5. `$PDGY,N2NET_INIT,{ALL|NORMAL}` → wait ACK
//!   6. `$PDGY,TX_LIMIT,OFF`          (no ACK)     (only if `rate_limit_off`)
//!
//! [`Encoder::init_bytes`] writes only step 1; the rest flow back
//! via [`super::DeviceEvent::SendBytes`] each time the decoder sees
//! an ACK.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

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
    /// `NORMAL` mode instead of `ALL` and the `N2NET_RESET` /
    /// `RX_LIST` steps run.
    pub rx_list: Option<String>,
    /// Comma-separated PGN filter for transmit. Triggers the
    /// `N2NET_RESET` / `TX_LIST` steps.
    pub tx_list: Option<String>,
    /// Disable the iKonvert TX rate limit. Off by default.
    pub rate_limit_off: bool,
    /// Skip the init handshake entirely. Useful when the "writer
    /// side" is `/dev/null` (replay-from-file mode), since there's
    /// no device on the other end to ACK the commands.
    pub skip_init: bool,
}

impl Config {
    fn has_lists(&self) -> bool {
        self.rx_list.is_some() || self.tx_list.is_some()
    }

    /// Replay-friendly variant: no init, no keepalive. The codec
    /// just decodes whatever bytes arrive on the read side.
    pub fn skip_init() -> Self {
        Self {
            skip_init: true,
            ..Self::default()
        }
    }
}

/// Start the iKonvert reader/writer threads.
pub fn run(
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    config: Config,
) -> DeviceHandle {
    let skip_init = config.skip_init;
    super::run(Decoder::new(config), Encoder { skip_init }, reader, writer)
}

/// Decoder buffers a partial line across reads and owns the
/// ACK-driven init state machine.
pub struct Decoder {
    acc: String,
    config: Config,
    /// Sequence counter that mirrors C's `sendInitState`. Even values
    /// are "ready to send the next command"; odd values are "waiting
    /// for the ACK of the command we just sent". `0` means init is
    /// complete.
    init_state: Arc<Mutex<u32>>,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        let start = if config.skip_init {
            STATE_DONE
        } else {
            // After `init_bytes()` sends `N2NET_OFFLINE`, the writer
            // thread is waiting for that ACK — start at the
            // corresponding odd state.
            STATE_WAIT_OFFLINE_ACK
        };
        Self {
            acc: String::with_capacity(1024),
            config,
            init_state: Arc::new(Mutex::new(start)),
        }
    }
}

impl DeviceDecoder for Decoder {
    fn decode(&mut self, bytes: &[u8], events: &mut Vec<DeviceEvent>) {
        self.acc.push_str(&String::from_utf8_lossy(bytes));
        while let Some(eol) = self.acc.find('\n') {
            let line: String = self.acc.drain(..=eol).collect();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                continue;
            }
            match ikonvert::parse_line(trimmed) {
                Ok(IkonvertLine::Frame(f)) => events.push(DeviceEvent::Frame(f)),
                Ok(IkonvertLine::Control(c)) => self.handle_control(&c, events),
                Ok(IkonvertLine::Other) => {}
                Err(e) => events.push(DeviceEvent::Error(format!("ikonvert: {e}"))),
            }
        }
    }
}

impl Decoder {
    fn handle_control(&self, body: &str, events: &mut Vec<DeviceEvent>) {
        // `body` is everything after the `$PDGY,` prefix. The C tool
        // dispatches on the head before the first comma — so do we.
        if let Some(rest) = body.strip_prefix("ACK,") {
            log::debug!("ikonvert: ACK ({rest})");
            self.advance_after_ack(events);
            return;
        }
        if let Some(rest) = body.strip_prefix("NAK,") {
            log::warn!("ikonvert: NAK ({rest})");
            // Stay at the current state — canboat C does the same;
            // a typical NAK is "already offline" which is harmless.
            return;
        }
        log::debug!("ikonvert control: {body}");
    }

    fn advance_after_ack(&self, events: &mut Vec<DeviceEvent>) {
        let mut state = self.init_state.lock().expect("ikonvert state poisoned");
        if *state == 0 || *state % 2 == 0 {
            // Either init is complete or the ACK is unsolicited.
            return;
        }
        *state -= 1;
        if let Some(cmd) = next_init_command(&mut state, &self.config) {
            events.push(DeviceEvent::SendBytes(cmd.into_bytes()));
        } else {
            log::info!("ikonvert: initialization complete");
        }
    }
}

pub struct Encoder {
    skip_init: bool,
}

impl DeviceEncoder for Encoder {
    fn init_bytes(&self) -> Vec<u8> {
        if self.skip_init {
            return Vec::new();
        }
        // Only the first command goes out unsolicited. Everything
        // else is gated on the corresponding ACK arriving back from
        // the device.
        log::info!("ikonvert: initialization start");
        TX_OFFLINE.as_bytes().to_vec()
    }

    fn encode_frame(&self, frame: &RawFrame) -> Option<Vec<u8>> {
        if frame.pgn >= IKONVERT_SYNTHETIC_PGN {
            log::debug!("ikonvert: skipping synthetic PGN {}", frame.pgn);
            return None;
        }
        Some(ikonvert::encode_tx_frame(frame).into_bytes())
    }
}

// State values mirror C's `sendInitState`. Even = "ready to evaluate
// case N and possibly emit". Odd = "waiting for the ACK that follows
// the command emitted at state N+1".
const STATE_DONE: u32 = 0;
const STATE_MAYBE_LIMIT_OFF: u32 = 2;
const STATE_WAIT_INIT_ACK: u32 = 3;
const STATE_SEND_INIT: u32 = 4;
const STATE_MAYBE_SHOWLISTS: u32 = 6;
const STATE_MAYBE_TX_LIST: u32 = 8;
const STATE_WAIT_TX_LIST_ACK: u32 = 7;
const STATE_MAYBE_RX_LIST: u32 = 10;
const STATE_WAIT_RX_LIST_ACK: u32 = 9;
const STATE_MAYBE_RESET: u32 = 12;
const STATE_WAIT_RESET_ACK: u32 = 11;
const STATE_WAIT_OFFLINE_ACK: u32 = 13;

/// Drive the state machine forward starting from an *even* state.
/// Returns the bytes of whatever command should go on the wire next,
/// or `None` when init is complete.
fn next_init_command(state: &mut u32, config: &Config) -> Option<String> {
    loop {
        match *state {
            STATE_MAYBE_RESET => {
                // Step 2 — only when the user has supplied filter lists.
                if config.has_lists() {
                    *state = STATE_WAIT_RESET_ACK;
                    log::info!("ikonvert: send N2NET_RESET");
                    return Some("$PDGY,N2NET_RESET\r\n".to_string());
                }
                *state = STATE_MAYBE_RX_LIST;
                // fall through
            }
            STATE_MAYBE_RX_LIST => {
                if let Some(list) = &config.rx_list {
                    *state = STATE_WAIT_RX_LIST_ACK;
                    log::info!("ikonvert: send RX_LIST {list}");
                    return Some(format!("$PDGY,RX_LIST,{list}\r\n"));
                }
                *state = STATE_MAYBE_TX_LIST;
            }
            STATE_MAYBE_TX_LIST => {
                if let Some(list) = &config.tx_list {
                    *state = STATE_WAIT_TX_LIST_ACK;
                    log::info!("ikonvert: send TX_LIST {list}");
                    return Some(format!("$PDGY,TX_LIST,{list}\r\n"));
                }
                *state = STATE_MAYBE_SHOWLISTS;
            }
            STATE_MAYBE_SHOWLISTS => {
                // C only emits SHOW_LISTS in verbose / log-debug mode;
                // we skip it unconditionally — no functional effect.
                *state = STATE_SEND_INIT;
            }
            STATE_SEND_INIT => {
                *state = STATE_WAIT_INIT_ACK;
                let cmd = if config.rx_list.is_some() {
                    TX_ONLINE_NORMAL
                } else {
                    TX_ONLINE_ALL
                };
                log::info!("ikonvert: send N2NET_INIT");
                return Some(cmd.to_string());
            }
            STATE_MAYBE_LIMIT_OFF => {
                // TX_LIMIT,OFF has no ACK; we move straight to DONE.
                let cmd = if config.rate_limit_off {
                    log::info!("ikonvert: send TX_LIMIT,OFF");
                    Some(TX_LIMIT_OFF.to_string())
                } else {
                    None
                };
                *state = STATE_DONE;
                return cmd;
            }
            STATE_DONE => return None,
            // Odd states: caller drove us into "waiting for ACK"
            // territory without an ACK arriving — bail.
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk the state machine the way an iKonvert would: send the
    /// first command via `init_bytes`, then feed each ACK back as the
    /// "next event" and collect the resulting commands.
    fn run_init(config: Config) -> Vec<String> {
        let encoder = Encoder { skip_init: false };
        let first = String::from_utf8(encoder.init_bytes()).unwrap();
        let mut commands = vec![first];

        let decoder = Decoder::new(config);
        loop {
            let mut events = Vec::new();
            decoder.handle_control("ACK,test", &mut events);
            let mut emitted_one = false;
            for ev in events {
                if let DeviceEvent::SendBytes(b) = ev {
                    commands.push(String::from_utf8(b).unwrap());
                    emitted_one = true;
                }
            }
            if !emitted_one {
                break;
            }
        }
        commands
    }

    #[test]
    fn default_init_sends_offline_then_init_all() {
        let cmds = run_init(Config::default());
        assert_eq!(
            cmds,
            vec![
                "$PDGY,N2NET_OFFLINE\r\n".to_string(),
                "$PDGY,N2NET_INIT,ALL\r\n".to_string(),
            ],
            "default init should be OFFLINE → INIT,ALL (no RESET, no lists)"
        );
    }

    #[test]
    fn rx_list_triggers_reset_rxlist_normal() {
        let mut cfg = Config::default();
        cfg.rx_list = Some("129025,129026".to_string());
        let cmds = run_init(cfg);
        assert_eq!(
            cmds,
            vec![
                "$PDGY,N2NET_OFFLINE\r\n".to_string(),
                "$PDGY,N2NET_RESET\r\n".to_string(),
                "$PDGY,RX_LIST,129025,129026\r\n".to_string(),
                "$PDGY,N2NET_INIT,NORMAL\r\n".to_string(),
            ]
        );
    }

    #[test]
    fn rate_limit_off_sends_after_init_with_no_ack() {
        let mut cfg = Config::default();
        cfg.rate_limit_off = true;
        let cmds = run_init(cfg);
        assert_eq!(
            cmds,
            vec![
                "$PDGY,N2NET_OFFLINE\r\n".to_string(),
                "$PDGY,N2NET_INIT,ALL\r\n".to_string(),
                "$PDGY,TX_LIMIT,OFF\r\n".to_string(),
            ]
        );
    }

    #[test]
    fn extra_ack_after_done_is_ignored() {
        let decoder = Decoder::new(Config::default());
        let mut events = Vec::new();
        decoder.handle_control("ACK,offline", &mut events); // → INIT,ALL
        events.clear();
        decoder.handle_control("ACK,init", &mut events); // → done
        events.clear();
        decoder.handle_control("ACK,stray", &mut events); // ignored
        assert!(events.is_empty(), "post-init ACKs must not emit commands");
    }
}
