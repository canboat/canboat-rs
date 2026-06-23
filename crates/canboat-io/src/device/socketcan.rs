//! Linux SocketCAN device adapter — a full NMEA 2000 bus participant.
//!
//! Wraps a raw `CAN_RAW` socket on a Linux SocketCAN interface and runs
//! the ISO 11783-5 address-claim handshake, heartbeat scheduler, and
//! ISO Request / Group Function responders, all on a single internal
//! worker thread. Outbound writes go through a buffered ring drained
//! one frame per `POLLOUT` wakeup so a shallow netdev qdisc never
//! stalls RX or the claim timers.
//!
//! Mirrors the bus-protocol layer of `canboat/socketcan-serial/socketcan-serial.c`.
//! Both the standalone `socketcan-serial` binary and the integrated
//! `canboat-pipeline` use this module via [`run`], which returns a
//! standard [`super::DeviceHandle`].
//!
//! `src` convention on outbound frames sent via `DeviceHandle::send_frame`:
//! `frame.src == 0` is treated as "use my claim address" and rewritten to
//! the currently-claimed source; any other value is sent on the wire as
//! given. This matches canboat C's stdin pump and lets quirk
//! synthesisers (e.g. the SCX-20 PGN 126996 fabrication) impersonate
//! other nodes by passing the impersonated `src` explicitly.
//!
//! Linux-only; on every other platform `run` returns an
//! `io::ErrorKind::Unsupported` error and `Config` is a placeholder.

#[cfg(target_os = "linux")]
pub use imp::run;

pub use config::Config;

mod config {
    /// Bus-participant configuration. All fields have sensible defaults
    /// via [`Config::default`]; tweak only what differs from canboat C
    /// `socketcan-serial`'s built-in defaults.
    #[derive(Debug, Clone)]
    pub struct Config {
        /// Preferred source address to claim. Defaults to 0.
        pub address: u8,
        /// Unique number for the ISO NAME's identity field. 0 = derive
        /// from the process id.
        pub unique: u32,
        /// Manufacturer code for the ISO NAME. Defaults to 999 (Signal K).
        pub manufacturer: u16,
        /// System Instance (4 bits). Default 15 = maximum, so our NAME
        /// loses arbitration against any real sensor that leaves this
        /// at 0 — we yield rather than steal an address.
        pub system_instance: u8,
        /// Heartbeat (PGN 126993) interval in ms; 0 disables.
        pub heartbeat_ms: u64,
        /// Skip the ISO address-claim handshake entirely (passive sniff).
        pub no_claim: bool,
        /// Quit if no frame is received for this many seconds (0 disables).
        pub timeout_secs: u64,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                address: 0,
                unique: 0,
                manufacturer: 999,
                system_instance: 15,
                heartbeat_ms: 60_000,
                no_claim: false,
                timeout_secs: 0,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run(_iface: &str, _config: Config) -> std::io::Result<super::DeviceHandle> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SocketCAN is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::{HashMap, VecDeque};
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use canboat_core::frame::RawFrame;
    use canboat_core::{FramePacketType, Reassembled, Reassembler};
    use socketcan::{CanSocket, EmbeddedFrame, ExtendedId, Socket};

    use super::config::Config;
    use crate::device::{from_parts, DeviceHandle, WriterCmd};
    use crate::fastpacket;

    const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;
    const CAN_ERR_FLAG: u32 = 0x2000_0000;

    const PGN_ISO_ACK: u32 = 59392;
    const PGN_ISO_REQUEST: u32 = 59904;
    const PGN_ISO_ADDRESS_CLAIM: u32 = 60928;
    const PGN_GROUP_FUNCTION: u32 = 126208;
    const PGN_PGN_LIST: u32 = 126464;
    const PGN_HEARTBEAT: u32 = 126993;
    const PGN_PRODUCT_INFO: u32 = 126996;

    /// Synthetic-PGN range — never on the wire, never sent to the bus.
    const CANBOAT_PGN_START: u32 = 0x40000;

    // Product Information (PGN 126996) content for the gateway itself.
    const N2K_DB_VERSION: u16 = 2100; // 2.100 at 0.001 resolution
    const PRODUCT_CODE: u16 = 1;
    const CERTIFICATION_LEVEL: u8 = 0; // Level A
    const LOAD_EQUIVALENCY: u8 = 1; // 1 LEN = 50 mA
    const MODEL_ID: &str = "socketcan-serial";

    // Group Function (PGN 126208) function codes and DURATION sentinels.
    const GROUP_FUNCTION_REQUEST: u8 = 0;
    const GROUP_FUNCTION_ACK: u8 = 2;
    const TX_INTERVAL_NO_CHANGE: u32 = 0xffff_ffff;
    const TX_INTERVAL_RESTORE_DEFAULT: u32 = 0xffff_fffe;

    // PGNs we originate / consume, reported via PGN 126464 on request.
    const TX_PGN_LIST: [u32; 7] = [
        PGN_ISO_ACK,
        PGN_ISO_REQUEST,
        PGN_ISO_ADDRESS_CLAIM,
        PGN_GROUP_FUNCTION,
        PGN_PGN_LIST,
        PGN_HEARTBEAT,
        PGN_PRODUCT_INFO,
    ];
    const RX_PGN_LIST: [u32; 3] = [PGN_ISO_REQUEST, PGN_ISO_ADDRESS_CLAIM, PGN_GROUP_FUNCTION];

    const ADDR_GLOBAL: u8 = 255;
    const ADDR_NULL: u8 = 254;
    const ADDR_MAX: u8 = 253;
    const CLAIM_TIMEOUT_MS: u64 = 250;
    const SCAN_TIMEOUT_MS: u64 = 1000;

    /// Hold outbound frames until the kernel CAN qdisc has room. The
    /// worker thread drains one frame per POLLOUT wakeup so a single
    /// fast-packet burst never starves RX or the claim timers. ~1 s of
    /// bus time at 250 kbit/s with the default txqueuelen.
    const TX_BUFFER_CAPACITY: usize = 1024;

    /// Worst-case latency for a user-side `send_frame` to reach the bus.
    /// The worker drains `cmd_rx` after each `poll()` wakeup; a 100 ms
    /// cap keeps stdin / quirk-synthesiser sends prompt without burning
    /// CPU on idle.
    const MAX_POLL_MS: u64 = 100;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// `YYYY-MM-DDTHH:MM:SS.mmmZ` from epoch milliseconds; matches
    /// canboat C's `fmtTimestamp`.
    fn format_iso(ms: u64) -> String {
        let secs = (ms / 1000) as i64;
        let millis = ms % 1000;
        let days = secs.div_euclid(86_400);
        let tod = secs.rem_euclid(86_400);
        let (y, mo, d) = days_to_ymd(days);
        let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
    }

    fn days_to_ymd(days: i64) -> (i32, u32, u32) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        ((y + i64::from(m <= 2)) as i32, m, d)
    }

    /// Decompose a 29-bit ISO 11783 CAN id into (prio, pgn, src, dst).
    /// Matches `getISO11783BitsFromCanId` in canboat/common/common.c.
    fn iso_decompose(id: u32) -> (u8, u32, u8, u8) {
        let prio = ((id >> 26) & 0x7) as u8;
        let rdp = (id >> 24) & 0x3;
        let pf = ((id >> 16) & 0xff) as u8;
        let ps = ((id >> 8) & 0xff) as u8;
        let src = (id & 0xff) as u8;
        if pf < 240 {
            (prio, (rdp << 16) | ((pf as u32) << 8), src, ps)
        } else {
            (
                prio,
                (rdp << 16) | ((pf as u32) << 8) | ps as u32,
                src,
                0xff,
            )
        }
    }

    /// Build the 29-bit ISO 11783 CAN id (without the EFF flag) from N2K
    /// fields. Mirrors `getCanIdFromISO11783Bits`.
    fn iso_compose(prio: u8, pgn: u32, src: u8, dst: u8) -> u32 {
        let mut id = src as u32;
        let pf = (pgn >> 8) & 0xff;
        if pf < 240 {
            id |= (dst as u32) << 8;
            id |= pgn << 8;
        } else {
            id |= pgn << 8;
        }
        id |= (prio as u32) << 26;
        id
    }

    /// Build the 64-bit ISO NAME from a [`Config`].
    fn build_name(config: &Config) -> u64 {
        let unique = if config.unique != 0 {
            config.unique & 0x1fffff
        } else {
            // SAFETY: getpid is always safe.
            (unsafe { libc::getpid() } as u32) & 0x1fffff
        };
        let manufacturer = config.manufacturer as u64 & 0x7ff;
        let device_instance: u64 = 0;
        let device_function: u64 = 130; // PC Gateway
        let device_class: u64 = 25; // Inter/Intranetwork Device
        let system_instance: u64 = config.system_instance as u64 & 0x0f;
        let industry_group: u64 = 4; // Marine
        let arbitrary: u64 = 1;
        (unique as u64)
            | (manufacturer << 21)
            | ((device_instance & 0x07) << 32)
            | ((device_instance >> 3 & 0x1f) << 35)
            | ((device_function & 0xff) << 40)
            | ((device_class & 0x7f) << 49)
            | ((system_instance & 0x0f) << 56)
            | ((industry_group & 0x07) << 60)
            | (arbitrary << 63)
    }

    fn put_string_fix(dst: &mut [u8], s: &str) {
        let n = s.len().min(dst.len());
        dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    }

    /// Outbound ring drained one frame per writability wakeup. Lives on
    /// the worker thread; not shared, no locking.
    struct TxBuffer {
        queue: VecDeque<socketcan::CanFrame>,
        overflowed: usize,
        /// Per-(pgn, src) fast-packet sequence counter, mod 8. The
        /// upper 3 bits of every fast-packet `frame[0]` carry this
        /// value; a strict receiver uses it to distinguish back-to-
        /// back instances of the same PGN from continuations of an
        /// in-flight reassembly. We previously left it at 0, so a
        /// receiver could fold two consecutive Product-Info responses
        /// into one corrupted reassembly.
        fast_seq: HashMap<(u32, u8), u8>,
    }

    impl TxBuffer {
        fn new() -> Self {
            Self {
                queue: VecDeque::with_capacity(64),
                overflowed: 0,
                fast_seq: HashMap::new(),
            }
        }

        /// Returns the next fast-packet sequence number for
        /// `(pgn, src)` and advances the counter.
        fn next_fast_seq(&mut self, pgn: u32, src: u8) -> u8 {
            let slot = self.fast_seq.entry((pgn, src)).or_insert(0);
            let s = *slot;
            *slot = (s + 1) & 0x07;
            s
        }

        fn push(&mut self, can_id: u32, data: &[u8]) {
            if self.queue.len() >= TX_BUFFER_CAPACITY {
                if self.overflowed == 0 {
                    log::error!(
                        "CAN TX buffer full ({TX_BUFFER_CAPACITY} frames), dropping outbound frame"
                    );
                }
                self.overflowed += 1;
                return;
            }
            let Some(id) = ExtendedId::new(can_id & CAN_EFF_MASK) else {
                return;
            };
            let Some(frame) = socketcan::CanFrame::new(socketcan::Id::Extended(id), data) else {
                log::error!("could not build CAN frame for id {can_id:#x}");
                return;
            };
            self.queue.push_back(frame);
        }

        fn is_empty(&self) -> bool {
            self.queue.is_empty()
        }
    }

    /// Bundles the resources every send-path needs: the socket, the TX
    /// ring, and the consumer-side channel that receives a `RawFrame`
    /// echo of every self-generated outbound. Passed by `&mut` through
    /// the Claimer's methods so they stay free-functions in spirit.
    struct Bus<'a> {
        tx_buf: &'a mut TxBuffer,
        frames_tx: &'a mpsc::Sender<RawFrame>,
    }

    impl<'a> Bus<'a> {
        /// Enqueue a self-generated outbound PGN. Splits >8-byte
        /// payloads into fast-packet chunks and pushes each chunk to
        /// the kernel queue. When `emit` is true the *same* chunks are
        /// also forwarded to `frames_tx` as single-frame `RawFrame`s so
        /// the consumer sees the on-wire footprint of our own emissions
        /// and reassembles them identically to bus traffic.
        fn send_pgn(&mut self, prio: u8, pgn: u32, src: u8, dst: u8, data: &[u8], emit: bool) {
            let can_id = iso_compose(prio, pgn, src, dst);
            // Single vs fast-packet is decided strictly from the PGN
            // type table generated at build time from canboat.json.
            // **Never** infer from `data.len()` alone: a single-frame
            // PGN whose payload happens to be 8 bytes (PGN 127508
            // Battery Status is the canonical example) must NOT be
            // wrapped in a fast-packet shell — the receiver's schema
            // would decode the seq/len header bytes as the first two
            // payload fields and produce wildly wrong values.
            // Conversely, a fast-packet PGN with ≤8 bytes of payload
            // (PGN 126208 Group Function ACK, 6 bytes) still has to go
            // out with the fast-packet wrapper because strict
            // receivers key on the PGN type, not the byte count.
            let is_fast = fastpacket::packet_type(pgn) == FramePacketType::Fast;
            if !is_fast {
                self.tx_buf.push(can_id, data);
                if emit {
                    self.emit_chunk(prio, pgn, src, dst, data);
                }
            } else {
                // Per ISO 11783-3: every fast-packet CAN frame is
                // exactly 8 bytes; the last chunk is padded with 0xff.
                // The first byte is `(seq << 5) | index`, with `seq`
                // incrementing per-(pgn, src) instance so consecutive
                // first frames are distinguishable from continuations.
                let seq = self.tx_buf.next_fast_seq(pgn, src);
                let mut index: u8 = 0;
                let mut remaining = data.len();
                let mut offset = 0;
                while remaining > 0 {
                    let mut frame = [0xffu8; 8];
                    frame[0] = (seq << 5) | (index & 0x1f);
                    let chunk;
                    let payload_start;
                    if index == 0 {
                        frame[1] = data.len() as u8;
                        chunk = remaining.min(6);
                        payload_start = 2;
                    } else {
                        chunk = remaining.min(7);
                        payload_start = 1;
                    }
                    frame[payload_start..payload_start + chunk]
                        .copy_from_slice(&data[offset..offset + chunk]);
                    self.tx_buf.push(can_id, &frame[..]);
                    if emit {
                        self.emit_chunk(prio, pgn, src, dst, &frame[..]);
                    }
                    offset += chunk;
                    remaining -= chunk;
                    index = index.wrapping_add(1);
                }
            }
        }

        /// Forward one CAN-frame-sized chunk to the consumer as a
        /// single-frame `RawFrame`. Consumer is responsible for fast-
        /// packet reassembly.
        fn emit_chunk(&self, prio: u8, pgn: u32, src: u8, dst: u8, chunk: &[u8]) {
            let f = RawFrame::new(
                Some(format_iso(now_ms())),
                prio,
                pgn,
                src,
                dst,
                chunk.iter().copied(),
            );
            let _ = self.frames_tx.send(f);
        }
    }

    #[derive(PartialEq)]
    enum ClaimState {
        Disabled,
        Scanning,
        Pending,
        Claimed,
        Failed,
    }

    struct Claimer {
        name: u64,
        address: u8,
        preferred: u8,
        state: ClaimState,
        deadline: u64,
        arbitrary: bool,
        heartbeat_interval: u64, // ms, 0 disables
        heartbeat_seq: u8,
        next_heartbeat: u64,    // ms
        last_product_info: u64, // ms; rate-limit broadcast bursts
        used: [bool; 256],
    }

    impl Claimer {
        fn new(config: &Config) -> Self {
            Self {
                name: build_name(config),
                address: config.address,
                preferred: config.address,
                state: if config.no_claim {
                    ClaimState::Disabled
                } else {
                    ClaimState::Pending
                },
                deadline: 0,
                arbitrary: true,
                heartbeat_interval: config.heartbeat_ms,
                heartbeat_seq: 0,
                next_heartbeat: 0,
                last_product_info: 0,
                used: [false; 256],
            }
        }

        fn name_to_bytes(&self) -> [u8; 8] {
            self.name.to_le_bytes()
        }

        fn start(&mut self, bus: &mut Bus<'_>) {
            self.state = ClaimState::Scanning;
            self.deadline = now_ms() + SCAN_TIMEOUT_MS;
            // Ask every node to (re)announce its address claim so we
            // learn which addresses are taken before we pick one. Sent
            // from the null address since we have not claimed yet.
            self.send_request(bus, ADDR_NULL, ADDR_GLOBAL, PGN_ISO_ADDRESS_CLAIM);
            log::debug!(
                "Scanning bus {SCAN_TIMEOUT_MS} ms before claiming (NAME {:#018x})",
                self.name
            );
        }

        fn begin_claim(&mut self, bus: &mut Bus<'_>) {
            if self.used[self.preferred as usize] {
                match self.pick_free() {
                    Some(next) => {
                        log::debug!(
                            "Preferred address {} is taken, using {next}",
                            self.preferred
                        );
                        self.address = next;
                    }
                    None => {
                        log::error!("No free address available; cannot claim");
                        self.address = ADDR_NULL;
                        self.state = ClaimState::Failed;
                        self.send_claim(bus, ADDR_GLOBAL);
                        return;
                    }
                }
            } else {
                self.address = self.preferred;
            }
            self.state = ClaimState::Pending;
            self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
            self.send_claim(bus, ADDR_GLOBAL);
            log::debug!(
                "Claiming address {} with NAME {:#018x}",
                self.address,
                self.name
            );
        }

        fn send_claim(&self, bus: &mut Bus<'_>, dst: u8) {
            let data = self.name_to_bytes();
            bus.send_pgn(6, PGN_ISO_ADDRESS_CLAIM, self.address, dst, &data, true);
        }

        fn send_request(&self, bus: &mut Bus<'_>, src: u8, dst: u8, pgn: u32) {
            let data = [pgn as u8, (pgn >> 8) as u8, (pgn >> 16) as u8];
            bus.send_pgn(6, PGN_ISO_REQUEST, src, dst, &data, true);
        }

        fn pick_free(&self) -> Option<u8> {
            (0..=ADDR_MAX).find(|a| !self.used[*a as usize])
        }

        fn on_claim(&mut self, bus: &mut Bus<'_>, src: u8, data: &[u8]) {
            if data.len() < 8 || src > ADDR_MAX {
                return;
            }
            let their_name = u64::from_le_bytes(data[..8].try_into().unwrap());
            // While scanning we own no address yet — just learn what is in use.
            if self.state == ClaimState::Scanning {
                self.used[src as usize] = true;
                return;
            }
            if src != self.address {
                self.used[src as usize] = true;
                return;
            }
            // Someone is claiming our address. Lowest NAME wins.
            if self.name < their_name {
                log::debug!(
                    "Won address {} conflict (our NAME lower), re-claiming",
                    self.address
                );
                self.state = ClaimState::Pending;
                self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
                self.send_claim(bus, ADDR_GLOBAL);
                return;
            }
            // We lost.
            self.used[src as usize] = true;
            if self.arbitrary {
                if let Some(next) = self.pick_free() {
                    log::debug!("Lost address {} conflict, moving to {next}", self.address);
                    self.address = next;
                    self.state = ClaimState::Pending;
                    self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
                    self.send_claim(bus, ADDR_GLOBAL);
                    return;
                }
                log::error!(
                    "Lost address {} and no free address left; cannot claim",
                    self.address
                );
            } else {
                log::error!(
                    "Lost address {} conflict and not arbitrary-address-capable; cannot claim",
                    self.address
                );
            }
            self.address = ADDR_NULL;
            self.state = ClaimState::Failed;
            self.send_claim(bus, ADDR_GLOBAL);
        }

        fn on_request(&mut self, bus: &mut Bus<'_>, src: u8, dst: u8, data: &[u8]) {
            if data.len() < 3 {
                return;
            }
            let requested = data[0] as u32 | (data[1] as u32) << 8 | (data[2] as u32) << 16;
            let addressed = dst == self.address;
            if !addressed && dst != ADDR_GLOBAL {
                return; // request is for some other node
            }

            // The address claim must be answerable even before fully claimed.
            if requested == PGN_ISO_ADDRESS_CLAIM {
                if matches!(self.state, ClaimState::Claimed | ClaimState::Pending) {
                    self.send_claim(bus, ADDR_GLOBAL);
                }
                return;
            }

            if self.state != ClaimState::Claimed {
                return; // need a claimed address to answer from
            }

            match requested {
                PGN_PRODUCT_INFO => self.send_product_info(bus),
                PGN_PGN_LIST => self.send_pgn_list(bus, src),
                PGN_HEARTBEAT => self.send_heartbeat(bus),
                _ => {
                    // ISO 11783-3: NAK an addressed request for a PGN we do
                    // not send; silently ignore an unsupported global request.
                    if addressed {
                        self.send_iso_ack(bus, src, 1 /* NAK */, requested);
                    }
                }
            }
        }

        // Product Information, PGN 126996. Broadcast (PDU2), so one reply
        // answers every requester; rate-limited to collapse discovery bursts.
        fn send_product_info(&mut self, bus: &mut Bus<'_>) {
            let now = now_ms();
            if now - self.last_product_info < 1000 {
                return;
            }
            self.last_product_info = now;

            let mut data = [0u8; 134];
            data[0..2].copy_from_slice(&N2K_DB_VERSION.to_le_bytes());
            data[2..4].copy_from_slice(&PRODUCT_CODE.to_le_bytes());
            put_string_fix(&mut data[4..36], MODEL_ID);
            put_string_fix(&mut data[36..68], env!("CARGO_PKG_VERSION"));
            put_string_fix(&mut data[68..100], ""); // model version
            put_string_fix(&mut data[100..132], &(self.name & 0x1fffff).to_string());
            data[132] = CERTIFICATION_LEVEL;
            data[133] = LOAD_EQUIVALENCY;
            bus.send_pgn(6, PGN_PRODUCT_INFO, self.address, ADDR_GLOBAL, &data, true);
        }

        // PGN List (Transmit and Receive), PGN 126464: one message per list.
        fn send_pgn_list(&self, bus: &mut Bus<'_>, dst: u8) {
            for (func, list) in [(0u8, &TX_PGN_LIST[..]), (1u8, &RX_PGN_LIST[..])] {
                let mut data = Vec::with_capacity(1 + 3 * list.len());
                data.push(func);
                for pgn in list {
                    data.extend_from_slice(&pgn.to_le_bytes()[..3]);
                }
                bus.send_pgn(6, PGN_PGN_LIST, self.address, dst, &data, true);
            }
        }

        // ISO Acknowledgement, PGN 59392.
        fn send_iso_ack(&self, bus: &mut Bus<'_>, dst: u8, control: u8, pgn: u32) {
            let p = pgn.to_le_bytes();
            let data = [control, 0xff, 0xff, 0xff, 0xff, p[0], p[1], p[2]];
            bus.send_pgn(6, PGN_ISO_ACK, self.address, dst, &data, true);
        }

        // Acknowledge Group Function, PGN 126208 function 2.
        fn send_ack_group_function(
            &self,
            bus: &mut Bus<'_>,
            dst: u8,
            pgn: u32,
            pgn_err: u8,
            param_err: u8,
        ) {
            let p = pgn.to_le_bytes();
            let data = [
                GROUP_FUNCTION_ACK,
                p[0],
                p[1],
                p[2],
                (pgn_err & 0x0f) | ((param_err & 0x0f) << 4),
                0, // number of parameters
            ];
            bus.send_pgn(6, PGN_GROUP_FUNCTION, self.address, dst, &data, true);
        }

        // NMEA Request Group Function (PGN 126208, function 0). We act only on
        // a request targeting our Heartbeat (PGN 126993): it sets the transmit
        // interval (or disables it), then we reply with an Acknowledge.
        fn handle_group_function(&mut self, bus: &mut Bus<'_>, src: u8, data: &[u8]) {
            if data.len() < 8
                || data[0] != GROUP_FUNCTION_REQUEST
                || self.state != ClaimState::Claimed
            {
                return;
            }
            let target = data[1] as u32 | (data[2] as u32) << 8 | (data[3] as u32) << 16;
            if target != PGN_HEARTBEAT {
                return;
            }
            // Transmission interval: 32-bit, 0.001s resolution => ms.
            let interval = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let mut param_err = 0u8;
            match interval {
                TX_INTERVAL_NO_CHANGE => {}
                TX_INTERVAL_RESTORE_DEFAULT => {
                    self.heartbeat_interval = 60000;
                    self.next_heartbeat = now_ms() + self.heartbeat_interval;
                    log::info!("Heartbeat interval restored to default 60000 ms");
                }
                0 => {
                    self.heartbeat_interval = 0;
                    log::info!("Heartbeat disabled by group function");
                }
                1000..=60000 => {
                    self.heartbeat_interval = interval as u64;
                    self.next_heartbeat = now_ms() + self.heartbeat_interval;
                    log::info!("Heartbeat interval set to {interval} ms by group function");
                }
                _ => {
                    param_err = 2; // transmission interval out of range
                    log::error!("Requested heartbeat interval {interval} ms out of range");
                }
            }
            self.send_ack_group_function(bus, src, PGN_HEARTBEAT, 0, param_err);
        }

        fn tick(&mut self, bus: &mut Bus<'_>, now: u64) {
            if self.state == ClaimState::Scanning && now >= self.deadline {
                self.begin_claim(bus);
                return;
            }
            if self.state == ClaimState::Pending && now >= self.deadline {
                self.state = ClaimState::Claimed;
                log::info!("Address {} claimed", self.address);
                self.send_product_info(bus); // announce ourselves once
                if self.heartbeat_interval > 0 {
                    self.next_heartbeat = now + self.heartbeat_interval;
                }
            }
            if self.state == ClaimState::Claimed
                && self.heartbeat_interval > 0
                && now >= self.next_heartbeat
            {
                self.send_heartbeat(bus);
                self.next_heartbeat = now + self.heartbeat_interval;
            }
        }

        // NMEA 2000 Heartbeat, PGN 126993. Sent every heartbeat_interval ms
        // once we own an address so other nodes know we are alive.
        fn send_heartbeat(&mut self, bus: &mut Bus<'_>) {
            let offset = (self.heartbeat_interval / 10) as u16; // field resolution 0.01 s
                                                                // Controller 1 State = Error Active (0), Controller 2 State = not
                                                                // available (3), Equipment Status = Operational (0), reserved = 1.
            let data = [
                offset as u8,
                (offset >> 8) as u8,
                self.heartbeat_seq,
                0xCC,
                0xff,
                0xff,
                0xff,
                0xff,
            ];
            bus.send_pgn(7, PGN_HEARTBEAT, self.address, ADDR_GLOBAL, &data, true);
            self.heartbeat_seq = if self.heartbeat_seq >= 252 {
                0
            } else {
                self.heartbeat_seq + 1
            };
        }
    }

    /// Try to write the oldest queued frame. Returns true if a frame was
    /// actually delivered; false on empty queue or kernel backpressure
    /// (the frame stays queued, retried on the next wakeup).
    fn tx_drain_one(sock: &CanSocket, tx_buf: &mut TxBuffer) -> bool {
        let Some(frame) = tx_buf.queue.front().cloned() else {
            return false;
        };
        match sock.write_frame(&frame) {
            Ok(()) => {
                tx_buf.queue.pop_front();
                if tx_buf.overflowed > 0 && tx_buf.queue.len() < TX_BUFFER_CAPACITY / 2 {
                    log::info!(
                        "CAN TX buffer recovered ({} frames had been dropped)",
                        tx_buf.overflowed
                    );
                    tx_buf.overflowed = 0;
                }
                true
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::ENOBUFS) =>
            {
                false
            }
            Err(e) => {
                log::error!("write to CAN: {e} (dropping frame)");
                tx_buf.queue.pop_front();
                false
            }
        }
    }

    /// Read one CAN frame plus its kernel SO_TIMESTAMP. `Ok(None)` means
    /// the socket has no more frames ready right now.
    fn recv_frame(fd: i32) -> std::io::Result<Option<(u32, usize, [u8; 8], u64)>> {
        let mut raw = [0u8; 16]; // struct can_frame
        let mut ctrl = [0u8; 64];
        // SAFETY: pointers refer to live local buffers for the duration
        // of the call; recvmsg only writes within them.
        unsafe {
            let mut iov = libc::iovec {
                iov_base: raw.as_mut_ptr() as *mut libc::c_void,
                iov_len: raw.len(),
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = ctrl.len() as _;

            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => Ok(None),
                    Some(code) if code == libc::EINTR => Ok(None),
                    _ => Err(e),
                };
            }
            if (n as usize) < raw.len() {
                return Ok(None);
            }

            let mut when = 0u64;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let c = &*cmsg;
                if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_TIMESTAMP {
                    let mut tv: libc::timeval = std::mem::zeroed();
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg),
                        &mut tv as *mut _ as *mut u8,
                        std::mem::size_of::<libc::timeval>(),
                    );
                    when = tv.tv_sec as u64 * 1000 + (tv.tv_usec as u64) / 1000;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }

            let id = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let dlc = raw[4] as usize;
            let mut data = [0u8; 8];
            data.copy_from_slice(&raw[8..16]);
            Ok(Some((id, dlc.min(8), data, when)))
        }
    }

    /// Translate an incoming single-frame CAN message. Drives the
    /// claim state machine, the Group Function responder (PGN 126208 —
    /// the one multi-frame PGN the library acts on directly, so we
    /// keep a small internal reassembler just for it), and forwards
    /// every bus single-frame to `frames_tx` as-is. Consumer reassembly
    /// uses the canboat-core PGN database (in canboat-pipeline /
    /// socketcan-serial).
    fn handle_frame(
        bus: &mut Bus<'_>,
        claimer: &mut Claimer,
        group_fn_reasm: &mut Reassembler,
        can_id: u32,
        data: &[u8],
        when: u64,
    ) {
        let (prio, pgn, src, dst) = iso_decompose(can_id);
        let single_frame = RawFrame::new(
            Some(format_iso(when)),
            prio,
            pgn,
            src,
            dst,
            data.iter().copied(),
        );

        if claimer.state != ClaimState::Disabled {
            if pgn == PGN_ISO_ADDRESS_CLAIM {
                claimer.on_claim(bus, src, data);
            } else if pgn == PGN_ISO_REQUEST {
                claimer.on_request(bus, src, dst, data);
            } else if pgn == PGN_GROUP_FUNCTION {
                // Reassemble locally so we can act on
                // Heartbeat-interval Request Group Functions even when
                // the consumer doesn't need a coalesced view.
                match group_fn_reasm.push(single_frame.clone(), FramePacketType::Fast) {
                    Reassembled::Complete(coalesced) => {
                        claimer.handle_group_function(bus, src, &coalesced.data);
                    }
                    Reassembled::PassThrough(coalesced) => {
                        claimer.handle_group_function(bus, src, &coalesced.data);
                    }
                    Reassembled::Partial => {}
                    Reassembled::Error(e) => log::debug!("group-function reassembly: {e}"),
                }
            }
        }

        // Forward the bus single-frame to the consumer untouched;
        // they reassemble using the canboat-core db.
        let _ = bus.frames_tx.send(single_frame);
    }

    /// Apply an outbound `WriterCmd` from the public `DeviceHandle` API.
    /// `src == 0` is interpreted as "use my claim address"; any other
    /// value is forwarded unchanged so quirk synthesisers can
    /// impersonate other nodes on the wire.
    fn dispatch_cmd(bus: &mut Bus<'_>, claimer: &Claimer, cmd: WriterCmd) {
        match cmd {
            WriterCmd::Frame(f) => {
                if f.pgn >= CANBOAT_PGN_START {
                    return; // synthetic, never goes on the bus
                }
                let src = if f.src == 0 { claimer.address } else { f.src };
                // emit=false: this is a user-initiated send; the caller
                // already has visibility into what they sent. (For the
                // SCX-20 quirk we want the synthetic 126996 to be
                // visible in the local pipeline too — the caller injects
                // it into the analyzer side directly.)
                bus.send_pgn(f.prio, f.pgn, src, f.dst, &f.data, false);
            }
            WriterCmd::Bytes(_) => {
                // The SocketCAN backend has no concept of raw "bytes"
                // since the wire format is frame-based. Silently drop;
                // log so a misuse is at least visible.
                log::debug!("WriterCmd::Bytes ignored by socketcan adapter");
            }
        }
    }

    /// Open the SocketCAN interface and spawn the bus-participant
    /// worker thread. Returns a standard [`DeviceHandle`] for the
    /// caller to drain RX from and push TX into.
    pub fn run(iface: &str, config: Config) -> std::io::Result<DeviceHandle> {
        let sock = CanSocket::open(iface)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        sock.set_nonblocking(true)?;
        let fd = sock.as_raw_fd();

        // Kernel RX timestamps so emitted frames carry the wire time
        // rather than when we got round to draining the kernel queue.
        let on: libc::c_int = 1;
        // SAFETY: setsockopt with a valid fd and an int-sized option.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as _,
            )
        };
        if rc < 0 {
            log::warn!(
                "SO_TIMESTAMP: {} (continuing without kernel timestamps)",
                std::io::Error::last_os_error()
            );
        }

        let (frames_tx, frames_rx) = mpsc::channel::<RawFrame>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<WriterCmd>();

        let join = thread::Builder::new()
            .name("socketcan-worker".into())
            .spawn(move || worker(sock, fd, config, frames_tx, cmd_rx))?;

        Ok(from_parts(frames_rx, cmd_tx, vec![join]))
    }

    /// The single worker thread that owns the socket and runs the poll
    /// loop. Polls the CAN fd, drains `cmd_rx` via `try_recv`, runs the
    /// claim/heartbeat timers, and drains the TX buffer one frame per
    /// writability wakeup.
    fn worker(
        sock: CanSocket,
        fd: i32,
        config: Config,
        frames_tx: mpsc::Sender<RawFrame>,
        cmd_rx: mpsc::Receiver<WriterCmd>,
    ) {
        let mut claimer = Claimer::new(&config);
        let mut tx_buf = TxBuffer::new();
        // Reassembler used *only* for PGN 126208 (Group Function), so
        // the library can act on Heartbeat-interval requests. Consumer
        // reassembly is the pipeline's / binary's responsibility.
        let mut group_fn_reasm = Reassembler::new();
        let mut last_frame = now_ms();
        let timeout_ms = config.timeout_secs.saturating_mul(1000);

        // Kick off the claim handshake if enabled.
        if claimer.state != ClaimState::Disabled {
            let mut bus = Bus {
                tx_buf: &mut tx_buf,
                frames_tx: &frames_tx,
            };
            claimer.start(&mut bus);
        }

        loop {
            let now = now_ms();

            // 1. Drain any user-side sends into the TX ring.
            loop {
                match cmd_rx.try_recv() {
                    Ok(cmd) => {
                        let mut bus = Bus {
                            tx_buf: &mut tx_buf,
                            frames_tx: &frames_tx,
                        };
                        dispatch_cmd(&mut bus, &claimer, cmd);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }

            // 2. Pick a poll timeout: soonest of claim deadline,
            //    heartbeat, MAX_POLL_MS, and (when TX is backed up) 5 ms
            //    as a safety net in case POLLOUT lags qdisc availability.
            let mut wait: u64 =
                if matches!(claimer.state, ClaimState::Pending | ClaimState::Scanning)
                    && claimer.deadline > now
                {
                    claimer.deadline - now
                } else if claimer.state == ClaimState::Claimed && claimer.heartbeat_interval > 0 {
                    claimer.next_heartbeat.saturating_sub(now)
                } else {
                    MAX_POLL_MS
                };
            if !tx_buf.is_empty() && wait > 5 {
                wait = 5;
            }
            if wait > MAX_POLL_MS {
                wait = MAX_POLL_MS;
            }
            let timeout_arg = wait.min(i32::MAX as u64) as i32;

            // 3. poll() — POLLIN always; POLLOUT only while TX is pending.
            let events = if tx_buf.is_empty() {
                libc::POLLIN
            } else {
                libc::POLLIN | libc::POLLOUT
            };
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: poll over a single live pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_arg) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                log::error!("socketcan poll: {e}");
                return;
            }

            // 4. Idle-timeout check.
            if timeout_ms > 0 && now_ms().saturating_sub(last_frame) >= timeout_ms {
                log::error!("Timeout {} seconds; no data received", config.timeout_secs);
                return;
            }

            // 5. Drain one TX frame per writability wakeup (or per
            //    safety-net timeout).
            if !tx_buf.is_empty() {
                tx_drain_one(&sock, &mut tx_buf);
            }

            // 6. Drain RX up to a batch budget; yield then so the claim
            //    timers keep advancing on a busy bus.
            if pfd.revents & libc::POLLIN != 0 {
                last_frame = now_ms();
                let mut budget = 256;
                while budget > 0 {
                    budget -= 1;
                    match recv_frame(fd) {
                        Ok(Some((id, dlc, data, when))) => {
                            if id & CAN_ERR_FLAG != 0 {
                                continue;
                            }
                            let mut bus = Bus {
                                tx_buf: &mut tx_buf,
                                frames_tx: &frames_tx,
                            };
                            handle_frame(
                                &mut bus,
                                &mut claimer,
                                &mut group_fn_reasm,
                                id & CAN_EFF_MASK,
                                &data[..dlc],
                                if when != 0 { when } else { now_ms() },
                            );
                        }
                        Ok(None) => break,
                        Err(e) => {
                            log::error!("socketcan recvmsg: {e}");
                            return;
                        }
                    }
                }
            }

            // 7. Claim / heartbeat timers.
            let mut bus = Bus {
                tx_buf: &mut tx_buf,
                frames_tx: &frames_tx,
            };
            claimer.tick(&mut bus, now_ms());
        }
    }
}
