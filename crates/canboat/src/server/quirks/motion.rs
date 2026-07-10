// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! B&G H5000 Motion Sensor impersonation.
//!
//! A Navico/B&G **Hercules H5000** sailing processor will only accept
//! roll/pitch attitude for heel/trim motion correction from a device whose
//! **PGN 126996 Product Code == `0x53F0` (21488)** — the code of the real
//! *H5000 Motion Sensor*. It is a single hard equality test in the CPU
//! firmware (`FUN_003ce89c`); manufacturer / device-class / function are
//! *not* the gate. So a generic third-party attitude sensor on the bus is
//! ignored no matter how correct its PGN 127257.
//!
//! With `--quirk motion` canboat presents itself as that Motion Sensor —
//! a distinct virtual node with its own ISO 11783-5 address claim (via the
//! shared [`canboat_io::address_claim::AddressClaim`]) — answering 126996
//! with product code `0x53F0`, and **relaying** an existing bus attitude
//! source's PGN 127257 under this identity so Hercules accepts it.
//!
//! Research: `n2k_research/navico/motion/hercules-acceptance.md` (recognition
//! gate, byte-proven against a real unit) and `digital-twin-spec.md`.
//!
//! Scope (deliberately minimal): address claim, 126996 Product Info, 126464
//! TX/RX PGN lists, and the 127257 relay. The Simnet source-selection
//! handshake (65323 / 130840) is not implemented yet.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use canboat_core::{ADDR_GLOBAL, DecodedPgn, RawFrame, field, format_iso_ms};
use canboat_io::address_claim::AddressClaim;
use canboat_io::nmea_responder::{self, ProductInfo};

const PGN_ISO_REQUEST: u32 = 59904;
const PGN_ISO_ADDRESS_CLAIM: u32 = 60928;
const PGN_PGN_LIST: u32 = 126464;
const PGN_PRODUCT_INFO: u32 = 126996;
const PGN_ATTITUDE: u32 = 127257;

/// ISO NAME fields identifying the H5000 Motion Sensor personality. The
/// class/function are *not* the Hercules acceptance gate (that is the
/// Product Code below), but a faithful twin still presents them.
const MFG_BANDG: u64 = 381;
const DEVICE_FUNCTION: u64 = 140; // "Ownship Attitude"
const DEVICE_CLASS: u64 = 60; // Navigation
const INDUSTRY_MARINE: u64 = 4;

/// Preferred source address. The real unit was seen at 24; if it's taken
/// the claim state machine picks the lowest free one. Kept non-zero so the
/// pipeline's own-node stamping (which rewrites src 0/255) never touches
/// our frames.
const PREFERRED_ADDRESS: u8 = 24;

/// PGN 126996 "Product Information" for the Motion Sensor — the value that
/// matters is the Product Code; the rest mirrors the captured genuine unit
/// (`n2k_research`: Model ID "H5000 Motion Sensor", Model Version "Motion",
/// SW "1.2.4"). **`PRODUCT_CODE` is THE Hercules acceptance gate.**
const PRODUCT_CODE: i64 = 21488; // 0x53F0
const DB_VERSION: i64 = 2100; // 2.100 at res 0.001
const MODEL_ID: &str = "H5000 Motion Sensor";
const SOFTWARE_VERSION: &str = "1.2.4";
const MODEL_VERSION: &str = "Motion";
const MODEL_SERIAL: &str = "canboat";
const CERTIFICATION_LEVEL: i64 = 2;
const LOAD_EQUIVALENCY: i64 = 1;

/// PGNs the twin transmits / receives, reported via PGN 126464 on request.
const TX_PGN_LIST: [u32; 4] = [
    PGN_ISO_ADDRESS_CLAIM,
    PGN_PRODUCT_INFO,
    PGN_PGN_LIST,
    PGN_ATTITUDE,
];
const RX_PGN_LIST: [u32; 2] = [PGN_ISO_REQUEST, PGN_ISO_ADDRESS_CLAIM];

/// Stateful Motion Sensor impersonation.
pub struct Motion {
    /// Our own virtual node's address-claim state machine.
    claim: AddressClaim,
    /// Base instant for deriving the monotonic ms the claim SM wants; set
    /// on the first `process` call.
    base: Option<Instant>,
    /// False until the claim handshake has been kicked off.
    started: bool,
    /// The bus source whose 127257 we relay. Latched to the first attitude
    /// source seen once we own an address (never ourselves), so we don't
    /// flip between sources or loop on our own re-emission.
    source: Option<u8>,
}

impl Default for Motion {
    fn default() -> Self {
        Self::new()
    }
}

impl Motion {
    pub fn new() -> Self {
        Self {
            claim: AddressClaim::new(build_name(), PREFERRED_ADDRESS, true),
            base: None,
            started: false,
            source: None,
        }
    }

    /// Drive the claim state machine and relay attitude. `now` is injected
    /// so the (relative) claim clock is deterministic in tests.
    pub fn process(&mut self, d: &DecodedPgn, now: Instant) -> Vec<RawFrame> {
        let base = *self.base.get_or_insert(now);
        let now_ms = now.saturating_duration_since(base).as_millis() as u64;

        let mut out = Vec::new();
        if !self.started {
            self.started = true;
            log::info!(
                "quirk(motion): starting H5000 Motion Sensor impersonation \
                 (claiming address, preferred {PREFERRED_ADDRESS})"
            );
            out.extend(self.claim.start(now_ms));
        }

        let was_claimed = self.claim.is_claimed();

        match d.pgn {
            // Learn/arbitrate addresses; drive our own claim.
            PGN_ISO_ADDRESS_CLAIM => {
                if let Some(their_name) = d.iso_name() {
                    out.extend(self.claim.on_address_claim(now_ms, d.src, their_name));
                }
            }
            // Answer requests addressed to us (or broadcast).
            PGN_ISO_REQUEST => out.extend(self.handle_request(d)),
            // Relay a chosen source's attitude under our identity.
            PGN_ATTITUDE => {
                if let Some(f) = self.maybe_relay(d) {
                    out.push(f);
                }
            }
            _ => {}
        }

        // Deadline-driven transitions (scan → claim → owned).
        out.extend(self.claim.tick(now_ms));

        // The moment we take ownership: log it and announce ourselves with
        // an unsolicited Product Information (as the real sensor does), so
        // the twin is discoverable — and visible in the log — without
        // waiting for a poll. PGN lists stay request-driven.
        if !was_claimed && let Some(addr) = self.claim.address() {
            log::info!(
                "quirk(motion): claimed address {addr} as the H5000 Motion Sensor \
                 (PGN 126996 product code 0x53F0); announcing product info, waiting \
                 for an attitude source to relay"
            );
            out.extend(self.product_info());
        }

        stamp(&mut out);
        out
    }

    /// Respond to an ISO Request for one of the PGNs we serve, when it is
    /// addressed to our claimed address or broadcast.
    fn handle_request(&self, d: &DecodedPgn) -> Vec<RawFrame> {
        let Some(requested) = d
            .field_ref(field::iso_request::PGN)
            .and_then(|f| f.value.as_i64())
        else {
            return Vec::new();
        };
        let requested = requested as u32;
        let addressed = self.claim.address() == Some(d.dst) || d.dst == ADDR_GLOBAL;
        if !addressed {
            return Vec::new();
        }
        match requested {
            PGN_ISO_ADDRESS_CLAIM => self.claim.respond_to_claim_request().into_iter().collect(),
            PGN_PRODUCT_INFO => {
                log::debug!(
                    "quirk(motion): answering PGN 126996 request from src {} (the Hercules \
                     acceptance gate)",
                    d.src
                );
                self.product_info().into_iter().collect()
            }
            PGN_PGN_LIST => {
                log::debug!(
                    "quirk(motion): answering PGN 126464 list request from src {}",
                    d.src
                );
                self.pgn_lists()
            }
            _ => Vec::new(),
        }
    }

    /// Re-emit `d` (a PGN 127257 from the latched attitude source) from our
    /// claimed address. `None` until we own an address, or for frames from
    /// any source other than the latched one (including our own re-emits).
    fn maybe_relay(&mut self, d: &DecodedPgn) -> Option<RawFrame> {
        let addr = self.claim.address()?;
        if d.src == addr {
            return None; // our own re-emitted frame fed back — never loop
        }
        // Latch the first attitude source we see once claimed.
        if self.source.is_none() {
            self.source = Some(d.src);
            log::info!(
                "quirk(motion): relaying PGN 127257 attitude from src {} under the \
                 Motion Sensor identity (addr {addr})",
                d.src
            );
        }
        if self.source != Some(d.src) {
            return None;
        }
        Some(RawFrame::new(
            None,
            d.prio,
            PGN_ATTITUDE,
            addr,
            ADDR_GLOBAL,
            d.data.iter().copied(),
        ))
    }

    /// Encode PGN 126996 with the Motion Sensor's product code — **the
    /// Hercules acceptance gate** — via the shared responder builder.
    fn product_info(&self) -> Option<RawFrame> {
        let addr = self.claim.address()?;
        ProductInfo {
            db_version: DB_VERSION,
            product_code: PRODUCT_CODE,
            model_id: MODEL_ID,
            software_version: SOFTWARE_VERSION,
            model_version: MODEL_VERSION,
            model_serial: MODEL_SERIAL,
            certification_level: CERTIFICATION_LEVEL,
            load_equivalency: LOAD_EQUIVALENCY,
        }
        .frame(addr)
    }

    /// PGN 126464 Transmit/Receive PGN lists via the shared responder builder.
    fn pgn_lists(&self) -> Vec<RawFrame> {
        match self.claim.address() {
            Some(addr) => {
                nmea_responder::pgn_list_frames(addr, ADDR_GLOBAL, &TX_PGN_LIST, &RX_PGN_LIST)
            }
            None => Vec::new(),
        }
    }
}

/// The 64-bit ISO NAME for the Motion Sensor personality. The Unique
/// Number is derived from the host machine id so it is stable per host and
/// distinct from a real unit's (avoiding a NAME clash if both are present).
fn build_name() -> u64 {
    let unique = (canboat_core::os::get_machine_id() as u64) & 0x1f_ffff;
    let arbitrary: u64 = 1;
    unique
        | (MFG_BANDG << 21)
        | (DEVICE_FUNCTION << 40)
        | (DEVICE_CLASS << 49)
        | (INDUSTRY_MARINE << 60)
        | (arbitrary << 63)
}

/// Stamp a host-clock timestamp on any frame that lacks one, so the local
/// analyzer / snapshot streams show these synthetic frames with a time.
fn stamp(frames: &mut [RawFrame]) {
    if frames.iter().all(|f| f.timestamp.is_some()) {
        return;
    }
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let ts = format_iso_ms(ms);
    for f in frames.iter_mut().filter(|f| f.timestamp.is_none()) {
        f.timestamp = Some(ts.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canboat_core::{PgnDatabase, Units};
    use std::time::Duration;

    fn si() -> &'static PgnDatabase {
        PgnDatabase::embedded(Units::Si)
    }

    fn dec(f: &RawFrame) -> DecodedPgn {
        si().decode(f).expect("decodes")
    }

    /// A decoded PGN 59904 ISO Request for `target`, from `src` to `dst`.
    fn request(src: u8, dst: u8, target: u32) -> DecodedPgn {
        let data = [target as u8, (target >> 8) as u8, (target >> 16) as u8];
        dec(&RawFrame::new(None, 6, PGN_ISO_REQUEST, src, dst, data))
    }

    /// A decoded PGN 127257 Attitude from `src` (roll/pitch payload).
    fn attitude(src: u8) -> DecodedPgn {
        let data = [0x00, 0xff, 0x7f, 0xcd, 0x00, 0x01, 0xfc, 0xff];
        dec(&RawFrame::new(
            None,
            3,
            PGN_ATTITUDE,
            src,
            ADDR_GLOBAL,
            data,
        ))
    }

    /// Advance `m` to a claimed address by feeding a spare frame across the
    /// scan + claim windows on an idle bus. Returns the claimed address.
    fn drive_to_claimed(m: &mut Motion, t0: Instant) -> u8 {
        // First call kicks off the scan (deadline t0 + 1000 ms).
        m.process(&attitude(200), t0);
        // Past scan window → begins claim (deadline + 250 ms).
        m.process(&attitude(200), t0 + Duration::from_millis(1001));
        // Past claim window → owned.
        m.process(&attitude(200), t0 + Duration::from_millis(1300));
        m.claim.address().expect("claimed")
    }

    #[test]
    fn claims_preferred_address_on_idle_bus() {
        let mut m = Motion::new();
        let addr = drive_to_claimed(&mut m, Instant::now());
        assert_eq!(addr, PREFERRED_ADDRESS);
    }

    #[test]
    fn answers_product_info_with_the_gate_code() {
        let mut m = Motion::new();
        let t0 = Instant::now();
        let addr = drive_to_claimed(&mut m, t0);
        let out = m.process(
            &request(9, addr, PGN_PRODUCT_INFO),
            t0 + Duration::from_millis(1400),
        );
        let pi = out
            .iter()
            .find(|f| f.pgn == PGN_PRODUCT_INFO)
            .expect("product info emitted");
        assert_eq!(pi.src, addr);
        let d = si().decode(pi).unwrap();
        assert_eq!(
            d.field_ref(field::product_information::PRODUCT_CODE)
                .and_then(|f| f.value.as_i64()),
            Some(PRODUCT_CODE),
            "the Hercules acceptance gate"
        );
        assert_eq!(
            d.field_ref(field::product_information::MODEL_ID)
                .and_then(|f| f.value.as_str()),
            Some(MODEL_ID)
        );
    }

    #[test]
    fn relays_latched_source_attitude_under_our_address() {
        let mut m = Motion::new();
        let t0 = Instant::now();
        let addr = drive_to_claimed(&mut m, t0);
        // A third-party attitude source at src 40.
        let out = m.process(&attitude(40), t0 + Duration::from_millis(1400));
        let relayed: Vec<_> = out
            .iter()
            .filter(|f| f.pgn == PGN_ATTITUDE && f.src == addr)
            .collect();
        assert_eq!(relayed.len(), 1, "relayed once, from our address");
        assert_eq!(relayed[0].data.len(), 8);
        // A different source is ignored once one is latched.
        let out = m.process(&attitude(41), t0 + Duration::from_millis(1500));
        assert!(out.iter().all(|f| f.pgn != PGN_ATTITUDE || f.src != addr));
    }

    #[test]
    fn does_not_relay_its_own_reemission() {
        let mut m = Motion::new();
        let t0 = Instant::now();
        let addr = drive_to_claimed(&mut m, t0);
        // Our own re-emitted frame (src == our address) fed back must not
        // latch as the source nor loop.
        let out = m.process(&attitude(addr), t0 + Duration::from_millis(1400));
        assert!(out.iter().all(|f| f.pgn != PGN_ATTITUDE || f.src != addr));
        assert_eq!(m.source, None, "own frame never latches as the source");
    }

    #[test]
    fn answers_address_claim_request() {
        let mut m = Motion::new();
        let t0 = Instant::now();
        let addr = drive_to_claimed(&mut m, t0);
        let out = m.process(
            &request(9, ADDR_GLOBAL, PGN_ISO_ADDRESS_CLAIM),
            t0 + Duration::from_millis(1400),
        );
        let c = out
            .iter()
            .find(|f| f.pgn == PGN_ISO_ADDRESS_CLAIM)
            .expect("claim answered");
        assert_eq!(c.src, addr);
    }
}
