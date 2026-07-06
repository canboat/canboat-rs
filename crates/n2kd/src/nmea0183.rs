// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! NMEA 0183 conversion from analyzer name-value JSON lines.
//!
//! This is now a thin input adapter: [`convert`] rebuilds each JSON
//! line into a [`canboat_core::DecodedPgn`] (via
//! [`canboat_core::json_to_decoded`]) and delegates to the shared
//! struct-path converter [`crate::decoded::convert_nmea0183`] — the
//! exact code the live `server` pipeline runs, so a JSON stream and a
//! live device produce identical sentences. The per-PGN sentence
//! coverage (RSA/HDG/VHW/DPT/VLW/VTG/GLL/RMC/GSA/MWV/MTW) therefore
//! lives once, in [`crate::decoded`].
//!
//! What still lives here is [`RateLimiter`] — the per-(src, rate-type)
//! 1 Hz gate and the SOG/COG cache — which both this path and the
//! `decoded` converter share.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use canboat_core::PgnDatabase;

use crate::decoded::{self, Handles};

/// Per-(src, rate-type) "this is the last time we let one through"
/// timestamps. Mirrors canboat's `rateLimitPassed[256][RATE_COUNT]`.
///
/// Also carries the single-slot SOG/COG cache that canboat C keeps as
/// `g_sog` / `g_cog` globals — refreshed on PGN 129026 and consumed by
/// the PGN 129029 handler when emitting RMC — and the cycling
/// multi-fragment AIVDM sequence id counter (`gps_ais.c::sequenceId`).
pub struct RateLimiter {
    last_passed: [[Option<Instant>; RATE_COUNT]; 256],
    enabled: bool,
    /// `(sog_ms, cog_deg, captured_at)` — None until we've seen at
    /// least one PGN 129026. Only honoured for ≤ 1s after capture.
    last_sog_cog: Option<(f64, f64, Instant)>,
    /// Cycling 0..9 — the next multi-fragment AIVDM message bumps
    /// this and uses the resulting digit as its sequence id, matching
    /// canboat C's `sequenceId` static in `gps_ais.c::aisToNmea0183`.
    pub ais_seq: u8,
}

/// Number of distinct rate-limited sentence classes — the width of the
/// per-source `last_passed` table. Matches [`crate::decoded::Rate`],
/// which owns the PGN → slot mapping the struct-path converter uses.
const RATE_COUNT: usize = 10;

impl RateLimiter {
    pub fn new(enabled: bool) -> Self {
        Self {
            last_passed: [[None; RATE_COUNT]; 256],
            enabled,
            last_sog_cog: None,
            ais_seq: 0,
        }
    }

    /// `true` if rate-limiting is on. Used by the `decoded` module's
    /// `should_drop_fast` shim so it can early-out when disabled
    /// without rebuilding the limiter's clock state.
    #[inline]
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// Direct slot access for [`crate::decoded`]. `src` is bounds-
    /// checked to `< 256` by its `u8` type; `rate` is indexed against
    /// `RATE_COUNT` and the caller is expected to pass a valid one.
    #[inline]
    pub(crate) fn last_passed_slot(&mut self, src: usize, rate: usize) -> &mut Option<Instant> {
        &mut self.last_passed[src][rate]
    }

    /// Refresh the single-slot SOG / COG cache that the `position`
    /// handler (when it gets struct-path support in a later phase)
    /// will consume for RMC emission.
    #[inline]
    pub(crate) fn record_sog_cog(&mut self, sog_ms: f64, cog_deg: f64) {
        self.last_sog_cog = Some((sog_ms, cog_deg, Instant::now()));
    }

    /// `(sog_ms, cog_deg)` if [`Self::record_sog_cog`] was called
    /// within the last second.
    #[inline]
    pub(crate) fn recent_sog_cog(&self) -> Option<(f64, f64)> {
        let (sog, cog, ts) = self.last_sog_cog?;
        if ts.elapsed() < Duration::from_secs(1) {
            Some((sog, cog))
        } else {
            None
        }
    }
}

/// Convert one analyzer name-value JSON line into zero or more NMEA
/// 0183 sentences, appending each to `out`. Returns the number of
/// sentences emitted.
///
/// This is a thin input adapter: the line is rebuilt into a
/// [`DecodedPgn`] and handed to the shared struct-path converter
/// ([`crate::decoded::convert_nmea0183`]) — literally the same code the
/// live `server` pipeline runs. The only n2kd-specific step is the
/// JSON → `DecodedPgn` parse.
pub fn convert(out: &mut String, msg: &str, rate_limiter: &mut RateLimiter) -> usize {
    let Some(decoded) = canboat_core::json_to_decoded(msg, PgnDatabase::embedded()) else {
        return 0;
    };
    decoded::convert_nmea0183(out, &decoded, rate_limiter, handles())
}

/// The pre-resolved [`Handles`] the struct-path converter needs, built
/// once against the embedded schema.
fn handles() -> &'static Handles {
    static HANDLES: OnceLock<Handles> = OnceLock::new();
    HANDLES.get_or_init(|| Handles::new(PgnDatabase::embedded()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdg_format() {
        // Analyzer name-value JSON: angle fields already in degrees,
        // the `Reference` lookup as `{"value":N,"name":...}`.
        let msg = r#"{"pgn":127250,"src":7,"fields":{"Heading":90.0,"Reference":{"value":1,"name":"Magnetic"},"Deviation":2.0,"Variation":-3.0}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(false);
        let n = convert(&mut out, msg, &mut rl);
        assert_eq!(n, 1);
        assert!(out.starts_with("$AH"), "got {out}");
        assert!(out.contains("HDG,90.0,2.0,E,3.0,W*"));
        assert!(out.ends_with("\r\n"));
    }

    #[test]
    fn mwv_apparent_wind() {
        let msg = r#"{"pgn":130306,"src":7,"fields":{"Wind Speed":5.0,"Wind Angle":90.0,"Reference":{"value":2,"name":"Apparent"}}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(false);
        convert(&mut out, msg, &mut rl);
        assert!(out.contains("MWV,90.0,R,18.0,K,A*"), "got {out}");
    }

    #[test]
    fn dpt_format() {
        let msg = r#"{"pgn":128267,"src":3,"fields":{"Depth":12.3,"Offset":0.5}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(false);
        convert(&mut out, msg, &mut rl);
        assert!(out.contains("DPT,12.3,0.5*"), "got {out}");
    }

    #[test]
    fn vtg_format() {
        // 5.144 m/s ≈ 10 kn; COG already in degrees.
        let msg = r#"{"pgn":129026,"src":3,"fields":{"SOG":5.144,"COG":180.0}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(false);
        convert(&mut out, msg, &mut rl);
        assert!(out.contains("VTG,180.0,T"), "got {out}");
        assert!(out.contains(",10.00,N,"), "got {out}");
    }

    #[test]
    fn rate_limit_drops_second_call_within_a_second() {
        let msg = r#"{"pgn":127250,"src":7,"fields":{"Heading":0.0,"Reference":{"value":1,"name":"Magnetic"}}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(true);
        assert_eq!(convert(&mut out, msg, &mut rl), 1);
        let len_after_first = out.len();
        // Same src + same rate-type within a second → dropped.
        convert(&mut out, msg, &mut rl);
        assert_eq!(out.len(), len_after_first);
    }
}
