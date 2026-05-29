//! Convert analyzer JSON lines to NMEA 0183 sentences.
//!
//! Mirrors `canboat/n2kd/nmea0183.c` + the GPS sentences in
//! `gps_ais.c`. Each handler takes the JSON line and appends the
//! ready-to-send NMEA 0183 sentence (with checksum) onto `out`.
//!
//! Coverage (the ones canboat C ships and we replicate):
//!
//!   127245 Rudder              → RSA
//!   127250 Vessel Heading      → HDG / HDT / HDM
//!   128259 Water Speed         → VHW
//!   128267 Water Depth         → DPT
//!   128275 Distance Log        → VLW
//!   129026 SOG / COG           → VTG (also caches sog/cog for RMC)
//!   129029 GNSS Position       → GLL + RMC (RMC reuses sog/cog
//!                                  cached from a recent 129026)
//!   129539 GPS DOP             → GSA
//!   130306 Wind Data           → MWV
//!   130311 Environmental       → MTW
//!
//! AIS-specific PGNs (129038/039/040/041/793/794/798/801/802/809/810)
//! pass through to the AIS port unchanged; full AIVDM bit-packing is
//! a separate undertaking and lives in `gps_ais.c` upstream.

use std::time::{Duration, Instant};

use crate::json;

/// m/s → knots.
const MS_TO_KNOTS: f64 = 1.943_84;
/// m/s → km/h.
const MS_TO_KMH: f64 = 3.6;
/// m → nautical miles.
const M_TO_NM: f64 = 1.0 / 1852.0;

/// Decode a `Reference` field — both `1` (canboat -nv) and `"Magnetic"`
/// (canboat default) get back to the integer enum value canboat C uses.
/// Returns -1 if the field is missing or unrecognised.
fn ref_value(msg: &str, field: &str, names: &[(&str, i64)]) -> i64 {
    if let Some(n) = json::lookup_int(msg, field) {
        return n;
    }
    if let Some(s) = json::value(msg, field) {
        for (name, val) in names {
            if s.starts_with(name) {
                return *val;
            }
        }
    }
    -1
}

/// Heading-reference name → numeric value. PGN 127250's
/// `Reference` lookup: 0=True, 1=Magnetic.
const HEADING_REF_NAMES: &[(&str, i64)] = &[("True", 0), ("Magnetic", 1)];
/// Wind-reference name → numeric value. PGN 130306's `Reference`
/// lookup is the WIND_REFERENCE enum:
///   0 True (ground referenced to North)
///   1 Magnetic (ground referenced to Magnetic North)
///   2 Apparent
///   3 True (boat referenced)
///   4 True (water referenced)
const WIND_REF_NAMES: &[(&str, i64)] = &[
    ("True (ground referenced to North)", 0),
    ("Magnetic", 1),
    ("Apparent", 2),
    ("True (boat referenced)", 3),
    ("True (water referenced)", 4),
];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rate {
    VesselHeading = 0,
    WindData,
    WaterDepth,
    WaterSpeed,
    Rudder,
    GpsSpeed,
    GpsDop,
    GpsPosition,
    Environmental,
    DistanceLog,
}
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

    /// Returns `true` if the caller should *drop* this conversion
    /// (rate-limit not yet expired). Returns `false` if we should
    /// emit. Updates the timestamp on emit.
    fn should_drop(&mut self, src: u8, rate: Rate) -> bool {
        if !self.enabled {
            return false;
        }
        let now = Instant::now();
        let slot = &mut self.last_passed[src as usize][rate as usize];
        if let Some(prev) = *slot {
            if now.duration_since(prev) < Duration::from_secs(1) {
                return true;
            }
        }
        *slot = Some(now);
        false
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

/// Convert one analyzer JSON line into zero or more NMEA 0183
/// sentences, appending each to `out`. Returns the number of
/// sentences emitted.
pub fn convert(out: &mut String, msg: &str, rate_limiter: &mut RateLimiter) -> usize {
    let Some(pgn) = json::int(msg, "pgn") else {
        return 0;
    };
    let src = json::int(msg, "src").unwrap_or(0) as u8;
    let rate = pgn_to_rate(pgn);
    if let Some(rt) = rate {
        if rate_limiter.should_drop(src, rt) {
            return 0;
        }
    }
    let before = out.len();
    match pgn {
        127245 => rudder(out, src, msg),
        127250 => vessel_heading(out, src, msg),
        128259 => water_speed(out, src, msg),
        128267 => water_depth(out, src, msg),
        128275 => distance_log(out, src, msg),
        129026 => sog_cog(out, src, msg, rate_limiter),
        129029 => position(out, src, msg, rate_limiter),
        129539 => gps_dop(out, src, msg),
        130306 => wind_data(out, src, msg),
        130311 => environmental(out, src, msg),
        // PGN 126992 (System Time) intentionally has no handler:
        // canboat C never emits ZDA either, opting to emit
        // date/time through RMC alongside the GPS position fix.
        _ => {}
    }
    if out.len() > before {
        1
    } else {
        0
    }
}

fn pgn_to_rate(pgn: i64) -> Option<Rate> {
    Some(match pgn {
        127250 => Rate::VesselHeading,
        130306 => Rate::WindData,
        128267 => Rate::WaterDepth,
        128259 => Rate::WaterSpeed,
        127245 => Rate::Rudder,
        129026 => Rate::GpsSpeed,
        129539 => Rate::GpsDop,
        129029 => Rate::GpsPosition,
        130311 => Rate::Environmental,
        128275 => Rate::DistanceLog,
        _ => return None,
    })
}

/// Wrap `body` as `$<talker><sentence>*<XX>\r\n`. The two-letter
/// talker is built from `src` the same way canboat does: high nibble
/// → 'A'..'Q' (skipping 'P' = proprietary), low nibble → 'A'..'P'.
fn create(out: &mut String, src: u8, body: &str) {
    let mut first = (b'A' + ((src >> 4) & 0x0f)) as char;
    let second = (b'A' + (src & 0x0f)) as char;
    if first >= 'P' {
        first = (first as u8 + 1) as char;
    }
    let start = out.len();
    out.push('$');
    out.push(first);
    out.push(second);
    out.push_str(body);
    let mut chk = 0u8;
    // Checksum: XOR of everything *between* the leading `$` and the
    // `*` — i.e. starts at start+1, ends at out.len()-1 just after we
    // appended body (we haven't appended the `*` yet).
    for b in &out.as_bytes()[start + 1..] {
        chk ^= *b;
    }
    out.push_str(&format!("*{chk:02X}\r\n"));
}

fn vessel_heading(out: &mut String, src: u8, msg: &str) {
    // Heading / Deviation / Variation arrive already converted to
    // degrees in canboat's default JSON output, so no rad→deg here.
    // (Canboat C's `-si` mode would have the SI rad form, but our
    // analyzer doesn't expose that yet.)
    let Some(heading) = json::number(msg, "Heading") else {
        return;
    };
    let reference = ref_value(msg, "Reference", HEADING_REF_NAMES);
    let dev = json::number(msg, "Deviation");
    let var = json::number(msg, "Variation");
    if let (Some(d), Some(v)) = (dev, var) {
        if reference == 1 {
            // HDG: heading,dev,dir,var,dir
            create(
                out,
                src,
                &format!(
                    "HDG,{:.1},{:.1},{},{:.1},{}",
                    heading,
                    d.abs(),
                    if d < 0.0 { 'W' } else { 'E' },
                    v.abs(),
                    if v < 0.0 { 'W' } else { 'E' },
                ),
            );
            return;
        }
    }
    if reference == 0 {
        create(out, src, &format!("HDT,{:.1},T", heading));
    } else if reference == 1 {
        create(out, src, &format!("HDM,{:.1},M", heading));
    }
}

fn wind_data(out: &mut String, src: u8, msg: &str) {
    let Some(speed) = json::number(msg, "Wind Speed") else {
        return;
    };
    let Some(angle) = json::number(msg, "Wind Angle") else {
        return;
    };
    let reference = ref_value(msg, "Reference", WIND_REF_NAMES);
    let ref_char = match reference {
        2 => 'R', // Apparent
        3 => 'T', // True (boat referenced)
        _ => return,
    };
    create(
        out,
        src,
        &format!("MWV,{:.1},{ref_char},{:.1},K,A", angle, speed * MS_TO_KMH),
    );
}

fn water_depth(out: &mut String, src: u8, msg: &str) {
    let Some(depth) = json::number(msg, "Depth") else {
        return;
    };
    let offset = json::number(msg, "Offset");
    let body = match offset {
        Some(o) => format!("DPT,{:.1},{:.1}", depth, o),
        None => format!("DPT,{:.1},", depth),
    };
    create(out, src, &body);
}

fn water_speed(out: &mut String, src: u8, msg: &str) {
    let Some(s) = json::number(msg, "Speed Water Referenced") else {
        return;
    };
    create(
        out,
        src,
        &format!("VHW,,T,,M,{:.1},N,{:.1},K", s * MS_TO_KNOTS, s * MS_TO_KMH),
    );
}

fn environmental(out: &mut String, src: u8, msg: &str) {
    // MTW only fires for the Water Temperature sub-type (source == 0).
    let Some(source) = json::lookup_int(msg, "Temperature Source") else {
        return;
    };
    if source != 0 {
        return;
    }
    let Some(t) = json::number(msg, "Temperature") else {
        return;
    };
    // canboat's `TEMP_K_TO_C`: if `t < 173.15` it's assumed already
    // in Celsius (a hack accommodating one buggy device).
    let celsius = if t < 173.15 { t } else { t - 273.15 };
    create(out, src, &format!("MTW,{celsius:.1},C"));
}

fn distance_log(out: &mut String, src: u8, msg: &str) {
    let Some(log) = json::number(msg, "Log") else {
        return;
    };
    let Some(trip) = json::number(msg, "Trip Log") else {
        return;
    };
    create(
        out,
        src,
        &format!("VLW,{:.1},N,{:.1},N", log * M_TO_NM, trip * M_TO_NM),
    );
}

fn rudder(out: &mut String, src: u8, msg: &str) {
    let Some(pos) = json::number(msg, "Position") else {
        return;
    };
    // canboat: $RSA,<-pos>,A,,F (the empty starboard field is
    // intentional — the C sets only the main sensor).
    create(out, src, &format!("RSA,{:.1},A,,F", -pos));
}

fn sog_cog(out: &mut String, src: u8, msg: &str, rl: &mut RateLimiter) {
    let Some(sog) = json::number(msg, "SOG") else {
        return;
    };
    let Some(cog) = json::number(msg, "COG") else {
        return;
    };
    // Cache for the next 129029 RMC. Single slot, latest-wins —
    // matches canboat C's `g_sog` / `g_cog` globals.
    rl.last_sog_cog = Some((sog, cog, Instant::now()));
    create(
        out,
        src,
        &format!(
            "VTG,{:.1},T,,M,{:.2},N,{:.2},K",
            cog,
            sog * MS_TO_KNOTS,
            sog * MS_TO_KMH
        ),
    );
}

fn position(out: &mut String, src: u8, msg: &str, rl: &RateLimiter) {
    let Some(lat) = json::number(msg, "Latitude") else {
        return;
    };
    let Some(lon) = json::number(msg, "Longitude") else {
        return;
    };
    let (lat_str, lat_hem) = latlon_to_nmea(lat, true);
    let (lon_str, lon_hem) = latlon_to_nmea(lon, false);

    // Time is `HH:MM:SS.SSSS` (or `:SS` with no fractional). Strip
    // colons and cap to 2 decimal places for the NMEA `hhmmss.ss` slot.
    let time_str = nmea_time_string(json::value_or_name(msg, "Time").unwrap_or(""));
    // Date is `YYYY.MM.DD` from canboat. Format as `DDMMYY`.
    let date_str = nmea_date_string(json::value_or_name(msg, "Date").unwrap_or(""));

    // GLL: $...GLL,llll.llll,N,yyyyy.yyyy,E,hhmmss.ss,A
    create(
        out,
        src,
        &format!("GLL,{lat_str},{lat_hem},{lon_str},{lon_hem},{time_str},A"),
    );

    // RMC: time, status, lat, NS, lon, EW, sog(knots), cog, date, var, varhem, mode.
    // Only fill in SOG / COG if we saw a 129026 within the last second.
    let (sog_str, cog_str) = match rl.last_sog_cog {
        Some((sog, cog, ts)) if ts.elapsed() < Duration::from_secs(1) => {
            (format!("{:.2}", sog * MS_TO_KNOTS), format!("{:.1}", cog))
        }
        _ => (String::new(), String::new()),
    };
    create(
        out,
        src,
        &format!(
            "RMC,{time_str},A,{lat_str},{lat_hem},{lon_str},{lon_hem},{sog_str},{cog_str},{date_str},,,A"
        ),
    );
}

/// `12:06:58.0000` → `120658`. Strips colons and then trims trailing
/// zeros plus the bare decimal point, mirroring canboat's
/// `cleanupTimeString` in `gps_ais.c`. So `120657.0000` → `120657`,
/// `120657.5000` → `120657.5`.
fn nmea_time_string(time: &str) -> String {
    if time.is_empty() {
        return String::new();
    }
    let mut s: String = time.chars().filter(|c| *c != ':').collect();
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// `2022.09.10` → `100922`. Day-month-year, two digits each.
fn nmea_date_string(date: &str) -> String {
    let mut parts = date.split('.');
    let y = parts.next().unwrap_or("");
    let mo = parts.next().unwrap_or("");
    let d = parts.next().unwrap_or("");
    if y.is_empty() || mo.is_empty() || d.is_empty() {
        return String::new();
    }
    let y2 = &y[y.len().saturating_sub(2)..];
    format!("{d:0>2}{mo:0>2}{y2:0>2}")
}

fn gps_dop(out: &mut String, src: u8, msg: &str) {
    // GSA mode is the integer code (1/2/3) rendered as a single digit,
    // matching canboat's getNmea0183ModeChar — `-nv` wraps it in a
    // `{value,name}` object, so unwrap it first. Missing field → empty
    // (canboat C leaves the slot blank rather than emitting a space).
    let mode: String = json::lookup_int(msg, "Actual Mode")
        .and_then(|n| char::from_digit(n as u32, 10))
        .map(|c| c.to_string())
        .unwrap_or_default();
    let p = json::value(msg, "PDOP").unwrap_or("");
    let h = json::value(msg, "HDOP").unwrap_or("");
    let v = json::value(msg, "VDOP").unwrap_or("");
    create(out, src, &format!("GSA,M,{mode},,,,,,,,,,,,,{p},{h},{v}"));
}

/// `±DDD.dddddd` decimal degrees → `DDMM.mmmm` (no zero-padded
/// degrees — matches canboat's `convert2kCoordinateToNMEA0183`, which
/// formats `degrees * 100 + minutes` with `%.4f` and lets `printf`
/// trim leading zeros). Per the NMEA 0183 spec, longitude should be
/// `DDDMM.mmmm` (3-digit degrees, zero-padded) — canboat C's
/// formatter doesn't pad, and we follow it for byte parity.
fn latlon_to_nmea(decimal: f64, is_lat: bool) -> (String, char) {
    let abs = decimal.abs();
    let deg = abs.floor();
    let combined = deg * 100.0 + (abs - deg) * 60.0;
    let hem = if is_lat {
        if decimal < 0.0 {
            'S'
        } else {
            'N'
        }
    } else if decimal < 0.0 {
        'W'
    } else {
        'E'
    };
    (format!("{combined:.4}"), hem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdg_format() {
        // Analyzer JSON arrives with degree values and a stringified
        // `Reference` lookup, not the SI radians + integer enum that
        // canboat-C-internally trades in.
        let msg = r#"{"pgn":127250,"src":7,"fields":{"Heading":90.0,"Reference":"Magnetic","Deviation":2.0,"Variation":-3.0}}"#;
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
        let msg = r#"{"pgn":130306,"src":7,"fields":{"Wind Speed":5.0,"Wind Angle":90.0,"Reference":"Apparent"}}"#;
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
        let msg = r#"{"pgn":127250,"src":7,"fields":{"Heading":0.0,"Reference":"Magnetic"}}"#;
        let mut out = String::new();
        let mut rl = RateLimiter::new(true);
        assert_eq!(convert(&mut out, msg, &mut rl), 1);
        let len_after_first = out.len();
        // Same src + same rate-type within a second → dropped.
        convert(&mut out, msg, &mut rl);
        assert_eq!(out.len(), len_after_first);
    }
}
