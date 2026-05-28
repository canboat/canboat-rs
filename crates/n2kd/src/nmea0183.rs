//! Convert analyzer JSON lines to NMEA 0183 sentences.
//!
//! Mirrors `canboat/n2kd/nmea0183.c` + the GPS sentences in
//! `gps_ais.c`. Each handler takes the JSON line and appends the
//! ready-to-send NMEA 0183 sentence (with checksum) onto `out`.
//!
//! Coverage (the ones canboat C ships and we replicate):
//!
//!   126992 System Time         → ZDA
//!   127245 Rudder              → RSA
//!   127250 Vessel Heading      → HDG / HDT / HDM
//!   128259 Water Speed         → VHW
//!   128267 Water Depth         → DPT
//!   128275 Distance Log        → VLW
//!   129026 SOG / COG           → VTG
//!   129029 GNSS Position       → GLL (+ RMC when SOG/COG were
//!                                  recently cached)
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
pub struct RateLimiter {
    last_passed: [[Option<Instant>; RATE_COUNT]; 256],
    enabled: bool,
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
    SystemTime,
}
const RATE_COUNT: usize = 11;

impl RateLimiter {
    pub fn new(enabled: bool) -> Self {
        Self {
            last_passed: [[None; RATE_COUNT]; 256],
            enabled,
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
        126992 => system_time(out, src, msg),
        127245 => rudder(out, src, msg),
        127250 => vessel_heading(out, src, msg),
        128259 => water_speed(out, src, msg),
        128267 => water_depth(out, src, msg),
        128275 => distance_log(out, src, msg),
        129026 => sog_cog(out, src, msg),
        129029 => position(out, src, msg),
        129539 => gps_dop(out, src, msg),
        130306 => wind_data(out, src, msg),
        130311 => environmental(out, src, msg),
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
        126992 => Rate::SystemTime,
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
    // canboat C formats the knots field with `%1f` which is a typo —
    // it ends up with no width / precision. We use `%.1f` for sanity.
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

fn sog_cog(out: &mut String, src: u8, msg: &str) {
    let Some(sog) = json::number(msg, "SOG") else {
        return;
    };
    let Some(cog) = json::number(msg, "COG") else {
        return;
    };
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

fn position(out: &mut String, src: u8, msg: &str) {
    let Some(lat) = json::number(msg, "Latitude") else {
        return;
    };
    let Some(lon) = json::number(msg, "Longitude") else {
        return;
    };
    let (lat_str, lat_hem) = latlon_to_nmea(lat, true);
    let (lon_str, lon_hem) = latlon_to_nmea(lon, false);
    // Plain GLL (no time / status fields).
    create(
        out,
        src,
        &format!("GLL,{lat_str},{lat_hem},{lon_str},{lon_hem},,A"),
    );
}

fn gps_dop(out: &mut String, src: u8, msg: &str) {
    let mode = json::value(msg, "Actual Mode")
        .map(|s| s.chars().next().unwrap_or(' '))
        .unwrap_or(' ');
    let p = json::value(msg, "PDOP").unwrap_or("");
    let h = json::value(msg, "HDOP").unwrap_or("");
    let v = json::value(msg, "VDOP").unwrap_or("");
    create(out, src, &format!("GSA,M,{mode},,,,,,,,,,,,,{p},{h},{v}"));
}

fn system_time(out: &mut String, src: u8, msg: &str) {
    let date = json::value(msg, "Date").unwrap_or("");
    let time = json::value(msg, "Time").unwrap_or("");
    // Expect `YYYY.MM.DD` and `HH:MM:SS[.SSSS]`.
    let mut date_parts = date.split('.');
    let (y, mo, d) = match (date_parts.next(), date_parts.next(), date_parts.next()) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return,
    };
    let mut time_parts = time.split(':');
    let (h, mi, s) = match (time_parts.next(), time_parts.next(), time_parts.next()) {
        (Some(h), Some(m), Some(s)) => (h, m, s),
        _ => return,
    };
    create(
        out,
        src,
        &format!("ZDA,{h:0>2}{mi:0>2}{s},{d},{mo},{y:0>4},,"),
    );
}

/// `±DDD.dddddd` decimal degrees → `DDMM.mmmm`/`DDDMM.mmmm` plus a
/// hemisphere character. Matches canboat's `convert2kCoordinateToNMEA0183`.
fn latlon_to_nmea(decimal: f64, is_lat: bool) -> (String, char) {
    let abs = decimal.abs();
    let deg = abs.floor() as u32;
    let minutes = (abs - deg as f64) * 60.0;
    let width = if is_lat { 2 } else { 3 };
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
    (
        format!("{deg:0>width$}{:07.4}", minutes, width = width),
        hem,
    )
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
