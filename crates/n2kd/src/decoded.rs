//! Struct-passing converters that take `&DecodedPgn` directly
//! instead of re-parsing a JSON string. Lets `n2kd-inproc` skip the
//! analyzer JSON → n2kd JSON-parse round trip when the two stages
//! run in the same process.
//!
//! Phase 3 scope: the highest-volume non-AIS PGNs the canboat n2kd
//! benchmark workload emits. Anything not listed in
//! [`Handles::supports`] falls back through the existing
//! `nmea0183::convert` JSON path so n2kd-inproc still produces a
//! complete output stream.
//!
//! The handler bodies mirror `nmea0183.rs` line-for-line — same
//! sentences, same field formats — but pull values via
//! [`canboat_core::FieldHandle`] in `O(1)` instead of via substring
//! scans through a JSON line.

use std::time::Instant;

use canboat_core::{DecodedPgn, FieldHandle, FieldValue, PgnDatabase};

use crate::nmea0183::RateLimiter;

/// m/s → knots.
const MS_TO_KNOTS: f64 = 1.943_84;
/// m/s → km/h.
const MS_TO_KMH: f64 = 3.6;

/// PGN ids the struct-path supports today. Anything else falls back
/// to the JSON path.
const SUPPORTED_PGNS: &[u32] = &[
    127245, 127250, 128259, 128267, 128275, 129026, 129029, 129539, 130306, 130311,
];

/// All `FieldHandle`s the struct-path needs. Built once at startup
/// from the same `PgnDatabase` the decoder uses, then shared
/// (immutably) across every decode/convert pair for the rest of the
/// process. ~30 handles × 16 bytes each is essentially free vs. the
/// JSON-parse savings.
pub struct Handles {
    // PGN 127250 Vessel Heading.
    vh_heading: FieldHandle,
    vh_deviation: FieldHandle,
    vh_variation: FieldHandle,
    vh_reference: FieldHandle,
    // PGN 130306 Wind Data.
    wd_wind_speed: FieldHandle,
    wd_wind_angle: FieldHandle,
    wd_reference: FieldHandle,
    // PGN 129026 SOG / COG.
    sc_sog: FieldHandle,
    sc_cog: FieldHandle,
    // PGN 127245 Rudder.
    ru_position: FieldHandle,
    // PGN 128259 Speed.
    sp_speed_water_referenced: FieldHandle,
    // PGN 128267 Water Depth.
    wd_depth: FieldHandle,
    wd_offset: FieldHandle,
    // PGN 128275 Distance Log.
    dl_log: FieldHandle,
    dl_trip_log: FieldHandle,
    // PGN 129029 GNSS Position Data.
    gp_lat: FieldHandle,
    gp_lon: FieldHandle,
    gp_date: FieldHandle,
    gp_time: FieldHandle,
    // PGN 129539 GNSS DOPs. canboat.json has HDOP/VDOP/TDOP — no
    // PDOP field is defined, so the JSON path's `json::value("PDOP")`
    // always returned None. We model the same here by simply
    // emitting an empty PDOP slot in the GSA sentence.
    dops_actual_mode: FieldHandle,
    dops_hdop: FieldHandle,
    dops_vdop: FieldHandle,
    // PGN 130311 Environmental Parameters.
    env_temp_source: FieldHandle,
    env_temp: FieldHandle,
}

impl Handles {
    /// Resolve every handle this module uses. Panics on missing
    /// fields — those would only happen if the PGN database the
    /// binary linked against differs from the canboat.json the
    /// handler bodies were written for.
    pub fn new(db: &PgnDatabase) -> Self {
        let f = |pgn: &str, field: &str| {
            db.field(pgn, field)
                .unwrap_or_else(|| panic!("missing field {pgn:?}.{field:?} in PGN database"))
        };
        Self {
            vh_heading: f("vesselHeading", "heading"),
            vh_deviation: f("vesselHeading", "deviation"),
            vh_variation: f("vesselHeading", "variation"),
            vh_reference: f("vesselHeading", "reference"),
            wd_wind_speed: f("windData", "windSpeed"),
            wd_wind_angle: f("windData", "windAngle"),
            wd_reference: f("windData", "reference"),
            sc_sog: f("cogSogRapidUpdate", "sog"),
            sc_cog: f("cogSogRapidUpdate", "cog"),
            ru_position: f("rudder", "position"),
            sp_speed_water_referenced: f("speed", "speedWaterReferenced"),
            wd_depth: f("waterDepth", "depth"),
            wd_offset: f("waterDepth", "offset"),
            dl_log: f("distanceLog", "log"),
            dl_trip_log: f("distanceLog", "tripLog"),
            gp_lat: f("gnssPositionData", "latitude"),
            gp_lon: f("gnssPositionData", "longitude"),
            gp_date: f("gnssPositionData", "date"),
            gp_time: f("gnssPositionData", "time"),
            dops_actual_mode: f("gnssDops", "actualMode"),
            dops_hdop: f("gnssDops", "hdop"),
            dops_vdop: f("gnssDops", "vdop"),
            env_temp_source: f("environmentalParameters", "temperatureSource"),
            env_temp: f("environmentalParameters", "temperature"),
        }
    }

    /// `true` if this module has a handler for `pgn`. n2kd-inproc
    /// uses this to decide whether to serialize JSON.
    #[inline]
    pub fn supports(pgn: u32) -> bool {
        SUPPORTED_PGNS.contains(&pgn)
    }
}

/// Top-level dispatcher — mirrors `nmea0183::convert`'s match table.
/// Returns the number of NMEA 0183 sentences appended to `out`.
pub fn convert_nmea0183(
    out: &mut String,
    decoded: &DecodedPgn,
    rl: &mut RateLimiter,
    h: &Handles,
) -> usize {
    let src = decoded.src;
    let pgn = decoded.pgn;
    let rate = pgn_to_rate(pgn);
    if let Some(rt) = rate {
        if rl.should_drop_fast(src, rt) {
            return 0;
        }
    }
    let before = out.len();
    match pgn {
        127245 => rudder(out, src, decoded, h),
        127250 => vessel_heading(out, src, decoded, h),
        128259 => water_speed(out, src, decoded, h),
        128267 => water_depth(out, src, decoded, h),
        128275 => distance_log(out, src, decoded, h),
        129026 => sog_cog(out, src, decoded, h, rl),
        129029 => position(out, src, decoded, h, rl),
        129539 => gps_dop(out, src, decoded, h),
        130306 => wind_data(out, src, decoded, h),
        130311 => environmental(out, src, decoded, h),
        _ => {}
    }
    if out.len() > before {
        1
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Rate {
    VesselHeading,
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

fn pgn_to_rate(pgn: u32) -> Option<Rate> {
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

/// `Rate` → index into `RateLimiter::last_passed_slot`. Must match
/// the discriminant order in `nmea0183.rs` since the two paths
/// share the same limiter state.
fn rate_index(r: Rate) -> usize {
    match r {
        Rate::VesselHeading => 0,
        Rate::WindData => 1,
        Rate::WaterDepth => 2,
        Rate::WaterSpeed => 3,
        Rate::Rudder => 4,
        Rate::GpsSpeed => 5,
        Rate::GpsDop => 6,
        Rate::GpsPosition => 7,
        Rate::Environmental => 8,
        Rate::DistanceLog => 9,
    }
}

/// Thin shim into the existing `RateLimiter` machinery — we
/// duplicate just enough to translate our `Rate` enum into the
/// position used by `nmea0183.rs`. Keeps the limiter's per-source
/// state shared between the two paths.
impl RateLimiter {
    pub(crate) fn should_drop_fast(&mut self, src: u8, rate: Rate) -> bool {
        if !self.enabled() {
            return false;
        }
        let slot = self.last_passed_slot(src as usize, rate_index(rate));
        let now = Instant::now();
        if let Some(prev) = *slot {
            if now.duration_since(prev) < std::time::Duration::from_secs(1) {
                return true;
            }
        }
        *slot = Some(now);
        false
    }
}

// =====================================================================
// Per-PGN handlers
// =====================================================================

fn vessel_heading(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let Some(heading) = decoded.field(&h.vh_heading).and_then(|f| f.value.as_f64()) else {
        return;
    };
    let reference = decoded
        .field(&h.vh_reference)
        .and_then(|f| f.value.lookup_value())
        .map(|v| v as i64)
        .unwrap_or(-1);
    let dev = decoded
        .field(&h.vh_deviation)
        .and_then(|f| f.value.as_f64());
    let var = decoded
        .field(&h.vh_variation)
        .and_then(|f| f.value.as_f64());
    if let (Some(d), Some(v)) = (dev, var) {
        if reference == 1 {
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

fn wind_data(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let Some(speed) = decoded
        .field(&h.wd_wind_speed)
        .and_then(|f| f.value.as_f64())
    else {
        return;
    };
    let Some(angle) = decoded
        .field(&h.wd_wind_angle)
        .and_then(|f| f.value.as_f64())
    else {
        return;
    };
    let reference = decoded
        .field(&h.wd_reference)
        .and_then(|f| f.value.lookup_value())
        .map(|v| v as i64)
        .unwrap_or(-1);
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

fn sog_cog(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles, rl: &mut RateLimiter) {
    let Some(sog) = decoded.field(&h.sc_sog).and_then(|f| f.value.as_f64()) else {
        return;
    };
    let Some(cog) = decoded.field(&h.sc_cog).and_then(|f| f.value.as_f64()) else {
        return;
    };
    // Cache the last (sog, cog) for the position handler's RMC
    // emission — same single-slot global behaviour as the JSON path.
    rl.record_sog_cog(sog, cog);
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

fn rudder(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let Some(pos) = decoded.field(&h.ru_position).and_then(|f| f.value.as_f64()) else {
        return;
    };
    create(out, src, &format!("RSA,{:.1},A,,F", -pos));
}

fn water_speed(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let Some(s) = decoded
        .field(&h.sp_speed_water_referenced)
        .and_then(|f| f.value.as_f64())
    else {
        return;
    };
    create(
        out,
        src,
        &format!("VHW,,T,,M,{:.1},N,{:.1},K", s * MS_TO_KNOTS, s * MS_TO_KMH),
    );
}

fn water_depth(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let Some(depth) = decoded.field(&h.wd_depth).and_then(|f| f.value.as_f64()) else {
        return;
    };
    let offset = decoded.field(&h.wd_offset).and_then(|f| f.value.as_f64());
    let body = match offset {
        Some(o) => format!("DPT,{:.1},{:.1}", depth, o),
        None => format!("DPT,{:.1},", depth),
    };
    create(out, src, &body);
}

fn distance_log(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    const M_TO_NM: f64 = 1.0 / 1852.0;
    let Some(log) = decoded.field(&h.dl_log).and_then(|f| f.value.as_f64()) else {
        return;
    };
    let Some(trip) = decoded.field(&h.dl_trip_log).and_then(|f| f.value.as_f64()) else {
        return;
    };
    create(
        out,
        src,
        &format!("VLW,{:.1},N,{:.1},N", log * M_TO_NM, trip * M_TO_NM),
    );
}

fn environmental(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    // MTW only fires for the Water Temperature sub-type (source == 0).
    let Some(source) = decoded
        .field(&h.env_temp_source)
        .and_then(|f| f.value.lookup_value())
    else {
        return;
    };
    if source != 0 {
        return;
    }
    let Some(t) = decoded.field(&h.env_temp).and_then(|f| f.value.as_f64()) else {
        return;
    };
    // canboat's `TEMP_K_TO_C`: if `t < 173.15` it's assumed already
    // in Celsius (a hack accommodating one buggy device).
    let celsius = if t < 173.15 { t } else { t - 273.15 };
    create(out, src, &format!("MTW,{celsius:.1},C"));
}

fn gps_dop(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles) {
    let mode: String = decoded
        .field(&h.dops_actual_mode)
        .and_then(|f| f.value.lookup_value())
        .and_then(|n| char::from_digit(n as u32, 10))
        .map(|c| c.to_string())
        .unwrap_or_default();
    // canboat.json's gnssDops doesn't carry a PDOP field — the JSON
    // path's `json::value(msg, "PDOP")` always returned None, so the
    // GSA slot is always empty. Match that.
    let pdop = String::new();
    let hdop = decoded
        .field(&h.dops_hdop)
        .and_then(|f| f.value.as_f64())
        .map(|v| format!("{v:.2}"))
        .unwrap_or_default();
    let vdop = decoded
        .field(&h.dops_vdop)
        .and_then(|f| f.value.as_f64())
        .map(|v| format!("{v:.2}"))
        .unwrap_or_default();
    create(
        out,
        src,
        &format!("GSA,M,{mode},,,,,,,,,,,,,{pdop},{hdop},{vdop}"),
    );
}

fn position(out: &mut String, src: u8, decoded: &DecodedPgn, h: &Handles, rl: &RateLimiter) {
    let Some(lat) = decoded.field(&h.gp_lat).and_then(|f| f.value.as_f64()) else {
        return;
    };
    let Some(lon) = decoded.field(&h.gp_lon).and_then(|f| f.value.as_f64()) else {
        return;
    };
    // Round to 7 decimal degrees BEFORE the degree-minute split so
    // we match the JSON path verbatim — that path goes through
    // analyzer's `%.7f` formatter and n2kd then parses the string
    // back, which is equivalent to a `round(v * 1e7) / 1e7` step.
    let lat = (lat * 1e7).round() / 1e7;
    let lon = (lon * 1e7).round() / 1e7;
    let (lat_str, lat_hem) = latlon_to_nmea(lat, true);
    let (lon_str, lon_hem) = latlon_to_nmea(lon, false);
    let time_str = decoded
        .field(&h.gp_time)
        .and_then(|f| match &f.value {
            FieldValue::Time { seconds, .. } => Some(*seconds),
            _ => None,
        })
        .map(|s| {
            let mut buf = String::with_capacity(13);
            // 0.0001-s resolution on Time → 4 fractional digits, then
            // canboat strips trailing zeros + bare decimal point.
            canboat_core::output::format_time(s, 4, false, &mut buf).ok();
            cleanup_time(buf)
        })
        .unwrap_or_default();
    let date_str = decoded
        .field(&h.gp_date)
        .and_then(|f| match &f.value {
            FieldValue::Date(d) => Some(*d),
            _ => None,
        })
        .map(|d| {
            let mut buf = String::with_capacity(10);
            canboat_core::output::format_date(d, &mut buf).ok();
            nmea_date_string(&buf)
        })
        .unwrap_or_default();

    create(
        out,
        src,
        &format!("GLL,{lat_str},{lat_hem},{lon_str},{lon_hem},{time_str},A"),
    );

    // RMC's sog/cog come from the cached PGN 129026 slot. If we
    // haven't seen one within the last second, leave the fields
    // blank — matches the JSON-path behaviour.
    let (sog_str, cog_str) = match rl.recent_sog_cog() {
        Some((sog, cog)) => (format!("{:.2}", sog * MS_TO_KNOTS), format!("{:.1}", cog)),
        None => (String::new(), String::new()),
    };
    create(
        out,
        src,
        &format!(
            "RMC,{time_str},A,{lat_str},{lat_hem},{lon_str},{lon_hem},{sog_str},{cog_str},{date_str},,,A"
        ),
    );
}

fn cleanup_time(mut s: String) -> String {
    // `12:06:58.0000` → `120658`. Mirror canboat's
    // `cleanupTimeString` in gps_ais.c.
    s.retain(|c| c != ':');
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

fn nmea_date_string(date: &str) -> String {
    // `2022.09.10` → `100922`. Day-month-year, two digits each.
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

// =====================================================================
// Local copy of the NMEA wrapping helper. Kept here so we don't have
// to expose `create`/`append_aivdm` from the existing module.
// =====================================================================

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
    for b in &out.as_bytes()[start + 1..] {
        chk ^= *b;
    }
    use std::fmt::Write as _;
    let _ = write!(out, "*{chk:02X}\r\n");
}

// `FieldValue::is_not_available` is used implicitly via `as_f64()`
// returning None for sentinel/NotAvailable fields — keep the import
// alive in case downstream code wants to call it directly.
#[allow(dead_code)]
fn _keep_import_alive(v: &FieldValue) -> bool {
    v.is_not_available()
}
