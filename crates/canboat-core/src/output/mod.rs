//! Output formatters for `DecodedPgn`.
//!
//! Both formatters write to a `&mut dyn fmt::Write` — no I/O. The
//! caller decides whether that's stdout, a `String` buffer, or a
//! TCP socket.
//!
//! For v0, the formatters cover the canboat default outputs (text
//! and compact JSON). `-debug` byte/bit annotation, `-empty`,
//! `-nv`, and camelCase variants are option fields on the format
//! options structs that the formatters honor as they grow.

pub mod json;
pub mod text;

pub use json::{write_json, JsonOptions};
pub use text::{write_text, TextOptions};

/// Round-up decimal precision implied by `resolution`, matching
/// canboat's algorithm in `analyzer/print.c`:
///
/// ```text
///   precision = 0
///   for r = resolution; 0 < r < 1.0; r *= 10:
///       precision++
/// ```
///
/// `resolution = 0.01` → 2 decimals; `0.0001` → 4; integer
/// resolutions → 0.
pub(crate) fn precision_for(resolution: f64) -> usize {
    if !resolution.is_finite() || resolution <= 0.0 {
        return 0;
    }
    let mut p = 0usize;
    let mut r = resolution;
    while r > 0.0 && r < 1.0 && p < 10 {
        p += 1;
        r *= 10.0;
    }
    p
}

/// Effective precision for a decoded field: honors the load-time
/// override from canboat's unit fix-up when non-zero, otherwise
/// derives it from the resolution.
pub(crate) fn effective_precision(precision: u8, resolution: Option<f64>) -> usize {
    if precision > 0 {
        precision as usize
    } else {
        precision_for(resolution.unwrap_or(1.0))
    }
}

/// Format days-since-1970-01-01 as `YYYY.MM.DD` (canboat text style).
pub(crate) fn format_date(days: u16, w: &mut dyn std::fmt::Write) -> std::fmt::Result {
    let (y, m, d) = days_to_ymd(days as i64);
    write!(w, "{:04}.{:02}.{:02}", y, m, d)
}

/// Convert days-since-1970-01-01 to (year, month, day) in the Gregorian
/// calendar. Adapted from Howard Hinnant's well-known civil-from-days
/// algorithm (public domain).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Shift epoch to 0000-03-01 to simplify leap-year math.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format seconds-since-midnight as `HH:MM:SS[.fff]`. Fractional
/// digits follow `precision`. When `trim_zero_fraction` is set and
/// the fractional part is zero, the `.fff` suffix is omitted — this
/// matches canboat's text-mode `fieldPrintTime`, where the JSON path
/// always shows the fraction and the text path skips it when zero.
pub(crate) fn format_time(
    seconds: f64,
    precision: usize,
    trim_zero_fraction: bool,
    w: &mut dyn std::fmt::Write,
) -> std::fmt::Result {
    if !seconds.is_finite() || seconds < 0.0 {
        return w.write_str("00:00:00");
    }
    let whole = seconds.trunc() as u64;
    let h = whole / 3600;
    let m = (whole / 60) % 60;
    let s = whole % 60;
    if precision == 0 {
        return write!(w, "{:02}:{:02}:{:02}", h, m, s);
    }
    let frac = (seconds - whole as f64) * 10f64.powi(precision as i32);
    let frac_rounded = frac.round() as u64;
    if trim_zero_fraction && frac_rounded == 0 {
        write!(w, "{:02}:{:02}:{:02}", h, m, s)
    } else {
        write!(
            w,
            "{:02}:{:02}:{:02}.{:0width$}",
            h,
            m,
            s,
            frac_rounded,
            width = precision
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_matches_canboat() {
        assert_eq!(precision_for(1.0), 0);
        assert_eq!(precision_for(0.1), 1);
        assert_eq!(precision_for(0.01), 2);
        assert_eq!(precision_for(0.001), 3);
        assert_eq!(precision_for(0.0001), 4);
        // Resolutions >= 1 round to 0 decimals.
        assert_eq!(precision_for(10.0), 0);
        // Edge: zero or negative.
        assert_eq!(precision_for(0.0), 0);
        assert_eq!(precision_for(-1.0), 0);
    }

    #[test]
    fn date_round_trips_known_dates() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(days_to_ymd(1), (1970, 1, 2));
        // 2022-09-10 → 19245 days since epoch.
        assert_eq!(days_to_ymd(19245), (2022, 9, 10));
        // Leap day 2024-02-29.
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn time_formats() {
        let mut out = String::new();
        format_time(3661.0, 0, false, &mut out).unwrap();
        assert_eq!(out, "01:01:01");
        let mut out = String::new();
        format_time(3661.5, 3, false, &mut out).unwrap();
        assert_eq!(out, "01:01:01.500");
    }
}
