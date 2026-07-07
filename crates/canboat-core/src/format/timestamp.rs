// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Canonicalise captured timestamps for output.
//!
//! canboat's input formats carry timestamps in inconsistent shapes:
//! ISO-8601 with a `T` and trailing `Z`, the classic canboat log form
//! `YYYY-MM-DD-HH:MM:SS.mmm` (a dash between date and time), a comma as
//! the millisecond separator (Actisense / Chetco), or bare time-of-day
//! with no date at all (Actisense ASCII, Airmar). We emit a single
//! canonical form so downstream consumers — and comma-delimited PLAIN
//! lines in particular — never trip over a stray comma inside the
//! timestamp field.
//!
//! * Date-bearing → `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC: `T` separator, dot
//!   fraction, three-digit milliseconds, trailing `Z`).
//! * Time-only    → `HH:MM:SS.mmm` (no date is available to anchor it to
//!   a UTC instant, so none is invented — only the separator is fixed).
//! * Unrecognised → returned verbatim, so an odd timestamp is never
//!   lost or corrupted.

use std::borrow::Cow;

/// Normalise `ts` to canboat-rs's canonical timestamp form (see the
/// module docs). Already-canonical inputs are returned borrowed (no
/// allocation); recognised non-canonical inputs are rewritten; anything
/// unrecognised is returned unchanged.
pub fn normalize_timestamp(ts: &str) -> Cow<'_, str> {
    // Fast path: the common live-gateway form is already canonical, so
    // avoid re-parsing and re-allocating it on the hot output path.
    if is_canonical(ts) {
        return Cow::Borrowed(ts);
    }

    let t = ts.trim();
    // Date-bearing: `YYYY-MM-DD` then one of [`T`, `-`, space] then time.
    if t.len() >= 19 {
        let b = t.as_bytes();
        if b[4] == b'-'
            && b[7] == b'-'
            && matches!(b[10], b'T' | b'-' | b' ')
            && b[0..4].iter().all(u8::is_ascii_digit)
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[8..10].iter().all(u8::is_ascii_digit)
            && let Some(time) = normalize_time(&t[11..])
        {
            return Cow::Owned(format!("{}T{}Z", &t[0..10], time));
        }
    }
    // Time-only.
    if let Some(time) = normalize_time(t) {
        return Cow::Owned(time);
    }
    Cow::Borrowed(ts)
}

/// True when `ts` is already exactly `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn is_canonical(ts: &str) -> bool {
    let b = ts.as_bytes();
    b.len() == 24
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[23] == b'Z'
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[17..19].iter().all(u8::is_ascii_digit)
        && b[20..23].iter().all(u8::is_ascii_digit)
}

/// Parse `HH:MM:SS` with an optional `.`/`,` fraction and reformat as
/// `HH:MM:SS.mmm`. Returns `None` when the shape or field ranges don't
/// hold, so the caller can fall back to emitting the value verbatim.
fn normalize_time(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 8 || b[2] != b':' || b[5] != b':' {
        return None;
    }
    if !b[0..2].iter().all(u8::is_ascii_digit)
        || !b[3..5].iter().all(u8::is_ascii_digit)
        || !b[6..8].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let h: u32 = s[0..2].parse().ok()?;
    let m: u32 = s[3..5].parse().ok()?;
    let sec: u32 = s[6..8].parse().ok()?;
    if h >= 24 || m >= 60 || sec >= 60 {
        return None;
    }
    // Optional fractional seconds: a `.`/`,` at index 8 then digits.
    // Anything after the digit run (a trailing `Z`, a timezone) is
    // dropped — canboat timestamps are UTC-naive.
    let mut ms = String::new();
    if b.len() > 8 {
        if b[8] != b'.' && b[8] != b',' {
            return None;
        }
        for &c in &b[9..] {
            if c.is_ascii_digit() {
                ms.push(c as char);
            } else {
                break;
            }
        }
    }
    // Pad/truncate the fraction to exactly three digits (milliseconds):
    // `.1` → `100`, `.107` → `107`, `.10734` → `107`.
    while ms.len() < 3 {
        ms.push('0');
    }
    Some(format!(
        "{}:{}:{}.{}",
        &s[0..2],
        &s[3..5],
        &s[6..8],
        &ms[..3]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_canonical_is_borrowed() {
        let ts = "2026-07-06T23:24:29.065Z";
        assert!(matches!(normalize_timestamp(ts), Cow::Borrowed(_)));
        assert_eq!(normalize_timestamp(ts), ts);
    }

    #[test]
    fn classic_canboat_log_form() {
        // Dash between date and time, dot millis, no T, no Z.
        assert_eq!(
            normalize_timestamp("2011-04-25-06:25:03.603"),
            "2011-04-25T06:25:03.603Z"
        );
    }

    #[test]
    fn iso_with_comma_millis_gets_dot_and_z() {
        assert_eq!(
            normalize_timestamp("2018-10-16T22:25:25,166"),
            "2018-10-16T22:25:25.166Z"
        );
    }

    #[test]
    fn iso_missing_z_gets_z() {
        assert_eq!(
            normalize_timestamp("2018-10-16T22:25:25.166"),
            "2018-10-16T22:25:25.166Z"
        );
    }

    #[test]
    fn date_time_without_fraction_pads_millis() {
        assert_eq!(
            normalize_timestamp("2011-04-25-06:25:03"),
            "2011-04-25T06:25:03.000Z"
        );
    }

    #[test]
    fn actisense_time_only_comma() {
        // The case that started this: comma would corrupt a PLAIN line.
        assert_eq!(normalize_timestamp("17:33:21,107"), "17:33:21.107");
    }

    #[test]
    fn airmar_time_only_no_fraction() {
        assert_eq!(normalize_timestamp("20:11:00"), "20:11:00.000");
    }

    #[test]
    fn short_fraction_pads_right() {
        // `.1` is a tenth of a second = 100 ms, not 1 ms.
        assert_eq!(normalize_timestamp("00:00:57,1"), "00:00:57.100");
    }

    #[test]
    fn overlong_fraction_truncates_to_millis() {
        assert_eq!(normalize_timestamp("00:00:57.123456"), "00:00:57.123");
    }

    #[test]
    fn unrecognised_passes_through() {
        assert_eq!(normalize_timestamp("not a timestamp"), "not a timestamp");
        assert_eq!(normalize_timestamp(""), "");
    }

    #[test]
    fn out_of_range_time_is_left_verbatim() {
        // 25:00:00 is not a valid time — don't pretend to normalise it.
        assert_eq!(normalize_timestamp("25:00:00"), "25:00:00");
    }
}
