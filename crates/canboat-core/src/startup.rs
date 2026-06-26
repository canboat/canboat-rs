//! The synthetic "CANboat: Startup" record (PGN 0x40200 / 262656).
//!
//! The canboat device-reader tools (actisense-serial, ikonvert-serial,
//! maretron-ipg, socketcan-serial) emit this as their first PGN so a
//! downstream consumer knows which producer and device a stream came
//! from. Mirrors `emitCanboatStartupRecord` in canboat/common/common.c.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::frame::RawFrame;

/// CANboat tool-specific fake-PGN base; also the startup record's PGN.
pub const CANBOAT_BEM: u32 = 0x40200;

/// Build the startup record, stamped with the current UTC time.
///
/// `version` is a `major.minor.patch` string (typically the binary's
/// `CARGO_PKG_VERSION`); `source` is the tool name and `device` the
/// opened device.
pub fn startup_record(version: &str, source: &str, device: &str) -> RawFrame {
    startup_record_at(version, source, device, now_iso())
}

/// As [`startup_record`] but with an explicit ISO-8601 timestamp
/// (used by tests so output is deterministic).
pub fn startup_record_at(version: &str, source: &str, device: &str, timestamp: String) -> RawFrame {
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    // Tolerate a trailing pre-release suffix like "1-rc1".
    let patch: u32 = parts
        .next()
        .map(|s| s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(""))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let ver = (major * 1000 + minor * 100 + patch) as u16;

    let mut data = [0u8; 66];
    data[0] = (ver & 0xff) as u8;
    data[1] = (ver >> 8) as u8;
    copy_fixed(&mut data[2..34], source);
    copy_fixed(&mut data[34..66], device);

    RawFrame::new(Some(timestamp), 7, CANBOAT_BEM, 0, 255, data)
}

/// Copy a string into a fixed-width NUL-padded field, always leaving at
/// least one trailing NUL (matches canboat's `strncpy(dst, s, len-1)`).
fn copy_fixed(dst: &mut [u8], s: &str) {
    let n = s.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`. No chrono — civil
/// date via the Howard-Hinnant algorithm, as elsewhere in this crate.
fn now_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_iso_ms(now.as_millis() as u64)
}

/// Format Unix milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ` (ISO-8601
/// Zulu). Used by the EBL reader so timestamp records replay with their
/// captured wall-clock time.
pub fn format_iso_ms(ms: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_version_and_strings() {
        let f = startup_record_at(
            "6.2.0",
            "socketcan-serial",
            "nmea2000",
            "2026-01-01T00:00:00.000Z".into(),
        );
        assert_eq!(f.pgn, CANBOAT_BEM);
        assert_eq!(f.prio, 7);
        assert_eq!(f.dst, 255);
        assert_eq!(f.data.len(), 66);
        // 6*1000 + 2*100 + 0 = 6200 = 0x1838, little-endian.
        assert_eq!(f.data[0], 0x38);
        assert_eq!(f.data[1], 0x18);
        assert_eq!(&f.data[2..18], b"socketcan-serial");
        assert_eq!(&f.data[34..42], b"nmea2000");
    }
}
