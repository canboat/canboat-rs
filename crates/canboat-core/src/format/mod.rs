//! Wire/line-format parsers (sans-I/O).
//!
//! Each submodule handles one canboat-recognised input format. The
//! [`detect`] / [`parse_any`] helpers auto-recognise the format from a
//! line's prefix; binaries pick a single parser via [`InputFormat`]
//! when the user forces it with `--format`.

pub mod actisense_ascii;
pub mod ikonvert;
pub mod ngt1;
pub mod plain;
pub mod ydwg02;

pub use ngt1::{
    encode_n2k_send_frame, encode_n2k_send_payload, encode_ngt_message, encode_startup_ping,
    Ngt1Decoder, NgtError, NgtEvent, NgtMessage, NGT_STARTUP_SEQ, N2K_MSG_RECEIVED, N2K_MSG_SEND,
    NGT_MSG_RECEIVED, NGT_MSG_SEND,
};
pub use plain::{parse_line as parse_plain, write_line as write_plain, ParseError as PlainError};

use crate::frame::RawFrame;

/// One of the canboat-supported ASCII line formats.
///
/// `Airmar`, `Chetco`, and `GarminCsv` are placeholders in v0 — their
/// parsers return [`PlainError::BadInteger`] for now and will be filled
/// in driven by user need / golden-test failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    /// Canboat PLAIN / FAST line (`<ts>,<prio>,<pgn>,...,<hex>,...`).
    Plain,
    /// Actisense N2K ASCII (`A<HHMMSS.mmm> <SDP> <PGN> <data...>`).
    ActisenseAscii,
    /// YDWG-02 / YDEN (`<HH:MM:SS.mmm> R <CANID> <data...>`).
    Ydwg02,
    /// Digital Yacht iKonvert (`!PDGY,...` or `$PDGY,...`).
    Ikonvert,
    /// Airmar (deferred — parser stub returns an error in v0).
    Airmar,
    /// Chetco `$PCDIN,...` (deferred).
    Chetco,
    /// Garmin CSV exports (deferred).
    GarminCsv,
}

/// Auto-detect the line format from a single representative line.
/// Returns `None` if nothing matches; callers should fall back to
/// [`InputFormat::Plain`] in that case (canboat's behavior).
pub fn detect(line: &str) -> Option<InputFormat> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    if t.starts_with("!PDGY,") || t.starts_with("$PDGY,") {
        return Some(InputFormat::Ikonvert);
    }
    if t.starts_with("$PCDIN") {
        return Some(InputFormat::Chetco);
    }
    if t.starts_with('A') && t.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {
        return Some(InputFormat::ActisenseAscii);
    }
    // YDWG02: starts with `HH:MM:SS` followed by `.mmm R/T <hex CAN id>`.
    if looks_like_ydwg02(t) {
        return Some(InputFormat::Ydwg02);
    }
    // PLAIN/FAST: ISO-like timestamp + `,prio,pgn,…`.
    if t.contains(',') {
        return Some(InputFormat::Plain);
    }
    None
}

fn looks_like_ydwg02(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 13 {
        return false;
    }
    // HH:MM:SS.mmm pattern in the first 12 chars.
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2] == b':'
        && bytes[3].is_ascii_digit()
        && bytes[4].is_ascii_digit()
        && bytes[5] == b':'
        && bytes[6].is_ascii_digit()
        && bytes[7].is_ascii_digit()
        && bytes[8] == b'.'
}

/// Parse a single line in `format`. iKonvert control sentences return
/// `Ok(None)`; everything else returns either a [`RawFrame`] or a
/// [`PlainError`].
pub fn parse_with(format: InputFormat, line: &str) -> Result<Option<RawFrame>, plain::ParseError> {
    match format {
        InputFormat::Plain => plain::parse_line(line).map(Some),
        InputFormat::ActisenseAscii => actisense_ascii::parse_line(line).map(Some),
        InputFormat::Ydwg02 => ydwg02::parse_line(line).map(Some),
        InputFormat::Ikonvert => match ikonvert::parse_line(line)? {
            ikonvert::IkonvertLine::Frame(f) => Ok(Some(f)),
            // Control sentences and stray noise are not frames.
            _ => Ok(None),
        },
        InputFormat::Airmar | InputFormat::Chetco | InputFormat::GarminCsv => Err(
            plain::ParseError::BadInteger {
                field: "format",
                value: format!("{format:?} parser is not yet implemented"),
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_plain() {
        assert_eq!(
            detect("2022-09-10T12:10:16.614Z,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0"),
            Some(InputFormat::Plain)
        );
    }

    #[test]
    fn detect_actisense_ascii() {
        assert_eq!(detect("A173321.107 23FF7 1F119 01 02"), Some(InputFormat::ActisenseAscii));
    }

    #[test]
    fn detect_ydwg02() {
        assert_eq!(
            detect("00:17:55.475 R 0DF50B23 FF FF"),
            Some(InputFormat::Ydwg02)
        );
    }

    #[test]
    fn detect_ikonvert() {
        assert_eq!(
            detect("!PDGY,127257,3,35,255,12.345,AQID"),
            Some(InputFormat::Ikonvert)
        );
    }

    #[test]
    fn detect_chetco() {
        assert_eq!(detect("$PCDIN,01F801,..."), Some(InputFormat::Chetco));
    }

    #[test]
    fn detect_blank_and_comment_ignored() {
        assert_eq!(detect(""), None);
        assert_eq!(detect("# a comment"), None);
    }
}
