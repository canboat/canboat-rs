// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Per-device NMEA 0183 output filter.
//!
//! The pipeline converts every decoded N2K record to NMEA 0183, so a
//! bus where several devices report the same measurement produces
//! several copies of each sentence on the 0183 outputs. The [`RateLimiter`]
//! (`n2kd::nmea0183`) caps each *source* to 1 Hz, but N devices reporting
//! one quantity still yield N sentences/s. This filter removes the
//! redundant *devices*: the user picks which device should own each
//! measurement, and the others are muted.
//!
//! Devices are keyed by their stable **NAME** (manufacturer code +
//! unique number from PGN 60928 ISO Address Claim) rather than source
//! address, which can be reassigned at any address-claim round. A
//! consequence, chosen deliberately: **a source whose NAME we haven't
//! learned yet produces no 0183 at all** — we can't attribute it to a
//! filter rule, so it stays silent until it claims. The pipeline's
//! request engine actively solicits PGN 60928, so this is a brief
//! startup gap, not a permanent blackout.
//!
//! This filter only ever affects the NMEA 0183 outputs. The N2K bus,
//! the analyzer JSON port, and the snapshot cache are untouched, so
//! other consumers (Signal K, plotters) still see every device. AIS
//! (`!AI…`) is converted on a separate path and is never filtered here.
//!
//! Scope of this module today: load mute rules from a JSON file and
//! apply them. The synthetic-PGN control channel that lets canboat-tui
//! edit the rules live plugs in on top of this core.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Stable device identity from PGN 60928: the two NAME fields that
/// uniquely identify a device across address changes (Unique Number is
/// 21 bits, unique per manufacturer; Manufacturer Code is 11 bits).
/// Mirrors canboat-tui's `device_cache::NameKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameKey {
    pub manufacturer_code: u16,
    pub unique_number: u32,
}

/// What the pipeline should do with one source's converted 0183 for a
/// single record.
pub enum Decision<'a> {
    /// Emit nothing — either the source has no learned NAME, or the
    /// whole device is muted.
    DropAll,
    /// Emit, but drop any sentence whose 3-letter formatter appears in
    /// this list (empty = pass everything through).
    Keep(&'a [String]),
}

/// One device's mute rule, keyed by NAME in [`FilterConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceRule {
    /// Mute the whole device — none of its measurements reach 0183.
    #[serde(default)]
    pub muted: bool,
    /// Mute individual sentence formatters (e.g. `["VHW", "VLW"]`)
    /// while letting the device's other sentences through.
    #[serde(default)]
    pub muted_sentences: Vec<String>,
}

/// On-disk config row: a NAME plus its rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceEntry {
    manufacturer_code: u16,
    unique_number: u32,
    #[serde(flatten)]
    rule: DeviceRule,
}

/// Persisted wire shape — a wrapper object holding the device list, so
/// schema-level metadata can be added later without breaking readers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FileFormat {
    #[serde(default)]
    devices: Vec<DeviceEntry>,
}

/// Runtime NMEA 0183 filter: the live `src → NAME` map (rebuilt from
/// PGN 60928 each session) plus the NAME-keyed mute rules.
pub struct NmeaFilter {
    /// `src → NAME`, learned from ISO Address Claims this session.
    src_name: [Option<NameKey>; 256],
    /// NAME → mute rule, loaded from the config file.
    rules: HashMap<NameKey, DeviceRule>,
}

impl NmeaFilter {
    /// Load mute rules from `path`. A missing file yields an empty
    /// rule set (filter is active but mutes nothing yet — it still
    /// enforces the "no NAME, no 0183" gate). A malformed file is an
    /// error so a typo doesn't silently disable filtering.
    pub fn load(path: &Path) -> Result<Self> {
        let rules = match std::fs::read_to_string(path) {
            Ok(body) => {
                let file: FileFormat = serde_json::from_str(&body).with_context(|| {
                    format!("parsing NMEA 0183 filter config {}", path.display())
                })?;
                file.devices
                    .into_iter()
                    .map(|e| {
                        (
                            NameKey {
                                manufacturer_code: e.manufacturer_code,
                                unique_number: e.unique_number,
                            },
                            e.rule,
                        )
                    })
                    .collect()
            }
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            src_name: [None; 256],
            rules,
        })
    }

    /// Record an ISO Address Claim: `src` now belongs to this NAME.
    pub fn note_address_claim(&mut self, src: u8, manufacturer_code: u16, unique_number: u32) {
        self.src_name[src as usize] = Some(NameKey {
            manufacturer_code,
            unique_number,
        });
    }

    /// Decide what to do with `src`'s converted 0183 for one record.
    pub fn decide(&self, src: u8) -> Decision<'_> {
        let Some(name) = self.src_name[src as usize] else {
            // No learned NAME — deliberately emit nothing.
            return Decision::DropAll;
        };
        match self.rules.get(&name) {
            Some(rule) if rule.muted => Decision::DropAll,
            Some(rule) => Decision::Keep(&rule.muted_sentences),
            None => Decision::Keep(&[]),
        }
    }

    /// Apply the filter to `buf`, a freshly-converted block of one or
    /// more `$`-prefixed NMEA 0183 sentences for source `src`. Rewrites
    /// `buf` in place, dropping muted sentences (or all of them). Lines
    /// that don't start with `$` are left untouched.
    pub fn apply(&self, src: u8, buf: &mut String) {
        match self.decide(src) {
            Decision::DropAll => buf.clear(),
            Decision::Keep(muted) => {
                if muted.is_empty() {
                    return;
                }
                let mut kept = String::with_capacity(buf.len());
                for line in buf.split_inclusive('\n') {
                    match sentence_formatter(line) {
                        Some(fmt) if muted.iter().any(|m| m == fmt) => {}
                        _ => kept.push_str(line),
                    }
                }
                *buf = kept;
            }
        }
    }
}

/// Extract the 3-letter sentence formatter from a `$ttFFF,…` line
/// (`tt` = 2-letter talker). Returns `None` for lines that aren't a
/// `$`-sentence or are too short.
fn sentence_formatter(line: &str) -> Option<&str> {
    let s = line.strip_prefix('$')?;
    // s = "ttFFF,…". Formatter is the 3 chars after the 2 talker chars.
    s.get(2..5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter_with(rules: &[(u16, u32, DeviceRule)]) -> NmeaFilter {
        let mut f = NmeaFilter {
            src_name: [None; 256],
            rules: HashMap::new(),
        };
        for (mfr, uniq, rule) in rules {
            f.rules.insert(
                NameKey {
                    manufacturer_code: *mfr,
                    unique_number: *uniq,
                },
                rule.clone(),
            );
        }
        f
    }

    #[test]
    fn no_name_drops_everything() {
        let f = filter_with(&[]);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf); // src 33 never claimed
        assert!(buf.is_empty());
    }

    #[test]
    fn known_name_no_rule_passes() {
        let mut f = filter_with(&[]);
        f.note_address_claim(33, 381, 1066791);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf);
        assert_eq!(buf, "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n");
    }

    #[test]
    fn muted_source_drops_everything() {
        let mut f = filter_with(&[(
            381,
            1066791,
            DeviceRule {
                muted: true,
                ..Default::default()
            },
        )]);
        f.note_address_claim(33, 381, 1066791);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn muted_sentence_drops_only_that_formatter() {
        let mut f = filter_with(&[(
            135,
            761920,
            DeviceRule {
                muted: false,
                muted_sentences: vec!["VLW".to_string()],
            },
        )]);
        f.note_address_claim(35, 135, 761920);
        // Airmar DST emits VHW + VLW + MTW; mute only VLW.
        let mut buf =
            "$CDVHW,,T,,M,4.6,N,8.6,K*5E\r\n$CDVLW,14467.8,N,14467.8,N*4A\r\n$CDMTW,17.0,C*01\r\n"
                .to_string();
        f.apply(35, &mut buf);
        assert_eq!(buf, "$CDVHW,,T,,M,4.6,N,8.6,K*5E\r\n$CDMTW,17.0,C*01\r\n");
    }

    #[test]
    fn formatter_extraction() {
        assert_eq!(sentence_formatter("$CBVHW,x*54\r\n"), Some("VHW"));
        assert_eq!(sentence_formatter("$AARSA,2.0*6B\r\n"), Some("RSA"));
        assert_eq!(sentence_formatter("!AIVDM,1*7B\r\n"), None);
        assert_eq!(sentence_formatter("$AB\r\n"), None);
    }
}
