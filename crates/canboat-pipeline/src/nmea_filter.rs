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
//! Devices are keyed by their stable **NAME** (the full 64-bit ISO NAME
//! from PGN 60928 ISO Address Claim) rather than source address, which
//! can be reassigned at any address-claim round. A consequence, chosen
//! deliberately: **a source whose NAME we haven't learned yet produces
//! no 0183 at all** — we can't attribute it to a filter rule, so it
//! stays silent until it claims. The pipeline's request engine actively
//! solicits PGN 60928, so this is a brief startup gap, not a permanent
//! blackout. A device that transmits an "unavailable" manufacturer code
//! is still uniquely identified by the rest of its NAME, so it is
//! filtered like any other — not lumped together or ignored.
//!
//! This filter only ever affects the NMEA 0183 outputs. The N2K bus,
//! the analyzer JSON port, and the snapshot cache are untouched, so
//! other consumers (Signal K, plotters) still see every device. AIS
//! (`!AI…`) is converted on a separate path and is never filtered here.
//!
//! Scope of this module today: load mute rules from a JSON file and
//! apply them. The synthetic-PGN control channel that lets canboat-tui
//! edit the rules live plugs in on top of this core.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Formatter token used in PGN 262657 / [`FilterReportRow`] to mean
/// "the whole source", as opposed to a specific 3-letter sentence.
pub const ALL_SENTENCES: &str = "ALL";

/// Stable device identity: the full 64-bit ISO NAME from the PGN 60928
/// payload (8 bytes, little-endian — the value the bus arbitrates on).
///
/// We key on the whole NAME rather than just Manufacturer Code + Unique
/// Number because some devices transmit an "unavailable" (`0x7FF`)
/// manufacturer code: their identity then lives entirely in the other
/// NAME fields (device function / class / instance). Those devices are
/// still unique on the bus — arbitration guarantees no two share a NAME
/// — so keying on the full 64 bits gives every claiming device a
/// distinct, stable key instead of lumping the "degenerate" ones
/// together or dropping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameKey(pub u64);

impl NameKey {
    fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }

    fn from_hex(s: &str) -> Option<Self> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .ok()
            .map(NameKey)
    }
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
    /// Full 64-bit ISO NAME as lowercase hex (see [`NameKey`]).
    name: String,
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

/// One row the pipeline broadcasts as a PGN 262657 Report so the TUI
/// can show, per source, what it emits and whether it's muted.
pub struct FilterReportRow {
    pub src: u8,
    /// 3-letter formatter, or [`ALL_SENTENCES`] for the whole source.
    pub sentence: String,
    pub muted: bool,
}

/// Runtime NMEA 0183 filter: the live `src → NAME` map (rebuilt from
/// PGN 60928 each session) plus the NAME-keyed mute rules. Rules are
/// keyed by NAME for stability across address changes, but the control
/// channel (PGN 262657) and reports address devices by source, which
/// this resolves at the boundary.
pub struct NmeaFilter {
    /// Where mute rules are persisted; rewritten on every edit.
    path: PathBuf,
    /// `src → NAME`, learned from ISO Address Claims this session.
    src_name: [Option<NameKey>; 256],
    /// NAME → mute rule, loaded from the config file.
    rules: HashMap<NameKey, DeviceRule>,
    /// `src → the sentence formatters we've seen it produce` this
    /// session — the menu of "what could be sent" a report exposes,
    /// recorded before any mute is applied so muted sentences still
    /// appear. Keyed by source (what the TUI addresses), not NAME.
    observed: HashMap<u8, BTreeSet<String>>,
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
                    .filter_map(|e| NameKey::from_hex(&e.name).map(|k| (k, e.rule)))
                    .collect()
            }
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            path: path.to_path_buf(),
            src_name: [None; 256],
            rules,
            observed: HashMap::new(),
        })
    }

    /// Persist the current rules to [`Self::path`]. Called after every
    /// edit so a change survives a pipeline restart.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut devices: Vec<DeviceEntry> = self
            .rules
            .iter()
            .map(|(k, rule)| DeviceEntry {
                name: k.to_hex(),
                rule: rule.clone(),
            })
            .collect();
        // Deterministic order so the file diffs cleanly.
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        let body = serde_json::to_string_pretty(&FileFormat { devices })
            .context("serialising NMEA 0183 filter config")?;
        std::fs::write(&self.path, body).with_context(|| format!("writing {}", self.path.display()))
    }

    /// Record an ISO Address Claim: `src` now belongs to this NAME
    /// (the full 64-bit value from the PGN 60928 payload).
    pub fn note_address_claim(&mut self, src: u8, name: u64) {
        self.src_name[src as usize] = Some(NameKey(name));
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
    /// more `$`-prefixed NMEA 0183 sentences for source `src`. Records
    /// each formatter as observed (so a report lists it even when
    /// muted), then rewrites `buf` in place, dropping muted sentences
    /// (or all of them). Lines that don't start with `$` are left
    /// untouched.
    pub fn apply(&mut self, src: u8, buf: &mut String) {
        // Observe first — the report's "what could be sent" menu must
        // include muted sentences, so record before dropping anything.
        for line in buf.split_inclusive('\n') {
            if let Some(fmt) = sentence_formatter(line)
                && !self.observed.get(&src).is_some_and(|s| s.contains(fmt))
            {
                self.observed
                    .entry(src)
                    .or_default()
                    .insert(fmt.to_string());
            }
        }
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

    /// Apply a PGN 262657 Set command addressed by source. `sentence`
    /// is a 3-letter formatter or [`ALL_SENTENCES`] for the whole
    /// device. A source with no learned NAME can't be persisted (we
    /// key rules by NAME) — such devices produce no 0183 anyway, so
    /// this is a no-op returning `false`. Otherwise the rule is updated
    /// and the config saved; returns `true`.
    pub fn set(&mut self, src: u8, sentence: &str, muted: bool) -> bool {
        let Some(name) = self.src_name[src as usize] else {
            log::debug!("PGN 262657 Set for src {src} ignored: no learned NAME");
            return false;
        };
        let rule = self.rules.entry(name).or_default();
        if sentence == ALL_SENTENCES {
            rule.muted = muted;
        } else if muted {
            if !rule.muted_sentences.iter().any(|s| s == sentence) {
                rule.muted_sentences.push(sentence.to_string());
            }
        } else {
            rule.muted_sentences.retain(|s| s != sentence);
        }
        // Drop a rule that no longer constrains anything, so the config
        // file doesn't accrue empty entries.
        if !rule.muted && rule.muted_sentences.is_empty() {
            self.rules.remove(&name);
        }
        if let Err(e) = self.save() {
            log::warn!("failed to persist NMEA 0183 filter change: {e:#}");
        }
        true
    }

    /// Build the per-source Report rows the pipeline broadcasts as PGN
    /// 262657 so the TUI can render the device/sentence matrix: for
    /// every source we've observed, an [`ALL_SENTENCES`] row carrying
    /// the whole-source mute state, then one row per observed formatter
    /// with its effective mute state.
    pub fn report(&self) -> Vec<FilterReportRow> {
        let mut rows = Vec::new();
        let mut srcs: Vec<u8> = self.observed.keys().copied().collect();
        srcs.sort_unstable();
        for src in srcs {
            let source_muted = matches!(self.decide(src), Decision::DropAll);
            rows.push(FilterReportRow {
                src,
                sentence: ALL_SENTENCES.to_string(),
                muted: source_muted,
            });
            if let Some(formatters) = self.observed.get(&src) {
                for fmt in formatters {
                    let muted = source_muted
                        || matches!(self.decide(src), Decision::Keep(m) if m.iter().any(|s| s == fmt));
                    rows.push(FilterReportRow {
                        src,
                        sentence: fmt.clone(),
                        muted,
                    });
                }
            }
        }
        rows
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

    // Arbitrary distinct 64-bit NAMEs for the tests.
    const NAME_SPEED: u64 = 0x0004_0000_1066_7913;
    const NAME_AIRMAR: u64 = 0x0004_0000_0761_9208;

    fn filter_with(rules: &[(u64, DeviceRule)]) -> NmeaFilter {
        let mut f = NmeaFilter {
            path: PathBuf::from("/dev/null"),
            src_name: [None; 256],
            rules: HashMap::new(),
            observed: HashMap::new(),
        };
        for (name, rule) in rules {
            f.rules.insert(NameKey(*name), rule.clone());
        }
        f
    }

    #[test]
    fn no_name_drops_everything() {
        let mut f = filter_with(&[]);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf); // src 33 never claimed
        assert!(buf.is_empty());
    }

    #[test]
    fn known_name_no_rule_passes() {
        let mut f = filter_with(&[]);
        f.note_address_claim(33, NAME_SPEED);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf);
        assert_eq!(buf, "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n");
    }

    #[test]
    fn muted_source_drops_everything() {
        let mut f = filter_with(&[(
            NAME_SPEED,
            DeviceRule {
                muted: true,
                ..Default::default()
            },
        )]);
        f.note_address_claim(33, NAME_SPEED);
        let mut buf = "$CBVHW,,T,,M,0.0,N,0.0,K*54\r\n".to_string();
        f.apply(33, &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn muted_sentence_drops_only_that_formatter() {
        let mut f = filter_with(&[(
            NAME_AIRMAR,
            DeviceRule {
                muted: false,
                muted_sentences: vec!["VLW".to_string()],
            },
        )]);
        f.note_address_claim(35, NAME_AIRMAR);
        // Airmar DST emits VHW + VLW + MTW; mute only VLW.
        let mut buf =
            "$CDVHW,,T,,M,4.6,N,8.6,K*5E\r\n$CDVLW,14467.8,N,14467.8,N*4A\r\n$CDMTW,17.0,C*01\r\n"
                .to_string();
        f.apply(35, &mut buf);
        assert_eq!(buf, "$CDVHW,,T,,M,4.6,N,8.6,K*5E\r\n$CDMTW,17.0,C*01\r\n");
    }

    #[test]
    fn degenerate_name_is_still_keyed() {
        // A device that claims an "unavailable" manufacturer code still
        // has a unique 64-bit NAME — it must be filterable, not dropped.
        let degenerate: u64 = 0xffff_ff00_ffe0_ffff;
        let mut f = filter_with(&[]);
        f.path = std::env::temp_dir().join("canboat-nmea-filter-degen.json");
        f.note_address_claim(53, degenerate);
        let mut buf = "$DFMWV,308.3,R,20.9,K,A*09\r\n".to_string();
        f.apply(53, &mut buf);
        assert_eq!(buf, "$DFMWV,308.3,R,20.9,K,A*09\r\n"); // passes: known NAME
        assert!(f.set(53, ALL_SENTENCES, true)); // and can be muted
        let mut buf2 = "$DFMWV,308.3,R,20.9,K,A*09\r\n".to_string();
        f.apply(53, &mut buf2);
        assert!(buf2.is_empty());
    }

    #[test]
    fn set_by_source_resolves_to_name_and_reports() {
        let mut f = filter_with(&[]);
        f.path = std::env::temp_dir().join("canboat-nmea-filter-test.json");
        f.note_address_claim(35, NAME_AIRMAR);
        // Observe what the Airmar produces.
        let mut buf = "$CDVHW,x*01\r\n$CDVLW,y*02\r\n$CDMTW,z*03\r\n".to_string();
        f.apply(35, &mut buf);
        // Mute only VLW via a Set addressed by source.
        assert!(f.set(35, "VLW", true));
        let mut buf2 = "$CDVHW,x*01\r\n$CDVLW,y*02\r\n$CDMTW,z*03\r\n".to_string();
        f.apply(35, &mut buf2);
        assert_eq!(buf2, "$CDVHW,x*01\r\n$CDMTW,z*03\r\n");
        // Report exposes ALL + every observed formatter, VLW muted.
        let rows = f.report();
        let vlw = rows
            .iter()
            .find(|r| r.src == 35 && r.sentence == "VLW")
            .unwrap();
        assert!(vlw.muted);
        let vhw = rows
            .iter()
            .find(|r| r.src == 35 && r.sentence == "VHW")
            .unwrap();
        assert!(!vhw.muted);
        assert!(
            rows.iter()
                .any(|r| r.src == 35 && r.sentence == ALL_SENTENCES && !r.muted)
        );
    }

    #[test]
    fn set_on_unknown_source_is_noop() {
        let mut f = filter_with(&[]);
        f.path = std::env::temp_dir().join("canboat-nmea-filter-noop.json");
        assert!(!f.set(99, ALL_SENTENCES, true)); // src 99 never claimed
    }

    #[test]
    fn formatter_extraction() {
        assert_eq!(sentence_formatter("$CBVHW,x*54\r\n"), Some("VHW"));
        assert_eq!(sentence_formatter("$AARSA,2.0*6B\r\n"), Some("RSA"));
        assert_eq!(sentence_formatter("!AIVDM,1*7B\r\n"), None);
        assert_eq!(sentence_formatter("$AB\r\n"), None);
    }
}
