// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! In-memory model of the bus, fed from the snapshot + live stream.
//!
//! Two structures matter:
//!
//! * [`Entry`] — one entry per `(pgn, src, secondary)` triple. The
//!   key shape exactly matches what canboat-pipeline / n2kd write
//!   into their TCP snapshot (port 2597) and stream (port 2598). On
//!   the snapshot port the key arrives encoded as the JSON field name
//!   `"<src>[_<secondary>]"`; on the stream port we recompute it via
//!   [`canboat_core::snapshot::classify_json_line`] so the two paths
//!   produce identical keys.
//!
//! * [`AppState`] — owns the entry map plus a derived view of which
//!   source addresses currently exist on the bus, with their
//!   manufacturer / product / model info pulled out of the cached
//!   ISO Address Claim (60928), Product Information (126996), and
//!   Configuration Information (126998) entries. The
//!   PGN-List-Transmit/Receive (126464) entry, when present, is
//!   exposed the same way.
//!
//! `AppState` is intentionally small and `tokio::sync::Mutex`-friendly
//! — the UI grabs it for one frame, the network task grabs it to
//! apply each incoming line. No background derivation runs; views are
//! computed on demand from the cached JSON values.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use indexmap::IndexMap;
use serde_json::Value;

use crate::device_cache::{CachedInfo, NameKey};

/// Cap on how many pending alerts (e.g. NAKed PGN 126208 ACKs) we
/// keep before dropping the oldest. Twenty is more than the user
/// can plausibly dismiss in one breath, but small enough that a
/// chatty bus can't grow the queue without bound.
pub const MAX_PENDING_ALERTS: usize = 20;

/// `(pgn, src, secondary)` — same shape as
/// [`canboat_core::snapshot`]'s internal cache key.
pub type EntryKey = (u32, u8, Option<String>);

/// One snapshot entry: a single decoded record indexed by its
/// composite primary key. `line` caches the latest observation so
/// the UI can pull fields without indirecting through
/// [`AppState::history`] on every frame; `history_indices` indexes
/// every observation we've seen for this key in chronological order
/// so the user can step through past instances with left / right
/// (and the [`Screen::TimeView`] flattens them all into one
/// timeline).
#[derive(Debug, Clone)]
pub struct Entry {
    pub pgn: u32,
    pub src: u8,
    pub secondary: Option<String>,
    /// PGN description from the record itself (full form, including
    /// the manufacturer prefix). Empty when the analyzer didn't emit
    /// one.
    pub description: String,
    pub line: Value,
    /// Wall-clock-ish moment we processed the most recent record for
    /// this key — drives both the "age" column and the interval
    /// estimate.
    pub last_update: Instant,
    /// Total records seen for this key since the entry was first
    /// inserted. Combined with [`Entry::first_seen`] and
    /// [`Entry::last_update`] this gives the average measured
    /// inter-arrival time (see [`Entry::interval`]).
    pub count: u64,
    /// First time we saw a record for this key. Anchors the
    /// interval average so the displayed cadence is `(last − first)
    /// / (count − 1)` and not perturbed by a single late frame.
    pub first_seen: Instant,
    /// Wire timestamp from the *first* observation, parsed to Unix
    /// milliseconds. `None` when the analyzer JSON line didn't
    /// carry a `"timestamp"` field. When both this and
    /// `last_stamp_ms` are present, [`Entry::interval`] uses them
    /// instead of the wall-clock `first_seen` / `last_update`
    /// pair — the whole point being that in log-replay mode the
    /// `Instant` pair reflects ingest speed, not real bus cadence.
    pub first_stamp_ms: Option<i64>,
    /// Wire timestamp from the *latest* observation, same units as
    /// [`Entry::first_stamp_ms`].
    pub last_stamp_ms: Option<i64>,
    /// Indices into [`AppState::history`], one per observation of
    /// this key, in chronological insertion order. The last index
    /// names the same record that `line` caches. Empty on
    /// synthetic silenced-override placeholder rows.
    pub history_indices: Vec<usize>,
}

impl Entry {
    /// Average measured transmission interval. Returns `None` until
    /// the second record arrives (one observation isn't enough to
    /// measure a cadence). Prefers wire timestamps
    /// (`first_stamp_ms`/`last_stamp_ms`) when both are present so
    /// the number reflects the real bus cadence even in log-replay
    /// mode; falls back to the wall-clock `first_seen`/`last_update`
    /// `Instant` pair when the analyzer JSON didn't carry a
    /// `"timestamp"` field (some formats don't).
    pub fn interval(&self) -> Option<std::time::Duration> {
        if self.count < 2 {
            return None;
        }
        let denom = self.count.saturating_sub(1) as u32;
        if let (Some(first), Some(last)) = (self.first_stamp_ms, self.last_stamp_ms) {
            let span_ms = (last - first).max(0) as u64;
            return Some(std::time::Duration::from_millis(span_ms) / denom);
        }
        let span = self.last_update.saturating_duration_since(self.first_seen);
        Some(span / denom)
    }
}

/// One row in the device list.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub src: u8,
    /// Manufacturer name from PGN 60928 (ISO Address Claim) or
    /// 126996 (Product Information). Empty when neither has been
    /// seen.
    pub manufacturer: String,
    /// Product model from PGN 126996 `"Model ID"`. Empty when 126996
    /// hasn't been seen for this src.
    pub model: String,
    /// Software version (PGN 126996 `"Software Version Code"`).
    pub software: String,
    /// Configuration installation description (PGN 126998
    /// `"Installation Description #1"`).
    pub installation: String,
    /// Distinct PGN numbers we've seen from this source.
    pub pgn_count: usize,
}

/// Per-source NMEA 0183 filter state, learned from the pipeline's PGN
/// 262657 Report frames. `muted` is the whole-source state; `sentences`
/// maps each 3-letter formatter the device can produce to its current
/// (effective) mute state. See [`AppState::apply_nmea0183_report`].
#[derive(Debug, Clone, Default)]
pub struct Nmea0183Device {
    pub muted: bool,
    pub sentences: BTreeMap<String, bool>,
}

/// One navigable row in the NMEA 0183 filter screen: either a
/// whole-source header (`sentence == None`) or one of its sentences.
#[derive(Debug, Clone)]
pub struct Nmea0183Row {
    pub src: u8,
    pub sentence: Option<String>,
    pub muted: bool,
}

/// Progress of a long-running background operation (currently the
/// capture save). Rendered as a bar; `done`/`total` are record counts.
#[derive(Debug, Clone)]
pub struct Progress {
    pub label: String,
    pub done: usize,
    pub total: usize,
}

/// One row in the `top`-style PGN-load view: a single PGN aggregated
/// across every source producing it, with the total observation count
/// and the summed message rate (messages/second). Highest-rate PGNs
/// sort first, so the busiest traffic floats to the top the way
/// `top(1)` shows the hungriest processes.
#[derive(Debug, Clone)]
pub struct PgnLoadRow {
    pub pgn: u32,
    /// Description from any contributing entry (they share a PGN, so
    /// the wording is the same modulo per-source manufacturer prefix).
    pub description: String,
    /// Distinct source addresses transmitting this PGN.
    pub sources: usize,
    /// Total records observed across all sources.
    pub count: u64,
    /// Summed transmission rate in messages/second, computed from each
    /// contributing entry's measured interval. `0.0` while no entry
    /// has enough samples to measure a cadence yet.
    pub rate: f32,
}

/// The `ALL` sentence token in PGN 262657 (whole-source mute). Mirrors
/// `canboat_pipeline::nmea_filter::ALL_SENTENCES`.
pub const NMEA0183_ALL: &str = "ALL";

/// What's feeding the cache — a live bus / pipeline endpoint or a
/// captured log file. Drives several UI affordances:
///
/// * `Mode::Log` hides the `i` (ISO Request) and `o` (override)
///   bindings; both rely on writing back to a live bus and would
///   silently do nothing against a file.
/// * The status bar's "endpoint" label switches between
///   `host:snap/stream` and `log: <path>` shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Live,
    Log,
}

/// Snapshot of source / connection state shown in the status bar.
#[derive(Debug, Clone)]
pub struct Status {
    pub mode: Mode,
    /// Live mode: hostname. Log mode: log file path (display form).
    pub host: String,
    /// Live mode: snapshot port; ignored / `0` in Log mode.
    pub snapshot_port: u16,
    /// Live mode: stream port; ignored / `0` in Log mode.
    pub stream_port: u16,
    /// Live: snapshot blob fully drained. Log: log file fully
    /// decoded.
    pub snapshot_loaded: bool,
    /// Live: stream socket up. Log: always `false`.
    pub stream_connected: bool,
    pub messages_seen: u64,
    pub last_error: Option<String>,
}

impl Status {
    pub fn new_live(host: String, snapshot_port: u16, stream_port: u16) -> Self {
        Self {
            mode: Mode::Live,
            host,
            snapshot_port,
            stream_port,
            snapshot_loaded: false,
            stream_connected: false,
            messages_seen: 0,
            last_error: None,
        }
    }

    pub fn new_log(path_display: String) -> Self {
        Self {
            mode: Mode::Log,
            host: path_display,
            snapshot_port: 0,
            stream_port: 0,
            snapshot_loaded: false,
            stream_connected: false,
            messages_seen: 0,
            last_error: None,
        }
    }

    /// Idle startup state (no `--host` / `--log`): a Log-shaped status
    /// with no source. `snapshot_loaded` is set so the status bar reads
    /// settled rather than a perpetual "loading…"; the UI opens the
    /// File ▸ Load dialog to get the user to a real source.
    pub fn new_idle() -> Self {
        Self {
            mode: Mode::Log,
            host: "(no source — File ▸ Load / Connect)".to_string(),
            snapshot_port: 0,
            stream_port: 0,
            snapshot_loaded: true,
            stream_connected: false,
            messages_seen: 0,
            last_error: None,
        }
    }
}

/// One observation of any PGN, in arrival order. The TUI keeps the
/// full history in [`AppState::history`] so each `Entry` can index
/// back into it for left/right navigation and the (forthcoming)
/// `TimeView` can iterate all records chronologically without
/// touching the per-key `Entry` map.
#[derive(Debug, Clone)]
pub struct HistoryRecord {
    /// ISO timestamp string from the analyzer JSON line, if any.
    pub timestamp: Option<String>,
    /// Local-clock arrival time — used as the chronological sort
    /// key when the wire `timestamp` is absent.
    pub seen_at: Instant,
    pub pgn: u32,
    pub src: u8,
    pub secondary: Option<String>,
    pub description: String,
    pub line: Value,
}

/// Shared state guarded by a [`tokio::sync::Mutex`] in the binary.
pub struct AppState {
    /// Insertion-ordered to keep the UI stable across renders. Insertions
    /// happen on first sight of a `(pgn, src, secondary)`; updates keep
    /// the slot in place.
    pub entries: IndexMap<EntryKey, Entry>,
    /// Every observation of every key, in chronological insertion
    /// order. `Entry::history_indices` points back into this. Grows
    /// unbounded; in `Mode::Log` it's capped by the file size, in
    /// `Mode::Live` we'll add a cap once long-running sessions need
    /// one.
    pub history: Vec<HistoryRecord>,
    pub status: Status,
    /// Bus-side warnings queued by the stream reader (e.g. a device
    /// NAKed one of our PGN 126208 Requests with a non-zero error
    /// code). The UI drains them one per draw into its toast slot
    /// so the user sees each alert and can dismiss it with any key.
    /// Bounded to [`MAX_PENDING_ALERTS`] entries — oldest dropped
    /// when the bus is shouting faster than the user can read.
    pub alerts: VecDeque<String>,
    /// A one-shot positive notice (e.g. "✓ Loaded N records", "✓ Saved
    /// …") raised by a background task. The UI drains it into its toast
    /// slot so the user gets confirmation an async load / save finished.
    pub notice: Option<String>,
    /// Progress of an in-flight capture save, `None` when idle. While
    /// `Some`, the UI shows a progress bar and Save / Load / Connect are
    /// disabled (the save task holds append-only indices into `history` /
    /// `raw_lines` that a reset would invalidate).
    pub save_progress: Option<Progress>,
    /// Persistent NAME → device-info cache, loaded at startup and
    /// saved at exit. Enriches `device_list()` with fields the
    /// current session hasn't observed (typical case: a log capture
    /// that includes ISO Address Claim but not the request-only
    /// Product Information PGN 126996).
    pub device_cache: HashMap<NameKey, CachedInfo>,
    /// Last-seen NAME per source address, populated from PGN 60928
    /// as records arrive. Used to route PGN 126996 / 126998 updates
    /// to the correct NAME in the cache (those PGNs don't carry a
    /// NAME themselves — they arrive addressed to the same `src` as
    /// the recent Address Claim).
    pub src_to_name: HashMap<u8, NameKey>,
    /// Per-source NMEA 0183 filter state, fed by the pipeline's PGN
    /// 262657 Report frames. Drives the `Screen::Nmea0183` view.
    pub nmea0183: BTreeMap<u8, Nmea0183Device>,
    /// Coalesced canboat PLAIN/FAST lines, one per decoded frame, in
    /// arrival order — the source for a "Save ▸ Raw" export. Only
    /// populated in log-replay mode, where the wire bytes are still
    /// available (`DecodedPgn::data`); the live JSON stream carries no
    /// raw bytes, so this stays empty there.
    pub raw_lines: Vec<String>,
}

impl AppState {
    pub fn new(status: Status, device_cache: HashMap<NameKey, CachedInfo>) -> Self {
        Self {
            entries: IndexMap::new(),
            history: Vec::new(),
            status,
            alerts: VecDeque::new(),
            notice: None,
            save_progress: None,
            device_cache,
            src_to_name: HashMap::new(),
            nmea0183: BTreeMap::new(),
            raw_lines: Vec::new(),
        }
    }

    /// Append an alert to [`AppState::alerts`], evicting the oldest
    /// entry when the queue is full.
    pub fn push_alert(&mut self, message: String) {
        if self.alerts.len() == MAX_PENDING_ALERTS {
            self.alerts.pop_front();
        }
        self.alerts.push_back(message);
    }

    /// Insert or refresh one record. `line` has already been parsed
    /// to a `Value` by the caller.
    pub fn upsert(
        &mut self,
        pgn: u32,
        src: u8,
        secondary: Option<String>,
        description: String,
        line: Value,
    ) {
        // PGN 262657 is the pipeline's NMEA 0183 filter control channel,
        // not a bus record — route its Report frames into the filter
        // view instead of the entry/device model.
        if pgn == 262657 {
            self.apply_nmea0183_report(&line);
            self.status.messages_seen = self.status.messages_seen.saturating_add(1);
            return;
        }
        let key = (pgn, src, secondary.clone());
        let now = Instant::now();
        let timestamp = line
            .pointer("/timestamp")
            .and_then(Value::as_str)
            .map(str::to_string);
        // Parse the wire timestamp to Unix ms so `Entry::interval`
        // can compute real bus cadence in log mode (where the
        // `Instant`-based diff is meaningless — it just measures
        // how fast we ingested lines).
        let stamp_ms = timestamp.as_deref().and_then(canboat_core::parse_iso_ms);

        // Append to the global chronological history first so the
        // entry's freshly-pushed index points at the right row.
        let history_idx = self.history.len();
        self.history.push(HistoryRecord {
            timestamp,
            seen_at: now,
            pgn,
            src,
            secondary: secondary.clone(),
            description: description.clone(),
            line: line.clone(),
        });

        match self.entries.get_mut(&key) {
            Some(e) => {
                e.line = line;
                e.description = description;
                e.last_update = now;
                e.count += 1;
                e.history_indices.push(history_idx);
                // Only overwrite `last_stamp_ms` when this record
                // carried a valid timestamp; a single record with
                // no `timestamp` field shouldn't null out the
                // interval for a whole burst.
                if let Some(ms) = stamp_ms {
                    e.last_stamp_ms = Some(ms);
                    if e.first_stamp_ms.is_none() {
                        e.first_stamp_ms = Some(ms);
                    }
                }
            }
            None => {
                self.entries.insert(
                    key,
                    Entry {
                        pgn,
                        src,
                        secondary,
                        description,
                        line,
                        last_update: now,
                        count: 1,
                        first_seen: now,
                        first_stamp_ms: stamp_ms,
                        last_stamp_ms: stamp_ms,
                        history_indices: vec![history_idx],
                    },
                );
            }
        }
        // Every 60928 / 126996 / 126998 record enriches the
        // persistent NAME → info cache. See
        // `AppState::observe_for_cache` for the extraction logic.
        self.observe_for_cache(pgn, src, self.history.last().map(|h| h.line.clone()));
        self.status.messages_seen = self.status.messages_seen.saturating_add(1);
    }

    /// Update the persistent [`AppState::device_cache`] from a
    /// freshly-observed record. PGN 60928 (ISO Address Claim)
    /// carries the NAME components; PGNs 126996 and 126998 carry
    /// product / configuration info that we key off the NAME learned
    /// from the last 60928 for the same source.
    fn observe_for_cache(&mut self, pgn: u32, src: u8, line: Option<Value>) {
        let Some(line) = line else { return };
        let now_stamp = line
            .pointer("/timestamp")
            .and_then(Value::as_str)
            .map(str::to_string);
        match pgn {
            60928 => {
                if let Some(key) = name_key_from_claim(&line) {
                    self.src_to_name.insert(src, key);
                    let info = CachedInfo {
                        manufacturer_name: manufacturer_name_from_claim(&line),
                        device_function: field_number(&line, "Device Function").map(|v| v as u32),
                        device_class: field_number(&line, "Device Class").map(|v| v as u32),
                        industry_group: field_number(&line, "Industry Group").map(|v| v as u32),
                        first_seen: now_stamp.clone(),
                        last_seen: now_stamp,
                        ..Default::default()
                    };
                    self.device_cache.entry(key).or_default().merge_from(info);
                }
            }
            126996 => {
                let Some(key) = self.src_to_name.get(&src).copied() else {
                    return;
                };
                let info = CachedInfo {
                    product_code: field_number(&line, "Product Code").map(|v| v as u32),
                    model_id: field_text(&line, "Model ID"),
                    software_version: field_text(&line, "Software Version Code"),
                    model_version: field_text(&line, "Model Version"),
                    model_serial_code: field_text(&line, "Model Serial Code"),
                    nmea_db_version: field_number(&line, "NMEA 2000 Version").map(|v| v as u32),
                    certification_level: field_number(&line, "NMEA 2000 Certification Level")
                        .map(|v| v as u32),
                    load_equivalency: field_number(&line, "Load Equivalency").map(|v| v as u32),
                    last_seen: now_stamp,
                    ..Default::default()
                };
                self.device_cache.entry(key).or_default().merge_from(info);
            }
            126998 => {
                let Some(key) = self.src_to_name.get(&src).copied() else {
                    return;
                };
                let info = CachedInfo {
                    installation_description_1: field_text(&line, "Installation Description #1"),
                    installation_description_2: field_text(&line, "Installation Description #2"),
                    manufacturer_information: field_text(&line, "Manufacturer Information"),
                    last_seen: now_stamp,
                    ..Default::default()
                };
                self.device_cache.entry(key).or_default().merge_from(info);
            }
            _ => {}
        }
    }

    /// Walk the cache and produce a stable, src-ordered device list,
    /// pulling identity fields out of the device-info PGNs. Cheap
    /// enough to run per frame (a typical bus has tens of devices and
    /// hundreds of entries).
    ///
    /// Anything not yet observed this session (typical case: a log
    /// capture missing the request-only PGN 126996) is backfilled
    /// from [`AppState::device_cache`] whenever we have a NAME for
    /// this source, so the DeviceDetail screen shows the same
    /// manufacturer / model / installation labels the user has seen
    /// on this device before.
    pub fn device_list(&self) -> Vec<DeviceInfo> {
        let mut by_src: BTreeMap<u8, DeviceInfo> = BTreeMap::new();
        let mut pgns_per_src: BTreeMap<u8, std::collections::BTreeSet<u32>> = BTreeMap::new();
        for entry in self.entries.values() {
            pgns_per_src.entry(entry.src).or_default().insert(entry.pgn);
            let dev = by_src.entry(entry.src).or_insert_with(|| DeviceInfo {
                src: entry.src,
                ..Default::default()
            });
            match entry.pgn {
                60928 => fill_from_claim(dev, &entry.line),
                126996 => fill_from_product_info(dev, &entry.line),
                126998 => fill_from_config_info(dev, &entry.line),
                _ => {}
            }
        }
        for (src, set) in pgns_per_src {
            if let Some(dev) = by_src.get_mut(&src) {
                dev.pgn_count = set.len();
            }
        }
        // Enrichment pass: anywhere a field is still empty, try the
        // persistent cache. Cache lookups are anchored on the NAME
        // we learned from this session's 60928 (if any) — a session
        // with only cached info and no fresh ISO claim can't be
        // enriched because we don't know which NAME owns which src.
        for dev in by_src.values_mut() {
            let Some(key) = self.src_to_name.get(&dev.src) else {
                continue;
            };
            let Some(cached) = self.device_cache.get(key) else {
                continue;
            };
            if dev.manufacturer.is_empty()
                && let Some(m) = &cached.manufacturer_name
            {
                dev.manufacturer = m.clone();
            }
            if dev.model.is_empty()
                && let Some(m) = &cached.model_id
            {
                dev.model = m.clone();
            }
            if dev.software.is_empty()
                && let Some(s) = &cached.software_version
            {
                dev.software = s.clone();
            }
            if dev.installation.is_empty()
                && let Some(i) = &cached.installation_description_1
            {
                dev.installation = i.clone();
            }
        }
        by_src.into_values().collect()
    }

    /// Fold one PGN 262657 Report frame into [`AppState::nmea0183`].
    /// Only Report frames (Function 0) carry state; a stray Set
    /// (Function 1) echoed back is ignored.
    fn apply_nmea0183_report(&mut self, line: &Value) {
        if field_number(line, "Function") != Some(0) {
            return;
        }
        let Some(src) = field_number(line, "Source") else {
            return;
        };
        let Some(sentence) = field_text(line, "Sentence") else {
            return;
        };
        let muted = field_number(line, "Muted").unwrap_or(0) != 0;
        let dev = self.nmea0183.entry(src as u8).or_default();
        if sentence == NMEA0183_ALL {
            dev.muted = muted;
        } else {
            dev.sentences.insert(sentence, muted);
        }
    }

    /// Flatten [`AppState::nmea0183`] into navigable rows: one
    /// whole-source header per device followed by its sentences,
    /// source-ordered.
    pub fn nmea0183_rows(&self) -> Vec<Nmea0183Row> {
        let mut rows = Vec::new();
        for (src, dev) in &self.nmea0183 {
            rows.push(Nmea0183Row {
                src: *src,
                sentence: None,
                muted: dev.muted,
            });
            for (sentence, muted) in &dev.sentences {
                rows.push(Nmea0183Row {
                    src: *src,
                    sentence: Some(sentence.clone()),
                    muted: *muted,
                });
            }
        }
        rows
    }

    /// Aggregate every entry by PGN for the `top`-style load view.
    /// Sums observation counts and measured message rates across all
    /// sources of each PGN, then sorts busiest-first (rate desc, then
    /// count desc, then PGN asc for a stable tie-break).
    pub fn pgn_load_rows(&self) -> Vec<PgnLoadRow> {
        let mut agg: HashMap<u32, (String, HashSet<u8>, u64, f32)> = HashMap::new();
        for e in self.entries.values() {
            // `count == 0` is the synthetic silenced-override sentinel —
            // no real traffic, so it doesn't belong in a load view.
            if e.count == 0 {
                continue;
            }
            let slot = agg.entry(e.pgn).or_default();
            if slot.0.is_empty() && !e.description.is_empty() {
                slot.0 = e.description.clone();
            }
            slot.1.insert(e.src);
            slot.2 += e.count;
            if let Some(iv) = e.interval() {
                let ms = iv.as_millis() as f32;
                if ms > 0.0 {
                    slot.3 += 1000.0 / ms;
                }
            }
        }
        let mut rows: Vec<PgnLoadRow> = agg
            .into_iter()
            .map(|(pgn, (description, srcs, count, rate))| PgnLoadRow {
                pgn,
                description,
                sources: srcs.len(),
                count,
                rate,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.rate
                .partial_cmp(&a.rate)
                .unwrap_or(Ordering::Equal)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.pgn.cmp(&b.pgn))
        });
        rows
    }

    /// All entries for `src`, sorted by PGN then secondary so the UI
    /// shows a stable list.
    pub fn entries_for_src(&self, src: u8) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.values().filter(|e| e.src == src).collect();
        v.sort_by(|a, b| {
            a.pgn
                .cmp(&b.pgn)
                .then_with(|| a.secondary.cmp(&b.secondary))
        });
        v
    }

    /// Latest cached PGN 126464 entries (PGN List — Transmit /
    /// Receive) for `src`, split into the two lists. Either Vec is
    /// empty when the corresponding direction hasn't been observed
    /// (yet).
    pub fn pgn_lists_for_src(&self, src: u8) -> PgnLists {
        let mut tx = Vec::new();
        let mut rx = Vec::new();
        for entry in self.entries.values() {
            if entry.pgn != 126464 || entry.src != src {
                continue;
            }
            let direction = entry
                .line
                .pointer("/fields/Function Code")
                .and_then(field_as_int);
            let list = collect_pgn_list(&entry.line);
            match direction {
                Some(0) => tx.extend(list),
                Some(1) => rx.extend(list),
                _ => {}
            }
        }
        tx.sort_unstable();
        tx.dedup();
        rx.sort_unstable();
        rx.dedup();
        PgnLists { tx, rx }
    }
}

/// TX / RX PGN lists pulled out of cached PGN 126464 records.
#[derive(Debug, Clone, Default)]
pub struct PgnLists {
    pub tx: Vec<u32>,
    pub rx: Vec<u32>,
}

impl PgnLists {
    pub fn is_empty(&self) -> bool {
        self.tx.is_empty() && self.rx.is_empty()
    }
}

/// Extract a `NameKey` (`(manufacturer_code, unique_number)`) from
/// an analyzer-JSON PGN 60928 record. Returns `None` when either
/// field is absent — an incomplete Address Claim isn't useful as a
/// cache key.
fn name_key_from_claim(line: &Value) -> Option<NameKey> {
    let mfr = field_number(line, "Manufacturer Code")?;
    let uid = field_number(line, "Unique Number")?;
    Some(NameKey {
        manufacturer_code: u16::try_from(mfr).ok()?,
        unique_number: u32::try_from(uid).ok()?,
    })
}

/// Pull the `-nv` display name of the Manufacturer Code lookup out
/// of a PGN 60928 record. Falls back to the bare-integer path so
/// non-`-nv` producers still populate the cache with *something*.
fn manufacturer_name_from_claim(line: &Value) -> Option<String> {
    let v = line.pointer("/fields/Manufacturer Code")?;
    v.pointer("/name")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Pull an integer out of `line.fields.<name>` (handles both the
/// bare-integer JSON shape and the `-nv` `{value, name}` object).
fn field_number(line: &Value, name: &str) -> Option<i64> {
    let v = line.pointer(&format!("/fields/{}", json_pointer_escape(name)))?;
    field_as_int(v)
}

fn fill_from_claim(dev: &mut DeviceInfo, line: &Value) {
    if dev.manufacturer.is_empty()
        && let Some(name) = field_text(line, "Manufacturer Code")
    {
        dev.manufacturer = name;
    }
}

fn fill_from_product_info(dev: &mut DeviceInfo, line: &Value) {
    if let Some(s) = field_text(line, "Model ID") {
        dev.model = s;
    }
    if let Some(s) = field_text(line, "Software Version Code") {
        dev.software = s;
    }
    // Product Info also carries the manufacturer code as text; only
    // backfill when the ISO Address Claim hasn't filled it in yet.
    if dev.manufacturer.is_empty()
        && let Some(s) = field_text(line, "Manufacturer")
    {
        dev.manufacturer = s;
    }
}

fn fill_from_config_info(dev: &mut DeviceInfo, line: &Value) {
    if let Some(s) = field_text(line, "Installation Description #1") {
        dev.installation = s;
    }
}

/// Pull a field's display text out of a parsed analyzer JSON line.
/// Handles both bare values and the `-nv` `{value, name}` lookup
/// object shape.
fn field_text(line: &Value, name: &str) -> Option<String> {
    let v = line.pointer(&format!("/fields/{}", json_pointer_escape(name)))?;
    if let Some(s) = v.as_str() {
        return Some(s.trim().to_string());
    }
    if let Some(obj) = v.as_object() {
        if let Some(s) = obj.get("name").and_then(Value::as_str) {
            return Some(s.trim().to_string());
        }
        if let Some(n) = obj.get("value") {
            return Some(n.to_string());
        }
    }
    if v.is_number() || v.is_boolean() {
        return Some(v.to_string());
    }
    None
}

fn field_as_int(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(obj) = v.as_object()
        && let Some(n) = obj.get("value").and_then(Value::as_i64)
    {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    None
}

/// Walk the `"PGN"` list inside a PGN 126464 record — canboat
/// renders it as `fields.list: [{ "PGN": <n> }, ...]`.
fn collect_pgn_list(line: &Value) -> Vec<u32> {
    let Some(arr) = line.pointer("/fields/list").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|elem| elem.pointer("/PGN").and_then(field_as_int))
        .filter_map(|n| u32::try_from(n).ok())
        .collect()
}

/// Escape a single JSON Pointer reference token per RFC 6901: `~` →
/// `~0`, `/` → `~1`. canboat field names are mostly ASCII without
/// either, but a few like `"Installation Description #1"` survive
/// unchanged; do this anyway so we never silently miss a field.
fn json_pointer_escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state() -> AppState {
        AppState::new(Status::new_live("t".into(), 0, 0), HashMap::new())
    }

    fn report(src: u8, sentence: &str, muted: u8) -> Value {
        json!({
            "pgn": 262657,
            "fields": {"Function": 0, "Source": src, "Sentence": sentence, "Muted": muted}
        })
    }

    #[test]
    fn nmea0183_report_builds_rows_and_stays_out_of_entries() {
        let mut s = state();
        s.upsert(262657, 0, None, String::new(), report(35, NMEA0183_ALL, 0));
        s.upsert(262657, 0, None, String::new(), report(35, "VHW", 0));
        s.upsert(262657, 0, None, String::new(), report(35, "VLW", 1));
        // Control frames don't pollute the bus/device model.
        assert!(s.entries.is_empty());
        assert!(s.device_list().is_empty());
        let rows = s.nmea0183_rows();
        // header (ALL) + VHW + VLW
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].src, 35);
        assert!(rows[0].sentence.is_none() && !rows[0].muted);
        assert_eq!(rows[1].sentence.as_deref(), Some("VHW"));
        assert!(!rows[1].muted);
        assert_eq!(rows[2].sentence.as_deref(), Some("VLW"));
        assert!(rows[2].muted);
    }

    #[test]
    fn whole_source_mute_updates_header() {
        let mut s = state();
        s.upsert(262657, 0, None, String::new(), report(53, "MWV", 0));
        s.upsert(262657, 0, None, String::new(), report(53, NMEA0183_ALL, 1));
        let rows = s.nmea0183_rows();
        assert!(rows[0].sentence.is_none() && rows[0].muted);
    }

    #[test]
    fn pgn_load_rows_aggregate_across_sources_and_sort_busiest_first() {
        let mut s = state();
        // 129025 seen from two sources (two observations from one of
        // them), 127250 seen once.
        s.upsert(129025, 10, None, "Position".into(), json!({"pgn": 129025}));
        s.upsert(129025, 10, None, "Position".into(), json!({"pgn": 129025}));
        s.upsert(129025, 11, None, "Position".into(), json!({"pgn": 129025}));
        s.upsert(127250, 10, None, "Heading".into(), json!({"pgn": 127250}));
        let rows = s.pgn_load_rows();
        assert_eq!(rows.len(), 2);
        let pos = rows.iter().find(|r| r.pgn == 129025).unwrap();
        assert_eq!(pos.sources, 2);
        assert_eq!(pos.count, 3);
        assert_eq!(pos.description, "Position");
        // Ties on rate (all zero until a cadence is measured) break by
        // count desc, so the 3-count PGN sorts ahead of the 1-count one.
        assert_eq!(rows[0].pgn, 129025);
    }
}
