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

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use indexmap::IndexMap;
use serde_json::Value;

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
    /// Indices into [`AppState::history`], one per observation of
    /// this key, in chronological insertion order. The last index
    /// names the same record that `line` caches. Empty on
    /// synthetic silenced-override placeholder rows.
    pub history_indices: Vec<usize>,
}

impl Entry {
    /// Average measured transmission interval. Returns `None` until
    /// the second record arrives (one observation isn't enough to
    /// measure a cadence). Computed as `(last_update − first_seen) /
    /// (count − 1)`, i.e. the mean inter-arrival time across every
    /// record we've seen for this key.
    pub fn interval(&self) -> Option<std::time::Duration> {
        if self.count < 2 {
            return None;
        }
        let span = self.last_update.saturating_duration_since(self.first_seen);
        Some(span / (self.count as u32 - 1))
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
}

impl AppState {
    pub fn new(status: Status) -> Self {
        Self {
            entries: IndexMap::new(),
            history: Vec::new(),
            status,
            alerts: VecDeque::new(),
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
        let key = (pgn, src, secondary.clone());
        let now = Instant::now();
        let timestamp = line
            .pointer("/timestamp")
            .and_then(Value::as_str)
            .map(str::to_string);

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
                        history_indices: vec![history_idx],
                    },
                );
            }
        }
        self.status.messages_seen = self.status.messages_seen.saturating_add(1);
    }

    /// Walk the cache and produce a stable, src-ordered device list,
    /// pulling identity fields out of the device-info PGNs. Cheap
    /// enough to run per frame (a typical bus has tens of devices and
    /// hundreds of entries).
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
        by_src.into_values().collect()
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

fn fill_from_claim(dev: &mut DeviceInfo, line: &Value) {
    if dev.manufacturer.is_empty() {
        if let Some(name) = field_text(line, "Manufacturer Code") {
            dev.manufacturer = name;
        }
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
    if dev.manufacturer.is_empty() {
        if let Some(s) = field_text(line, "Manufacturer") {
            dev.manufacturer = s;
        }
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
    if let Some(obj) = v.as_object() {
        if let Some(n) = obj.get("value").and_then(Value::as_i64) {
            return Some(n);
        }
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
