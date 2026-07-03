// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! ratatui rendering + keyboard handling.
//!
//! Three screens, plus three modals:
//!
//! * [`Screen::Devices`] — top-level list of source addresses with
//!   manufacturer / model / PGN-count columns. `Enter` drills in;
//!   `q` quits.
//!
//! * [`Screen::DeviceDetail`] — every cached `(pgn, secondary)`
//!   tuple this device has produced, with the latest update time
//!   and per-tuple receive count. The PGN-List-Transmit / Receive
//!   pair from PGN 126464 is shown at the bottom; `i` sends an ISO
//!   Request for 126464 so the device tells us what it actually
//!   carries.
//!
//! * [`Screen::EntryDetail`] — the latest JSON line for the selected
//!   `(pgn, src, secondary)` tuple, pretty-printed.
//!
//! Modals (rendered on top of whichever screen is active, in priority
//! order — the highest-priority match wins for both rendering and
//! key handling):
//!
//! 1. **Error** — shown whenever `AppState::status.last_error` carries
//!    a string the user hasn't yet acknowledged. Any key dismisses it.
//! 2. **Connecting** — shown at startup until both connections settle
//!    (success or failure). Auto-dismisses on clean two-way success;
//!    any key dismisses it manually.
//! 3. **Override** — opened with `o` from `DeviceDetail` for the
//!    highlighted PGN. Accepts a transmission interval in ms; `0`
//!    means "stop transmitting". Hidden entirely (no key binding,
//!    not advertised in the hint bar) when the overrides file
//!    can't be persisted — see `App::overrides_writable`. A
//!    silenced PGN stays visible on its device's list (with an OFF
//!    marker, sourced from the overrides file) so the user can
//!    later re-enable it.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap,
};

use crate::iso;
use crate::overrides::{self, INTERVAL_OFF, Override, Overrides, default_path};
use crate::state::{AppState, DeviceInfo, Entry, Mode};

/// Per-PGN well-known transmit defaults, used purely as UI hints
/// when the user opens the override dialog. Picking the right default
/// is on the user — this is just a starting value.
fn default_interval_hint(pgn: u32) -> u32 {
    match pgn {
        127251 => 100,
        127257 | 127250 => 100,
        129025 | 129026 | 129029 => 250,
        130306 => 100,
        _ => 1000,
    }
}

#[derive(Clone)]
pub enum Screen {
    Devices,
    DeviceDetail {
        src: u8,
    },
    EntryDetail {
        src: u8,
        pgn: u32,
        secondary: Option<String>,
        /// Which observation in the entry's `history_indices` is
        /// currently being displayed. Defaults to the latest on
        /// drill-in; ← / → step backwards / forwards through past
        /// records. Clamped at draw time so the buffer being mutated
        /// underneath us (new records arriving in live mode) doesn't
        /// produce a stale index.
        history_pos: usize,
        /// Where to return on Esc/Backspace/h. `Screen::DeviceDetail`
        /// when the user drilled in from the per-device PGN list;
        /// `Screen::TimeView` when they drilled in from a timeline
        /// row. Preserving the origin means "back" behaves the way
        /// the user expects instead of always dumping them on the
        /// device tree.
        return_to: Box<Screen>,
    },
    /// Chronological list of every observed record. Toggled with
    /// `t` (time) / `d` (devices). Most useful in log-replay mode
    /// where the timeline is finite and the user wants to see the
    /// exact sequence a device booted / claimed / negotiated in,
    /// but it works in live mode too.
    TimeView,
}

pub struct App {
    pub screen: Screen,
    pub devices_state: ListState,
    pub detail_state: ListState,
    /// Selection state for the `TimeView` screen — one row per
    /// observation in `AppState::history`.
    pub time_state: ListState,
    /// Vertical scroll offset for the pretty-printed JSON in the
    /// `EntryDetail` screen. Reset to 0 when drilling in.
    pub entry_scroll: u16,
    pub overrides: Overrides,
    pub overrides_path: std::path::PathBuf,
    /// Set at startup by probing the overrides file with
    /// [`overrides::is_writable`]. When `false` the `o` override
    /// affordance is removed everywhere — the key binding does
    /// nothing and the per-screen hint bar omits it — so the user
    /// isn't shown a feature whose state can't be persisted. If a
    /// later `save()` fails (disk full, perms revoked) we flip this
    /// back to `false` and surface the error.
    pub overrides_writable: bool,
    pub modal: Option<OverrideModal>,
    /// Last status / error toast (cleared on next keystroke).
    pub toast: Option<String>,
    /// Current bus-side alert shown in the status bar — drained one
    /// per draw from `AppState::alerts` (e.g. a NAKed PGN 126208
    /// Acknowledge). Cleared on any keystroke, at which point the
    /// next draw pulls the next pending alert if any. Has higher
    /// priority than `toast` in the status-bar render path so
    /// device-reported failures don't get drowned out by our own
    /// "Sent override" confirmations.
    pub alert: Option<String>,
    pub should_quit: bool,
    /// True once the user has dismissed the startup "Connecting…"
    /// modal (or it auto-dismissed itself after both connections
    /// came up clean).
    pub connecting_dismissed: bool,
    /// The most recent error message the user has already
    /// acknowledged. Whenever `state.status.last_error` is `Some(e)`
    /// and `e != last_acknowledged_error`, a fatal-error modal is
    /// drawn over everything until the user presses a key.
    pub last_acknowledged_error: Option<String>,
    /// Active text-entry prompt for `/` (search) or `f` (PGN filter)
    /// on the TimeView screen. When `Some`, keystrokes go into the
    /// buffer; Enter applies, Esc cancels.
    pub text_prompt: Option<TextPrompt>,
    /// Active source-select modal for `s` on the TimeView screen —
    /// a checkbox list of currently-known sources, Space to toggle,
    /// Enter to apply.
    pub src_select: Option<SrcSelect>,
    /// Currently active substring search on TimeView (from `/`).
    /// Case-insensitive match against a canonical row string
    /// (`<timestamp> src <src> pgn <pgn> <description>`). `n` / `N`
    /// step through matches; `/` with empty input clears.
    pub search_query: Option<String>,
    /// Currently active PGN allowlist (from `f`). `None` = show all;
    /// `Some([])` behaves the same but is never produced (empty
    /// input clears back to `None`).
    pub filter_pgns: Option<Vec<u32>>,
    /// Currently active source allowlist (from `s`). Same
    /// conventions as `filter_pgns`.
    pub filter_srcs: Option<Vec<u8>>,
}

/// One-line text prompt shown at the bottom of the screen when the
/// user presses `/` or `f` on TimeView. `kind` picks what Enter
/// does with the buffered text.
pub struct TextPrompt {
    pub kind: TextPromptKind,
    pub buffer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextPromptKind {
    /// `/` — substring search across formatted row text.
    Search,
    /// `f` — comma-separated PGN allowlist. Empty clears.
    FilterPgns,
}

/// State for the interactive source-select modal (`s` on TimeView).
/// The list is snapshot at open time from `AppState::device_list()`;
/// cursor + selected set live here so the user can toggle multiple
/// sources before hitting Enter.
pub struct SrcSelect {
    pub sources: Vec<(u8, String)>,
    pub selected: std::collections::HashSet<u8>,
    pub cursor: usize,
}

pub struct OverrideModal {
    pub src: u8,
    pub pgn: u32,
    pub input: String,
    pub manufacturer_code: Option<u16>,
    pub industry_code: Option<u8>,
    /// PGN description captured at modal open time — stored on the
    /// resulting [`Override`] so a later silenced-row display can
    /// label the PGN even after the live cache entry ages out.
    pub description: Option<String>,
}

impl App {
    pub fn new() -> Self {
        let overrides_path = default_path();
        let overrides = Overrides::load_or_default(&overrides_path);
        let overrides_writable = overrides::is_writable(&overrides_path);
        let mut devices_state = ListState::default();
        devices_state.select(Some(0));
        let mut detail_state = ListState::default();
        detail_state.select(Some(0));
        let mut time_state = ListState::default();
        time_state.select(Some(0));
        Self {
            screen: Screen::Devices,
            devices_state,
            detail_state,
            time_state,
            entry_scroll: 0,
            overrides,
            overrides_path,
            overrides_writable,
            modal: None,
            toast: None,
            alert: None,
            should_quit: false,
            connecting_dismissed: false,
            last_acknowledged_error: None,
            text_prompt: None,
            src_select: None,
            search_query: None,
            filter_pgns: None,
            filter_srcs: None,
        }
    }

    /// Row visibility filter for TimeView. Returns the indices into
    /// `state.history` of the records that pass the currently-active
    /// PGN + source filters (both AND-combined; `None` = pass all).
    /// Used both by the renderer (which rows to display) and by
    /// search navigation (which rows are candidates for `n`/`N`).
    pub fn visible_history_indices(&self, state: &AppState) -> Vec<usize> {
        if self.filter_pgns.is_none() && self.filter_srcs.is_none() {
            return (0..state.history.len()).collect();
        }
        state
            .history
            .iter()
            .enumerate()
            .filter(|(_, h)| {
                self.filter_pgns
                    .as_ref()
                    .is_none_or(|list| list.contains(&h.pgn))
                    && self
                        .filter_srcs
                        .as_ref()
                        .is_none_or(|list| list.contains(&h.src))
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Composed row list for the DeviceDetail screen: live cached
    /// entries for `src`, plus a synthetic row for every silenced
    /// override on this `src` whose PGN isn't already represented
    /// by a live entry. The synthetic row has `count = 0` (which
    /// [`format_entry_row`] reads as "show OFF instead of every
    /// X ms") and carries the description we captured when the
    /// user set the override, so even an aged-out PGN stays
    /// visible and labelled.
    pub fn detail_rows(&self, src: u8, state: &AppState) -> Vec<Entry> {
        let mut rows: Vec<Entry> = state.entries_for_src(src).into_iter().cloned().collect();
        let live_pgns: std::collections::HashSet<u32> = rows.iter().map(|e| e.pgn).collect();
        for ov in self.overrides.silenced() {
            if ov.src != src || live_pgns.contains(&ov.pgn) {
                continue;
            }
            rows.push(synthesize_silenced_entry(ov));
        }
        rows.sort_by(|a, b| {
            a.pgn
                .cmp(&b.pgn)
                .then_with(|| a.secondary.cmp(&b.secondary))
        });
        rows
    }

    /// Re-emit every stored override to the bus. Called on startup
    /// after the stream connection is up so user changes persist
    /// across target reboots.
    pub fn replay_overrides(&self, writer: &crate::client::Writer) {
        for ov in &self.overrides.entries {
            let line = match (ov.manufacturer_code, ov.industry_code) {
                (Some(mfr), Some(ind)) => iso::request_transmission_interval_proprietary(
                    ov.src,
                    ov.pgn,
                    mfr,
                    ind,
                    ov.interval_ms,
                ),
                _ => iso::request_transmission_interval(ov.src, ov.pgn, ov.interval_ms),
            };
            let _ = writer.send(line);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, state: &AppState, writer: &crate::client::Writer) {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }
        // Ctrl-C always quits, even with a modal open.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }
        // The fatal-error modal trumps every other input — dismiss
        // it by acknowledging the current error string, then return.
        if has_unacknowledged_error(self, state) {
            self.last_acknowledged_error = state.status.last_error.clone();
            return;
        }
        // The connecting modal eats every other keypress so a user
        // tapping a key while reading "Connecting…" doesn't accidentally
        // start navigating the (still empty) device list.
        if !self.connecting_dismissed {
            self.connecting_dismissed = true;
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(key, writer);
            return;
        }
        // Text prompt (/ or f) trumps every other key on TimeView.
        if self.text_prompt.is_some() {
            self.handle_text_prompt_key(key, state);
            return;
        }
        // Source-select modal (s) trumps everything else too.
        if self.src_select.is_some() {
            self.handle_src_select_key(key);
            return;
        }
        self.toast = None;
        self.alert = None;
        // Left/right on EntryDetail steps through past instances.
        // Handled *before* the shared-borrow match so we can grab a
        // `&mut history_pos` inside the Screen without conflicting
        // with the `&self.screen` borrow the main match takes.
        if let Screen::EntryDetail { history_pos, .. } = &mut self.screen {
            match key.code {
                KeyCode::Left | KeyCode::Char('H') => {
                    *history_pos = history_pos.saturating_sub(1);
                    self.entry_scroll = 0;
                    return;
                }
                KeyCode::Right | KeyCode::Char('L') => {
                    *history_pos = history_pos.saturating_add(1);
                    self.entry_scroll = 0;
                    return;
                }
                _ => {}
            }
        }
        match (&self.screen, key.code) {
            (_, KeyCode::Char('q')) => self.should_quit = true,
            // Global view toggles — `t` opens TimeView; `d` returns
            // to the device tree from anywhere. Both preserve the
            // per-screen ListState so the user's position isn't lost
            // when toggling back.
            (_, KeyCode::Char('t')) => self.screen = Screen::TimeView,
            (Screen::TimeView, KeyCode::Char('d')) => self.screen = Screen::Devices,
            (Screen::TimeView, KeyCode::Down) | (Screen::TimeView, KeyCode::Char('j')) => {
                let n = self.visible_history_indices(state).len();
                navigate_list(&mut self.time_state, n, 1);
            }
            (Screen::TimeView, KeyCode::Up) | (Screen::TimeView, KeyCode::Char('k')) => {
                let n = self.visible_history_indices(state).len();
                navigate_list(&mut self.time_state, n, -1);
            }
            (Screen::TimeView, KeyCode::Char('/')) => {
                self.text_prompt = Some(TextPrompt {
                    kind: TextPromptKind::Search,
                    buffer: self.search_query.clone().unwrap_or_default(),
                });
            }
            (Screen::TimeView, KeyCode::Char('f')) => {
                let buffer = self
                    .filter_pgns
                    .as_ref()
                    .map(|list| {
                        list.iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                self.text_prompt = Some(TextPrompt {
                    kind: TextPromptKind::FilterPgns,
                    buffer,
                });
            }
            (Screen::TimeView, KeyCode::Char('s')) => {
                let devs = state.device_list();
                let sources: Vec<(u8, String)> = devs
                    .iter()
                    .map(|d| {
                        let label = if d.manufacturer.is_empty() && d.model.is_empty() {
                            format!("src {}", d.src)
                        } else {
                            format!(
                                "src {:3}  {} {}",
                                d.src,
                                d.manufacturer.as_str(),
                                d.model.as_str()
                            )
                        };
                        (d.src, label)
                    })
                    .collect();
                let selected = self
                    .filter_srcs
                    .as_ref()
                    .cloned()
                    .map(|v| v.into_iter().collect())
                    .unwrap_or_else(|| sources.iter().map(|(s, _)| *s).collect());
                self.src_select = Some(SrcSelect {
                    sources,
                    selected,
                    cursor: 0,
                });
            }
            (Screen::TimeView, KeyCode::Char('n')) => {
                self.jump_search(state, 1);
            }
            (Screen::TimeView, KeyCode::Char('N')) => {
                self.jump_search(state, -1);
            }
            (Screen::TimeView, KeyCode::Enter) => {
                // Translate the visible-row cursor to an actual
                // `state.history` index — the filter may hide most
                // of the raw list.
                let visible = self.visible_history_indices(state);
                if let Some(target) = self
                    .time_state
                    .selected()
                    .and_then(|i| visible.get(i).copied())
                    && let Some(row) = state.history.get(target)
                {
                    // Drilling in from TimeView opens EntryDetail for
                    // the record the cursor is on, positioned to
                    // exactly that observation — so you can Esc back
                    // and left/right through nearby instances.
                    let key = (row.pgn, row.src, row.secondary.clone());
                    if let Some(entry) = state.entries.get(&key) {
                        let history_pos = entry
                            .history_indices
                            .iter()
                            .position(|i| *i == target)
                            .unwrap_or(entry.history_indices.len().saturating_sub(1));
                        self.entry_scroll = 0;
                        self.screen = Screen::EntryDetail {
                            src: row.src,
                            pgn: row.pgn,
                            secondary: row.secondary.clone(),
                            history_pos,
                            return_to: Box::new(Screen::TimeView),
                        };
                    }
                }
            }
            (Screen::TimeView, KeyCode::Esc) => self.screen = Screen::Devices,
            (Screen::Devices, KeyCode::Down) | (Screen::Devices, KeyCode::Char('j')) => {
                navigate_list(&mut self.devices_state, state.device_list().len(), 1);
            }
            (Screen::Devices, KeyCode::Up) | (Screen::Devices, KeyCode::Char('k')) => {
                navigate_list(&mut self.devices_state, state.device_list().len(), -1);
            }
            (Screen::Devices, KeyCode::Enter) => {
                let devs = state.device_list();
                if let Some(d) = self.devices_state.selected().and_then(|i| devs.get(i)) {
                    self.screen = Screen::DeviceDetail { src: d.src };
                    self.detail_state.select(Some(0));
                }
            }
            (Screen::DeviceDetail { src }, KeyCode::Down)
            | (Screen::DeviceDetail { src }, KeyCode::Char('j')) => {
                let n = self.detail_rows(*src, state).len();
                navigate_list(&mut self.detail_state, n, 1);
            }
            (Screen::DeviceDetail { src }, KeyCode::Up)
            | (Screen::DeviceDetail { src }, KeyCode::Char('k')) => {
                let n = self.detail_rows(*src, state).len();
                navigate_list(&mut self.detail_state, n, -1);
            }
            (Screen::DeviceDetail { src }, KeyCode::Enter) => {
                let rows = self.detail_rows(*src, state);
                if let Some(row) = self.detail_state.selected().and_then(|i| rows.get(i)) {
                    // Silenced rows (`count == 0`) have a Null `line`
                    // and no live data to show in EntryDetail; skip
                    // the drill-in so the user doesn't land on a
                    // pretty-printed `null`.
                    if row.count == 0 {
                        return;
                    }
                    self.entry_scroll = 0;
                    // Start at the most recent observation. Saturating
                    // is fine — a live entry has count >= 1, and we
                    // skipped count==0 rows above.
                    let history_pos = row.history_indices.len().saturating_sub(1);
                    let return_src = *src;
                    self.screen = Screen::EntryDetail {
                        src: return_src,
                        pgn: row.pgn,
                        secondary: row.secondary.clone(),
                        history_pos,
                        return_to: Box::new(Screen::DeviceDetail { src: return_src }),
                    };
                }
            }
            (Screen::DeviceDetail { src }, KeyCode::Char('i'))
                if state.status.mode == Mode::Live =>
            {
                // Ask the device to publish its PGN List (Transmit/Receive).
                let line = iso::iso_request(*src, 126464);
                if writer.send(line) {
                    self.toast = Some(format!("Sent ISO Request 126464 → src {src}"));
                } else {
                    self.toast = Some("Writer channel closed".into());
                }
            }
            (Screen::DeviceDetail { src }, KeyCode::Char('o'))
                if state.status.mode == Mode::Live && self.overrides_writable =>
            {
                let rows = self.detail_rows(*src, state);
                if let Some(row) = self.detail_state.selected().and_then(|i| rows.get(i)) {
                    // Live row: read mfr/ind off the cached JSON.
                    // Silenced row (`count == 0`): line is Null — pull
                    // mfr/ind/description back from the override file
                    // entry that put it on the list in the first place.
                    let (mfr, ind, desc) = if row.count == 0 {
                        let ov = self
                            .overrides
                            .entries
                            .iter()
                            .find(|o| o.src == row.src && o.pgn == row.pgn);
                        (
                            ov.and_then(|o| o.manufacturer_code),
                            ov.and_then(|o| o.industry_code),
                            ov.and_then(|o| o.description.clone()),
                        )
                    } else {
                        let (m, i) = proprietary_codes(row);
                        let d = (!row.description.is_empty()).then(|| row.description.clone());
                        (m, i, d)
                    };
                    self.modal = Some(OverrideModal {
                        src: *src,
                        pgn: row.pgn,
                        input: default_interval_hint(row.pgn).to_string(),
                        manufacturer_code: mfr,
                        industry_code: ind,
                        description: desc,
                    });
                }
            }
            (Screen::DeviceDetail { .. }, KeyCode::Esc)
            | (Screen::DeviceDetail { .. }, KeyCode::Backspace)
            | (Screen::DeviceDetail { .. }, KeyCode::Char('h')) => {
                self.screen = Screen::Devices;
            }
            (Screen::EntryDetail { .. }, KeyCode::Down)
            | (Screen::EntryDetail { .. }, KeyCode::Char('j')) => {
                self.entry_scroll = self.entry_scroll.saturating_add(1);
            }
            (Screen::EntryDetail { .. }, KeyCode::Up)
            | (Screen::EntryDetail { .. }, KeyCode::Char('k')) => {
                self.entry_scroll = self.entry_scroll.saturating_sub(1);
            }
            (Screen::EntryDetail { .. }, KeyCode::PageDown)
            | (Screen::EntryDetail { .. }, KeyCode::Char(' ')) => {
                self.entry_scroll = self.entry_scroll.saturating_add(10);
            }
            (Screen::EntryDetail { .. }, KeyCode::PageUp) => {
                self.entry_scroll = self.entry_scroll.saturating_sub(10);
            }
            (Screen::EntryDetail { .. }, KeyCode::Home)
            | (Screen::EntryDetail { .. }, KeyCode::Char('g')) => {
                self.entry_scroll = 0;
            }
            (Screen::EntryDetail { .. }, KeyCode::End)
            | (Screen::EntryDetail { .. }, KeyCode::Char('G')) => {
                self.entry_scroll = u16::MAX;
            }
            (Screen::EntryDetail { return_to, .. }, KeyCode::Esc)
            | (Screen::EntryDetail { return_to, .. }, KeyCode::Backspace)
            | (Screen::EntryDetail { return_to, .. }, KeyCode::Char('h')) => {
                // Restore whatever screen the user drilled in from —
                // DeviceDetail when coming via the per-device PGN
                // list, TimeView when coming via the timeline. The
                // `return_to` is captured at drill-in time so
                // subsequent state changes can't mislead us.
                self.screen = (**return_to).clone();
            }
            _ => {}
        }
    }

    /// Key routing when the `/` or `f` text prompt is active.
    /// Digits + letters + hyphen + comma go into the buffer; Enter
    /// commits (kind-specific interpretation), Esc cancels without
    /// touching the filter/search state.
    fn handle_text_prompt_key(&mut self, key: KeyEvent, state: &AppState) {
        let Some(prompt) = self.text_prompt.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.text_prompt = None;
            }
            KeyCode::Backspace => {
                prompt.buffer.pop();
            }
            KeyCode::Enter => {
                let raw = prompt.buffer.trim().to_string();
                let kind = prompt.kind;
                self.text_prompt = None;
                match kind {
                    TextPromptKind::Search => {
                        if raw.is_empty() {
                            self.search_query = None;
                        } else {
                            self.search_query = Some(raw);
                            self.jump_search(state, 0);
                        }
                    }
                    TextPromptKind::FilterPgns => {
                        if raw.is_empty() {
                            self.filter_pgns = None;
                        } else {
                            let list: Vec<u32> = raw
                                .split(|c: char| c == ',' || c.is_whitespace())
                                .filter(|t| !t.is_empty())
                                .filter_map(|t| t.parse().ok())
                                .collect();
                            self.filter_pgns = (!list.is_empty()).then_some(list);
                            self.time_state.select(Some(0));
                        }
                    }
                }
            }
            KeyCode::Char(c) => {
                prompt.buffer.push(c);
            }
            _ => {}
        }
    }

    /// Key routing for the source-select checkbox modal. `Space`
    /// toggles the current cursor's source; `a` / `A` toggles all;
    /// Enter commits; Esc cancels.
    fn handle_src_select_key(&mut self, key: KeyEvent) {
        let Some(sel) = self.src_select.as_mut() else {
            return;
        };
        let len = sel.sources.len();
        match key.code {
            KeyCode::Esc => {
                self.src_select = None;
            }
            KeyCode::Enter => {
                let selected = sel.selected.clone();
                let full = sel.sources.iter().all(|(s, _)| selected.contains(s));
                self.src_select = None;
                // "All sources selected" is the same as no filter —
                // canonicalise so the status bar doesn't lie.
                self.filter_srcs = if full || selected.is_empty() {
                    None
                } else {
                    let mut v: Vec<u8> = selected.into_iter().collect();
                    v.sort_unstable();
                    Some(v)
                };
                self.time_state.select(Some(0));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    sel.cursor = (sel.cursor + 1) % len;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 {
                    sel.cursor = (sel.cursor + len - 1) % len;
                }
            }
            KeyCode::Char(' ') => {
                if let Some((src, _)) = sel.sources.get(sel.cursor)
                    && !sel.selected.insert(*src)
                {
                    sel.selected.remove(src);
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                if sel.selected.len() == sel.sources.len() {
                    sel.selected.clear();
                } else {
                    sel.selected = sel.sources.iter().map(|(s, _)| *s).collect();
                }
            }
            _ => {}
        }
    }

    /// Advance search cursor by `dir` (`+1` next, `-1` prev, `0`
    /// stay-or-find-first). Search matches against the same
    /// canonical row string [`format_time_row`] renders — case-
    /// insensitive substring match. No-op when there's no query.
    fn jump_search(&mut self, state: &AppState, dir: i32) {
        let Some(q_lower) = self.search_query.as_ref().map(|s| s.to_lowercase()) else {
            return;
        };
        let visible = self.visible_history_indices(state);
        if visible.is_empty() {
            return;
        }
        let cur = self.time_state.selected().unwrap_or(0);
        let matches: Vec<usize> = visible
            .iter()
            .enumerate()
            .filter(|(_, hi)| {
                state
                    .history
                    .get(**hi)
                    .is_some_and(|h| row_search_string(h).to_lowercase().contains(&q_lower))
            })
            .map(|(vpos, _)| vpos)
            .collect();
        if matches.is_empty() {
            self.toast = Some(format!(
                "no matches for \"{}\"",
                self.search_query.as_deref().unwrap_or("")
            ));
            return;
        }
        let target = match dir.cmp(&0) {
            std::cmp::Ordering::Equal => matches
                .iter()
                .copied()
                .find(|m| *m >= cur)
                .unwrap_or(matches[0]),
            std::cmp::Ordering::Greater => matches
                .iter()
                .copied()
                .find(|m| *m > cur)
                .unwrap_or(matches[0]),
            std::cmp::Ordering::Less => matches
                .iter()
                .copied()
                .rev()
                .find(|m| *m < cur)
                .unwrap_or(*matches.last().unwrap()),
        };
        self.time_state.select(Some(target));
    }

    fn handle_modal_key(&mut self, key: KeyEvent, writer: &crate::client::Writer) {
        let Some(modal) = self.modal.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.modal = None;
            }
            KeyCode::Backspace => {
                modal.input.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                modal.input.push(c);
            }
            KeyCode::Enter => {
                let interval_ms: u32 = match modal.input.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        self.toast = Some("Enter an integer in milliseconds".into());
                        return;
                    }
                };
                let line = match (modal.manufacturer_code, modal.industry_code) {
                    (Some(mfr), Some(ind)) => iso::request_transmission_interval_proprietary(
                        modal.src,
                        modal.pgn,
                        mfr,
                        ind,
                        interval_ms,
                    ),
                    _ => iso::request_transmission_interval(modal.src, modal.pgn, interval_ms),
                };
                let sent = writer.send(line);
                self.overrides.set(Override {
                    src: modal.src,
                    pgn: modal.pgn,
                    interval_ms,
                    manufacturer_code: modal.manufacturer_code,
                    industry_code: modal.industry_code,
                    description: modal.description.clone(),
                });
                match self.overrides.save(&self.overrides_path) {
                    Ok(()) if sent => {
                        self.toast = Some(format!(
                            "Sent PGN 126208 override → src {} pgn {} = {} ms",
                            modal.src, modal.pgn, interval_ms
                        ));
                    }
                    Ok(()) => {
                        self.toast = Some("Override saved; writer channel closed".into());
                    }
                    Err(e) => {
                        // Persistence just broke (e.g. disk full or
                        // perms revoked). Hide the override
                        // affordance for the rest of the session so
                        // the user isn't shown a feature whose state
                        // can no longer be persisted.
                        self.overrides_writable = false;
                        self.toast = Some(format!(
                            "Override sent but persist failed: {e} — disabling further overrides this session"
                        ));
                    }
                }
                self.modal = None;
            }
            _ => {}
        }
    }
}

/// Read manufacturer + industry codes off a cached proprietary-PGN
/// record, so the override dialog can pre-fill them. Returns
/// `(None, None)` for non-proprietary PGNs.
fn proprietary_codes(entry: &Entry) -> (Option<u16>, Option<u8>) {
    if !is_proprietary_pgn(entry.pgn) {
        return (None, None);
    }
    let mfr = entry
        .line
        .pointer("/fields/Manufacturer Code")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.pointer("/value").and_then(|n| n.as_i64()))
        })
        .and_then(|n| u16::try_from(n).ok());
    let ind = entry
        .line
        .pointer("/fields/Industry Code")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.pointer("/value").and_then(|n| n.as_i64()))
        })
        .and_then(|n| u8::try_from(n).ok());
    (mfr, ind)
}

fn is_proprietary_pgn(pgn: u32) -> bool {
    matches!(pgn, 0xEF00..=0xEFFF | 0xFF00..=0xFFFF | 0x1EF00..=0x1EFFF | 0x1FF00..=0x1FFFF)
}

fn navigate_list(state: &mut ListState, len: usize, delta: i32) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as i32;
    let next = (cur + delta).rem_euclid(len as i32) as usize;
    state.select(Some(next));
}

pub type Tty = Terminal<CrosstermBackend<Stdout>>;

pub fn draw(tty: &mut Tty, app: &mut App, state: &AppState) -> Result<()> {
    // Clamp the entry-detail history cursor + scroll offset to
    // whatever the visible entry currently holds. Both can race
    // against ingest (live mode: new observations grow the
    // history; log mode: it's frozen) so re-check every frame.
    if let Screen::EntryDetail {
        src,
        pgn,
        secondary,
        history_pos,
        ..
    } = &mut app.screen
    {
        let key = (*pgn, *src, secondary.clone());
        if let Some(entry) = state.entries.get(&key) {
            let max_pos = entry.history_indices.len().saturating_sub(1);
            if *history_pos > max_pos {
                *history_pos = max_pos;
            }
            let line = entry
                .history_indices
                .get(*history_pos)
                .and_then(|idx| state.history.get(*idx))
                .map(|h| &h.line)
                .unwrap_or(&entry.line);
            let pretty = serde_json::to_string_pretty(line).unwrap_or_else(|_| line.to_string());
            let lines = pretty.lines().count() as u16;
            let max_scroll = lines.saturating_sub(1);
            if app.entry_scroll > max_scroll {
                app.entry_scroll = max_scroll;
            }
        }
    }
    // Auto-dismiss the connecting modal.
    //
    // * Live mode: wait for both connections to come up clean.
    // * Log mode: the modal talks about "connecting" — irrelevant
    //   for a file. Dismiss immediately; the status bar already
    //   shows `loading… / loaded` as the file is ingested.
    if !app.connecting_dismissed
        && (state.status.mode == Mode::Log
            || (state.status.snapshot_loaded
                && state.status.stream_connected
                && state.status.last_error.is_none()))
    {
        app.connecting_dismissed = true;
    }
    tty.draw(|f| {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(area);
        draw_status_bar(f, chunks[0], app, state);
        match &app.screen {
            Screen::Devices => draw_devices(f, chunks[1], app, state),
            Screen::DeviceDetail { src } => draw_device_detail(f, chunks[1], app, state, *src),
            Screen::EntryDetail {
                src,
                pgn,
                secondary,
                history_pos,
                ..
            } => {
                draw_entry_detail(
                    f,
                    chunks[1],
                    state,
                    *src,
                    *pgn,
                    secondary.as_deref(),
                    *history_pos,
                    app.entry_scroll,
                );
            }
            Screen::TimeView => draw_time_view(f, chunks[1], app, state),
        }
        // The bottom line: text prompt when `/` or `f` is active,
        // otherwise the per-screen keybinding hint.
        if let Some(prompt) = &app.text_prompt {
            draw_text_prompt(f, chunks[2], prompt);
        } else {
            draw_hint_bar(f, chunks[2], app, state);
        }
        // Modal stack — last drawn wins. Override dialog is least
        // important, connecting overlay sits above it, fatal-error
        // modal trumps everything.
        if let Some(modal) = &app.modal {
            draw_modal(f, area, modal);
        }
        if let Some(sel) = &app.src_select {
            draw_src_select_modal(f, area, sel);
        }
        if !app.connecting_dismissed {
            draw_connecting_modal(f, area, state);
        }
        if has_unacknowledged_error(app, state) {
            if let Some(err) = state.status.last_error.as_deref() {
                draw_error_modal(f, area, err);
            }
        }
    })?;
    Ok(())
}

/// True when there's an error in `state.status.last_error` that the
/// user hasn't yet dismissed via a keystroke.
fn has_unacknowledged_error(app: &App, state: &AppState) -> bool {
    match (
        state.status.last_error.as_deref(),
        app.last_acknowledged_error.as_deref(),
    ) {
        (Some(cur), Some(ack)) => cur != ack,
        (Some(_), None) => true,
        _ => false,
    }
}

fn draw_status_bar(f: &mut ratatui::Frame<'_>, area: Rect, app: &App, state: &AppState) {
    let s = &state.status;
    let first = match s.mode {
        Mode::Live => {
            let conn = if s.stream_connected { "live" } else { "disc" };
            let snap = if s.snapshot_loaded { "ok" } else { "…" };
            format!(
                " canboat-tui  endpoint {host}:{snap_port}/{stream_port}  snap:{snap}  stream:{conn}  msgs:{msgs}  devs:{devs}  entries:{entries}",
                host = s.host,
                snap_port = s.snapshot_port,
                stream_port = s.stream_port,
                msgs = s.messages_seen,
                devs = state.device_list().len(),
                entries = state.entries.len(),
            )
        }
        Mode::Log => {
            let load = if s.snapshot_loaded {
                "loaded"
            } else {
                "loading…"
            };
            format!(
                " canboat-tui  log: {host}  {load}  msgs:{msgs}  devs:{devs}  entries:{entries}",
                host = s.host,
                msgs = s.messages_seen,
                devs = state.device_list().len(),
                entries = state.entries.len(),
            )
        }
    };
    // Second line priority: alert > toast > error > hint.
    //
    // * `alert` is a bus-side warning (e.g. a NAKed PGN 126208 ACK)
    //   surfaced from the stream reader. Yellow + bold so it stands
    //   out against our own action confirmations.
    // * `toast` is a confirmation / hint for an action the user
    //   just took (override sent, ISO request fired).
    // * `error` is a persistent connection / I/O error that hasn't
    //   yet been dismissed; rendered red so it stays visible.
    //
    // Alerts trump toasts so a device-reported failure isn't
    // drowned out by an immediately-prior "Sent override → …"
    // confirmation.
    let second: Line<'static> = match (&app.alert, &app.toast, &s.last_error) {
        (Some(a), _, _) => Line::from(Span::styled(
            format!(" {a}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        (_, Some(t), _) => Line::from(format!(" {t}")),
        (_, _, Some(e)) => Line::from(vec![
            Span::styled(
                " error: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(e.clone(), Style::default().fg(Color::Red)),
        ]),
        _ => Line::from(format!(
            " {}",
            screen_hint(&app.screen, app.overrides_writable, s.mode)
        )),
    };
    let lines = vec![Line::from(first), second];
    let p = Paragraph::new(lines).style(Style::default().bg(Color::Blue).fg(Color::White));
    f.render_widget(p, area);
}

fn draw_hint_bar(f: &mut ratatui::Frame<'_>, area: Rect, app: &App, state: &AppState) {
    let p = Paragraph::new(format!(
        " {}",
        screen_hint(&app.screen, app.overrides_writable, state.status.mode)
    ))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}

/// Per-screen one-line keybinding cheat sheet. Kept in one place so
/// the top status-bar fallback line and the bottom hint bar stay in
/// sync, and so a binding that doesn't apply (e.g. `i`/`o` on the
/// EntryDetail screen, or on the DeviceDetail screen in log mode)
/// doesn't get advertised where it would do nothing.
fn screen_hint(screen: &Screen, overrides_writable: bool, mode: Mode) -> &'static str {
    match (screen, mode) {
        (Screen::Devices, _) => "q quit | ↑↓ move | Enter open device | t timeline",
        // Log mode: no live bus → no `i` / `o`.
        (Screen::DeviceDetail { .. }, Mode::Log) => {
            "q quit | ↑↓ move | Enter open entry | Esc back | t timeline"
        }
        (Screen::DeviceDetail { .. }, Mode::Live) if overrides_writable => {
            "q quit | ↑↓ move | Enter open entry | Esc back | t timeline | i ISO 126464 | o override interval"
        }
        // `o` omitted when the overrides file isn't writable.
        (Screen::DeviceDetail { .. }, Mode::Live) => {
            "q quit | ↑↓ move | Enter open entry | Esc back | t timeline | i ISO 126464"
        }
        (Screen::EntryDetail { .. }, _) => {
            "q quit | ↑↓ scroll 1 | ←→ prev/next instance | PgUp/PgDn scroll 10 | Esc back"
        }
        (Screen::TimeView, _) => {
            "q quit | ↑↓ move | Enter drill in | / search | n/N next/prev | f filter pgns | s filter sources | d device view | Esc back"
        }
    }
}

fn draw_devices(f: &mut ratatui::Frame<'_>, area: Rect, app: &mut App, state: &AppState) {
    let devices = state.device_list();
    let items: Vec<ListItem> = devices
        .iter()
        .map(|d| ListItem::new(format_device_row(d)))
        .collect();
    // Force-select row 0 the moment the list is non-empty (and the
    // user hasn't picked something else yet). Combined with
    // `HighlightSpacing::Always` below this keeps the column layout
    // stable from the first frame: the marker slot is reserved and
    // row 0 already wears the highlight, so the first ↓ keystroke
    // moves cursor → row 1 without shifting any column to the right.
    if !devices.is_empty() && app.devices_state.selected().is_none() {
        app.devices_state.select(Some(0));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Devices ({} src)", devices.len())),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ")
        .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(list, area, &mut app.devices_state);
}

fn format_device_row(d: &DeviceInfo) -> Line<'static> {
    let mfr = if d.manufacturer.is_empty() {
        "(unknown)".to_string()
    } else {
        d.manufacturer.clone()
    };
    Line::from(vec![
        Span::styled(format!(" {:3} ", d.src), Style::default().fg(Color::Yellow)),
        Span::raw(format!(" {:20.20}", mfr)),
        Span::raw(format!(" {:24.24}", d.model)),
        Span::raw(format!(" sw {:14.14}", d.software)),
        Span::raw(format!(" pgns {:3}", d.pgn_count)),
        Span::raw(format!("  {}", d.installation)),
    ])
}

fn draw_device_detail(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut App,
    state: &AppState,
    src: u8,
) {
    let lists = state.pgn_lists_for_src(src);
    let bottom_h = if lists.is_empty() { 0 } else { 4 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(bottom_h)])
        .split(area);

    let rows = app.detail_rows(src, state);
    let items: Vec<ListItem> = rows
        .iter()
        .map(|e| ListItem::new(format_entry_row(e, state.status.mode)))
        .collect();
    let title = match state.device_list().iter().find(|d| d.src == src) {
        Some(d) => format!(
            "src {} — {} {} ({} entries)",
            src,
            d.manufacturer,
            d.model,
            rows.len(),
        ),
        None => format!("src {} ({} entries)", src, rows.len()),
    };
    // Same trick as `draw_devices`: select row 0 on first sight of a
    // non-empty list so the marker is visible and the layout is
    // stable from the first frame.
    if !rows.is_empty() && app.detail_state.selected().is_none() {
        app.detail_state.select(Some(0));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ")
        .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(list, chunks[0], &mut app.detail_state);

    if bottom_h > 0 {
        draw_pgn_lists(f, chunks[1], &lists);
    }
}

fn format_entry_row(e: &Entry, mode: Mode) -> Line<'static> {
    // `count == 0` is the sentinel for a synthetic silenced-override
    // row — no live data, no measured interval, no meaningful age.
    // Render it as an OFF row in dim grey so the user can see at a
    // glance which PGNs they've silenced.
    if e.count == 0 {
        let description = if e.description.is_empty() {
            "(disabled)"
        } else {
            e.description.as_str()
        };
        let dim = Style::default().fg(Color::DarkGray);
        return Line::from(vec![
            Span::styled(format!(" {:6} ", e.pgn), Style::default().fg(Color::Yellow)),
            Span::styled(format!("{:14.14}", ""), dim),
            Span::styled(format!(" {description:30.30}"), dim),
            Span::styled(format!(" {:>13}", "OFF"), Style::default().fg(Color::Red)),
            Span::styled(format!(" {:>10}", ""), dim),
            Span::styled(format!(" {:>13}", "(silenced)"), dim),
        ]);
    }
    let sec = e
        .secondary
        .as_deref()
        .map(|s| format!(":{s}"))
        .unwrap_or_default();
    let mut spans = vec![
        Span::styled(format!(" {:6} ", e.pgn), Style::default().fg(Color::Cyan)),
        Span::raw(format!("{:14.14}", sec)),
        Span::raw(format!(" {:30.30}", e.description)),
        Span::raw(format!(" every {}", format_interval(e.interval()))),
    ];
    // "age" is wall-clock seconds since `last_update` — a real
    // measurement in Live mode, but in Log mode it's just "how long
    // since we ingested this line", which is meaningless. Skip it.
    if mode == Mode::Live {
        let age = e.last_update.elapsed().as_secs();
        spans.push(Span::raw(format!(" age {age:>4}s")));
    }
    spans.push(Span::raw(format!(" count {:>6}", e.count)));
    Line::from(spans)
}

/// Build a placeholder `Entry` for a silenced override so it can
/// appear in the DeviceDetail row list alongside live entries. The
/// `count == 0` sentinel is what tells [`format_entry_row`] to draw
/// it as an OFF row and what tells the `o` key handler to read
/// mfr / industry / description back from the override file rather
/// than the (null) `line`.
fn synthesize_silenced_entry(ov: &Override) -> Entry {
    let now = std::time::Instant::now();
    Entry {
        pgn: ov.pgn,
        src: ov.src,
        secondary: None,
        description: ov.description.clone().unwrap_or_default(),
        line: serde_json::Value::Null,
        last_update: now,
        count: 0,
        first_seen: now,
        first_stamp_ms: None,
        last_stamp_ms: None,
        // Silenced placeholders carry no observations — `count == 0`
        // is the sentinel that tells the row renderer to draw OFF
        // and the EntryDetail handler to skip drill-in.
        history_indices: Vec::new(),
    }
}

/// Render a measured transmission interval as a fixed-width string
/// for the PGN row. The raw average bounces around as new samples
/// arrive (one slow frame at 100 ms nominal will read 102, 99, 103…),
/// which is distracting at a glance; snap each cadence to a step
/// sized for its magnitude so the displayed number stays put unless
/// the real rate actually changes.
///
/// Step ladder:
///
/// * `<  200 ms` → nearest 10 ms
/// * `<  1   s`  → nearest 50 ms
/// * `<  10  s`  → nearest 100 ms (displayed as ms)
/// * `≥ 10  s`   → nearest 1 s
///
/// `None` (count < 2) prints `—` so the column stays right-aligned.
fn format_interval(d: Option<std::time::Duration>) -> String {
    let Some(d) = d else {
        return format!("{:>7}", "—");
    };
    let ms = d.as_millis() as u64;
    let step = match ms {
        0..=199 => 10,
        200..=999 => 50,
        1_000..=9_999 => 100,
        _ => 1000,
    };
    let rounded = ((ms + step / 2) / step) * step;
    if rounded < 10_000 {
        format!("{rounded:>5}ms")
    } else {
        format!("{:>6.1}s", rounded as f32 / 1000.0)
    }
}

fn draw_pgn_lists(f: &mut ratatui::Frame<'_>, area: Rect, lists: &crate::state::PgnLists) {
    let tx = lists
        .tx
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let rx = lists
        .rx
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let text = vec![
        Line::from(vec![
            Span::styled("TX: ", Style::default().fg(Color::Green)),
            Span::raw(tx),
        ]),
        Line::from(vec![
            Span::styled("RX: ", Style::default().fg(Color::Magenta)),
            Span::raw(rx),
        ]),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("PGN List (126464)"),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

#[allow(clippy::too_many_arguments)]
fn draw_entry_detail(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &AppState,
    src: u8,
    pgn: u32,
    secondary: Option<&str>,
    history_pos: usize,
    scroll: u16,
) {
    let key = (pgn, src, secondary.map(|s| s.to_string()));
    let Some(entry) = state.entries.get(&key) else {
        let p = Paragraph::new("(entry no longer in cache)").block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("PGN {pgn} src {src}")),
        );
        f.render_widget(p, area);
        return;
    };
    // Render the observation indexed by `history_pos`; fall back to
    // `entry.line` (the cached latest) if the index has slipped out
    // of bounds — `draw` clamps but a synth row might still reach
    // here with an empty history_indices.
    let (line, timestamp) = entry
        .history_indices
        .get(history_pos)
        .and_then(|idx| state.history.get(*idx))
        .map(|h| (&h.line, h.timestamp.as_deref()))
        .unwrap_or((&entry.line, None));
    let pretty = serde_json::to_string_pretty(line).unwrap_or_else(|_| line.to_string());
    let total = entry.history_indices.len().max(1);
    let position = format!("[{}/{total}]", history_pos + 1);
    let stamp = timestamp.map(|t| format!(" {t}")).unwrap_or_default();
    let age_suffix = if state.status.mode == Mode::Live {
        format!("  age {}s", entry.last_update.elapsed().as_secs())
    } else {
        String::new()
    };
    let title = format!(
        "PGN {} src {} {}{}  {}  count {}{age_suffix}",
        entry.pgn,
        entry.src,
        entry
            .secondary
            .as_deref()
            .map(|s| format!("[{s}] "))
            .unwrap_or_default(),
        position,
        stamp,
        entry.count,
    );
    let p = Paragraph::new(pretty)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(p, area);
}

/// Chronological table view — one row per observation in
/// `AppState::history`. Columns: index / timestamp / src / pgn /
/// description. Enter drills into the corresponding EntryDetail
/// screen, positioned to that specific observation.
fn draw_time_view(f: &mut ratatui::Frame<'_>, area: Rect, app: &mut App, state: &AppState) {
    let visible = app.visible_history_indices(state);
    // Clamp cursor to the (possibly reduced) filter subset.
    if !visible.is_empty() && app.time_state.selected().is_none() {
        app.time_state.select(Some(0));
    }
    if let Some(sel) = app.time_state.selected()
        && sel >= visible.len()
    {
        app.time_state
            .select(visible.len().checked_sub(1).or(Some(0)));
    }
    let items: Vec<ListItem> = visible
        .iter()
        .filter_map(|hi| state.history.get(*hi).map(|h| (hi, h)))
        .map(|(hi, h)| ListItem::new(format_time_row(*hi, h)))
        .collect();
    let mut title_parts = vec![format!("Timeline ({}", visible.len())];
    if state.history.len() != visible.len() {
        title_parts.push(format!(" of {}", state.history.len()));
    }
    title_parts.push(")".to_string());
    if let Some(list) = &app.filter_pgns {
        title_parts.push(format!(
            "  pgns: {}",
            list.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(list) = &app.filter_srcs {
        title_parts.push(format!(
            "  srcs: {}",
            list.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(q) = &app.search_query {
        title_parts.push(format!("  /{q}"));
    }
    let title: String = title_parts.concat();
    let list_widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ")
        .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(list_widget, area, &mut app.time_state);
}

/// Canonical row string for search matching — a plain-text form of
/// [`format_time_row`] without ANSI/ratatui styling. Kept in sync so
/// searching for whatever the user sees on-screen finds the row.
fn row_search_string(h: &crate::state::HistoryRecord) -> String {
    let stamp = h.timestamp.as_deref().unwrap_or("");
    let sec = h.secondary.as_deref().unwrap_or("");
    format!(
        "{stamp} src {} pgn {} {sec} {}",
        h.src, h.pgn, h.description
    )
}

/// One row on the `TimeView` screen — index, timestamp, src, pgn,
/// and description columns. Timestamp column is right-padded to a
/// fixed width so `src`/`pgn` line up column-wise across rows.
fn format_time_row(idx: usize, h: &crate::state::HistoryRecord) -> Line<'static> {
    // Prefer the wire timestamp from the analyzer JSON; fall back
    // to relative wall-clock age (`+<N>s`) computed from `seen_at`
    // when the record didn't carry one.
    let stamp: String = match h.timestamp.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => format!("+{}s", h.seen_at.elapsed().as_secs()),
    };
    let sec = h
        .secondary
        .as_deref()
        .map(|s| format!(":{s}"))
        .unwrap_or_default();
    Line::from(vec![
        Span::styled(format!(" {idx:>6}  "), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{stamp:<24}"), Style::default().fg(Color::White)),
        Span::styled(
            format!(" src {:3}", h.src),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("  {:6}{sec:<10}", h.pgn),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(format!("  {}", h.description)),
    ])
}

/// Compute a centered rect of at most `max_w` × `max_h`, clamped to
/// `area`. Used by every modal so they end up in the same place.
fn centered_rect(area: Rect, max_w: u16, max_h: u16) -> Rect {
    let w = max_w.min(area.width.saturating_sub(2));
    let h = max_h.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

fn draw_modal(f: &mut ratatui::Frame<'_>, area: Rect, modal: &OverrideModal) {
    let rect = centered_rect(area, 60, 8);
    f.render_widget(Clear, rect);
    let mfr = modal
        .manufacturer_code
        .map(|m| format!(" mfr={m}"))
        .unwrap_or_default();
    let ind = modal
        .industry_code
        .map(|i| format!(" ind={i}"))
        .unwrap_or_default();
    let text = vec![
        Line::from(format!(
            "Override PGN {} on src {}{mfr}{ind}",
            modal.pgn, modal.src
        )),
        Line::from(""),
        Line::from(format!("New interval (ms): {}_", modal.input)),
        Line::from(""),
        Line::from("Enter to send (and persist) • Esc to cancel"),
        Line::from(format!(
            "Off = interval {INTERVAL_OFF} (rejected unless allow_disable in file)"
        )),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("PGN 126208 Command"),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, rect);
}

/// Centered "Connecting…" overlay shown at startup until both the
/// snapshot and live-stream connections terminate (success or
/// failure). The body live-updates from `state.status` so the user
/// sees each connection's progress.
fn draw_connecting_modal(f: &mut ratatui::Frame<'_>, area: Rect, state: &AppState) {
    let rect = centered_rect(area, 64, 10);
    f.render_widget(Clear, rect);
    let s = &state.status;
    let snap_status = if s.snapshot_loaded {
        Span::styled(
            "✓ loaded",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else if s
        .last_error
        .as_deref()
        .is_some_and(|e| e.starts_with("snapshot"))
    {
        Span::styled(
            "✗ failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("… connecting", Style::default().fg(Color::Yellow))
    };
    let stream_status = if s.stream_connected {
        Span::styled(
            "✓ connected",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else if s
        .last_error
        .as_deref()
        .is_some_and(|e| e.starts_with("stream"))
    {
        Span::styled(
            "✗ failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("… connecting", Style::default().fg(Color::Yellow))
    };
    let text = vec![
        Line::from(format!("Connecting to {}", s.host)),
        Line::from(""),
        Line::from(vec![
            Span::raw(format!("  Snapshot  :{:<5}  ", s.snapshot_port)),
            snap_status,
        ]),
        Line::from(vec![
            Span::raw(format!("  Stream    :{:<5}  ", s.stream_port)),
            stream_status,
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to continue (auto-dismisses when both up)",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                " canboat-tui ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, rect);
}

/// Centered red-bordered modal shown whenever
/// `state.status.last_error` carries a value the user hasn't yet
/// acknowledged. Dismissed with any keystroke.
fn draw_error_modal(f: &mut ratatui::Frame<'_>, area: Rect, message: &str) {
    // Word-wrapped lines fit in a generous box; cap height at 12 so a
    // multi-paragraph error never eats the whole terminal.
    let rect = centered_rect(area, 72, 12);
    f.render_widget(Clear, rect);
    let text = vec![
        Line::from(Span::styled(
            "Fatal error",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(message.to_string()),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(Span::styled(
                    " Error ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, rect);
}

/// One-line text-prompt bar — replaces the hint bar while `/` or
/// `f` is active. Renders `<prefix> <buffer>_` with a fake cursor
/// glyph at the end of the buffer.
fn draw_text_prompt(f: &mut ratatui::Frame<'_>, area: Rect, prompt: &TextPrompt) {
    let prefix = match prompt.kind {
        TextPromptKind::Search => "/",
        TextPromptKind::FilterPgns => "filter pgns: ",
    };
    let text = format!(" {prefix}{}_", prompt.buffer);
    let p = Paragraph::new(text).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(p, area);
}

/// Source-select checkbox modal — shown while the `s` prompt is
/// active on TimeView. Each row is `[x] <label>`; `Space` toggles
/// the cursor's row, `a` toggles all, Enter applies, Esc cancels.
fn draw_src_select_modal(f: &mut ratatui::Frame<'_>, area: Rect, sel: &SrcSelect) {
    let w = 60.min(area.width.saturating_sub(2));
    let h = (sel.sources.len() as u16 + 6)
        .min(area.height.saturating_sub(2))
        .max(6);
    let rect = centered_rect(area, w, h);
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = sel
        .sources
        .iter()
        .map(|(src, label)| {
            let mark = if sel.selected.contains(src) {
                "[x]"
            } else {
                "[ ]"
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {mark}  "), Style::default().fg(Color::Green)),
                Span::raw(label.clone()),
            ]))
        })
        .collect();
    let mut list_state = ListState::default();
    list_state.select(Some(sel.cursor));
    let title = format!(
        " Filter sources ({}/{})",
        sel.selected.len(),
        sel.sources.len()
    );
    let list = List::new(items)
        .block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                title,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ")
        .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(list, rect, &mut list_state);
    // Overlay a footer hint on the bottom-most row.
    if rect.height >= 2 {
        let hint_area = Rect {
            x: rect.x + 1,
            y: rect.y + rect.height - 1,
            width: rect.width.saturating_sub(2),
            height: 1,
        };
        let hint = Paragraph::new(" Space toggle | a toggle-all | Enter apply | Esc cancel ")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, hint_area);
    }
}
