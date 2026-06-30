//! ratatui rendering + keyboard handling.
//!
//! Three screens, plus a modal:
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
//! * Modal: `o` from `DeviceDetail` opens the override dialog for
//!   the highlighted PGN — accepts a transmission interval in ms.
//!   "Disable" (`0xFFFFFFFE`) is only accepted when the persistent
//!   overrides file already authorises it.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::iso;
use crate::overrides::{INTERVAL_DISABLE, Override, Overrides, default_path};
use crate::state::{AppState, DeviceInfo, Entry};

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

pub enum Screen {
    Devices,
    DeviceDetail {
        src: u8,
    },
    EntryDetail {
        src: u8,
        pgn: u32,
        secondary: Option<String>,
    },
}

pub struct App {
    pub screen: Screen,
    pub devices_state: ListState,
    pub detail_state: ListState,
    pub overrides: Overrides,
    pub overrides_path: std::path::PathBuf,
    pub modal: Option<OverrideModal>,
    /// Last status / error toast (cleared on next keystroke).
    pub toast: Option<String>,
    pub should_quit: bool,
}

pub struct OverrideModal {
    pub src: u8,
    pub pgn: u32,
    pub input: String,
    pub manufacturer_code: Option<u16>,
    pub industry_code: Option<u8>,
}

impl App {
    pub fn new() -> Self {
        let overrides_path = default_path();
        let overrides = Overrides::load_or_default(&overrides_path);
        let mut devices_state = ListState::default();
        devices_state.select(Some(0));
        let mut detail_state = ListState::default();
        detail_state.select(Some(0));
        Self {
            screen: Screen::Devices,
            devices_state,
            detail_state,
            overrides,
            overrides_path,
            modal: None,
            toast: None,
            should_quit: false,
        }
    }

    /// Re-emit every stored override to the bus. Called on startup
    /// after the stream connection is up so user changes persist
    /// across target reboots.
    pub fn replay_overrides(&self, writer: &crate::client::Writer) {
        for ov in &self.overrides.entries {
            let line = match (ov.manufacturer_code, ov.industry_code) {
                (Some(mfr), Some(ind)) => iso::command_transmission_interval_proprietary(
                    ov.src,
                    ov.pgn,
                    mfr,
                    ind,
                    ov.interval_ms,
                ),
                _ => iso::command_transmission_interval(ov.src, ov.pgn, ov.interval_ms),
            };
            let _ = writer.send(line);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, state: &AppState, writer: &crate::client::Writer) {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(key, writer);
            return;
        }
        self.toast = None;
        // Ctrl-C always quits.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }
        match (&self.screen, key.code) {
            (_, KeyCode::Char('q')) => self.should_quit = true,
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
                let n = state.entries_for_src(*src).len();
                navigate_list(&mut self.detail_state, n, 1);
            }
            (Screen::DeviceDetail { src }, KeyCode::Up)
            | (Screen::DeviceDetail { src }, KeyCode::Char('k')) => {
                let n = state.entries_for_src(*src).len();
                navigate_list(&mut self.detail_state, n, -1);
            }
            (Screen::DeviceDetail { src }, KeyCode::Enter) => {
                let entries = state.entries_for_src(*src);
                if let Some(e) = self
                    .detail_state
                    .selected()
                    .and_then(|i| entries.get(i).copied())
                {
                    self.screen = Screen::EntryDetail {
                        src: *src,
                        pgn: e.pgn,
                        secondary: e.secondary.clone(),
                    };
                }
            }
            (Screen::DeviceDetail { src }, KeyCode::Char('i')) => {
                // Ask the device to publish its PGN List (Transmit/Receive).
                let line = iso::iso_request(*src, 126464);
                if writer.send(line) {
                    self.toast = Some(format!("Sent ISO Request 126464 → src {src}"));
                } else {
                    self.toast = Some("Writer channel closed".into());
                }
            }
            (Screen::DeviceDetail { src }, KeyCode::Char('o')) => {
                let entries = state.entries_for_src(*src);
                if let Some(e) = self
                    .detail_state
                    .selected()
                    .and_then(|i| entries.get(i).copied())
                {
                    let (mfr, ind) = proprietary_codes(e);
                    self.modal = Some(OverrideModal {
                        src: *src,
                        pgn: e.pgn,
                        input: default_interval_hint(e.pgn).to_string(),
                        manufacturer_code: mfr,
                        industry_code: ind,
                    });
                }
            }
            (Screen::DeviceDetail { .. }, KeyCode::Esc)
            | (Screen::DeviceDetail { .. }, KeyCode::Backspace)
            | (Screen::DeviceDetail { .. }, KeyCode::Char('h')) => {
                self.screen = Screen::Devices;
            }
            (Screen::EntryDetail { src, .. }, KeyCode::Esc)
            | (Screen::EntryDetail { src, .. }, KeyCode::Backspace)
            | (Screen::EntryDetail { src, .. }, KeyCode::Char('h')) => {
                let src = *src;
                self.screen = Screen::DeviceDetail { src };
            }
            _ => {}
        }
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
                if interval_ms == INTERVAL_DISABLE
                    && !self.overrides.allows_disable(modal.src, modal.pgn)
                {
                    self.toast = Some(format!(
                        "Refusing to disable PGN {} on src {} — add an entry with allow_disable: true in {} first",
                        modal.pgn,
                        modal.src,
                        self.overrides_path.display(),
                    ));
                    self.modal = None;
                    return;
                }
                let line = match (modal.manufacturer_code, modal.industry_code) {
                    (Some(mfr), Some(ind)) => iso::command_transmission_interval_proprietary(
                        modal.src,
                        modal.pgn,
                        mfr,
                        ind,
                        interval_ms,
                    ),
                    _ => iso::command_transmission_interval(modal.src, modal.pgn, interval_ms),
                };
                let sent = writer.send(line);
                self.overrides.set(Override {
                    src: modal.src,
                    pgn: modal.pgn,
                    interval_ms,
                    allow_disable: self.overrides.allows_disable(modal.src, modal.pgn),
                    manufacturer_code: modal.manufacturer_code,
                    industry_code: modal.industry_code,
                });
                if let Err(e) = self.overrides.save(&self.overrides_path) {
                    self.toast = Some(format!("Override saved in memory; disk write failed: {e}"));
                } else if sent {
                    self.toast = Some(format!(
                        "Sent PGN 126208 override → src {} pgn {} = {} ms",
                        modal.src, modal.pgn, interval_ms
                    ));
                } else {
                    self.toast = Some("Override saved; writer channel closed".into());
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
            } => {
                draw_entry_detail(f, chunks[1], state, *src, *pgn, secondary.as_deref());
            }
        }
        draw_hint_bar(f, chunks[2], app);
        if let Some(modal) = &app.modal {
            draw_modal(f, area, modal);
        }
    })?;
    Ok(())
}

fn draw_status_bar(f: &mut ratatui::Frame<'_>, area: Rect, app: &App, state: &AppState) {
    let s = &state.status;
    let conn = if s.stream_connected { "live" } else { "disc" };
    let snap = if s.snapshot_loaded { "ok" } else { "…" };
    let first = format!(
        " canboat-tui  endpoint {host}:{snap_port}/{stream_port}  snap:{snap}  stream:{conn}  msgs:{msgs}  devs:{devs}  entries:{entries}",
        host = s.host,
        snap_port = s.snapshot_port,
        stream_port = s.stream_port,
        msgs = s.messages_seen,
        devs = state.device_list().len(),
        entries = state.entries.len(),
    );
    let second = match (&app.toast, &s.last_error) {
        (Some(t), _) => format!(" {t}"),
        (_, Some(e)) => format!(" error: {e}"),
        _ => String::from(
            " (q quit  ↑/↓ move  Enter drill in  Esc back  i = ISO 126464  o = override interval)",
        ),
    };
    let lines = vec![Line::from(first), Line::from(second)];
    let p = Paragraph::new(lines).style(Style::default().bg(Color::Blue).fg(Color::White));
    f.render_widget(p, area);
}

fn draw_hint_bar(f: &mut ratatui::Frame<'_>, area: Rect, _app: &App) {
    let p = Paragraph::new(
        " q quit | ↑↓ move | Enter open | Esc back | i ISO 126464 | o override interval",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}

fn draw_devices(f: &mut ratatui::Frame<'_>, area: Rect, app: &mut App, state: &AppState) {
    let devices = state.device_list();
    let items: Vec<ListItem> = devices
        .iter()
        .map(|d| ListItem::new(format_device_row(d)))
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Devices ({} src)", devices.len())),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ");
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

    let entries = state.entries_for_src(src);
    let items: Vec<ListItem> = entries
        .iter()
        .map(|e| ListItem::new(format_entry_row(e)))
        .collect();
    let title = match state.device_list().iter().find(|d| d.src == src) {
        Some(d) => format!(
            "src {} — {} {} ({} entries)",
            src,
            d.manufacturer,
            d.model,
            entries.len(),
        ),
        None => format!("src {} ({} entries)", src, entries.len()),
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" ▶ ");
    f.render_stateful_widget(list, chunks[0], &mut app.detail_state);

    if bottom_h > 0 {
        draw_pgn_lists(f, chunks[1], &lists);
    }
}

fn format_entry_row(e: &Entry) -> Line<'static> {
    let age = e.last_update.elapsed().as_secs();
    let sec = e
        .secondary
        .as_deref()
        .map(|s| format!(":{s}"))
        .unwrap_or_default();
    Line::from(vec![
        Span::styled(format!(" {:6} ", e.pgn), Style::default().fg(Color::Cyan)),
        Span::raw(format!("{:14.14}", sec)),
        Span::raw(format!(" {:30.30}", e.description)),
        Span::raw(format!(" age {age:>4}s")),
        Span::raw(format!(" count {:>6}", e.count)),
    ])
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

fn draw_entry_detail(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &AppState,
    src: u8,
    pgn: u32,
    secondary: Option<&str>,
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
    let pretty =
        serde_json::to_string_pretty(&entry.line).unwrap_or_else(|_| entry.line.to_string());
    let title = format!(
        "PGN {} src {} {}  count {}  age {}s",
        entry.pgn,
        entry.src,
        entry
            .secondary
            .as_deref()
            .map(|s| format!("[{s}] "))
            .unwrap_or_default(),
        entry.count,
        entry.last_update.elapsed().as_secs(),
    );
    let p = Paragraph::new(pretty)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_modal(f: &mut ratatui::Frame<'_>, area: Rect, modal: &OverrideModal) {
    let w = 60.min(area.width.saturating_sub(2));
    let h = 8.min(area.height.saturating_sub(2));
    let x = area.x + (area.width - w) / 2;
    let y = area.y + (area.height - h) / 2;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
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
            "Disable sentinel: {} (rejected unless allow_disable in file)",
            INTERVAL_DISABLE
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
