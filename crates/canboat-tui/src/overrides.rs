// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! Persistent PGN-rate overrides.
//!
//! Each entry is one "the user wants device X's PGN Y to transmit at
//! interval Z" rule. Storing this on disk has two purposes:
//!
//! 1. **Replay on next startup** — every recorded override is
//!    re-sent to the bus when the TUI reconnects, so a change you
//!    made yesterday survives a target reboot.
//!
//! 2. **Re-enable silenced PGNs** — once an override sets `interval_ms
//!    = 0` ("stop transmitting"), no more records arrive for the
//!    PGN and the live cache drops it. The TUI's DeviceDetail
//!    screen reads this file directly to keep the silenced PGN in
//!    its list so the user can later open the `o` dialog and set a
//!    non-zero cadence again. That re-enable path is the reason
//!    `manufacturer_code` / `industry_code` / `description` are
//!    persisted alongside `interval_ms`.
//!
//! The file lives at `~/.config/canboat-tui/overrides.json` by
//! default (or `$XDG_CONFIG_HOME/canboat-tui/overrides.json` when
//! `XDG_CONFIG_HOME` is set).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// "Stop transmitting" value for the PGN 126208 Request envelope's
/// 32-bit Transmission interval field (1 ms units). The captured
/// Furuno SCX-20 setting-tool traffic in
/// `../canboat/samples/scx20-setting-tool-pgn-130578to130846-off.raw`
/// uses `0` here.
pub const INTERVAL_OFF: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Override {
    pub src: u8,
    pub pgn: u32,
    /// Desired interval in milliseconds. [`INTERVAL_OFF`] (= `0`)
    /// means "stop transmitting"; any positive value is the new
    /// cadence in milliseconds.
    pub interval_ms: u32,
    /// Manufacturer Code for proprietary PGNs (range 0xFF00-0xFFFF
    /// / 0x1FF00-0x1FFFF). Required to scope the PGN 126208 Request
    /// to the right vendor. Mirrors the live record's `fields
    /// .Manufacturer Code` at the time the override was first
    /// stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer_code: Option<u16>,
    /// Industry Code (typically 4 = Marine) for proprietary PGNs;
    /// see [`Override::manufacturer_code`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub industry_code: Option<u8>,
    /// Human-readable PGN description (e.g. `"Furuno: Six Degrees
    /// Of Freedom Movement"`), captured at override time so the
    /// DeviceDetail screen can label a silenced row even after the
    /// live cache entry has aged out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Overrides {
    pub entries: Vec<Override>,
}

impl Overrides {
    pub fn load_or_default(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self).context("serialising overrides")?;
        std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Upsert by (src, pgn). Returns whether a previous entry was
    /// replaced.
    pub fn set(&mut self, ov: Override) -> bool {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.src == ov.src && e.pgn == ov.pgn)
        {
            *existing = ov;
            true
        } else {
            self.entries.push(ov);
            false
        }
    }

    /// Iterate over overrides that currently silence a PGN
    /// (`interval_ms == INTERVAL_OFF`). The DeviceDetail screen uses
    /// this to inject synthetic rows for PGNs that have stopped
    /// transmitting so the user can re-enable them.
    pub fn silenced(&self) -> impl Iterator<Item = &Override> {
        self.entries
            .iter()
            .filter(|e| e.interval_ms == INTERVAL_OFF)
    }
}

/// Resolve the default overrides path, honouring `XDG_CONFIG_HOME`.
pub fn default_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("canboat-tui/overrides.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/canboat-tui/overrides.json");
    }
    PathBuf::from("canboat-tui-overrides.json")
}

/// Test whether `path` is writable as the overrides file. Creates
/// the parent directory and probes the file with `OpenOptions::open`
/// (write + create) — no content is written, so a no-overrides
/// session leaves the file empty/untouched (or non-existent if the
/// caller doesn't subsequently `save()`).
///
/// The TUI calls this once at startup; on `false` it hides the `o`
/// override affordance entirely (no key handler, no hint-bar entry)
/// so the user isn't shown a feature whose state can't be persisted.
pub fn is_writable(path: &PathBuf) -> bool {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .is_ok()
}
