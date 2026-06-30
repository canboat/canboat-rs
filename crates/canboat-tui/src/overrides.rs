//! Persistent PGN-rate overrides.
//!
//! Each entry is one "the user wants device X's PGN Y to transmit at
//! interval Z" rule. Storing this on disk has two purposes:
//!
//! 1. **Replay on next startup** — every recorded override is
//!    re-sent to the bus when the TUI reconnects, so a change you
//!    made yesterday survives a target reboot.
//!
//! 2. **Authorisation gate for "turn off"** — the user is permitted
//!    to set `interval_ms = 0xFFFFFFFE` ("disable transmission") only
//!    when a matching entry already exists on disk with
//!    `allow_disable: true`. This file is the persistent record the
//!    spec asks us to require before silencing a PGN.
//!
//! The file lives at `~/.config/canboat-tui/overrides.json` by
//! default (or `$XDG_CONFIG_HOME/canboat-tui/overrides.json` when
//! `XDG_CONFIG_HOME` is set).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Sentinel value for "disable transmission" in the NMEA 2000 group
/// function `Transmission interval` parameter (1 ms units).
pub const INTERVAL_DISABLE: u32 = 0xFFFF_FFFE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Override {
    pub src: u8,
    pub pgn: u32,
    /// Desired interval in milliseconds, or one of the sentinels
    /// above.
    pub interval_ms: u32,
    /// Required to be `true` before the TUI is allowed to send an
    /// override with `interval_ms == INTERVAL_DISABLE`. The TUI
    /// itself never flips this — the user must edit the file by
    /// hand, which serves as the explicit acknowledgement that a
    /// PGN is being silenced.
    #[serde(default)]
    pub allow_disable: bool,
    /// Required for proprietary PGNs (range 0xFF00-0xFFFF / 0x1FF00-
    /// 0x1FFFF): the manufacturer that scopes the group function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer_code: Option<u16>,
    /// Required for proprietary PGNs: the industry code. Defaults to
    /// 4 (Marine) at the call site when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub industry_code: Option<u8>,
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

    pub fn allows_disable(&self, src: u8, pgn: u32) -> bool {
        self.entries
            .iter()
            .any(|e| e.src == src && e.pgn == pgn && e.allow_disable)
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
