//! `canboat-tui` — interactive terminal UI for an NMEA 2000 bus.
//!
//! Connects to either `canboat-pipeline` or `n2kd`. On startup the
//! TUI loads the one-shot snapshot from the status port (default
//! 2597) and then stays subscribed to the live stream port (default
//! 2598). Outgoing writes (ISO Requests, PGN 126208 overrides) are
//! sent back over the stream socket — that path works against
//! canboat-pipeline (its analyzer port is bidirectional) but is
//! silently dropped by n2kd.
//!
//! The state model is shared with the snapshot module
//! ([`canboat_core::snapshot::classify_json_line`]) so the keys we
//! show in the TUI are byte-identical to the ones stored on the
//! snapshot port.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{Event, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::Mutex;
use tokio::time::interval;

mod client;
mod iso;
mod overrides;
mod state;
mod ui;

use crate::state::{AppState, Status};

#[derive(Parser, Debug)]
#[command(
    name = "canboat-tui",
    about = "Interactive terminal UI for an NMEA 2000 bus, fed by n2kd or canboat-pipeline."
)]
struct Args {
    /// Hostname or IP of the n2kd / canboat-pipeline endpoint.
    /// Required unless `--log` is set (there is no default: pick a
    /// live endpoint or a capture on purpose, don't blindly connect
    /// to localhost).
    #[arg(long, required_unless_present = "log", conflicts_with = "log")]
    host: Option<String>,
    /// Snapshot port (default 2597 — canboat-pipeline `--snapshot-port`
    /// or n2kd JSON snapshot). Ignored when `--log` is set.
    #[arg(long, default_value_t = 2597)]
    snapshot_port: u16,
    /// Live JSON stream port (default 2598 — canboat-pipeline
    /// `--analyzer-port` or n2kd JSON stream). Ignored when `--log`
    /// is set.
    #[arg(long, default_value_t = 2598)]
    stream_port: u16,
    /// Replay a captured log file instead of connecting to a live
    /// endpoint. Accepts any analyzer-readable format (PLAIN, FAST,
    /// Actisense, iKonvert, YDWG02 — auto-detected on the first
    /// content line). Mutually exclusive with `--host`. The `o`
    /// (override) and `i` (ISO request) keys are disabled in this
    /// mode since they need a live bus.
    #[arg(long, value_name = "PATH")]
    log: Option<std::path::PathBuf>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // Mirror canboat-cli's env_logger plumbing so the user can turn
    // on RUST_LOG=debug when something looks off.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .try_init();

    let args = Args::parse();
    // Clap enforces `--host XOR --log` above — so exactly one of
    // these branches matches.
    let status = match (&args.log, &args.host) {
        (Some(path), _) => Status::new_log(path.display().to_string()),
        (None, Some(host)) => Status::new_live(host.clone(), args.snapshot_port, args.stream_port),
        (None, None) => unreachable!("clap's required_unless_present guarantees one is Some"),
    };
    let state = Arc::new(Mutex::new(AppState::new(status)));

    // Writer channel is created up front in both modes — in log mode
    // nothing ever sends through it (the `o` / `i` handlers are gated
    // on Mode::Live), but having the same `Writer` shape keeps the
    // UI code path uniform.
    let (writer, writer_rx) = client::make_writer();
    if let Some(path) = args.log.clone() {
        // Log mode: drive the analyzer's library decode pipeline on a
        // blocking thread; no snapshot/stream sockets. Drop
        // `writer_rx` — nothing will write to the channel.
        drop(writer_rx);
        client::spawn_log_load(path, state.clone());
    } else {
        // Live mode: kick off both network tasks in the background;
        // the UI loop surfaces their progress / errors via the status
        // bar. `args.host` is guaranteed `Some` here by the CLI
        // match above.
        let host = args.host.clone().expect("--host required in live mode");
        client::spawn_snapshot_load(host.clone(), args.snapshot_port, state.clone());
        client::spawn_stream_connection(host, args.stream_port, state.clone(), writer_rx);
    }

    let mut app = ui::App::new();
    if args.log.is_none() {
        // Persisted overrides are queued to the writer immediately;
        // they flush to the socket as soon as the stream task
        // connects. Log mode has nothing to write back to, so skip.
        app.replay_overrides(&writer);
    }

    let mut tty = setup_tty()?;
    let res = run_loop(&mut tty, &mut app, state, writer).await;
    restore_tty(&mut tty)?;
    res
}

async fn run_loop(
    tty: &mut ui::Tty,
    app: &mut ui::App,
    state: Arc<Mutex<AppState>>,
    writer: client::Writer,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut redraw = interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            biased;
            ev = events.next() => {
                match ev {
                    Some(Ok(Event::Key(key))) => {
                        let s = state.lock().await;
                        app.handle_key(key, &s, &writer);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        let mut s = state.lock().await;
                        s.status.last_error = Some(format!("terminal: {e}"));
                    }
                    None => break,
                }
            }
            _ = redraw.tick() => {}
        }
        if app.should_quit {
            break;
        }
        let mut s = state.lock().await;
        // Drain one queued bus-side alert into the UI's display slot
        // per draw. The reader task pushes alerts onto `state.alerts`
        // as they arrive; the UI shows them in the status bar and
        // clears them on any keystroke, so the user sees each one in
        // turn instead of just the most recent.
        if app.alert.is_none() {
            app.alert = s.alerts.pop_front();
        }
        ui::draw(tty, app, &s)?;
    }
    Ok(())
}

fn setup_tty() -> Result<ui::Tty> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    Ok(Terminal::new(backend)?)
}

fn restore_tty(tty: &mut ui::Tty) -> Result<()> {
    disable_raw_mode()?;
    execute!(tty.backend_mut(), LeaveAlternateScreen)?;
    tty.show_cursor()?;
    Ok(())
}
