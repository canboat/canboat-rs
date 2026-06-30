//! `n2kd`: TCP multiplexer for an analyzer JSON stream.
//!
//! Mirrors `canboat/n2kd/main.c`. The analyzer feeds JSON-per-line on
//! stdin; we fan that out to several TCP ports of clients:
//!
//! | Port (default)   | Behaviour                                                                      |
//! |------------------|--------------------------------------------------------------------------------|
//! | `port`     (2597) | **JSON snapshot** — on connect, send the latest line per `(pgn, src)`, close. |
//! | `port+1`   (2598) | **JSON stream** — each connected client receives every line as it arrives.    |
//! | `port+2`   (2599) | **NMEA 0183 stream** — converted sentences (HDG / MWV / DPT / RSA / VTG / …). |
//! | `port+3`   (2600) | **AIS-only stream** — the AIS-related PGNs in JSON, unconverted.              |
//! | `port+4`   (2601) | **Status stream** — periodic `{"clients":N,"pgns":[…]}` snapshots.            |
//! | `port+5`   (2602) | **Raw input** — clients write canboat PLAIN/FAST; we forward to stdout.       |
//!
//! Plus an optional UDP NMEA 0183 broadcast (`--udp183 <host:port>`)
//! and a periodic device-claim / product-info auto-request engine
//! (canboat's `requestAddressClaimAndProductInfo`) that emits ISO
//! request PLAIN lines on stdout for devices we've seen.
//!
//! AIS NMEA 0183 conversion (AIVDM bit-packing) is deferred — those
//! PGNs flow unchanged through the AIS port; the NMEA stream simply
//! doesn't emit AIVDM sentences yet.

use n2kd::request_engine::{self, RequestEngine};
use n2kd::{ais, json, nmea0183};

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use canboat_core::snapshot::{SnapshotInput, SnapshotStore};
use clap::Parser;

use crate::nmea0183::RateLimiter;

/// Default TCP base port.
const DEFAULT_PORT: u16 = 2597;

/// AIS PGN list — these flow through the AIS port verbatim. Matches
/// the `PGN_AIS_*` defines in nmea0183.c.
const AIS_PGNS: &[u32] = &[
    129038, 129039, 129040, 129041, 129793, 129794, 129798, 129801, 129802, 129809, 129810,
];

#[derive(Debug, Parser)]
#[command(
    name = "n2kd",
    about = "Multiplex analyzer JSON stdin to TCP clients",
    version
)]
struct Cli {
    /// Base TCP port. `+1`=stream, `+2`=nmea0183, `+3`=raw input, `+4`=ais, `+5`=status. Matches canboat C n2kd.
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Filter incoming JSON by source address. Comma-separated list
    /// of `u8`; prepend `!` for a negative match (e.g. `!1,2`
    /// allows everything except sources 1 and 2). Mirrors canboat
    /// `srcFilter`.
    #[arg(long)]
    src_filter: Option<String>,

    /// Rate-limit each (src, kind) of NMEA 0183 sentence to at most
    /// one per second. Mirrors canboat's `--rate-limit`.
    #[arg(long)]
    rate_limit: bool,

    /// Restrict mode: suppress all stdout output (claim requests in
    /// normal mode, NMEA sentences in `--nmea0183` mode). Matches
    /// canboat's `-r`.
    #[arg(short = 'r', long)]
    restrict: bool,

    /// Bind on `0.0.0.0` instead of `127.0.0.1`.
    #[arg(long)]
    public: bool,

    /// UDP-broadcast each NMEA 0183 sentence. Canboat's C tool takes
    /// two positional args (`-u <host> <port>`); we accept that form
    /// for drop-in script compatibility, plus a single-arg
    /// `<host:port>` shorthand. Either way, the value lands in the
    /// LAN where OpenCPN / Navionics receivers can pick it up.
    #[arg(
        short = 'u',
        long = "udp183",
        value_names = &["HOST", "PORT"],
        num_args = 1..=2,
    )]
    udp183: Vec<String>,

    /// Start no TCP servers and send NMEA 0183 / AIVDM data on
    /// stdout. Mirrors canboat's `--nmea0183` flag — mainly for
    /// pipeline / debug use.
    #[arg(long)]
    nmea0183: bool,

    /// Copy data received from TCP clients on the raw-input port back
    /// to stdout (as well as forwarding to the analyzer pipeline).
    /// Matches canboat C's `-o` flag. Off by default to keep stdout
    /// clean for downstream consumers.
    #[arg(short = 'o', long = "output")]
    output_copy: bool,

    /// Pin the log timestamp string. Matches canboat C's `-fixtime`,
    /// used by deterministic-output tests. Accepted but currently
    /// inert in Rust's `env_logger` setup.
    #[arg(long = "fixtime", value_name = "STR")]
    fixtime: Option<String>,

    /// Suppress the periodic ISO Address Claim / Product Info request
    /// engine. By default it's on (matching canboat C); `-r` /
    /// `--restrict` also turns it off.
    #[arg(long)]
    no_request_claims: bool,

    /// Verbose / debug logging — alias of `-d`.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Quiet — only show errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    if let Err(e) = run(cli) {
        eprintln!("n2kd: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let level = if cli.quiet {
        "error"
    } else if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let src_filter = parse_src_filter(cli.src_filter.as_deref())?;
    let bind_addr: Ipv4Addr = if cli.public {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    // `-u host port` (canboat C) and `-u host:port` (ergonomic) both
    // arrive as `Vec<String>` here. Re-stitch into a single
    // `host:port` for `open_udp_broadcast` to resolve.
    let udp = match cli.udp183.as_slice() {
        [] => None,
        [one] => Some(open_udp_broadcast(one)?),
        [host, port] => Some(open_udp_broadcast(&format!("{host}:{port}"))?),
        _ => anyhow::bail!("--udp183 / -u accepts at most 2 args (host [port])"),
    };
    if let Some(ts) = cli.fixtime.as_deref() {
        log::debug!("--fixtime accepted but not applied to logging: {ts}");
    }

    let engine = Arc::new(RequestEngine::new());
    let mut hub = Hub::new(src_filter, cli.rate_limit, udp, Arc::clone(&engine));
    hub.nmea_to_stdout = cli.nmea0183 && !cli.restrict;
    let hub = Arc::new(hub);

    if !cli.nmea0183 {
        spawn_listener(
            bind_addr,
            cli.port + 1,
            "json-stream",
            Arc::clone(&hub),
            Subscription::JsonStream,
        )?;
        spawn_listener(
            bind_addr,
            cli.port + 2,
            "nmea0183-stream",
            Arc::clone(&hub),
            Subscription::Nmea0183Stream,
        )?;
        spawn_raw_input_listener(bind_addr, cli.port + 3, cli.output_copy && !cli.restrict)?;
        spawn_ais_listener(bind_addr, cli.port + 4, Arc::clone(&hub))?;
        spawn_snapshot_listener(bind_addr, cli.port, Arc::clone(&hub))?;
        spawn_status_listener(bind_addr, cli.port + 5, Arc::clone(&hub))?;
    }
    // Default-on like canboat C; `-r` / `--restrict` and the explicit
    // `--no-request-claims` opt-out both turn it off. Skip in
    // `--nmea0183` debug mode too — stdout is already busy.
    if !cli.restrict && !cli.no_request_claims && !cli.nmea0183 {
        spawn_claim_request_engine(Arc::clone(&engine));
    }

    run_stdin_pump(&hub)
}

fn parse_src_filter(arg: Option<&str>) -> Result<Option<SrcFilter>> {
    let Some(s) = arg else { return Ok(None) };
    let s = s.trim();
    let (negate, body) = match s.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let mut srcs = Vec::new();
    for tok in body.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let v: u8 = tok
            .parse()
            .with_context(|| format!("--src-filter token {tok:?}"))?;
        srcs.push(v);
    }
    Ok(Some(SrcFilter { srcs, negate }))
}

#[derive(Debug, Clone)]
struct SrcFilter {
    srcs: Vec<u8>,
    /// `true` → match `!N` style: allow everything except listed.
    negate: bool,
}

impl SrcFilter {
    fn allows(&self, src: u8) -> bool {
        let hit = self.srcs.contains(&src);
        if self.negate { !hit } else { hit }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum Subscription {
    /// Every JSON line as-is.
    JsonStream,
    /// Converted NMEA 0183 sentences.
    Nmea0183Stream,
}

/// Open a UDP socket bound to an ephemeral local port; we'll
/// `send_to` the target on each broadcast. The string is `host:port`.
fn open_udp_broadcast(target: &str) -> Result<UdpBroadcast> {
    let mut iter = target
        .to_socket_addrs()
        .with_context(|| format!("resolving udp183 target {target:?}"))?;
    let addr = iter
        .next()
        .with_context(|| format!("no addresses for {target:?}"))?;
    let sock = UdpSocket::bind("0.0.0.0:0").context("binding ephemeral UDP socket")?;
    // Many embedded receivers listen on the broadcast address — enable
    // SO_BROADCAST so a `255.255.255.255` target works too.
    sock.set_broadcast(true).ok();
    Ok(UdpBroadcast { sock, addr })
}

struct UdpBroadcast {
    sock: UdpSocket,
    addr: std::net::SocketAddr,
}
impl UdpBroadcast {
    fn send(&self, bytes: &[u8]) {
        let _ = self.sock.send_to(bytes, self.addr);
    }
}

fn spawn_listener(
    bind: Ipv4Addr,
    port: u16,
    name: &'static str,
    hub: Arc<Hub>,
    sub: Subscription,
) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding {name} on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} ({name})");
    thread::Builder::new()
        .name(format!("n2kd-{name}"))
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::warn!("accept on {name}: {e}");
                        continue;
                    }
                };
                let peer = stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|_| "?".into());
                log::info!("{name} client connected from {peer}");
                let hub2 = Arc::clone(&hub);
                thread::Builder::new()
                    .name(format!("n2kd-{name}-{peer}"))
                    .spawn(move || run_stream_client(stream, hub2, sub))
                    .ok();
            }
        })
        .context("spawning listener")?;
    Ok(())
}

fn spawn_snapshot_listener(bind: Ipv4Addr, port: u16, hub: Arc<Hub>) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding json-snapshot on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} (json-snapshot)");
    thread::Builder::new()
        .name("n2kd-json-snapshot".into())
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::warn!("accept on json-snapshot: {e}");
                        continue;
                    }
                };
                let hub2 = Arc::clone(&hub);
                thread::Builder::new()
                    .spawn(move || run_snapshot_client(stream, hub2))
                    .ok();
            }
        })
        .context("spawning snapshot listener")?;
    Ok(())
}

fn spawn_raw_input_listener(bind: Ipv4Addr, port: u16, copy_to_stdout: bool) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding raw-input on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} (raw-input)");
    thread::Builder::new()
        .name("n2kd-raw-input".into())
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::warn!("accept on raw-input: {e}");
                        continue;
                    }
                };
                thread::Builder::new()
                    .spawn(move || run_raw_input_client(stream, copy_to_stdout))
                    .ok();
            }
        })
        .context("spawning raw-input listener")?;
    Ok(())
}

/// AIS port — connect-and-dump like the JSON snapshot port, but the
/// filter is AIS-described PGNs plus the special-cased PGNs 129026
/// (COG/SOG) and 129029 (Position). Mirrors canboat C n2kd's
/// `CLIENT_AIS` path in `n2kd/main.c:757-765`.
fn spawn_ais_listener(bind: Ipv4Addr, port: u16, hub: Arc<Hub>) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding ais on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} (ais)");
    thread::Builder::new()
        .name("n2kd-ais".into())
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::warn!("accept on ais: {e}");
                        continue;
                    }
                };
                let hub2 = Arc::clone(&hub);
                thread::Builder::new()
                    .spawn(move || run_ais_client(stream, hub2))
                    .ok();
            }
        })
        .context("spawning ais listener")?;
    Ok(())
}

/// Status port — connect-and-dump, just like the JSON snapshot port,
/// but emits the canboat C `{<pgn>:{description,<src>:{last,interval,
/// count}}}` shape. Mirrors `n2kd/main.c`'s `CLIENT_STATUS_STREAM`
/// behavior.
fn spawn_status_listener(bind: Ipv4Addr, port: u16, hub: Arc<Hub>) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding status on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} (status)");
    thread::Builder::new()
        .name("n2kd-status".into())
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::warn!("accept on status: {e}");
                        continue;
                    }
                };
                let hub2 = Arc::clone(&hub);
                thread::Builder::new()
                    .spawn(move || run_status_client(stream, hub2))
                    .ok();
            }
        })
        .context("spawning status listener")?;
    Ok(())
}

/// Spawn the library `request_engine` with an emit closure that
/// writes canboat PLAIN-format ISO requests to stdout — a downstream
/// writer (e.g. `actisense-serial`) puts them on the bus.
fn spawn_claim_request_engine(engine: Arc<RequestEngine>) {
    request_engine::spawn(engine, |dst, pgn| {
        println!(
            "{}",
            request_engine::format_iso_request_plain(&now_iso(), dst, pgn)
        );
    });
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400) as u32;
    let h = day_secs / 3600;
    let m = (day_secs / 60) % 60;
    let s = day_secs % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}-{h:02}:{m:02}:{s:02}.000")
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Per-stream-client handler.
fn run_stream_client(mut stream: TcpStream, hub: Arc<Hub>, sub: Subscription) {
    let (tx, rx) = mpsc::channel::<String>();
    hub.subscribe(sub, tx);
    while let Ok(line) = rx.recv() {
        if stream.write_all(line.as_bytes()).is_err() {
            return;
        }
    }
}

fn run_snapshot_client(mut stream: TcpStream, hub: Arc<Hub>) {
    let dump = hub.snapshot();
    let _ = stream.write_all(dump.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn run_status_client(mut stream: TcpStream, hub: Arc<Hub>) {
    let dump = hub.status_snapshot();
    let _ = stream.write_all(dump.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn run_ais_client(mut stream: TcpStream, hub: Arc<Hub>) {
    let dump = hub.ais_snapshot();
    let _ = stream.write_all(dump.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn run_raw_input_client(stream: TcpStream, copy_to_stdout: bool) {
    let reader = BufReader::new(stream);
    if !copy_to_stdout {
        // Drain the connection to keep the client side healthy, but
        // discard — matches canboat C's default (echo only with `-o`).
        for _line in reader.lines().map_while(|r| r.ok()) {}
        return;
    }
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    for line in reader.lines().map_while(|r| r.ok()) {
        let mut line = line;
        line.push('\n');
        if lock.write_all(line.as_bytes()).is_err() {
            return;
        }
        let _ = lock.flush();
    }
}

fn run_stdin_pump(hub: &Hub) -> Result<()> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::with_capacity(4096);
    loop {
        line.clear();
        let n = lock.read_line(&mut line).context("reading stdin")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("{\"version\"") {
            // Analyzer banner — broadcast on JSON stream, skip cache.
            hub.broadcast(Subscription::JsonStream, &line);
            continue;
        }
        if !trimmed.starts_with("{\"timestamp\"") {
            log::debug!("ignoring non-PGN line: {trimmed:.80}");
            continue;
        }
        // canboat C requires the line to end with `}}` (the closing
        // brace of `fields` plus the outer brace) — see
        // `n2kd/main.c:982`. Empty-fields records like `{"pgn":...,
        // "description":"..."}` (no fields block) drop out; they
        // would otherwise create cache entries with no payload and
        // diverge from canboat C's view of the bus.
        if !trimmed.ends_with("}}") {
            log::debug!("ignoring fieldless record: {trimmed:.80}");
            continue;
        }
        let Some(meta) = extract_meta(trimmed) else {
            hub.broadcast(Subscription::JsonStream, &line);
            continue;
        };
        if !hub.src_allowed(meta.src) {
            continue;
        }
        hub.note_device_seen(meta.pgn, meta.src);
        // `line` carries the trailing `\n` from `read_line`; the
        // snapshot's nested wrapper would print that as a blank line
        // after every entry. Strip it before stashing.
        //
        // For PGNs whose primary key lives inside a repeating set
        // (PGN 130824 et al.) `store` walks the `"list":[…]` array
        // and emits one cache entry per iteration, each with a
        // spliced-down single-element `"list":[…]` so subsequent
        // records refresh the matching iteration in place.
        hub.store(&meta, trimmed);
        hub.broadcast(Subscription::JsonStream, &line);
        // The AIS port is a one-shot snapshot now, not a live stream —
        // see `spawn_ais_listener`. No per-line broadcast.
        // NMEA 0183 conversion: append each generated sentence to a
        // small buffer and ship it once. AIS PGNs get the AIVDM
        // encoder; everything else goes through the simple-sentence
        // table.
        let mut nmea = String::new();
        let n_sentences = if AIS_PGNS.contains(&meta.pgn) {
            let mut rl = hub.rate_limiter.lock().unwrap();
            ais::convert(&mut nmea, trimmed, &mut rl.ais_seq)
        } else {
            let mut rl = hub.rate_limiter.lock().unwrap();
            nmea0183::convert(&mut nmea, trimmed, &mut rl)
        };
        if n_sentences > 0 {
            hub.broadcast(Subscription::Nmea0183Stream, &nmea);
            hub.udp_broadcast(nmea.as_bytes());
            if hub.nmea_to_stdout {
                let stdout = io::stdout();
                let mut lock = stdout.lock();
                let _ = lock.write_all(nmea.as_bytes());
                let _ = lock.flush();
            }
        }
    }
    Ok(())
}

/// Classified record ready to hand to the snapshot store and to
/// route to the broadcast subscribers.
///
/// `secondary` is the top-level composite primary key (always
/// computed). When the PGN's PK lives inside a repeating set, the
/// per-iteration suffix is appended at store time inside
/// [`Hub::store`] — `extract_meta` doesn't know how many
/// iterations the `"list":[…]` array carries.
#[derive(Debug, Clone)]
struct Meta {
    pgn: u32,
    src: u8,
    /// Schema-driven secondary discriminator (top-level PK only).
    /// `None` when the PGN has no top-level PK.
    secondary: Option<String>,
    /// Set when [`canboat_core::snapshot::is_ais_pgn`] flags this PGN
    /// as AIS-described. Drives the longer `AIS_TTL` and the AIS
    /// subscriber fan-out.
    is_ais: bool,
    /// The PGN's full description (e.g. `"Simnet: Device Status"`) for
    /// the snapshot wrapper. Empty when the analyzer didn't emit a
    /// `"description":` key.
    description: String,
}

fn extract_meta(line: &str) -> Option<Meta> {
    let pgn = json::int(line, "pgn")? as u32;
    let src = json::int(line, "src")? as u8;
    let description = json::value(line, "description").unwrap_or("").to_string();
    let is_ais = canboat_core::snapshot::is_ais_pgn(pgn);
    // Schema-driven primary key: walk every top-level field marked
    // `PartOfPrimaryKey` on this PGN and `_`-join the resolved
    // numeric/text values. canboat-rs's deliberate divergence from
    // canboat C n2kd's first-name-from-hardcoded-list behavior; see
    // issue #2 and [`canboat_core::snapshot::composite_secondary`].
    let secondary = match canboat_core::PgnDatabase::embedded().first_pgn(pgn) {
        Some(info) => canboat_core::snapshot::composite_secondary(info, |f| {
            json::lookup_text(line, f.name).map(|s| s.to_string())
        }),
        None => None,
    };
    Some(Meta {
        pgn,
        src,
        secondary,
        is_ais,
        description,
    })
}

struct Hub {
    cache: SnapshotStore,
    engine: Arc<RequestEngine>,
    subscribers: Mutex<HashMap<u8, Vec<Sender<String>>>>,
    src_filter: Option<SrcFilter>,
    rate_limiter: Mutex<RateLimiter>,
    udp: Option<UdpBroadcast>,
    /// `--nmea0183` mode: NMEA / AIVDM sentences are also written to
    /// the process's stdout. Off in the normal TCP-multiplex mode.
    nmea_to_stdout: bool,
}

impl Hub {
    fn new(
        src_filter: Option<SrcFilter>,
        rate_limit: bool,
        udp: Option<UdpBroadcast>,
        engine: Arc<RequestEngine>,
    ) -> Self {
        Self {
            cache: SnapshotStore::new(),
            engine,
            subscribers: Mutex::new(HashMap::new()),
            src_filter,
            rate_limiter: Mutex::new(RateLimiter::new(rate_limit)),
            udp,
            nmea_to_stdout: false,
        }
    }

    fn src_allowed(&self, src: u8) -> bool {
        match &self.src_filter {
            None => true,
            Some(f) => f.allows(src),
        }
    }

    fn note_device_seen(&self, pgn: u32, src: u8) {
        self.engine.note_device_seen(pgn, src);
    }

    fn store(&self, meta: &Meta, line: &str) {
        // Fast path: PGN has no PK fields inside a repeating set, so
        // one record → one cache entry.
        let info = canboat_core::PgnDatabase::embedded().first_pgn(meta.pgn);
        let repeat_set = info.and_then(canboat_core::snapshot::repeating_pk_set);
        let Some(rs) = repeat_set else {
            self.cache.store(SnapshotInput {
                pgn: meta.pgn,
                src: meta.src,
                secondary: meta.secondary.clone(),
                is_ais: meta.is_ais,
                pgn_description: meta.description.clone(),
                line: line.to_string(),
            });
            return;
        };
        // Per-iteration path (PGN 130824 family). The repeating set
        // is emitted as `"<key>":[{…},{…}]` inside `"fields":{…}`;
        // canboat uses `"list"` for set 1 and `"list2"` for set 2.
        let list_key = if rs == 1 { "list" } else { "list2" };
        let Some((arr_start, arr_end)) = json::array_span(line, list_key) else {
            // The repeating set declared no iterations on the wire
            // (count=0). Nothing to deconstruct — store the single
            // record under the top-level PK alone.
            self.cache.store(SnapshotInput {
                pgn: meta.pgn,
                src: meta.src,
                secondary: meta.secondary.clone(),
                is_ais: meta.is_ais,
                pgn_description: meta.description.clone(),
                line: line.to_string(),
            });
            return;
        };
        let arr = &line[arr_start..arr_end];
        let elements = json::split_object_array(arr);
        let pgn_info = info.expect("repeat_set source implies info present");
        for (iter, elem) in elements.iter().enumerate() {
            let secondary = canboat_core::snapshot::per_iteration_secondary(
                pgn_info,
                rs,
                iter as u32,
                |f| json::lookup_text(line, f.name).map(|s| s.to_string()),
                |f, _| json::lookup_text(elem, f.name).map(|s| s.to_string()),
            );
            // Splice the array down to just this element so the
            // cached line shows only its own iteration's fields.
            let mut spliced = String::with_capacity(line.len() - arr.len() + elem.len() + 2);
            spliced.push_str(&line[..arr_start]);
            spliced.push('[');
            spliced.push_str(elem);
            spliced.push(']');
            spliced.push_str(&line[arr_end..]);
            self.cache.store(SnapshotInput {
                pgn: meta.pgn,
                src: meta.src,
                secondary,
                is_ais: meta.is_ais,
                pgn_description: meta.description.clone(),
                line: spliced,
            });
        }
    }

    /// Canboat C–compatible nested-JSON dump of every live cache
    /// entry (one big string ending in `}\n`, or `\n` when empty).
    fn snapshot(&self) -> String {
        self.cache.snapshot()
    }

    /// Canboat C–compatible per-PGN status dump
    /// (`{<pgn>:{description,<src>:{last,interval,count}}}`).
    fn status_snapshot(&self) -> String {
        self.cache.status_snapshot()
    }

    /// Canboat C–compatible AIS snapshot dump — same shape as
    /// `snapshot()` but filtered to AIS-described PGNs + 129026 +
    /// 129029.
    fn ais_snapshot(&self) -> String {
        self.cache.ais_snapshot()
    }

    fn subscribe(&self, sub: Subscription, tx: Sender<String>) {
        let key = sub as u8;
        self.subscribers
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .push(tx);
    }

    fn broadcast(&self, sub: Subscription, line: &str) {
        let key = sub as u8;
        let mut subs = self.subscribers.lock().unwrap();
        let Some(list) = subs.get_mut(&key) else {
            return;
        };
        list.retain(|tx| tx.send(line.to_string()).is_ok());
    }

    fn udp_broadcast(&self, bytes: &[u8]) {
        if let Some(udp) = &self.udp {
            udp.send(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pgn_src() {
        let line = r#"{"timestamp":"2026-01-01T00:00:00","prio":2,"src":7,"dst":255,"pgn":127251,"description":"Rate of Turn","fields":{"Rate":0}}"#;
        let meta = extract_meta(line).unwrap();
        assert_eq!(meta.pgn, 127251);
        assert_eq!(meta.src, 7);
        assert!(!meta.is_ais);
        assert_eq!(meta.description, "Rate of Turn");
        assert!(meta.secondary.is_none());
    }

    #[test]
    fn ais_message_marks_is_ais_and_keys_on_user_id() {
        let line = r#"{"timestamp":"…","src":23,"pgn":129039,"fields":{"Message ID":18,"User ID":"244180106"}}"#;
        let meta = extract_meta(line).unwrap();
        assert!(meta.is_ais);
        // Schema 2.5.0 declares only `User ID` as PartOfPrimaryKey on
        // PGN 129039 — Message ID is NOT a discriminator here. The
        // hand-rolled SECONDARY_FIELDS list got the same answer by
        // accident (User ID happened to sit ahead of Message ID); the
        // schema-driven path is right for the right reason.
        assert_eq!(meta.secondary.as_deref(), Some("244180106"));
    }

    #[test]
    fn extract_meta_uses_lookup_numeric_value() {
        // -nv mode wraps a lookup as `{"value":1,"name":"Outside
        // Temperature"}`; the composite snapshot key uses the raw
        // numeric `value` (short, stable across schema label edits).
        // PGN 130312 (Temperature) declares `Instance + Source` as a
        // composite primary key, with Source being a LOOKUP into
        // TEMPERATURE_SOURCE.
        let line = r#"{"src":7,"pgn":130312,"fields":{"Instance":0,"Source":{"value":1,"name":"Outside Temperature"},"Actual Temperature":18.5}}"#;
        let meta = extract_meta(line).unwrap();
        // Composite PK: `<Instance>_<Source-value>`
        assert_eq!(meta.secondary.as_deref(), Some("0_1"));
    }

    #[test]
    fn extract_meta_handles_key_true_lookup_objects() {
        // PGN 127501 Instance is a `{"value":N,"key":true}` lookup —
        // no name to consider, value extraction still works.
        let line = r#"{"src":17,"pgn":127501,"fields":{"Instance":{"value":0,"key":true}}}"#;
        let meta = extract_meta(line).unwrap();
        assert_eq!(meta.secondary.as_deref(), Some("0"));
    }

    #[test]
    fn composite_pk_keys_distinguish_otherwise_identical_records() {
        // PGN 127509 (Inverter Status) declares `Instance + AC Instance
        // + DC Instance` as a composite PK. Two records that share
        // Instance=0 but differ in AC Instance must get distinct cache
        // keys — canboat C n2kd's first-match SECONDARY_FIELDS would
        // collapse them into the same `<src>_0` entry, dropping data.
        let a =
            r#"{"src":35,"pgn":127509,"fields":{"Instance":0,"AC Instance":0,"DC Instance":1}}"#;
        let b =
            r#"{"src":35,"pgn":127509,"fields":{"Instance":0,"AC Instance":1,"DC Instance":0}}"#;
        let ma = extract_meta(a).unwrap();
        let mb = extract_meta(b).unwrap();
        assert_eq!(ma.secondary.as_deref(), Some("0_0_1"));
        assert_eq!(mb.secondary.as_deref(), Some("0_1_0"));
        assert_ne!(ma.secondary, mb.secondary);
    }

    /// Build a Hub with no source filter / rate limit / UDP — just
    /// enough surface to exercise `Hub::store` and the snapshot dump.
    fn test_hub() -> Hub {
        let engine = Arc::new(RequestEngine::new());
        Hub::new(None, false, None, engine)
    }

    #[test]
    fn store_pgn_130824_emits_one_entry_per_iteration() {
        // Hand-built analyzer-JSON line for PGN 130824 src=27 with
        // three Key/Value pairs (`Polar Speed`, `Polar Performance`,
        // `Opposite Tack COG`). Each Key field is the `-nv` lookup
        // object whose `value` becomes the per-iteration cache key.
        let line = r#"{"timestamp":"…","prio":3,"src":27,"dst":255,"pgn":130824,"description":"B&G: key-value data","fields":{"Manufacturer Code":{"value":381,"name":"B & G"},"Industry Code":{"value":4,"name":"Marine Industry"},"list":[{"Key":{"value":126,"name":"Polar Speed"},"Length":2,"Value":2.03},{"Key":{"value":124,"name":"Polar Performance"},"Length":2,"Value":128.0},{"Key":{"value":306,"name":"Opposite Tack COG"},"Length":2,"Value":103.6}]}}"#;
        let hub = test_hub();
        let meta = extract_meta(line).expect("extract meta");
        // Top-level secondary is None for 130824 — the PK lives in
        // the `list`.
        assert!(meta.secondary.is_none());
        hub.store(&meta, line);
        let dump = hub.snapshot();
        assert!(
            dump.contains("\"27_126\":"),
            "missing src_<key=126> (Polar Speed):\n{dump}"
        );
        assert!(
            dump.contains("\"27_124\":"),
            "missing src_<key=124> (Polar Performance):\n{dump}"
        );
        assert!(
            dump.contains("\"27_306\":"),
            "missing src_<key=306> (Opposite Tack COG):\n{dump}"
        );
        // Each spliced line keeps a single-element list so subsequent
        // records refresh that iteration in place.
        assert_eq!(
            dump.matches("\"list\":[{").count(),
            3,
            "expected 3 single-element list payloads:\n{dump}"
        );
    }

    #[test]
    fn store_pgn_130824_preserves_other_iterations_on_partial_update() {
        let initial = r#"{"src":27,"pgn":130824,"description":"B&G: key-value data","fields":{"list":[{"Key":{"value":126},"Length":2,"Value":2.03},{"Key":{"value":124},"Length":2,"Value":128.0}]}}"#;
        let hub = test_hub();
        let meta = extract_meta(initial).unwrap();
        hub.store(&meta, initial);

        // Second record carries only key 126 with a refreshed value.
        let update = r#"{"src":27,"pgn":130824,"description":"B&G: key-value data","fields":{"list":[{"Key":{"value":126},"Length":2,"Value":4.00}]}}"#;
        let meta = extract_meta(update).unwrap();
        hub.store(&meta, update);

        let dump = hub.snapshot();
        // Both Keys still present — partial update didn't blow away
        // the non-mentioned iteration.
        assert!(dump.contains("\"27_126\":"), "Polar Speed missing:\n{dump}");
        assert!(
            dump.contains("\"27_124\":"),
            "Polar Performance dropped on partial update:\n{dump}"
        );
        // And the refreshed value made it into the cached line.
        assert!(
            dump.contains("\"Value\":4"),
            "expected refreshed Polar Speed value=4 in dump:\n{dump}"
        );
    }

    #[test]
    fn negative_src_filter() {
        let f = parse_src_filter(Some("!1,2")).unwrap().unwrap();
        assert!(f.allows(3));
        assert!(!f.allows(1));
        assert!(!f.allows(2));
    }

    #[test]
    fn positive_src_filter() {
        let f = parse_src_filter(Some("7,8")).unwrap().unwrap();
        assert!(f.allows(7));
        assert!(!f.allows(9));
    }
}
