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

mod json;
mod nmea0183;

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use crate::nmea0183::RateLimiter;

/// Default TCP base port.
const DEFAULT_PORT: u16 = 2597;
/// Sensor PGN cache TTL — matches canboat's `SENSOR_TIMEOUT`.
const SENSOR_TIMEOUT: Duration = Duration::from_secs(120);
/// AIS-shaped PGN cache TTL — matches canboat's `AIS_TIMEOUT`.
const AIS_TIMEOUT: Duration = Duration::from_secs(3600);
/// How often the status port emits a snapshot.
const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// Spacing between individual claim-request emissions — matches
/// `DEVICE_REQUEST_SPACING` in main.c.
const DEVICE_REQUEST_SPACING: Duration = Duration::from_secs(1);
/// Minimum time between repeating a claim or product-info request for
/// the same device — matches `DEVICE_REQUEST_INTERVAL`.
const DEVICE_REQUEST_INTERVAL: Duration = Duration::from_secs(300);

/// PGN 60928 — ISO Address Claim.
const PGN_CLAIM: u32 = 60928;
/// PGN 126996 — Product Information.
const PGN_PROD_INFO: u32 = 126996;
/// PGN 126998 — Configuration Information (also auto-requested by
/// canboat).
const PGN_CONFIG_INFO: u32 = 126998;

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
    /// Base TCP port. `+1`=stream, `+2`=nmea0183, `+3`=ais, `+4`=status, `+5`=raw input.
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Filter incoming JSON by source address. Comma-separated list
    /// of `u8`; prepend `!` for a negative match (e.g. `!1,2`
    /// allows everything except sources 1 and 2). Mirrors canboat
    /// `srcFilter`.
    #[arg(long)]
    src_filter: Option<String>,

    /// Rate-limit each (src, kind) of NMEA 0183 sentence to at most
    /// one per second. Mirrors canboat's `-r`.
    #[arg(short = 'r', long)]
    rate_limit: bool,

    /// Bind on `0.0.0.0` instead of `127.0.0.1`.
    #[arg(long)]
    public: bool,

    /// Also UDP-broadcast each NMEA 0183 sentence to `<host:port>`
    /// (matches canboat `-udp183`). Useful for OpenCPN / Navionics
    /// receivers listening on the LAN.
    #[arg(long, value_name = "HOST:PORT")]
    udp183: Option<String>,

    /// Emit periodic ISO Address Claim / Product Info requests on
    /// stdout for every device we've seen on the bus. Off by default
    /// because it pollutes the stdout PLAIN stream when not wired
    /// back to a writeable bridge.
    #[arg(long)]
    request_claims: bool,

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
    let udp = match cli.udp183.as_deref() {
        Some(addr) => Some(open_udp_broadcast(addr)?),
        None => None,
    };

    let hub = Arc::new(Hub::new(src_filter, cli.rate_limit, udp));

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
    spawn_listener(
        bind_addr,
        cli.port + 3,
        "ais-stream",
        Arc::clone(&hub),
        Subscription::AisStream,
    )?;
    spawn_listener(
        bind_addr,
        cli.port + 4,
        "status",
        Arc::clone(&hub),
        Subscription::StatusStream,
    )?;
    spawn_snapshot_listener(bind_addr, cli.port, Arc::clone(&hub))?;
    spawn_raw_input_listener(bind_addr, cli.port + 5)?;

    spawn_status_emitter(Arc::clone(&hub));
    if cli.request_claims {
        spawn_claim_request_engine(Arc::clone(&hub));
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
        if self.negate {
            !hit
        } else {
            hit
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum Subscription {
    /// Every JSON line as-is.
    JsonStream,
    /// Converted NMEA 0183 sentences.
    Nmea0183Stream,
    /// AIS-related PGNs only, as JSON.
    AisStream,
    /// Periodic `{"clients":N,"pgns":[…]}` status snapshots.
    StatusStream,
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
        .spawn(move || loop {
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
        .spawn(move || loop {
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
        })
        .context("spawning snapshot listener")?;
    Ok(())
}

fn spawn_raw_input_listener(bind: Ipv4Addr, port: u16) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(bind, port))
        .with_context(|| format!("binding raw-input on {bind}:{port}"))?;
    log::info!("listening on {bind}:{port} (raw-input)");
    thread::Builder::new()
        .name("n2kd-raw-input".into())
        .spawn(move || loop {
            let stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) => {
                    log::warn!("accept on raw-input: {e}");
                    continue;
                }
            };
            thread::Builder::new()
                .spawn(move || run_raw_input_client(stream))
                .ok();
        })
        .context("spawning raw-input listener")?;
    Ok(())
}

/// Periodic status emission. Sends `{"clients":N,"pgns":N}` etc. to
/// every status subscriber every [`STATUS_INTERVAL`].
fn spawn_status_emitter(hub: Arc<Hub>) {
    thread::Builder::new()
        .name("n2kd-status".into())
        .spawn(move || loop {
            thread::sleep(STATUS_INTERVAL);
            let snap = hub.status_snapshot();
            hub.broadcast(Subscription::StatusStream, &snap);
        })
        .ok();
}

/// Periodic claim-request engine. Walks devices we've seen, emits a
/// PLAIN-format ISO request on stdout for each one that needs a
/// claim or product-info refresh. Honours the same intervals as
/// canboat: at most one request per `DEVICE_REQUEST_SPACING`,
/// repeating the same device no more often than
/// `DEVICE_REQUEST_INTERVAL`.
fn spawn_claim_request_engine(hub: Arc<Hub>) {
    thread::Builder::new()
        .name("n2kd-claim-engine".into())
        .spawn(move || {
            let mut next_claim = 0u8;
            let mut next_prod = 0u8;
            let mut last_claim_emit = Instant::now() - DEVICE_REQUEST_SPACING;
            let mut last_prod_emit = Instant::now() - DEVICE_REQUEST_SPACING;
            loop {
                thread::sleep(Duration::from_millis(500));
                let now = Instant::now();
                if now.duration_since(last_claim_emit) >= DEVICE_REQUEST_SPACING {
                    if let Some(dst) =
                        hub.find_next_device_needing_request(&mut next_claim, PgnRequestKind::Claim)
                    {
                        emit_iso_request(dst, PGN_CLAIM);
                        last_claim_emit = now;
                    }
                }
                if now.duration_since(last_prod_emit) >= DEVICE_REQUEST_SPACING {
                    if let Some(dst) = hub.find_next_device_needing_request(
                        &mut next_prod,
                        PgnRequestKind::ProductInfo,
                    ) {
                        // canboat asks for both 126996 (Product Info)
                        // and 126998 (Configuration Info) under the
                        // same scheduling slot.
                        emit_iso_request(dst, PGN_PROD_INFO);
                        emit_iso_request(dst, PGN_CONFIG_INFO);
                        last_prod_emit = now;
                    }
                }
            }
        })
        .ok();
}

/// PGN 59904 "ISO Request" — `<ts>,6,59904,0,<dst>,3,<pgn LE bytes>`.
fn emit_iso_request(dst: u8, pgn: u32) {
    let now = now_iso();
    let b0 = pgn & 0xff;
    let b1 = (pgn >> 8) & 0xff;
    let b2 = (pgn >> 16) & 0xff;
    println!("{now},6,59904,0,{dst},3,{b0:02x},{b1:02x},{b2:02x}");
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

#[derive(Copy, Clone)]
enum PgnRequestKind {
    Claim,
    ProductInfo,
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
    for line in hub.snapshot() {
        if stream.write_all(line.as_bytes()).is_err() {
            return;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn run_raw_input_client(stream: TcpStream) {
    let reader = BufReader::new(stream);
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
        let Some(meta) = extract_meta(trimmed) else {
            hub.broadcast(Subscription::JsonStream, &line);
            continue;
        };
        if !hub.src_allowed(meta.src) {
            continue;
        }
        hub.note_device_seen(meta.pgn, meta.src);
        hub.store(meta, line.clone());
        hub.broadcast(Subscription::JsonStream, &line);
        if AIS_PGNS.contains(&meta.pgn) {
            hub.broadcast(Subscription::AisStream, &line);
        }
        // NMEA 0183 conversion: append each generated sentence to a
        // small buffer and ship it once.
        let mut nmea = String::new();
        let n_sentences = {
            let mut rl = hub.rate_limiter.lock().unwrap();
            nmea0183::convert(&mut nmea, trimmed, &mut rl)
        };
        if n_sentences > 0 {
            hub.broadcast(Subscription::Nmea0183Stream, &nmea);
            hub.udp_broadcast(nmea.as_bytes());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    pgn: u32,
    src: u8,
    secondary: u64,
    is_ais_like: bool,
}

fn extract_meta(line: &str) -> Option<Meta> {
    let pgn = json::int(line, "pgn")? as u32;
    let src = json::int(line, "src")? as u8;
    let secondary = SECONDARY_KEYS
        .iter()
        .find_map(|(k, _)| {
            let idx = line.find(k)?;
            let after = &line[idx + k.len()..];
            let end = after.find([',', '}']).unwrap_or(after.len());
            Some(djb2_hash(after[..end].trim_matches(['"', ' ', ':'])))
        })
        .unwrap_or(0);
    let is_ais_like = SECONDARY_KEYS
        .iter()
        .any(|(k, ais)| *ais && line.contains(k));
    Some(Meta {
        pgn,
        src,
        secondary,
        is_ais_like,
    })
}

fn djb2_hash(s: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = (h.wrapping_shl(5)).wrapping_add(h).wrapping_add(b as u64);
    }
    h
}

const SECONDARY_KEYS: &[(&str, bool)] = &[
    ("Instance\":", false),
    ("\"Reference\":", false),
    ("\"User ID\":", true),
    ("\"Message ID\":", true),
    ("\"Proprietary ID\":", false),
];

struct Hub {
    cache: Mutex<HashMap<(u32, u8, u64), CacheEntry>>,
    devices: Mutex<HashMap<u8, DeviceState>>,
    subscribers: Mutex<HashMap<u8, Vec<Sender<String>>>>,
    src_filter: Option<SrcFilter>,
    rate_limiter: Mutex<RateLimiter>,
    udp: Option<UdpBroadcast>,
}

struct CacheEntry {
    line: String,
    expires_at: Instant,
}

#[derive(Default, Debug, Clone, Copy)]
struct DeviceState {
    seen: bool,
    last_claim_received: Option<Instant>,
    last_claim_requested: Option<Instant>,
    last_prod_info_received: Option<Instant>,
    last_prod_info_requested: Option<Instant>,
}

impl Hub {
    fn new(src_filter: Option<SrcFilter>, rate_limit: bool, udp: Option<UdpBroadcast>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(HashMap::new()),
            src_filter,
            rate_limiter: Mutex::new(RateLimiter::new(rate_limit)),
            udp,
        }
    }

    fn src_allowed(&self, src: u8) -> bool {
        match &self.src_filter {
            None => true,
            Some(f) => f.allows(src),
        }
    }

    fn note_device_seen(&self, pgn: u32, src: u8) {
        let now = Instant::now();
        let mut devs = self.devices.lock().unwrap();
        let entry = devs.entry(src).or_default();
        entry.seen = true;
        if pgn == PGN_CLAIM {
            entry.last_claim_received = Some(now);
        } else if pgn == PGN_PROD_INFO {
            entry.last_prod_info_received = Some(now);
        }
    }

    fn find_next_device_needing_request(&self, next: &mut u8, kind: PgnRequestKind) -> Option<u8> {
        let now = Instant::now();
        let devs = self.devices.lock().ok()?;
        for offset in 0..=u8::MAX as u16 {
            let idx = next.wrapping_add(offset as u8);
            let Some(state) = devs.get(&idx) else {
                continue;
            };
            if !state.seen {
                continue;
            }
            let (last_received, last_requested) = match kind {
                PgnRequestKind::Claim => (state.last_claim_received, state.last_claim_requested),
                PgnRequestKind::ProductInfo => (
                    state.last_prod_info_received,
                    state.last_prod_info_requested,
                ),
            };
            if last_received.is_some_and(|t| now.duration_since(t) < DEVICE_REQUEST_INTERVAL) {
                continue;
            }
            if last_requested.is_some_and(|t| now.duration_since(t) < DEVICE_REQUEST_INTERVAL) {
                continue;
            }
            // Stamp it requested. Re-take the lock as mutable.
            drop(devs);
            let mut devs = self.devices.lock().unwrap();
            if let Some(state) = devs.get_mut(&idx) {
                match kind {
                    PgnRequestKind::Claim => state.last_claim_requested = Some(now),
                    PgnRequestKind::ProductInfo => state.last_prod_info_requested = Some(now),
                }
            }
            *next = idx.wrapping_add(1);
            return Some(idx);
        }
        None
    }

    fn store(&self, meta: Meta, line: String) {
        let ttl = if meta.is_ais_like {
            AIS_TIMEOUT
        } else {
            SENSOR_TIMEOUT
        };
        let entry = CacheEntry {
            line,
            expires_at: Instant::now() + ttl,
        };
        self.cache
            .lock()
            .unwrap()
            .insert((meta.pgn, meta.src, meta.secondary), entry);
    }

    fn snapshot(&self) -> Vec<String> {
        let now = Instant::now();
        let mut guard = self.cache.lock().unwrap();
        guard.retain(|_, v| v.expires_at > now);
        guard.values().map(|v| v.line.clone()).collect()
    }

    fn status_snapshot(&self) -> String {
        let cache_len = self.cache.lock().unwrap().len();
        let devs_seen = self.devices.lock().unwrap().len();
        let total_subs: usize = self
            .subscribers
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum();
        format!("{{\"clients\":{total_subs},\"devices\":{devs_seen},\"pgns\":{cache_len}}}\n")
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
        let line = r#"{"timestamp":"2026-01-01T00:00:00","prio":2,"src":7,"dst":255,"pgn":127251,"fields":{"Rate":0}}"#;
        let meta = extract_meta(line).unwrap();
        assert_eq!(meta.pgn, 127251);
        assert_eq!(meta.src, 7);
        assert!(!meta.is_ais_like);
    }

    #[test]
    fn ais_message_marked_ais_like() {
        let line = r#"{"timestamp":"…","src":23,"pgn":129039,"fields":{"Message ID":18,"User ID":"244180106"}}"#;
        let meta = extract_meta(line).unwrap();
        assert!(meta.is_ais_like);
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
