// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! `canboat-pipeline` — single-process N2K → NMEA 0183 pipeline.
//!
//! Combines the work that the C canboat stack normally splits across
//! three processes (a device reader like `actisense-serial`, the
//! `analyzer`, and `n2kd`) into one binary. `RawFrame`s flow between
//! stages as structs over mpsc channels — no PLAIN/FAST text
//! serialization between stages — so the formatter/parser tax pays
//! out only at the human-readable boundaries (NMEA 0183 stdout and
//! the optional CSV TCP server).
//!
//! Input modes:
//!
//! * **stdin** (no `--actisense` / `--ikonvert` / `--maretron`): the
//!   binary parses PLAIN/FAST lines off stdin. Compatible with
//!   `analyzer < file.raw | canboat-pipeline` style pipelines that used
//!   to exist with `n2kd-inproc`.
//! * **device**: a [`canboat_io::device`] reader stage opens the
//!   chosen serial port / TCP socket and emits `RawFrame`s
//!   directly. In this mode, the write-only input port and the lazy
//!   output TCP servers are also wired up.
//!
//! Output: NMEA 0183 sentences on stdout.
//!
//! ## TCP port layout
//!
//! Base-relative offsets match canboat C `n2kd` (and the `n2kd`
//! crate) one-for-one, so no port number ever means two different
//! things across the three implementations. Every output stream is
//! read-only; the single write path is the input port.
//!
//! | Port | Flag | Dir | Purpose |
//! |------|------|-----|---------|
//! | 2597 | `--snapshot-port`       | out | JSON snapshot per `(pgn, src)`, then close |
//! | 2598 | `--analyzer-port`       | out | analyzer JSON stream (read-only) |
//! | 2599 | `--nmea0183-port`       | out | NMEA 0183 stream |
//! | 2600 | `--input-port`          | in  | **write-only** raw PLAIN/FAST → bus |
//! | 2601 | `--ais-port`            | out | AIS snapshot, then close |
//! | 2602 | *(reserved)*            | —   | future status stream (n2kd `port+5`) |
//! | 2603 | `--raw-port`            | out | raw frame output stream |
//! | 2604 | `--analyzer-binary-port`| out | binary `WirePgn` stream |

mod nmea_filter;
mod pipeline;
mod quirks;
mod snapshot;
mod tcp;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

use anyhow::{Result, bail};

use canboat_core::format::{
    InputFormat, detect, header_implies_coalesced, parse_format_header, parse_with,
};
use canboat_core::output::{CamelCase, JsonOptions};
use canboat_core::{PgnDatabase, RawFrame};
use canboat_io::device::{self, FrameSender, Supervisor};
use canboat_io::open_serial_rw;
use n2kd::request_engine::{self, RequestEngine};

use crate::server::pipeline::Hubs;
use crate::server::snapshot::SnapshotStore;
use n2kd::serving::{BinHub, Hub};

/// Single-process device-reader → analyzer → n2kd pipeline server.
#[derive(Debug, clap::Args)]
#[command(after_help = canboat_cli::help_footer())]
pub struct Args {
    /// Read frames from an Actisense NGT-1 / W2K-1 on this serial
    /// device path (e.g. `/dev/ttyUSB0`).
    #[arg(
        long,
        value_name = "DEVICE",
        conflicts_with_all = ["ikonvert", "maretron", "canboat_csv", "socketcan"]
    )]
    actisense: Option<String>,

    /// Read frames from a Digital Yacht iKonvert on this serial
    /// device path.
    #[arg(
        long,
        value_name = "DEVICE",
        conflicts_with_all = ["actisense", "maretron", "canboat_csv", "socketcan"]
    )]
    ikonvert: Option<String>,

    /// Read frames from a Maretron IPG100/200 over TCP. Accepts either
    /// `host:port` or `tcp://host[:port]`. Default port 6543 (bus 0).
    #[arg(
        long,
        value_name = "URL",
        conflicts_with_all = ["actisense", "ikonvert", "canboat_csv", "socketcan"]
    )]
    maretron: Option<String>,

    /// Read frames from a Linux SocketCAN interface (e.g. `can0`,
    /// `nmea2000`). The pipeline becomes a full NMEA 2000 bus
    /// participant: it claims an ISO address, answers ISO Requests and
    /// Group Functions, and sends Heartbeats. Linux-only.
    #[arg(
        long,
        value_name = "IFACE",
        conflicts_with_all = ["actisense", "ikonvert", "maretron", "canboat_csv"]
    )]
    socketcan: Option<String>,

    /// Preferred ISO source address to claim on the SocketCAN bus.
    /// Defaults to 0; the claim machine will pick a free address if
    /// this one is taken. Ignored without `--socketcan`.
    #[arg(
        long = "socketcan-address",
        value_name = "ADDR",
        default_value_t = 0,
        requires = "socketcan"
    )]
    socketcan_address: u8,

    /// Chain into another `canboat-pipeline` instance over its
    /// bidirectional Raw CSV port (default 2603). Accepts
    /// `host:port` or `tcp://host[:port]`. Wire format is
    /// canboat PLAIN/FAST CSV in both directions, so all frames
    /// and any client writes flow end-to-end.
    ///
    /// When `--canboat-csv-write` is also given, this URL is used
    /// only as a read source (e.g. an iptee'd raw stream), and
    /// outbound writes are diverted to the write URL instead.
    #[arg(
        long,
        value_name = "URL",
        conflicts_with_all = ["actisense", "ikonvert", "maretron", "socketcan"]
    )]
    canboat_csv: Option<String>,

    /// Optional separate sink for outbound PLAIN/FAST frames when
    /// chaining via `--canboat-csv`. Use this when the read source
    /// is a one-way feed (e.g. iptee on actisense-serial output)
    /// and writes need to go to a different endpoint (e.g. n2kd's
    /// input-stream port). Without this flag, reads and writes
    /// share the single `--canboat-csv` socket.
    #[arg(long, value_name = "URL", requires = "canboat_csv")]
    canboat_csv_write: Option<String>,

    /// Baud rate for serial devices. Defaults: 115200 for NGT-1,
    /// 230400 for iKonvert. Ignored for Maretron.
    #[arg(long, value_name = "BAUD")]
    baud: Option<u32>,

    /// Maretron login password (default: empty).
    #[arg(long, default_value = "")]
    maretron_password: String,

    /// iKonvert RX filter list (`<pgn>,<pgn>,...`). When set, init
    /// brings the device online in `NORMAL` mode and runs the
    /// `N2NET_RESET` + `RX_LIST` handshake steps.
    #[arg(long, value_name = "PGN,PGN,...")]
    ikonvert_rx: Option<String>,

    /// iKonvert TX filter list (`<pgn>,<pgn>,...`). Triggers the
    /// `N2NET_RESET` + `TX_LIST` handshake steps.
    #[arg(long, value_name = "PGN,PGN,...")]
    ikonvert_tx: Option<String>,

    /// Disable the iKonvert TX rate limit. Use at your own risk.
    #[arg(long)]
    ikonvert_rate_limit_off: bool,

    /// Suppress the periodic ISO Address Claim / Product Info request
    /// engine. By default it runs whenever a device writer is wired up
    /// (matching canboat C `n2kd`'s default). Stdin-only mode always
    /// skips the engine — there's nowhere to send the requests.
    #[arg(long)]
    no_request_claims: bool,

    /// Apply a device-specific firmware-quirk workaround on the bus.
    /// Currently only `scx20` is recognised: when something on the bus
    /// asks for PGN 126996 Product Information, fabricate the response
    /// on behalf of a known SCX-20 (it sometimes "forgets" how to
    /// answer). The single-value form accepted today is expected to
    /// grow into a repeatable flag once more quirks land.
    ///
    /// Only works with `--socketcan` — every other device backend
    /// rewrites the source address on outbound, which would defeat the
    /// impersonation.
    #[arg(long, value_enum, value_name = "NAME")]
    quirk: Option<quirks::QuirkKind>,

    /// Bind address for all TCP listeners. Defaults to `0.0.0.0` so
    /// clients on the LAN (chartplotters, OpenCPN, etc.) can
    /// connect. Pass `127.0.0.1` to restrict access to the local
    /// host.
    #[arg(long, default_value = "0.0.0.0")]
    bind: Ipv4Addr,

    /// Port for the snapshot server — on connect, dumps the latest
    /// analyzer JSON line per `(pgn, src, secondary)` then closes.
    /// Matches canboat C `n2kd`'s base port (`-p`). AIS-described
    /// PGNs are filtered out; they go to `--ais-port` instead, except
    /// PGN 129026 and 129029 which appear in both. Enabling this
    /// forces JSON serialization for every decoded record so the
    /// cache stays current; disable with `0` if you don't need it.
    #[arg(long, default_value_t = 2597)]
    snapshot_port: u16,

    /// Port for the analyzer JSON server — one decoded PGN per line.
    /// Matches canboat C `n2kd`'s `port+1` stream port: read-only.
    /// Injection goes through `--input-port` instead; this port is
    /// kept free for a future "analyzed write" feature that would
    /// accept JSON here. Lazy: formatting is skipped when no client is
    /// subscribed. `0` disables.
    #[arg(long, default_value_t = 2598)]
    analyzer_port: u16,

    /// Port for the read-only NMEA 0183 server (includes AIVDM).
    /// Matches canboat C `n2kd`'s `port+2` NMEA 0183 port. `0`
    /// disables.
    #[arg(long, default_value_t = 2599)]
    nmea0183_port: u16,

    /// Write-only raw input port — the canonical `SERVER_INPUT_STREAM`
    /// slot (canboat C `n2kd` `port+3`). Clients connect and write
    /// canboat PLAIN/FAST lines that are injected onto the bus
    /// (device mode only); nothing is streamed back, so it never
    /// forces JSON/CSV serialization. This is the cheap write path for
    /// a consumer that reads its data on another port (e.g. the
    /// analyzer-binary stream). `0` disables.
    #[arg(long, default_value_t = 2600)]
    input_port: u16,

    /// Read-only raw N2K output stream. Clients receive every frame as
    /// a `# format=FAST` PLAIN line (already-coalesced fast-packet
    /// payloads — never the per-CAN-frame PLAIN format). Reading is
    /// lazy (skipped with no client). Injection is NOT accepted here —
    /// use `--input-port`. `0` disables. (Previously this port was
    /// bidirectional at 2600 under `--csv-port` / `--raw-input-port`;
    /// the write side moved to `--input-port` and the read side moved
    /// here to keep the input slot write-only.)
    #[arg(long, default_value_t = 2603)]
    raw_port: u16,

    /// Port for the AIS snapshot server — on connect, dumps the
    /// latest analyzer JSON line for every AIS-described PGN (plus
    /// PGN 129026 and 129029) then closes. Matches canboat C
    /// `n2kd`'s `port+4` AIS port. `0` disables.
    #[arg(long, default_value_t = 2601)]
    ais_port: u16,

    /// Port for the read-only binary analyzer stream: each decoded PGN
    /// as a length-prefixed postcard `WirePgn` (see the canboat-wire
    /// crate), preceded by a one-shot `Hello` handshake carrying the
    /// schema hash. Far cheaper for a Rust consumer than parsing the
    /// analyzer JSON — no field re-serialization here, no JSON parse
    /// there — but the client MUST link an identical schema. Lazy:
    /// nothing is encoded when no client is subscribed, so it's cheap
    /// to leave on. Canonical slot 2604 (after the reserved status
    /// slot at 2602 and the raw output stream at 2603). `0` disables.
    #[arg(long, default_value_t = 2604)]
    analyzer_binary_port: u16,

    /// Also write NMEA 0183 sentences (including AIVDM) to stdout —
    /// mirrors canboat C `n2kd`'s `--nmea0183` flag. Off by default,
    /// matching n2kd's TCP-multiplex behaviour; subscribers should
    /// connect to `--nmea0183-port` (2599) instead.
    #[arg(long)]
    nmea0183_stdout: bool,

    /// Disable the 1 Hz NMEA 0183 rate limit. By default each
    /// `(source, quantity)` is limited to one sentence per second on
    /// the NMEA 0183 outputs (matching canboat C `n2kd`), so a bus
    /// with several devices reporting the same measurement doesn't
    /// flood downstream 0183 consumers. AIS (`!AI…`) is never rate-
    /// limited. Pass this to emit every converted sentence unthrottled
    /// (e.g. for byte-for-byte parity captures).
    #[arg(long = "no-nmea0183-rate-limit")]
    no_nmea0183_rate_limit: bool,

    /// Enable the per-device NMEA 0183 filter, reading mute rules from
    /// this JSON file (a missing file starts with no mutes). When set,
    /// the 0183 outputs only carry sentences from devices whose NAME
    /// (PGN 60928) the pipeline has learned and that aren't muted — so
    /// several devices reporting one measurement no longer each reach
    /// downstream 0183 consumers. Off when unset: every converted
    /// sentence is emitted, as before. The N2K bus is never affected.
    #[arg(long = "nmea0183-filter", value_name = "PATH")]
    nmea0183_filter: Option<std::path::PathBuf>,

    /// Emit field keys + PGN descriptions as camelCase
    /// identifiers (`"uniqueNumber"` instead of `"Unique Number"`)
    /// on the analyzer JSON / snapshot TCP ports. Matches canboat
    /// C's `-camel`.
    #[arg(long, conflicts_with = "upper_camel")]
    camel: bool,

    /// Same as `--camel` but UpperCamelCase (`"UniqueNumber"`).
    /// Matches canboat C's `-upper-camel`.
    #[arg(long = "upper-camel")]
    upper_camel: bool,

    /// Verbose logging.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Quiet — only errors.
    #[arg(short = 'q', long)]
    quiet: bool,
}

pub fn run(cli: Args) -> Result<()> {
    // Refuse --quirk without --socketcan up front: every other device
    // backend rewrites the source address on outbound, which makes the
    // quirk's impersonation a no-op on the wire.
    if cli.quirk.is_some() && cli.socketcan.is_none() {
        anyhow::bail!(
            "--quirk only works with --socketcan; other device backends \
             rewrite src on outbound writes so an impersonated frame \
             cannot reach the bus with the original source address"
        );
    }

    let level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
    canboat_cli::log_startup(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // The schema is compiled into the binary; no JSON loading, no
    // path discovery, no synthetic-PGN merge — `canboat-core/build.rs`
    // already folded `data/synthetic-pgns.json` into the static
    // tables.
    let db = PgnDatabase::embedded();

    let camel_case = if cli.upper_camel {
        CamelCase::Upper
    } else if cli.camel {
        CamelCase::Lower
    } else {
        CamelCase::Off
    };
    // JsonOptions mirror the pipeline's per-record serializer settings
    // so per-iteration snapshot lines (PGN 130824 etc.) come out
    // byte-identical to the regular `analyzer` port stream.
    let json_opts = JsonOptions {
        include_empty: false,
        name_value: true,
        debug: false,
        camel_case,
    };

    let snapshot = if cli.snapshot_port != 0 {
        Some(Arc::new(SnapshotStore::new(json_opts.clone())))
    } else {
        None
    };
    let engine = Arc::new(RequestEngine::new());

    // Pick the frame source and (if a device) its writer handle. In
    // device mode the source is a Supervisor that survives serial /
    // TCP disconnects with exponential backoff.
    //
    // `pre_coalesced` is true when each `RawFrame` from this source
    // is already a complete PGN payload (iKonvert / Maretron). In
    // that case the pipeline skips the fast-packet reassembler —
    // those gateways have already done the coalescing on the wire.
    let OpenedSource {
        frames_rx,
        supervisor,
        pre_coalesced,
        claim_addr: device_claim_addr,
    } = open_source(&cli)?;
    let device_sender = supervisor.as_ref().map(|s| s.frame_sender());

    // Quirks (e.g. SCX-20 PGN 126996 fabrication) need to write the
    // synthetic onto the wire — they grab their own clone of the
    // device sender and live inside `Hubs`.
    let quirks_kinds = cli.quirk.into_iter().collect();
    let hubs = Hubs {
        raw: Arc::new(Hub::new()),
        nmea: Arc::new(Hub::new()),
        analyzer: Arc::new(Hub::new()),
        bin: Arc::new(BinHub::new()),
        snapshot: snapshot.clone(),
        engine: Arc::clone(&engine),
        quirks: quirks::Quirks::new(quirks_kinds),
        device_sender: device_sender.clone(),
    };

    // In device mode treat stdin like `actisense-serial -p`: parse
    // PLAIN/FAST lines, write the resulting frames to the device,
    // AND loop them back into the pipeline source so they show up in
    // NMEA 0183 / TCP outputs alongside device-originated frames.
    // TCP read/write ports get the same loopback channel so client
    // writes behave the same way.
    let (frames_rx, inject) = match device_sender.clone() {
        Some(sender) => {
            let (rx, loopback) = install_stdin_loopback(frames_rx, sender, pre_coalesced.clone());
            let inject = tcp::InjectPoint {
                device: device_sender.clone().expect("device_sender Some"),
                loopback,
                claim_addr: device_claim_addr.clone(),
            };
            (rx, Some(inject))
        }
        None => (frames_rx, None),
    };

    // Mirror canboat C `n2kd`'s periodic ISO claim / product-info
    // auto-request. Only meaningful when there's a device writer to
    // put the requests on the bus; in stdin-only mode there is no
    // sink, so we skip the engine entirely. `--no-request-claims`
    // disables it explicitly (matches n2kd's flag).
    if !cli.no_request_claims
        && let Some(sender) = device_sender.clone()
    {
        request_engine::spawn(Arc::clone(&engine), move |dst, pgn| {
            let _ = sender.send_frame(request_engine::iso_request_frame(0, dst, pgn));
        });
    }

    let mut tcp_joins: Vec<thread::JoinHandle<()>> = Vec::new();
    if let Some(store) = snapshot.as_ref() {
        tcp_joins.push(tcp::spawn_snapshot(
            cli.bind,
            cli.snapshot_port,
            store.clone(),
        )?);
    }
    // Write-only input port (canboat C `n2kd` `port+3`
    // `SERVER_INPUT_STREAM`): clients write PLAIN/FAST lines that we
    // encode and forward onto the bus. Unlike canboat C n2kd's passive
    // input, injection actually reaches the device; unlike the old
    // bidirectional raw port, nothing is streamed back, so it adds no
    // serialization cost — the cheap write path.
    if cli.input_port != 0 {
        tcp_joins.push(tcp::spawn_input_server(
            "input",
            cli.bind,
            cli.input_port,
            inject.clone(),
        )?);
    }
    // Raw output stream: every coalesced frame as a PLAIN line under a
    // `# format=FAST` header so downstream tools (canboat C analyzer,
    // canboatjs) know the stream is pre-coalesced. Read-only — writes
    // go to `--input-port`.
    if cli.raw_port != 0 {
        tcp_joins.push(tcp::spawn_stream_server(
            "raw",
            cli.bind,
            cli.raw_port,
            hubs.raw.clone(),
            Some(tcp::CANBOAT_FORMAT_FAST_HEADER),
        )?);
    }
    if cli.nmea0183_port != 0 {
        // NMEA 0183 is strictly read-only — clients trying to write
        // get an immediate FIN on the read direction.
        tcp_joins.push(tcp::spawn_stream_server(
            "nmea0183",
            cli.bind,
            cli.nmea0183_port,
            hubs.nmea.clone(),
            None,
        )?);
    }
    if cli.analyzer_port != 0 {
        // Analyzer-JSON stream is read-only, matching canboat C
        // n2kd's `port+1` stream port. Injection lives on the
        // input port instead. (Kept free for a future "analyzed
        // write" feature that would accept JSON here.)
        tcp_joins.push(tcp::spawn_stream_server(
            "analyzer",
            cli.bind,
            cli.analyzer_port,
            hubs.analyzer.clone(),
            None,
        )?);
    }
    if cli.ais_port != 0 {
        if let Some(store) = snapshot.as_ref() {
            tcp_joins.push(tcp::spawn_ais_snapshot(
                cli.bind,
                cli.ais_port,
                store.clone(),
            )?);
        } else {
            log::warn!(
                "--ais-port {} ignored: snapshot port is disabled, no AIS cache to dump",
                cli.ais_port,
            );
        }
    }
    if cli.analyzer_binary_port != 0 {
        // Read-only binary analyzer stream. Shares the decode with the
        // JSON/NMEA outputs; only the (lazy) WirePgn encode is extra.
        tcp_joins.push(tcp::spawn_binary_stream(
            cli.bind,
            cli.analyzer_binary_port,
            hubs.bin.clone(),
        )?);
    }

    let _ = inject; // No further use in this function

    let nmea_filter = match cli.nmea0183_filter.as_deref() {
        Some(path) => {
            let f = nmea_filter::NmeaFilter::load(path)?;
            log::info!(
                "NMEA 0183 per-device filter enabled from {}",
                path.display()
            );
            Some(f)
        }
        None => None,
    };

    pipeline::run(
        db,
        frames_rx,
        hubs,
        pre_coalesced,
        json_opts,
        pipeline::Nmea0183Options {
            emit_stdout: cli.nmea0183_stdout,
            rate_limit: !cli.no_nmea0183_rate_limit,
            filter: nmea_filter,
        },
    );

    // After the pipeline drains, signal the supervisor to stop
    // reconnecting. The TCP accept threads run forever — leak them;
    // process exit will reap them.
    if let Some(s) = supervisor {
        s.shutdown();
    }
    Ok(())
}

/// Open whichever input source the CLI selected. Returns
/// `(frames_rx, optional_supervisor, pre_coalesced)`.
///
/// * `pre_coalesced` is `true` when each `RawFrame` produced by the
///   source is already a complete PGN payload — the iKonvert and the
///   Maretron IPG do their own fast-packet coalescing on the wire,
///   so the pipeline must skip the reassembler for them. Sending
///   small coalesced payloads through the reassembler causes their
///   leading bytes to be misread as fast-packet headers.
/// * `supervisor` is `None` only in stdin mode; the caller skips
///   wiring the write-only TCP port and the supervisor shutdown.
///
/// In device mode the supervisor's manager thread handles reconnect
/// on disconnect/EOF with exponential backoff up to 30 s, so a flaky
/// serial port or TCP gateway doesn't take the pipeline down.
/// What `open_source` hands back to `run`. Separate struct (rather
/// than a return tuple) because the field count grew past what
/// clippy's `type_complexity` lint will tolerate.
struct OpenedSource {
    frames_rx: mpsc::Receiver<RawFrame>,
    supervisor: Option<Supervisor>,
    pre_coalesced: Arc<AtomicBool>,
    /// Live claim address of the device backend, when known (today
    /// only `--socketcan` exposes one). Read by the CSV-port
    /// injector to rewrite client-supplied default-`src` frames.
    claim_addr: Option<Arc<std::sync::atomic::AtomicU8>>,
}

fn open_source(cli: &Args) -> Result<OpenedSource> {
    if let Some(path) = cli.actisense.as_deref() {
        let baud = cli.baud.unwrap_or(115_200);
        let path = path.to_string();
        let factory = NamedFactory::new("ngt1", move || {
            let (reader, writer) = open_serial_rw(&path, baud)?;
            Ok(device::ngt1::run(reader, writer))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // NGT-1's `N2K_MSG_RECEIVED` (0x93) frames carry full PGN
        // payloads — fast-packet coalescing happens inside the
        // device, not on the wire we receive. Skip the reassembler.
        return Ok(OpenedSource {
            frames_rx: rx,
            supervisor: Some(sup),
            pre_coalesced: Arc::new(AtomicBool::new(true)),
            claim_addr: None,
        });
    }
    if let Some(path) = cli.ikonvert.as_deref() {
        let baud = cli.baud.unwrap_or(230_400);
        let path = path.to_string();
        let rx_list = cli.ikonvert_rx.clone();
        let tx_list = cli.ikonvert_tx.clone();
        let rate_limit_off = cli.ikonvert_rate_limit_off;
        let factory = NamedFactory::new("ikonvert", move || {
            let (reader, writer) = open_serial_rw(&path, baud)?;
            let config = device::ikonvert::Config {
                rx_list: rx_list.clone(),
                tx_list: tx_list.clone(),
                rate_limit_off,
                ..Default::default()
            };
            Ok(device::ikonvert::run(reader, writer, config))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // iKonvert coalesces fast-packets internally; skip the
        // reassembler entirely.
        return Ok(OpenedSource {
            frames_rx: rx,
            supervisor: Some(sup),
            pre_coalesced: Arc::new(AtomicBool::new(true)),
            claim_addr: None,
        });
    }
    if let Some(url) = cli.maretron.as_deref() {
        let url = url.to_string();
        let password = cli.maretron_password.clone();
        let factory = NamedFactory::new("maretron", move || {
            let (reader, writer) = open_maretron_pair(&url)?;
            let cfg = device::maretron::Config {
                password: password.clone(),
                fixtime: None,
            };
            Ok(device::maretron::run(reader, writer, cfg))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // Maretron IPG ships full PGN payloads per 0xA5 frame.
        return Ok(OpenedSource {
            frames_rx: rx,
            supervisor: Some(sup),
            pre_coalesced: Arc::new(AtomicBool::new(true)),
            claim_addr: None,
        });
    }
    if let Some(read_url) = cli.canboat_csv.as_deref() {
        let read_url = read_url.to_string();
        let write_url = cli.canboat_csv_write.clone();
        let factory = NamedFactory::new("canboat-csv", move || {
            let (reader, writer) = match &write_url {
                Some(w) => open_canboat_csv_split(&read_url, w)?,
                None => open_canboat_csv_pair(&read_url)?,
            };
            Ok(device::canboat_csv::run(reader, writer))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // Wire format is canboat PLAIN/FAST — each line is already
        // a complete PGN payload, so skip the reassembler.
        return Ok(OpenedSource {
            frames_rx: rx,
            supervisor: Some(sup),
            pre_coalesced: Arc::new(AtomicBool::new(true)),
            claim_addr: None,
        });
    }
    if let Some(iface) = cli.socketcan.as_deref() {
        let iface = iface.to_string();
        let config = device::socketcan::Config {
            address: cli.socketcan_address,
            model_version: Some("canboat-pipeline-rs"),
            ..device::socketcan::Config::default()
        };
        // Shared across factory reconnects so the live claim address
        // survives supervisor-driven device-session restarts.
        let claim_addr = Arc::new(std::sync::atomic::AtomicU8::new(
            device::socketcan::CLAIM_UNCLAIMED,
        ));
        let claim_for_factory = Arc::clone(&claim_addr);
        let factory = NamedFactory::new("socketcan", move || {
            device::socketcan::run(&iface, config.clone(), Arc::clone(&claim_for_factory))
        });
        let sup = Supervisor::new(factory);
        let (rx, sup) = split_supervisor(sup);
        // The SocketCAN adapter reassembles internally (driven by the
        // `canboat-io::fastpacket` table) and hands us coalesced
        // `RawFrame`s, matching the NGT-1 / iKonvert contract — skip
        // the pipeline's own reassembler.
        return Ok(OpenedSource {
            frames_rx: rx,
            supervisor: Some(sup),
            pre_coalesced: Arc::new(AtomicBool::new(true)),
            claim_addr: Some(claim_addr),
        });
    }
    // stdin fallback — no device, no reconnect logic needed. We
    // can't know in advance whether the upstream uses PLAIN
    // (per-CAN-frame, needs reassembly) or FAST (already coalesced).
    // The stdin pump watches for `# format=<NAME>` headers and flips
    // the flag when it sees one declaring a coalesced format; the
    // pipeline itself also flips it on the first >8-byte payload.
    let pre_coalesced = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<RawFrame>();
    let coalesced_for_pump = pre_coalesced.clone();
    thread::Builder::new()
        .name("stdin-pump".into())
        .spawn(move || stdin_pump(tx, coalesced_for_pump, None))
        .expect("spawn stdin-pump");
    Ok(OpenedSource {
        frames_rx: rx,
        supervisor: None,
        pre_coalesced,
        claim_addr: None,
    })
}

/// Swap the `Supervisor::frames_rx` out so the pipeline can own it
/// while we keep the supervisor for shutdown / frame_sender access.
fn split_supervisor(mut sup: Supervisor) -> (mpsc::Receiver<RawFrame>, Supervisor) {
    let (_dummy_tx, dummy_rx) = mpsc::channel::<RawFrame>();
    let rx = std::mem::replace(&mut sup.frames_rx, dummy_rx);
    (rx, sup)
}

/// A [`device::DeviceFactory`] that carries a static name and a
/// closure. We can't `impl DeviceFactory for FnMut()` directly because
/// the blanket name() default returns `"device"`; this wrapper plumbs
/// the device-kind label through to the supervisor's log lines.
struct NamedFactory<F> {
    name: &'static str,
    open: F,
}

impl<F> NamedFactory<F>
where
    F: FnMut() -> io::Result<device::DeviceHandle> + Send + 'static,
{
    fn new(name: &'static str, open: F) -> Self {
        Self { name, open }
    }
}

impl<F> device::DeviceFactory for NamedFactory<F>
where
    F: FnMut() -> io::Result<device::DeviceHandle> + Send + 'static,
{
    fn open(&mut self) -> io::Result<device::DeviceHandle> {
        (self.open)()
    }
    fn name(&self) -> &str {
        self.name
    }
}

fn open_maretron_pair(url: &str) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    open_tcp_pair(url, 6543, "maretron")
}

fn open_canboat_csv_pair(url: &str) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    open_tcp_pair(url, 2603, "canboat-csv")
}

/// Split-mode: read frames from `read_url`, send frames out to
/// `write_url`. Two independent TCP connections; the unused
/// directions of each are dropped (their kernel-side socket
/// references remain alive via the other half, but we never
/// touch them).
///
/// Use case: chaining into a pipeline whose read source is a
/// one-way feed (e.g. `iptee` mirroring the raw output of
/// `actisense-serial`) while the write sink is a separate
/// endpoint (e.g. `n2kd`'s input-stream port on `port + 3`).
fn open_canboat_csv_split(
    read_url: &str,
    write_url: &str,
) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    let (read_half, _unused_write) = open_tcp_pair(read_url, 2603, "canboat-csv read")?;
    let (_unused_read, write_half) = open_tcp_pair(write_url, 2603, "canboat-csv write")?;
    Ok((read_half, write_half))
}

/// Open a TCP socket and return cloned read/write halves. Mirrors
/// what the device codecs need: a separate `Box<dyn Read>` and
/// `Box<dyn Write>` over the same underlying connection. Tolerates
/// `tcp://` URL prefix, fills in `default_port` when the user
/// didn't include one.
fn open_tcp_pair(
    url: &str,
    default_port: u16,
    log_label: &'static str,
) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let raw = url.strip_prefix("tcp://").unwrap_or(url);
    let with_port = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:{default_port}")
    };
    let resolved = with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other(format!("no addresses for {with_port}")))?;
    log::info!("{log_label}: connecting to {resolved}");
    let stream = TcpStream::connect_timeout(&resolved, Duration::from_secs(10))?;
    let read_clone = stream.try_clone()?;
    Ok((Box::new(read_clone), Box::new(stream)))
}

/// Read PLAIN/FAST lines off stdin, parse to `RawFrame`, push onto
/// `tx`. Auto-detects between PLAIN and FAST on the first non-empty
/// line. When `device_sender` is `Some`, each parsed frame is also
/// forwarded to the device — mirroring `actisense-serial -p`'s
/// "send to device AND echo to stdout" behaviour, where the echo
/// half is implemented here as a loopback into the pipeline source.
fn stdin_pump(
    tx: mpsc::Sender<RawFrame>,
    pre_coalesced: Arc<AtomicBool>,
    device_sender: Option<FrameSender>,
) {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::with_capacity(1024);
    let mut active_format: Option<InputFormat> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                log::error!("stdin read: {e}");
                return;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            // `# format=<NAME>` headers — emitted by the canboat C
            // reader binaries — pin both the parser format and (for
            // any coalesced format) the pipeline's reassembly bypass.
            if let Some(fmt) = parse_format_header(trimmed) {
                if active_format.is_none() {
                    active_format = Some(fmt);
                    log::info!("input format set by header: {:?}", fmt);
                }
                if header_implies_coalesced(trimmed) && !pre_coalesced.swap(true, Ordering::Relaxed)
                {
                    log::debug!(
                        "stdin header declares coalesced format; \
                         pipeline will skip reassembly"
                    );
                }
            }
            continue;
        }
        if active_format.is_none() {
            active_format = detect(trimmed).or(Some(InputFormat::Plain));
        }
        let Ok(Some(frame)) = parse_with(active_format.unwrap(), trimmed) else {
            continue;
        };
        if let Some(sender) = &device_sender {
            // Drop on the floor if the device is currently
            // disconnected; the supervisor will reconnect, but stdin
            // injection is best-effort.
            let _ = sender.send_frame(frame.clone());
        }
        if tx.send(frame).is_err() {
            return;
        }
    }
}

/// Spawn a forwarder thread that pulls from `device_frames_rx` into a
/// fresh merge channel, plus a stdin pump that parses PLAIN/FAST
/// lines from stdin and pushes them onto the same merge channel
/// *and* writes them to the device via `sender`. Returns
/// `(merge_rx, loopback_tx)` — the receiver becomes the pipeline's
/// source and the sender is handed to TCP servers so client writes
/// can join the same loopback.
fn install_stdin_loopback(
    device_frames_rx: mpsc::Receiver<RawFrame>,
    sender: FrameSender,
    pre_coalesced: Arc<AtomicBool>,
) -> (mpsc::Receiver<RawFrame>, mpsc::Sender<RawFrame>) {
    let (merge_tx, merge_rx) = mpsc::channel::<RawFrame>();
    let merge_tx_device = merge_tx.clone();
    let merge_tx_stdin = merge_tx.clone();
    thread::Builder::new()
        .name("device-forward".into())
        .spawn(move || {
            while let Ok(f) = device_frames_rx.recv() {
                if merge_tx_device.send(f).is_err() {
                    return;
                }
            }
        })
        .expect("spawn device-forward");
    thread::Builder::new()
        .name("stdin-pump".into())
        .spawn(move || stdin_pump(merge_tx_stdin, pre_coalesced, Some(sender)))
        .expect("spawn stdin-pump");
    (merge_rx, merge_tx)
}

// Suppress an unused-import warning when no device flag is built (we
// rely on `bail!` for the future "no source AND not interactive"
// branch — keeping the import wired up here documents the intent).
#[allow(dead_code)]
fn _no_source() -> Result<()> {
    bail!("no input source");
}
