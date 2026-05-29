# canboat-rs

A Rust implementation of (most of) the [canboat](https://github.com/canboat/canboat)
NMEA 2000 tooling. Sister project to canboat — same PGN database, same wire
formats, but built as a sans-I/O library with thin sync and async adapters
above it.

## Architecture

- **`canboat-core`** — sans-I/O library. PGN database, format parsers,
  reassembly, decoder, encoder, output formatters. No `std::io`, no
  `tokio`, no threads.
- **`canboat-io`** — sync `std::io` adapters (stdin, `serialport`,
  `std::net`). Used by the standalone binaries.
- **`canboat-tokio`** — async tokio adapters. Used to embed the canboat
  decode pipeline in a tokio application (e.g. merrimac-rs).
- **`canboat-cli`** — shared CLI plumbing for the standalone binaries.
- **Binaries** — each links `canboat-core` + `canboat-io` +
  `canboat-cli`. Sync, small.

## Binary status

The following binaries are working against real hardware / real
captures and pass the byte-for-byte golden-test suite where one
exists:

| Binary             | What it does                                                                  | Hardware-tested      |
|--------------------|-------------------------------------------------------------------------------|----------------------|
| `analyzer`         | Decode PLAIN/FAST (and other formats) into canboat text or JSON. Drop-in for canboat C's analyzer; `--si`, `--camel` / `--upper-camel`, `-empty`, `-nv`, `-debug`, `-geo` flags. | yes (replay)         |
| `ikonvert-serial`  | Digital Yacht iKonvert ↔ canboat PLAIN/FAST. ACK-driven init handshake, mid-stream device-reset recovery. | yes (live device)    |
| `n2kd`             | Analyzer-JSON → NMEA 0183 / AIVDM multiplexer, drop-in for canboat C `n2kd`.   | yes (replay)         |
| `canboat-pipeline` | Single-process device-reader → analyzer → n2kd. Snapshot / NMEA 0183 / analyzer-JSON / CSV-R/W / write-only TCP servers, supervisor-based device reconnect, lazy formatting. | yes (live iKonvert)  |

Other binaries (`actisense-serial`, `maretron-ipg`, `replay`,
`candump2analyzer`, `pcap2candump`, `socketcan-writer`) build and
have unit tests but haven't been exercised end-to-end against
hardware in this repo yet.

See [PGN data](data/VERSION) for the upstream canboat release this repo
tracks.

## Performance

Wall-clock numbers on an M1 Pro, release build, running over the
`n2kd_raw_50x` corpus — 1.26 M PGN frames synthesised by replaying
canboat's `dirona-actisense-serial.raw` sample 50× through the
analyzer to give a sustained input. Each step also produces 1.26 M
NMEA 0183 sentences as output:

| Pipeline                                | Wall time | Throughput            |
|-----------------------------------------|----------:|-----------------------|
| `analyzer` alone (PGN decode only)      |  3.32 s   | 380 k frames / s      |
| `analyzer \| n2kd` (piped, two procs)   |  6.50 s   | 194 k sentences / s   |
| `canboat-pipeline` (single proc)        |  3.50 s   | 360 k sentences / s   |

`canboat-pipeline` is **46 % faster wall-time** than the equivalent
piped `analyzer | n2kd` setup, while doing strictly more work
(it's a long-running service with TCP fan-out). On CPU time the
ratio is closer to **3.4 ×** (3.42 s user vs. 10.7 s combined for
the piped pipeline). The savings come from a few design choices:

- **Structs between stages.** `RawFrame` and `DecodedPgn` move
  across mpsc channels between the device reader, the analyzer,
  and the NMEA 0183 converter. No JSON text round-trip for any
  PGN the struct path covers (currently all non-fallback PGNs +
  all 11 AIS encoders). The fallback JSON path is the only
  remaining string serialisation in the hot loop.
- **Lazy formatting on every output port.** Each TCP server hub
  checks `has_subscribers()` (one relaxed atomic load) before
  spending cycles to format. With no clients connected, the only
  active per-frame cost on the analyzer-JSON, NMEA-0183, and CSV
  ports is that atomic. Numbers above are with all ports idle.
- **O(1) field lookups.** `DecodedPgn::field(handle)` is one
  array-indexed load through a pre-resolved `FieldHandle` — no
  field-name string compares in the hot path.
- **TCP_NODELAY on every accepted client socket** so per-sentence
  writes don't sit in Nagle's 40 ms coalescing window.
- **`LineWriter` on stdout** (when `--nmea0183-stdout` is on) so
  each sentence flushes on its newline rather than batching into
  64 KB chunks.

Enabling the canboat-C-compatible snapshot port (`--snapshot-port
N`, default 2597) forces JSON to be serialised for every decoded
record so the cache stays warm, costing about **50 %** more wall
time (3.50 s → 4.50 s on the same corpus). Disable with
`--snapshot-port 0` to get back to the lazy hot path.

End-to-end on real iKonvert hardware (Pi 4, ~50 frames / s of
real bus traffic) the binary holds steady at <2 % CPU.

## License

Apache-2.0. See [LICENSE](LICENSE).
