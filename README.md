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

## License

Apache-2.0. See [LICENSE](LICENSE).
