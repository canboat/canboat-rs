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
- **Binaries** — `analyzer`, `actisense-serial`, … each links
  `canboat-core` + `canboat-io` + `canboat-cli`. Sync, small.

See [PGN data](data/VERSION) for the upstream canboat release this repo
tracks.

## License

Apache-2.0. See [LICENSE](LICENSE).
