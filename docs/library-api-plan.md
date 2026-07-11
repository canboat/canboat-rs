# canboat as a library: API surface & implementation plan

Status: **plan / not started.** Branch `feat/library-facade`, fresh from `main`
(PR #34 and the rest merged). This is the work we complete **before** canboat-rs
merges into canboat (v8 / the keel line — see the companion
`keel/MERGE-CANBOAT-RS.md` in that repo).

## 0. Goal & governing principles

Turn the workspace into **one library with a deliberately tiny public API**, so an
external party adds *one* crate with *one* feature flag and thinks only in terms of
`Frame` ⇆ `DecodedPgn`. `merrimac-rs` is rebuilt on top of it — **including
re-serving all the existing TCP ports** — as the proof it works.

Principles (in priority order):

1. **Smallest surface wins.** Every `pub` is a liability. Default to private. The
   current `canboat-core` exposes 15 wide-open `pub mod`s (`analyzer_json`, `bits`,
   `db`, `decode`, `encode`, `format`, `frame`, `from_json`, `os`, `output`,
   `reassembly`, `snapshot`, `startup`, `types`, `units`) — treat *all* of that as
   internal until proven otherwise. Nothing is public because it happens to be public
   today.
2. **Rename freely.** No compatibility obligation to the current names. Pick the names
   the *external* reader wants — `RawFrame`→`Frame`, `PgnDatabase`→`Database`,
   `FieldRef`→`FieldId` (and `FieldHandle` goes private); `DecodedPgn` stays. We control
   every consumer, so incidental helper types get renamed or hidden at will.
3. **One entry crate.** External parties depend on **`canboat`** only. The sub-crates
   (`canboat-core`, `-io`, `-wire`, `-bridge`) become implementation detail — their
   incidental `pub`s are demoted to `pub(crate)` or `#[doc(hidden)]`. Depending on a
   sub-crate directly is unsupported.
4. **The facade *is* the contract.** Its public API is locked by a `cargo public-api`
   snapshot test and `#![deny(missing_docs)]`. A PR that widens the surface must change
   the snapshot on purpose.
5. **Features gate weight, not correctness.** `decode` (default) is thread-free,
   async-free, I/O-free. You only pay for threads/sockets when you ask for `io` or
   `bridge`.

## 1. Crate topology

Keep the focused workspace crates (the sans-I/O core is worth keeping separate for
compile time and discipline), but front them with a single facade:

```
canboat            ← the ONLY crate an external party names. Facade + curated re-exports.
  │                  (also hosts the CLI bin target; lib and bin share the workspace)
  ├─ canboat-core    sans-I/O: schema, decode, encode, reassembly, formatters   [feature: decode]
  ├─ canboat-io      byte sources: serial, container, text/ngt1/ikonvert readers [feature: io]
  ├─ canboat-wire    postcard WirePgn + Hello handshake                          [feature: wire]
  └─ canboat-bridge  live bus: source→decode→quirks→transmit + optional serving  [feature: bridge]
                       (absorbs today's crates/canboat/src/{server,n2kd})
```

`canboat-tokio` and `canboat-cli` fold in or stay bin-only; they are **not** part of
the public library surface.

## 2. The complete public API surface (grand strokes)

This is the entire intended `pub` surface of `canboat`. If it isn't here, it's private.
Organized by feature; each maps to a persona from the design discussion.

**Names locked 2026-07-11:** `Frame` (was `RawFrame`), `Database` (was `PgnDatabase`),
`FieldId` (was `FieldRef`; `FieldHandle` now private), transport seam `read::FrameSource`
with `*Reader` impls, network-management module `device::{Name, Claimer, Responder}`
(feature flag still `node`), bridge input enum `Input` (named off the `FrameSource` trait),
analyzer-JSON entry `read::from_analyzer_json` (was free fn `json_to_decoded`).

```
canboat
│  #![deny(missing_docs)]   public API locked by a cargo-public-api snapshot test
│
├── prelude                 // one glob import covers the 90% path
│     Database, Units, Frame,
│     DecodedPgn, DecodedField, FieldValue, FieldId, DecodeError
│
├── ─────────── feature `decode` (default): sans-I/O core ───────────
│
│   // schema & database
│   Database               // was PgnDatabase. ::embedded(Units) -> &'static; .decode(&Frame),
│                          //   .message(pgn), .field(pgn,field)->FieldId, .lookup(..)
│   Units { Si, Metric }
│   FieldId                // was FieldRef. THE single field-addressing type: carries the
│                          //   &'static schema refs, so it drives decode-access, encode,
│                          //   AND introspection. FieldHandle is now private. O(1) decode
│                          //   access with the id-hash baked into PgnInfo at build time.
│   SCHEMA_HASH, CANBOAT_VERSION, SCHEMA_VERSION
│
│   schema::               // introspection (persona: schema-as-data / codegen)
│     PgnInfo, FieldInfo, FieldType, PacketType,
│     LookupTable, BitLookupTable, IndirectLookupTable   // only the read-facing shape
│   ids::{ pgn, field }    // generated compile-time FieldId/PgnInfo constants: ids::pgn::WIND_DATA, …
│
│   // frames — the wire-side pivot
│   Frame                  // was RawFrame. + consts ADDR_GLOBAL, ADDR_NULL, FRAME_MAX_SIZE, FASTPACKET_MAX_SIZE
│   Reassembler, Reassembled   // fast-packet; ReassemblyError, FramePacketType
│
│   // decode (inbound) — persona #1/#2, the DecodedPgn seam
│   DecodedPgn             // .field(FieldId) [O(1)], .field_by_name,
│                          //   .pgn/.src/.dst/.prio/.timestamp/.id/.description
│   DecodedField           // .value, .name(), .as_f64_in(Units)
│   FieldValue { Number, Integer, Float, String, Lookup, BitField, Mmsi, … }
│   DecodeError
│
│   // encode (outbound) — persona #4
│   MessageBuilder         // db.message(pgn).set(FieldId, EncodeValue).build() -> Frame
│   EncodeValue, EncodeError
│
│   // formatters — persona #3 (DecodedPgn -> bytes/text)
│   output::
│     write_json, JsonOptions, CamelCase
│     write_text
│     write_nmea0183        [sub-feature `nmea0183`]
│     write_ais / Aivdm     [sub-feature `ais`]
│
├── ─────────── `read` trait + json under `decode`; the `*Reader` impls under `io` ───────────
│
│   read::
│     trait FrameSource     // the ONE abstraction: -> Option<Frame>. BYO-transport
│                           //   consumers implement this over their own CAN driver.
│     Decoder               // FrameSource + Reassembler + &Database -> Iterator<DecodedPgn>
│     PlainReader           // canboat "PLAIN"/"FAST" text
│     Ngt1Reader            // Actisense NGT-1 / W2K-1
│     IkonvertReader
│     MaretronReader
│     ContainerReader       // .pcap / .pcap.gz / .nif
│     from_analyzer_json    // analyzer-JSON text -> DecodedPgn (was the free fn json_to_decoded)
│   // low-level byte helpers stay private unless a consumer proves a need.
│
├── ─────────── feature `wire`: cross-process transport ───────────
│
│   wire::
│     Hello, WirePgn, PgnIndex, pgn_id_hash,
│     append_frame, try_read_frame, decode_frame, MAX_FRAME_LEN
│
├── ─────────── feature `node`: be a compliant N2K device (no transport) ───────────
│
│   device::                // (module `device`; feature flag stays `node`)
│     Name                  // 64-bit NMEA NAME builder (mfr, function, instance, …)
│     Claimer               // NAME-arbitration address-claim state machine, Frame in/out
│     Responder             // answers ISO request (59904), product (126996), config (126998)
│                           //   caller owns the bus; feeds Frame in, gets Frame out
│
└── ─────────── feature `bridge`: the live bus, fully assembled ───────────
│
    bridge::
      Bridge                // the handle an embedder holds
      BridgeBuilder         // Bridge::builder()
      BridgeConfig          // plain struct (NO clap) — the config type
      Input { SocketCan(String), Custom(Box<dyn FrameSource + Send>) }  // named off `read::FrameSource`
      Quirk { Motion, Wmm, Scx20 }
      Ports, ServeConfig    // the optional half-#2 serving layer
      ServeHandle           // shutdown handle for the served ports

      // methods on Bridge:
      //   builder() -> BridgeBuilder            (.input/.quirks/.units/.config_dir/.build)
      //   decoded() -> Receiver<DecodedPgn>     in-process stream (persona #1)
      //   raw()     -> Receiver<Frame>          (optional, for BYO-decode)
      //   transmit(Frame)                       inject with the claimed src
      //   message(pgn) -> MessageBuilder        convenience for transmit
      //   serve(Ports) -> io::Result<ServeHandle>   spawn 2597..2606 for other consumers
      //   shutdown()                            stop reader + listeners cleanly
```

That's it. Everything else — `bits`, `os`, `startup`, `analyzer_json`, the raw
`format::*` parsers, the internal `db` helpers, `FieldHandle`, `FieldOverrides`, the
socketcan plumbing, the address-claim internals — is **private**.

### Notes on deliberate exclusions

- **Field addressing is ONE type (`FieldId`).** `FieldHandle` is demoted to a private
  impl detail. The current per-access `djb2_hash_str(pgn.id)` in `field_ref` is removed by
  baking the id-hash into `PgnInfo` at build time, so `DecodedPgn::field(FieldId)` is a pure
  O(1) array index in release — equal-or-faster than today, never slower.
- **`snapshot`** (current-value cache) is *not* top-level. It rides inside `bridge` (a
  `Bridge::snapshot()` accessor) and stays out of the sans-I/O core surface until a
  consumer needs it standalone. Smaller is better.
- **`Frame` fields**: expose the constructor (`Frame::new`) and accessors; keep the
  `SmallVec` data representation private (return `&[u8]`), so the internal storage type
  isn't part of the contract.
- **Lookup/`schema` types** expose only what an introspecting consumer reads; the
  build-time emission shape stays hidden.
- **No `os`, no `startup`** in public — those are binary concerns.

## 3. Enforcing "this is the only pub"

1. `#![deny(missing_docs)]` on `canboat` — forces intent on every public item.
2. A `cargo public-api` snapshot test (checked-in `public-api.txt`) in CI; a diff fails
   the build. This is the mechanical guarantee the surface can't creep.
3. Sub-crates: run `cargo public-api` on each and drive their surface toward "only what
   the facade re-exports." Everything else → `pub(crate)` / `#[doc(hidden)]`.
4. Grep gate: no workspace-external `Cargo.toml` may name a `canboat-*` sub-crate. The
   facade is the only supported dependency.

## 4. Implementation phases (each independently shippable)

**Phase 0 — Facade skeleton.** Add the `canboat` library target + feature flags
(`decode` default, `io`, `wire`, `node`, `bridge`, `nmea0183`, `ais`). Empty re-export
modules. Wire up the `cargo public-api` snapshot test. No behaviour change.

**Phase 1 — Curate the core (`decode`).** The big *subtractive* pass. Re-export the
curated set from the facade under the names in §2; introspection under `schema::`, id
constants under `ids::`, the prelude landed. Collapse `FieldHandle` into `FieldId` (one
public field-addressing type) and drop the per-access `djb2` hashing — decode access is
now a pure `O(1)` array index by schema order with a debug-only `&str` PGN check. Verify:
facade compiles on `decode` alone (no threads/socket deps) and `cargo public-api` matches
§2's core block.

> **Status (done):** `FieldHandle`/`djb2` removed; `DecodedPgn::field(FieldId)` is the sole
> accessor; `PgnDatabase::field()` returns `FieldId`; the n2kd struct-path (`decoded.rs`)
> retyped to hold the generated constants directly. Snapshots blessed for all three
> library feature-sets. All tests green except one **pre-existing** golden failure
> (`mixed_format_text_debug`, fails identically on `main` — stale 130824-rate fixture,
> unrelated).
>
> **Deferred to Phase 5:** demoting `canboat-core`'s 15 wide-open `pub mod`s to
> `pub(crate)`. They can't shrink while the bin modules (`server`/`n2kd`/`tui`) and the
> sibling crates import `canboat_core::{decode,encode,output,reassembly,frame,…}`
> directly. That lockdown happens when those modules move into `canboat-bridge`. Until
> then the *facade's* surface is the enforced contract (§3), and it is already minimal.

**Phase 2 — `read` + BYO-transport.** Define `trait FrameSource` and the `Decoder`
convenience. Document "bring your own CAN driver → implement `FrameSource`" as a
first-class path. Expose the ready-made readers under `io`.

> **Status (done):** `FrameSource` + `Decoder` live in **canboat-core** (under `decode`,
> not `io`), so a BYO-transport consumer implements the trait and drives the decoder with
> zero I/O deps — the one `std::io` touchpoint in core, documented as such. canboat-io's
> old `FrameReader` trait is now a re-export alias of `canboat_core::FrameSource` (its
> `mpsc::Receiver<RawFrame>` impl moved to core to satisfy the orphan rule; all 13 call
> sites and the bins keep compiling). Facade `read` exposes `FrameSource`, `Decoder`,
> `from_analyzer_json` (decode) and `PlainReader` (= `LineFrameReader`), `EblReader`,
> `open_capture(path)` (io). Tests: a custom `FrameSource`, the `mpsc::Receiver` path, and
> an `open_capture` PLAIN-file round-trip (which caught a real bug — `container::plain_reader`
> only handles actual `.pcap`/`.nif`, so `open_capture` branches on `is_container`).
> Snapshots re-blessed.
>
> **Deferred:** distinct `Ngt1Reader`/`IkonvertReader`/`MaretronReader` types are *not*
> needed — live gateways flow through the device supervisor as an `mpsc::Receiver<RawFrame>`,
> which already *is* a `FrameSource`. If a consumer ever wants a standalone push-decoder
> wrapper for those, add it then. `output::write_nmea0183` / `write_ais` still pending the
> `nmea0183`/`ais` feature wiring.

**Phase 3 — `wire`.** Mostly re-export; `canboat-wire` is already clean. Rename into
`wire::` namespace; hide anything not in §2.

**Phase 4 — `node` (module `device`).** Promote the already-extracted `address_claim` +
`nmea_responder` (from the motion-quirk work) into the `device::` API: `Name`, `Claimer`,
`Responder`, all `Frame`-in/`Frame`-out, transport-agnostic. Hide the internals. (Feature
flag is `node`; the module is `device` per the naming decision.)

**Phase 5 — `bridge` (the big one).** Move `crates/canboat/src/{server,n2kd}` into
`canboat-bridge`. Untangle the binary plumbing identified in the feasibility pass:
- replace the `clap::Args` config with a plain `BridgeConfig`;
- delete the in-lib `env_logger::init()` / `log_startup` (host owns logging);
- make the config-dir injectable (explicit path or disabled) instead of the
  `/etc/default/canboat` probe;
- split the pipeline core (source→decode→quirks→transmit→`Receiver<DecodedPgn>`) from
  the serving layer (the `Hub` fan-out + TCP ports), so `serve()` is optional;
- return a `ServeHandle`/`Bridge::shutdown()` that closes listeners instead of leaking
  accept threads.
Keep the CLI `canboat server` working by having the bin build a `BridgeConfig` from clap
and call the same API. Verify: `canboat server` behaves identically (n2kd parity harness
green).

**Phase 6 — Prove it with `merrimac-rs`.** See §5.

**Phase 7 — Lock & document.** Finalize the `public-api.txt` snapshot, `deny(missing_docs)`,
the sub-crate demotions, and the CI grep gate. Cross-link the keel merge doc. Now
canboat-rs is ready to fold into canboat.

## 5. The proof: `merrimac-rs` on the facade (all ports intact)

merrimac already links `canboat-core` + `canboat-wire` and works in `DecodedPgn`, so the
port is mostly *deletion*:

1. **Swap deps** → `canboat = { features = ["bridge", "wire", "nmea0183", "ais"] }`.
   Drop the direct `canboat-core`/`canboat-wire` path deps (facade re-exports them).
2. **Replace ingestion.** `src/n2k/client.rs:1630-1831` (`receive_binary_data` /
   `handle_binary_connection`: TCP connect, `Hello` handshake, `WirePgn` decode,
   `rehydrate`) collapses to `let rx = bridge.decoded();`. The postcard codec, the
   schema-hash handshake, and the whole reconnect/alarm retry loop are deleted — no wire,
   no possible mismatch. merrimac's `Message`/interest-index/`Accumulator` layer
   downstream is source-agnostic and unchanged.
3. **Replace outbound.** `src/n2k/builder.rs` `RawN2K::build()` PLAIN-text path → 
   `bridge.message(pgn).set(..).build()` + `bridge.transmit(..)`. merrimac stops stamping
   `src = 0xFF`: as the real bridge it is address-claimed, so its transmits (and the
   MasterBus→N2K bridge in `src/masterbus/mod.rs:1170`) carry a proper source.
4. **Collapse the duplicate schema.** Delete merrimac's hand-rolled `N2kDefinitions`
   JSON loader (`src/n2k/mod.rs:30-351`) and the shipped `canboat.json` (2.3 MB); use the
   facade's embedded schema. `build.rs`'s compile-time field resolution keeps working,
   now via `canboat::ids` / `Database::field(pgn, field) -> FieldId`.
5. **merrimac becomes the CAN owner** — `Bridge::builder().source(Source::SocketCan("can0"))
   .quirks([Motion, Wmm]).build()`. It already manages a CAN interface for MasterBus
   (`ensure_can_device`, `CAP_NET_ADMIN`), so this is familiar.
6. **Re-serve every existing port** — the load-bearing part of the proof, because the Pi
   has *several* other consumers (Signal K, TUI, NMEA0183 devices) on 2597–2606. merrimac
   calls `bridge.serve(Ports::default())` so it *replaces* the standalone `canboat server`
   while those consumers keep working unchanged. One binary, one systemd unit, no localhost
   TCP hops for merrimac itself — but the ports are still there for everyone else.

**Success = merrimac runs as a single process that (a) reads N2K in-process, (b) transmits
address-claimed, and (c) still serves 2597–2606 identically** — verified against the n2kd
parity harness and the live boat. That exercises decode, encode, node (claim), bridge, and
serve — i.e. every feature except the file readers — which is exactly the coverage we want
before merging into canboat.

## 6. Risks & open questions

- **Surface creep during extraction.** The temptation in Phase 5 is to re-expose server
  internals "just in case." The `public-api.txt` gate is the discipline; if `merrimac`
  needs something not in §2, add it deliberately with a doc comment, don't leak a module.
- **`serve()` reuse vs. rebind.** The current listeners are leaked and can't rebind. The
  `ServeHandle` must genuinely close sockets so a restart (or a second `Bridge`) works —
  the one piece needing real design, not mechanical moves.
- **Two-worker tokio + a blocking CAN reader.** The bridge core is `std::thread`+`mpsc`;
  merrimac is 2-worker tokio. merrimac already bridges exactly this for MasterBus, so the
  pattern is proven — but the `bridge.decoded()` receiver must have a tokio-friendly form
  (an `mpsc` the async side can poll, or a `canboat-tokio` adapter behind the `tokio`
  feature).
- **Naming.** With rename freedom, settle the `read`/`FrameSource`, `node`, and `bridge`
  names *before* Phase 1 so the snapshot isn't churned. (Bridge/keel/helm metaphor already
  chosen for the crate.)
- **AIS/0183 as sub-features.** Confirm they compile out cleanly when a consumer wants
  bare decode — no accidental always-on dependency.
