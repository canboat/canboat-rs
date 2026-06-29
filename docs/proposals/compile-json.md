# Compile-time canboat.json codegen

Branch: `compile_json`. Status: proposal, no code yet.

## Goal

Replace runtime parsing/indexing of [`data/canboat.json`](../../data/canboat.json)
(2.3 MB, 80k lines, 579 PGNs, 4 569 fields, 251 lookup tables) with code
generated at compile time. Targets in order of payoff:

1. `canboat-pipeline` — long-running, latency-sensitive, decodes every frame on
   the bus. Primary target.
2. `analyzer` — short-lived CLI, but it shares the same decoder via
   [`canboat-core`](../../crates/canboat-core), so it comes along for free.
3. The other binaries (`candump2analyzer`, `replay`, the device readers, `n2kd`)
   don't load `PgnDatabase` today and stay unaffected.

`analyzer` is **not** a library — it's a thin `main.rs` wrapping
`canboat_core::PgnDatabase::decode()`. `canboat-pipeline` calls the same API
([`pipeline.rs`](../../crates/canboat-pipeline/src/pipeline.rs)). So if we
change `canboat-core`, both improve. There is no separate "analyzer core" to
juggle.

## Why bother

Today every binary that decodes pays ~100 ms of startup to:

- `serde_json::from_reader` over 2.3 MB ([`db.rs:267`](../../crates/canboat-core/src/db.rs))
- Build `pgn_index: HashMap<u32, Vec<usize>>` over 579 PGNs
- Build `by_value: HashMap<u64, u32>` for each of 228 lookup tables
- Build `by_bit` / `by_pair` indices for 18 bit-lookups + 1 indirect
- Apply non-SI unit fix-ups field-by-field

The schema is immutable after load. Nothing mutates it at runtime — analyzer
only *merges* the bundled synthetic-pgns once, and even that we can fold into
the generated code. So everything done at load is pure compile-time work
masquerading as runtime work.

There is already precedent: [`canboat-io/build.rs`](../../crates/canboat-io/build.rs)
parses `canboat.json` at build time to emit a 4 KB fastpacket bitmap. We're
extending the same pattern to the whole schema.

## Where it pays off most: multiplexed proprietary PGNs

You called this out and it's the strongest part of the case. The 51 multiplexed
PGNs follow a uniform shape: leading bits are a *manufacturer + industry code*
pair (typically bits 0..13), and remaining match fields are sub-protocol /
function / command discriminators.

| PGN     | Variants | Owner / shape                                    |
|---------|----------|--------------------------------------------------|
| 130820  | 50       | BEP/CZone — Manufacturer + Industry + Msg ID     |
| 126720  | 41       | Garmin — Manufacturer + sub-protocol + Msg ID    |
| 130816  | 24       | proprietary fast-packet catch-all                |
| ...     | 2–8      | ~48 others                                       |

Today decode does:

```
for variant in pgn_index[pgn] {
    for match_field in variant.fields where match_value.is_some() {
        extract_bits(...) == expected ?
    }
}
```

For PGN 130820 with 50 variants × ~2 match fields each, that's up to 100
`extract_bits` calls per frame, all on the same leading bits — re-decoding the
manufacturer ID 50 times before picking a variant.

Compile-time we generate exactly the nested match you described:

```rust
fn dispatch_130820(payload: &[u8]) -> Option<&'static PgnInfo> {
    let mfg = read_bits_u16(payload, 0, 11);
    let industry = read_bits_u8(payload, 13, 3);
    match (mfg, industry) {
        (137, 4) => match read_bits_u16(payload, 24, 16) { // BEP
            0x0001 => Some(&PGN_130820_BEP_ALARM_STRING),
            0x0002 => Some(&PGN_130820_BEP_DIPSWITCH_LABEL),
            ...
            _      => Some(&PGN_130820_BEP_FALLBACK),
        },
        (229, 4) => match read_bits_u16(payload, 24, 16) { // Garmin
            ...
        },
        _ => fallback_130820(),
    }
}
```

One leading-bits extract, then a jump-table on manufacturer, then a jump-table
on function code. ~50× → ~2 reads + 2 matches. This is the change that matters
most; everything else is icing.

## Proposal: phased, parsing first

### Phase 0 — schema crate split (prep)

Move `PgnInfo`, `FieldInfo`, `FieldType`, `LookupTable` etc. out of
[`canboat-core/src/types.rs`](../../crates/canboat-core/src/types.rs) into a
new `canboat-schema` crate. **The types stay identical.** Two reasons:

- The `build.rs` that generates the data needs to reference these types
  without pulling in `canboat-core`'s decoder.
- `serde` derives stay on the schema types but are gated behind a `json`
  feature, so the generated code can construct values directly without
  dragging serde into release builds.

This is a mechanical move. Existing code keeps working.

### Phase 1 — `canboat-schema-gen` build crate

New crate `canboat-schema-gen` (proc-macro-style helper, but probably a plain
binary invoked from `build.rs` since the output is large and codegen-only).
Reads `data/canboat.json`, emits a single Rust file with:

```rust
pub const PGNS: &[PgnInfo] = &[ /* 579 entries */ ];
pub const PGN_INDEX: phf::Map<u32, &'static [u32]> = phf_map! { ... };
pub const LOOKUPS: &[LookupTable] = &[ /* 228 entries */ ];
pub const LOOKUP_BY_NAME: phf::Map<&'static str, u32> = phf_map! { ... };
// bit / indirect / field-type lookups likewise
```

Two key design points:

- **`phf`** for the perfect-hash maps. Compiles to a static table, no runtime
  allocation, O(1) lookup, no HashMap rebuild.
- **`&'static` everywhere.** All `String`s in the schema become `&'static str`
  (interned by virtue of being in `.rodata`). All `Vec<FieldInfo>` become
  `&'static [FieldInfo]`. This needs a parallel const-friendly variant of the
  schema types — either via a `cfg` switch on `String` vs `&'static str`, or by
  making the runtime types generic over a string/slice trait. I lean toward the
  cfg switch: less churn, no GAT gymnastics.

Apply the non-SI unit fix-ups [`db.rs:69–202`](../../crates/canboat-core/src/db.rs)
at codegen time, not at startup. SI vs non-SI becomes a build feature flag
(`canboat-core/Cargo.toml`), default non-SI to match today.

Output goes to `$OUT_DIR/schema.rs` and is `include!`'d from `canboat-core`.

### Phase 2 — `PgnDatabase::embedded()`

A new constructor in [`canboat-core/src/db.rs`](../../crates/canboat-core/src/db.rs):

```rust
impl PgnDatabase {
    pub fn embedded() -> &'static Self { &EMBEDDED_DB }
}
static EMBEDDED_DB: PgnDatabase = PgnDatabase {
    pgns: generated::PGNS,
    pgn_index: PgnIndex::Static(&generated::PGN_INDEX),
    lookups: generated::LOOKUPS,
    ...
};
```

`PgnDatabase::load()` stays, behind a `runtime-json` feature for callers that
want to point at a newer `canboat.json` without recompiling. `analyzer` keeps
its `--db <path>` flag but only honors it when that feature is on; default
build silently ignores it (or warns).

`first_pgn`, `field`, `decode`, `lookup` — same signatures, but read from
static slices/phf maps instead of `Vec` / `HashMap`. Synthetic-pgns merging
([`analyzer/src/main.rs:158`](../../crates/analyzer/src/main.rs)) gets folded
into the codegen: the generator reads `synthetic-pgns.json` too.

At this phase, **decode logic is unchanged** — still a linear walk through
variants. We just eliminated parse + index build at startup. Expected win:
~100 ms cold-start gone, ~2 MB of `HashMap` allocation gone, decode unchanged.

### Phase 3 — generated dispatch for multiplexed PGNs

This is the big one. For each PGN number with >1 variant, the generator emits
a hand-tuned dispatch function:

```rust
// canboat-core/src/generated_dispatch.rs (in OUT_DIR)
pub(crate) fn dispatch(pgn: u32, payload: &[u8]) -> Option<&'static PgnInfo> {
    match pgn {
        130820 => dispatch_130820(payload),
        126720 => dispatch_126720(payload),
        ...
        // single-variant PGNs: direct return
        129025 => Some(&PGN_129025),
        ...
        _ => None,
    }
}
```

`PgnDatabase::decode()` calls into `dispatch()` first, falls back to
`fallback_pgn()` for unknown PGN ranges (same semantics as today).

The generator's job for a multi-variant PGN:

1. Group variants by their match fields in declaration order.
2. Detect the longest common-prefix match-field sequence across variants
   (almost always: industry code + manufacturer code first, then function/msg
   discriminators). This isn't required for correctness but produces the
   cleanest nested matches.
3. Emit nested `match` arms keyed on the discriminator values.
4. Final arm: the variant flagged `Fallback: true` if present, else first
   non-match variant, else `None`.

This subsumes the per-frame linear scan. No runtime regression because
unmatched cases still hit the same fallback.

### Phase 4 (later, optional) — generated decoders per PGN

Once dispatch is generated, each variant could get a generated decoder too:
`fn decode_pgn_130822_simrad_set_lights(payload: &[u8]) -> DecodedPgn`. That
unrolls the field loop in [`decode.rs:316`](../../crates/canboat-core/src/decode.rs)
and lets rustc inline bit extraction per field. Likely the largest perf win
but also the biggest binary-size cost — defer until Phase 3 lands and we
have numbers.

## Build-side concerns

- **Compile time.** The fastpacket build.rs already parses canboat.json once.
  Codegen for full schema: ~300–500 KB of generated Rust (~3 000–5 000 lines
  of `PgnInfo { ... }` literals + dispatch tables). rustc handles megabyte-
  scale codegen fine, but it'll add a few seconds to clean builds of
  `canboat-core`. Mitigation: keep generated code in `canboat-schema-data`,
  a leaf crate with no deps, so changes don't invalidate the rest.
- **Re-generation triggers.** `cargo:rerun-if-changed=../../data/canboat.json`
  on the build.rs (already done for fastpacket — extend the same pattern).
- **Determinism.** Generator must emit stable output across runs (sorted
  phf inputs, deterministic iteration over JSON maps). The `phf` crate
  handles this; we just need to feed it sorted keys.
- **No-std friendliness.** Static tables are no-std-friendly. The runtime
  loader has `serde` + `std::io` — keep it gated.

## Risks / open questions

1. **Match fields with multi-byte non-aligned offsets.** A naive
   `read_bits(payload, off, len)` is fine but should be `#[inline]` and ideally
   const-friendly. Worth checking that LLVM merges adjacent reads in the
   nested match.
2. **PGNs with non-prefix match fields.** A few variants may discriminate on
   a field deep in the payload (e.g. position 40+). Generator should handle
   "no common prefix" by falling back to the current linear-scan style for
   that PGN. Not all 51 multi-variant PGNs need to win.
3. **`canboat.json` upgrades.** Today `git pull` + rebuild is enough. With
   codegen the same is true — but the runtime `--db <path>` override stops
   working in default builds. Decision: keep it behind feature `runtime-json`,
   on by default in `analyzer`, off by default in `canboat-pipeline`.
   `analyzer` is the natural "I want to try a newer schema" tool.
4. **Test database.** [`decode.rs:1664–1678`](../../crates/canboat-core/src/decode.rs)
   uses `OnceLock<PgnDatabase>` lazily loaded from disk. After Phase 2, point
   tests at `PgnDatabase::embedded()` instead.

## Proposed first PR

Phase 0 + Phase 1, no behavior change:

- Add `canboat-schema` crate (types only, moved from `canboat-core`).
- Add `canboat-schema-gen` build helper.
- Generate `schema.rs` into `OUT_DIR`, but **don't use it yet** — just check
  it compiles and that `phf` lookups round-trip against today's `PgnDatabase`
  via a unit test that loads both and compares all 579 PGNs.

That gives us the build machinery without touching runtime decode. Phase 2
(switch `analyzer` + `canboat-pipeline` to `embedded()`) lands as PR #2,
Phase 3 (multiplexed dispatch) as PR #3 with benchmarks.

## What I'd like feedback on before writing code

- Type duplication vs. cfg-switched string type. Cleanest is two near-identical
  type families (`schema::owned::PgnInfo` with `String`, `schema::static_::PgnInfo`
  with `&'static str`) but it doubles the surface. The cfg-switch is uglier but
  doesn't.
- Where the generator lives: separate crate (clean) vs. inline build.rs
  (precedent: canboat-io). I'd go separate crate because the generated output
  exceeds what's comfortable to debug inside a build.rs.
- Whether to keep `runtime-json` on by default in `analyzer`. Cost is the
  full serde-json dep + parse path staying in the binary; benefit is "just
  drop a newer canboat.json next to it" still works.
