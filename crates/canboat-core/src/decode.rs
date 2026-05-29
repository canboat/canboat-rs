//! Decode a `RawFrame` into a structured `DecodedPgn`.
//!
//! The decoder looks the frame's PGN up in the database, picks the
//! matching variant (manufacturer-specific PGNs disambiguated by
//! `Match` field values), and walks each field, extracting raw bits
//! and applying scaling, units, and lookup-table resolution.
//!
//! No I/O. No formatting — the result is a structured event ready for
//! the output formatter or for direct consumption by merrimac-rs.

use crate::bits::{extract_bits, is_unavailable, Extracted};
use crate::db::PgnDatabase;
use crate::frame::RawFrame;
use crate::types::{FieldInfo, FieldType, PgnInfo};

/// canboat-style "not available" check with the RangeMax exception:
/// if the field's explicit `RangeMax` (after applying resolution) equals
/// the bit-width max, the entire range is valid and no sentinel
/// stripping is performed. Matches the threshold logic in
/// `analyzer/print.c:418`.
fn unavailable_with_range(f: &FieldInfo, ex: Extracted) -> bool {
    if let (Some(rmax), Some(res)) = (f.range_max, f.resolution) {
        if res > 0.0 {
            let range_max_raw = (rmax / res + 0.5) as i64;
            if range_max_raw == ex.max {
                return false;
            }
        }
    }
    is_unavailable(ex)
}

/// One decoded field.
#[derive(Debug, Clone)]
pub struct DecodedField {
    pub order: u8,
    pub id: std::sync::Arc<str>,
    pub name: std::sync::Arc<str>,
    pub unit: Option<std::sync::Arc<str>>,
    /// Resolution as carried in canboat.json. The formatter uses this
    /// to pick a sensible number of decimal digits.
    pub resolution: Option<f64>,
    /// Explicit decimal precision from the canboat unit fix-up (e.g.
    /// `rad → deg` sets precision = 1). `0` means "derive from
    /// resolution"; the formatter walks the resolution otherwise.
    pub precision: u8,
    /// Zero-based iteration index for fields inside a repeating set;
    /// `None` for non-repeating fields.
    pub repeat_index: Option<u32>,
    /// Which RepeatingFieldSet this field belongs to: 1 → emitted under
    /// JSON `"list"`, 2 → under `"list2"`. `0` for non-repeating.
    pub repeat_set: u8,
    /// True if this field participates in the PGN's primary key. The
    /// JSON formatter under `-nv` annotates these with `"key":true`.
    pub part_of_primary_key: bool,
    /// Bit offset of this field within the PGN payload. The `-debug`
    /// JSON formatter uses this to extract the matching bytes/bits from
    /// the parent `DecodedPgn::data`. `None` for synthetic fields.
    pub bit_offset: Option<u32>,
    /// Bit length of this field. `None` for variable-length fields whose
    /// length depends on payload content (STRING_LAU, VARIABLE).
    pub bit_length: Option<u32>,
    pub value: FieldValue,
}

/// The decoded value of one field.
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// Scaled numeric value (`resolution * raw + offset`).
    Number(f64),
    /// Unscaled integer (used for fields with `resolution == 1` and no
    /// unit — counts, instances, etc.).
    Integer(i64),
    /// IEEE 754 float decoded from 32 raw bits.
    Float(f64),
    /// Raw bytes (BINARY) — uninterpreted.
    Binary(Vec<u8>),
    /// LOOKUP / INDIRECT_LOOKUP result.
    Lookup { value: u64, name: Option<String> },
    /// BITLOOKUP result — list of set bits with the bit-flag value
    /// (1 << bit) and resolved name for each.
    BitField {
        value: u64,
        bits: Vec<(u64, String)>,
    },
    /// Decoded text (STRING_FIX, STRING_LZ, STRING_LAU).
    String(String),
    /// 16-bit days since 1970-01-01.
    Date(u16),
    /// Seconds since midnight (post-resolution scaling) plus the raw
    /// integer the decoder extracted. The raw is needed for `-nv`
    /// output `{"value":raw,"name":"HH:MM:SS.SSSS"}`.
    Time { raw: i64, seconds: f64 },
    /// MMSI as a 9-digit identifier.
    Mmsi(u32),
    /// 24-bit PGN number. `description` is the target PGN's
    /// human-readable name from the database, if known.
    Pgn {
        value: u32,
        description: Option<std::sync::Arc<str>>,
    },
    /// ISO_NAME — a 64-bit packed identifier that is also a valid
    /// PGN 60928 (ISO Address Claim) payload. We carry the raw value
    /// and the recursively-decoded subfields side by side so the
    /// formatter can choose either form.
    IsoName {
        value: u64,
        subfields: Vec<DecodedField>,
    },
    /// RESERVED / SPARE — value preserved but the field is meaningless.
    /// The raw bytes (in field order, no resolution) ride along so the
    /// JSON formatter can emit them as hex strings, matching canboat.
    Reserved {
        value: u64,
        bytes: Vec<u8>,
        bit_length: u32,
    },
    Spare {
        value: u64,
        bytes: Vec<u8>,
        bit_length: u32,
    },
    /// Field exists but raw value is the canboat "not-available" sentinel.
    NotAvailable,
    /// Field decoding not yet implemented for this `FieldType`.
    Unsupported { field_type: &'static str },
}

impl FieldValue {
    /// Extract a `f64` for numeric variants. `Integer` widens; `Time`
    /// returns the post-resolution `seconds` value (matching what
    /// formatters show). Non-numeric variants return `None`.
    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            FieldValue::Number(v) | FieldValue::Float(v) => Some(*v),
            FieldValue::Integer(v) => Some(*v as f64),
            FieldValue::Time { seconds, .. } => Some(*seconds),
            FieldValue::Date(d) => Some(*d as f64),
            FieldValue::Mmsi(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Extract a `i64` from integer-shaped variants. `Lookup` returns
    /// the raw enum integer; `Number` truncates; `Time` returns the
    /// raw scaled-out integer the decoder kept around.
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Integer(v) => Some(*v),
            FieldValue::Number(v) => Some(*v as i64),
            FieldValue::Lookup { value, .. } => Some(*value as i64),
            FieldValue::BitField { value, .. } => Some(*value as i64),
            FieldValue::Time { raw, .. } => Some(*raw),
            FieldValue::Date(d) => Some(*d as i64),
            FieldValue::Mmsi(v) => Some(*v as i64),
            FieldValue::Pgn { value, .. } => Some(*value as i64),
            _ => None,
        }
    }

    /// Raw `u64` for `Lookup` / `BitField`. Use when you specifically
    /// want the enum tag without worrying about sign.
    #[inline]
    pub fn lookup_value(&self) -> Option<u64> {
        match self {
            FieldValue::Lookup { value, .. } => Some(*value),
            FieldValue::BitField { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// `&str` for `String` / for the resolved `Lookup`/`BitField`
    /// label when one was found. Non-text variants return `None`.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s.as_str()),
            FieldValue::Lookup { name: Some(n), .. } => Some(n.as_str()),
            _ => None,
        }
    }

    /// `true` when the field decoded to the canboat "not-available"
    /// sentinel — useful for callers that want to fall back to a
    /// default rather than emit nothing.
    #[inline]
    pub fn is_not_available(&self) -> bool {
        matches!(self, FieldValue::NotAvailable)
    }
}

/// A fully decoded PGN event.
#[derive(Debug, Clone)]
pub struct DecodedPgn {
    pub timestamp: Option<String>,
    pub prio: u8,
    pub pgn: u32,
    pub src: u8,
    pub dst: u8,
    pub description: std::sync::Arc<str>,
    /// canboat.json `Id` — stable camelCase identifier.
    pub id: std::sync::Arc<str>,
    /// The raw payload bytes the fields were decoded from. Kept on
    /// the DecodedPgn so the `-debug` JSON formatter can extract
    /// per-field `bytes` / `bits` annotations without holding the
    /// original `RawFrame`.
    pub data: Vec<u8>,
    pub fields: Vec<DecodedField>,
    /// `[set1, set2]` — true when the decoder reached the start
    /// field of the corresponding repeating set during this decode.
    /// False when the payload ran out before the set's start field
    /// or the PGN doesn't define a set at that index. The JSON
    /// formatter uses these to emit canboat's empty-`"list":[{}]`
    /// placeholder when the count is zero — matching the
    /// `"list":[{` opener that analyzer/analyzer.c:1276 emits the
    /// moment it sees the start field.
    pub has_repeating_set: [bool; 2],
}

impl DecodedPgn {
    /// Look up a non-repeating field by its pre-resolved
    /// [`crate::FieldHandle`]. Returns `None` when the field wasn't
    /// decoded in this payload (truncated, NotAvailable filtered by
    /// the decoder, etc.).
    ///
    /// In phase 1 this is a linear scan of `self.fields`; phase 2
    /// turns `self.fields` into a schema-ordered slot vector and
    /// this method becomes a single array load.
    #[inline]
    pub fn field(&self, h: &crate::FieldHandle) -> Option<&DecodedField> {
        // Debug-only: catch handles that were minted against a
        // different PGN id than the record was decoded under. Free
        // in release builds.
        debug_assert!(
            h.pgn_id_hash == crate::db::djb2_hash_str(&self.id),
            "FieldHandle/PGN mismatch: handle was minted for a different PGN id ({} != {})",
            h.pgn_id_hash,
            crate::db::djb2_hash_str(&self.id),
        );
        self.fields.iter().find(|f| f.order == h.field_order)
    }

    /// Same as [`Self::field`] but skips the debug assert — useful
    /// for callers that intentionally use a single handle across
    /// multiple PGN ids.
    #[inline]
    pub fn field_unchecked(&self, h: &crate::FieldHandle) -> Option<&DecodedField> {
        self.fields.iter().find(|f| f.order == h.field_order)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("PGN {pgn} not found in database")]
    UnknownPgn { pgn: u32 },
    #[error("PGN {pgn} payload too short for field {field:?}")]
    ShortPayload { pgn: u32, field: String },
}

impl PgnDatabase {
    /// Decode one frame.
    ///
    /// Picks the matching PGN variant (via `Match` field values) and
    /// walks every field. For unknown PGNs returns
    /// `DecodeError::UnknownPgn`.
    pub fn decode(&self, frame: &RawFrame) -> Result<DecodedPgn, DecodeError> {
        let info = self
            .pick_variant(frame)
            .ok_or(DecodeError::UnknownPgn { pgn: frame.pgn })?;

        let (fields, has_repeating_set) = decode_fields(info, &frame.data, self)?;

        Ok(DecodedPgn {
            timestamp: frame.timestamp.clone(),
            prio: frame.prio,
            pgn: frame.pgn,
            src: frame.src,
            dst: frame.dst,
            description: info.description.clone(),
            id: info.id.clone(),
            data: frame.data.to_vec(),
            fields,
            has_repeating_set,
        })
    }

    /// Choose the best PGN definition for a frame.
    ///
    /// Priority — strict canboat semantics:
    ///
    ///   1. **JSON-order scan of variants for this PGN number.** Return
    ///      the first variant whose every `Match` field equals the raw
    ///      bits at that field's offset. JSON insertion order encodes
    ///      author-defined priority; an earlier matching specific
    ///      variant always beats a later one, and a matching specific
    ///      variant always beats the per-PGN-number fallback even when
    ///      the fallback is listed first (as in PGN 126208 etc).
    ///
    ///   2. **In-PGN fallback.** If no specific variant matched, return
    ///      the `Fallback: true` variant for this PGN number, if any.
    ///      Falls back further to any no-`Match` variant — though in
    ///      canboat.json those two are the same entry.
    ///
    ///   3. **Inter-PGN fallback.** If the PGN number itself is not in
    ///      the database, return the largest `Fallback: true` entry
    ///      whose PGN number is `<= frame.pgn`. This is the catch-all
    ///      that covers the range — e.g. unknown PGNs in
    ///      `[0x1ef00, 0x1ef00]` get
    ///      `0x1ef00ManufacturerProprietaryFastPacketAddressed`.
    pub fn pick_variant(&self, frame: &RawFrame) -> Option<&PgnInfo> {
        let mut in_pgn_fallback: Option<&PgnInfo> = None;
        for info in self.pgn_variants(frame.pgn) {
            let mut has_match = false;
            let mut all_ok = true;
            for f in &info.fields {
                let Some(expected) = f.match_value else {
                    continue;
                };
                has_match = true;
                let Some(bit_offset) = f.bit_offset else {
                    all_ok = false;
                    break;
                };
                let Some(bit_length) = f.bit_length else {
                    all_ok = false;
                    break;
                };
                match extract_bits(
                    &frame.data,
                    bit_offset as usize,
                    bit_length as usize,
                    f.signed.unwrap_or(false),
                    f.offset.unwrap_or(0),
                ) {
                    Some(ex) if ex.value == expected => {}
                    _ => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if has_match && all_ok {
                return Some(info);
            }
            // Record the in-PGN fallback. Prefer an explicit
            // `Fallback: true` over a happenstance no-Match variant if
            // both exist; otherwise take the first no-Match variant
            // (canboat keeps at most one no-Match variant per PGN, and
            // it carries the Fallback flag).
            if !has_match && (info.fallback.unwrap_or(false) || in_pgn_fallback.is_none()) {
                in_pgn_fallback = Some(info);
            }
        }
        if let Some(v) = in_pgn_fallback {
            return Some(v);
        }
        // Either there were no entries for this PGN at all, or every
        // entry had `Match` fields that didn't match the frame's bits
        // (Maretron-specific PGN 130823 seen on a Navico bus, etc.).
        // Mirror canboat's `searchForUnknownPgn` — walk the load order
        // and return the most recent `Fallback: true` entry whose PGN
        // is <= the unknown one. Same range stub used for PGNs that
        // aren't in canboat.json.
        self.find_catchall(frame.pgn)
    }

    /// Inter-PGN catch-all: the latest `Fallback: true` definition
    /// whose PGN number is `<= pgn`. PGN numbers in canboat.json are
    /// non-decreasing, so a linear scan finds the right one in JSON
    /// order. Called only when no entry for `pgn` exists at all.
    fn find_catchall(&self, pgn: u32) -> Option<&PgnInfo> {
        let mut best: Option<&PgnInfo> = None;
        for info in self.pgns() {
            if info.pgn > pgn {
                break;
            }
            if info.fallback.unwrap_or(false) {
                best = Some(info);
            }
        }
        best
    }
}

/// Walk a PGN's fields, decoding each in turn.
///
/// Handles repeating field sets (`RepeatingFieldSet1`) — when the
/// walker reaches `repeating_field_set1_start_field`, it pulls the
/// count from the already-decoded count field, then re-runs the set
/// of `size` repeating fields N times. Each iteration's fields share
/// the layout of the first iteration shifted by `iteration_bits`
/// (the sum of `BitLength` over the set).
///
/// `Condition`-gated alternative fields are skipped (full evaluation
/// is deferred to a later commit).
/// State the decoder threads through fields so VARIABLE-typed fields
/// can find their target metadata.
///
/// - `target_pgn` is updated whenever a [`FieldValue::Pgn`] is emitted
///   (PGN 126208 group functions carry the target PGN in field 2).
/// - `current_param_idx` is updated whenever a `FIELD_INDEX` field is
///   emitted, so the next VARIABLE field knows which target field's
///   metadata to use.
#[derive(Default, Debug, Clone)]
struct DecodeContext {
    target_pgn: Option<u32>,
    current_param_idx: Option<u32>,
    /// Resolved DYNAMIC_FIELD_KEY entry — set when a key field is
    /// decoded, read by the matching DYNAMIC_FIELD_VALUE, cleared
    /// after. Stored as cloned data so we don't have to thread a
    /// lifetime through every decoder.
    dynamic_field_type: Option<crate::types::LookupFieldTypeValue>,
    /// Byte length from a DYNAMIC_FIELD_LENGTH field. Cleared with
    /// `dynamic_field_type` after the value is decoded.
    dynamic_length_bytes: Option<u32>,
}

fn decode_fields(
    info: &PgnInfo,
    data: &[u8],
    db: &PgnDatabase,
) -> Result<(Vec<DecodedField>, [bool; 2]), DecodeError> {
    let mut out = Vec::with_capacity(info.fields.len());
    let mut ctx = DecodeContext::default();
    let start1 = info.repeating_field_set1_start_field;
    let size1 = info.repeating_field_set1_size;
    let count_field1 = info.repeating_field_set1_count_field;
    let start2 = info.repeating_field_set2_start_field;
    let size2 = info.repeating_field_set2_size;
    let count_field2 = info.repeating_field_set2_count_field;
    let mut entered = [false, false];

    let mut i = 0usize;
    // Running bit cursor — used both for variable-length fields that
    // lack an explicit BitOffset and as the entry point for repeating
    // sets that follow other variable-length content.
    let mut cursor_bits: u32 = 0;
    while i < info.fields.len() {
        let f = &info.fields[i];

        // Repeating set 1 starts here? `count_field1` can be absent
        // (e.g. PGN 126464 PGN List) — in that case canboat repeats
        // until the payload runs out.
        if let (Some(start), Some(size)) = (start1, size1) {
            if (f.order as u32) == start {
                // Only mark as "entered" if the start field is
                // actually within the payload — canboat C's main
                // loop stops once `startBit >> 3 >= length`, so a
                // truncated PGN payload never reaches the start
                // field and never emits the list opener.
                let bit_offset = f.bit_offset.unwrap_or(cursor_bits);
                if (bit_offset as usize) < data.len() * 8 {
                    entered[0] = true;
                }
                cursor_bits = decode_repeating(
                    info,
                    data,
                    db,
                    &mut out,
                    &mut ctx,
                    i,
                    size as usize,
                    count_field1,
                    cursor_bits,
                    1,
                );
                i += size as usize;
                continue;
            }
        }
        // Repeating set 2?
        if let (Some(start), Some(size)) = (start2, size2) {
            if (f.order as u32) == start {
                let bit_offset = f.bit_offset.unwrap_or(cursor_bits);
                if (bit_offset as usize) < data.len() * 8 {
                    entered[1] = true;
                }
                cursor_bits = decode_repeating(
                    info,
                    data,
                    db,
                    &mut out,
                    &mut ctx,
                    i,
                    size as usize,
                    count_field2,
                    cursor_bits,
                    2,
                );
                i += size as usize;
                continue;
            }
        }

        if f.condition.is_some() {
            i += 1;
            continue;
        }
        // Variable-length fields (STRING_LAU and friends) after the
        // first one have no `BitOffset` in canboat.json — they sit at
        // the byte after the previous variable field ends. Use a
        // running `cursor_bits` for those; honor an explicit BitOffset
        // when one is given.
        let effective_offset = f.bit_offset.unwrap_or(cursor_bits);
        if let Some((decoded, bits_consumed)) =
            decode_one_field_at(f, info, data, db, effective_offset, &mut ctx)
        {
            cursor_bits = effective_offset + bits_consumed;
            out.push(decoded);
        }
        i += 1;
    }
    Ok((out, entered))
}

#[allow(clippy::too_many_arguments)]
fn decode_repeating(
    info: &PgnInfo,
    data: &[u8],
    db: &PgnDatabase,
    out: &mut Vec<DecodedField>,
    ctx: &mut DecodeContext,
    start_idx: usize,
    set_size: usize,
    count_field_order: Option<u32>,
    base_cursor: u32,
    set_number: u8,
) -> u32 {
    // Look up the count from the already-decoded fields when a count
    // field is set; otherwise repeat until the payload runs out
    // (matches canboat's default g_variableFieldRepeat[0] = 255 path).
    // Canboat's `printFields` always enters the repeat block with
    // `repetition = 1` once it reaches the set's start field, even
    // when the count field decoded to zero (see analyzer.c:1284 vs
    // 1300). The decremented `variableFields` counter only triggers
    // *additional* loops, so count=0 yields exactly one iteration as
    // long as payload remains. Match that here: floor count at 1
    // when it's set, fall back to "iterate until payload runs out"
    // when the count field is NotAvailable or otherwise unresolved.
    let raw_count: Option<u32> = count_field_order.and_then(|cf| {
        out.iter()
            .find(|d| (d.order as u32) == cf)
            .and_then(|d| match &d.value {
                FieldValue::Integer(n) if *n >= 0 => Some(*n as u32),
                FieldValue::Number(n) if *n >= 0.0 => Some(*n as u32),
                _ => None,
            })
    });
    // count=0 still produces exactly one (truncated) iteration — see
    // the long comment above the call site. Track this case so the text
    // formatter only labels the *first* field with " 1".
    let count_was_zero = raw_count == Some(0);
    let max_iters: u32 = match raw_count {
        Some(n) => n.max(1),
        None => u32::MAX,
    };

    let set = &info.fields[start_idx..start_idx + set_size];
    if set.is_empty() {
        return base_cursor;
    }
    let payload_bits = (data.len() as u32).saturating_mul(8);

    // Use the iteration's first field's BitOffset if available — that
    // anchors iteration 0 to the canboat.json layout. After that we
    // run on a per-iteration sub-cursor that advances by each field's
    // actual `bits_consumed` (handles variable-length VARIABLE fields).
    let mut iter_cursor = set[0].bit_offset.unwrap_or(base_cursor);

    for iter in 0..max_iters {
        if iter_cursor >= payload_bits {
            break;
        }
        let mut sub_cursor = iter_cursor;
        let mut produced_any = false;
        let mut first_field_of_iter = true;
        for sf in set {
            if sf.condition.is_some() {
                continue;
            }
            // Iteration 0 honors the explicit BitOffset from JSON;
            // later iterations follow the running sub_cursor since
            // bit_offsets aren't repeated per iteration in JSON.
            let off = if iter == 0 {
                sf.bit_offset.unwrap_or(sub_cursor)
            } else {
                sub_cursor
            };
            if let Some((mut d, bits)) = decode_one_field_at(sf, info, data, db, off, ctx) {
                // Canboat's `repetition` counter is reset to 0 at the
                // top of each loop iteration when `*variableFields == 0`
                // — so a forced count=0 iteration only labels its first
                // field. Drop `repeat_index` (but keep `repeat_set` for
                // JSON list-grouping) on later fields to match.
                d.repeat_set = set_number;
                d.repeat_index = if count_was_zero && !first_field_of_iter {
                    None
                } else {
                    Some(iter)
                };
                first_field_of_iter = false;
                out.push(d);
                sub_cursor = off + bits;
                produced_any = true;
            } else if let Some(bl) = sf.bit_length {
                // Field couldn't decode but has a known size; advance
                // past it so subsequent fields in this iteration still
                // line up.
                sub_cursor = off + bl;
            }
        }
        // If this iteration produced nothing decodable, stop — we ran
        // off the end of the payload.
        if !produced_any {
            break;
        }
        iter_cursor = sub_cursor;
    }
    iter_cursor
}

/// Decode one field. Returns the `DecodedField` and the number of
/// payload bits it actually consumed (which differs from `bit_length`
/// for variable-length types like STRING_LAU and VARIABLE).
fn decode_one_field_at(
    f: &FieldInfo,
    info: &PgnInfo,
    data: &[u8],
    db: &PgnDatabase,
    bit_offset: u32,
    ctx: &mut DecodeContext,
) -> Option<(DecodedField, u32)> {
    let signed = f.signed.unwrap_or(false);
    let offset_k = f.offset.unwrap_or(0);

    // STRING_LAU figures out its own length from the data byte.
    if matches!(f.field_type, Some(FieldType::StringLau)) {
        let (value, bits_consumed) = decode_string_lau(data, bit_offset);
        return Some((
            DecodedField {
                order: f.order,
                id: f.id.clone(),
                name: f.name.clone(),
                unit: f.unit.clone(),
                resolution: f.resolution,
                precision: f.precision,
                repeat_index: None,
                repeat_set: 0,
                part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
                bit_offset: Some(bit_offset),
                bit_length: Some(bits_consumed),
                value,
            },
            bits_consumed,
        ));
    }

    // VARIABLE: dynamic field type — look up the target field's
    // metadata via (ctx.target_pgn, ctx.current_param_idx), then
    // recursively decode with that metadata at the current cursor.
    if matches!(f.field_type, Some(FieldType::Variable)) {
        return decode_variable(f, data, db, bit_offset, ctx);
    }

    // DYNAMIC_FIELD_VALUE has `BitLengthVariable: true` and no
    // explicit `BitLength` in canboat.json — its width comes from
    // the matching DYNAMIC_FIELD_LENGTH (or the resolved KEY's table
    // entry). Handle it before the `bit_length?` check below would
    // bail out.
    if matches!(f.field_type, Some(FieldType::DynamicFieldValue)) {
        // Capture unit / resolution / precision from the resolved key
        // entry *before* `decode_dynamic_field_value` drains the
        // context slots.
        let unit = ctx
            .dynamic_field_type
            .as_ref()
            .and_then(|v| v.unit.clone())
            .or_else(|| f.unit.clone());
        let resolution = ctx
            .dynamic_field_type
            .as_ref()
            .and_then(|v| v.resolution)
            .or(f.resolution);
        let precision = ctx
            .dynamic_field_type
            .as_ref()
            .map(|v| v.precision)
            .filter(|&p| p > 0)
            .unwrap_or(f.precision);
        let (val, consumed_bits) = decode_dynamic_field_value(data, bit_offset, db, ctx);
        return Some((
            DecodedField {
                order: f.order,
                id: f.id.clone(),
                name: f.name.clone(),
                unit,
                resolution,
                precision,
                repeat_index: None,
                repeat_set: 0,
                part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
                bit_offset: Some(bit_offset),
                bit_length: Some(consumed_bits),
                value: val,
            },
            consumed_bits,
        ));
    }

    // STRING_LZ / BINARY with `BitLengthVariable: true` and no
    // explicit `BitLength` — read to the payload end (canboat's
    // equivalent: `if (*bits == 0)` in `fieldPrintBinary` /
    // `printString`). Falls through to the normal decode path with a
    // zero bit_length so the decoders know to consume what's left.
    if matches!(
        f.field_type,
        Some(FieldType::StringLz) | Some(FieldType::Binary)
    ) && f.bit_length.is_none()
    {
        let payload_bits = (data.len() as u32).saturating_mul(8);
        let avail = payload_bits.saturating_sub(bit_offset);
        let avail = avail - (avail & 7); // round down to whole bytes
        let value = match f.field_type {
            Some(FieldType::StringLz) => decode_string_lz(data, bit_offset, avail),
            _ => decode_binary(data, bit_offset, avail),
        };
        return Some((
            DecodedField {
                order: f.order,
                id: f.id.clone(),
                name: f.name.clone(),
                unit: f.unit.clone(),
                resolution: f.resolution,
                precision: f.precision,
                repeat_index: None,
                repeat_set: 0,
                part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
                bit_offset: Some(bit_offset),
                bit_length: Some(avail),
                value,
            },
            avail,
        ));
    }

    let bit_length = f.bit_length?;

    let value = match f.field_type {
        Some(FieldType::Number) | Some(FieldType::Decimal) => {
            decode_number(f, data, bit_offset, bit_length, signed, offset_k)
        }
        Some(FieldType::Float) => decode_float(data, bit_offset, bit_length),
        Some(FieldType::Lookup) => decode_lookup(f, data, bit_offset, bit_length, db),
        Some(FieldType::IndirectLookup) => {
            decode_indirect_lookup(f, info, data, bit_offset, bit_length, db)
        }
        Some(FieldType::BitLookup) => decode_bitlookup(f, data, bit_offset, bit_length, db),
        Some(FieldType::Reserved) => {
            decode_reserved(data, bit_offset, bit_length, signed, offset_k, true)
        }
        Some(FieldType::Spare) => {
            decode_reserved(data, bit_offset, bit_length, signed, offset_k, false)
        }
        Some(FieldType::Binary) => decode_binary(data, bit_offset, bit_length),
        Some(FieldType::Mmsi) => decode_mmsi(data, bit_offset, bit_length),
        Some(FieldType::Pgn) => decode_pgn_field(data, bit_offset, bit_length, db),
        Some(FieldType::Date) => decode_date(data, bit_offset, bit_length),
        Some(FieldType::Time) | Some(FieldType::Duration) => {
            decode_time(f, data, bit_offset, bit_length, signed)
        }
        Some(FieldType::StringFix) => decode_string_fix(data, bit_offset, bit_length),
        Some(FieldType::StringLz) => decode_string_lz(data, bit_offset, bit_length),
        Some(FieldType::StringLau) => unreachable!("STRING_LAU handled above"),
        Some(FieldType::Variable) => unreachable!("VARIABLE handled above"),
        Some(FieldType::IsoName) => decode_iso_name(data, bit_offset, bit_length, db),
        Some(FieldType::DynamicFieldKey) => {
            decode_dynamic_field_key(f, data, db, bit_offset, bit_length, ctx)
        }
        Some(FieldType::DynamicFieldLength) => {
            decode_dynamic_field_length(data, bit_offset, bit_length, ctx)
        }
        Some(FieldType::DynamicFieldValue) => unreachable!("DYNAMIC_FIELD_VALUE handled above"),
        Some(FieldType::FieldIndex) => decode_number(f, data, bit_offset, bit_length, signed, 0),
        None => FieldValue::Unsupported {
            field_type: "<no field type>",
        },
    };

    // Update the running context based on what we just decoded so the
    // next field can interpret VARIABLE / FIELD_INDEX correctly.
    match &value {
        FieldValue::Pgn { value: p, .. } => ctx.target_pgn = Some(*p),
        FieldValue::Integer(n) if matches!(f.field_type, Some(FieldType::FieldIndex)) => {
            ctx.current_param_idx = Some(*n as u32);
        }
        _ => {}
    }
    // canboat C also picks up dynamic field lengths by FIELD NAME
    // (`analyzer/analyzer.c::fillGlobalsBasedOnFieldName`): any field
    // literally named `Length` updates `g_length`, which the next
    // DYNAMIC_FIELD_VALUE then consumes. Several PGNs use a regular
    // NUMBER field for this rather than the explicit
    // `DYNAMIC_FIELD_LENGTH` type (e.g. Simnet Parameter Set 130846).
    if f.is_dynamic_length_marker {
        let raw_len = match &value {
            FieldValue::Integer(n) if *n >= 0 => Some(*n as u32),
            FieldValue::Number(n) if *n >= 0.0 => Some(*n as u32),
            _ => None,
        };
        if let Some(n) = raw_len {
            ctx.dynamic_length_bytes = Some(n);
        }
    }

    Some((
        DecodedField {
            order: f.order,
            id: f.id.clone(),
            name: f.name.clone(),
            unit: f.unit.clone(),
            resolution: f.resolution,
            precision: f.precision,
            repeat_index: None,
            repeat_set: 0,
            part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
            bit_offset: Some(bit_offset),
            bit_length: Some(bit_length),
            value,
        },
        bit_length,
    ))
}

/// Resolve a VARIABLE field by looking up the target field's metadata
/// in the database, then decoding with that metadata at the current
/// cursor.
///
/// Used by PGN 126208 group functions where a `Parameter` /
/// `FIELD_INDEX` field picks one of the target PGN's fields, and the
/// next VARIABLE field carries that field's value in its native shape.
fn decode_variable(
    f: &FieldInfo,
    data: &[u8],
    db: &PgnDatabase,
    bit_offset: u32,
    ctx: &mut DecodeContext,
) -> Option<(DecodedField, u32)> {
    let target_pgn = ctx.target_pgn?;
    let target_idx = ctx.current_param_idx?;
    let target_info = db.first_pgn(target_pgn)?;
    let target_field = target_info
        .fields
        .iter()
        .find(|tf| (tf.order as u32) == target_idx)?;
    // Recurse with the target field's metadata at the current cursor.
    // The outer field's name (e.g. "Value", "Selection Value") wraps
    // the decoded result so the JSON keeps the right field label.
    let mut sub_ctx = DecodeContext::default();
    let (sub, bits) = decode_one_field_at(
        target_field,
        target_info,
        data,
        db,
        bit_offset,
        &mut sub_ctx,
    )?;
    // canboat rounds the VARIABLE field's consumption UP to whole
    // bytes — `*bits = (*bits + 7) & ~0x07` in `fieldPrintVariable`.
    // Without this, Set2 in PGN 126208 Read Fields lands 5 bits early
    // and reads the next Parameter's bits from the wrong nibble.
    let bits_byte_aligned = bits.div_ceil(8) * 8;
    Some((
        DecodedField {
            order: f.order,
            id: f.id.clone(),
            name: f.name.clone(),
            unit: target_field.unit.clone().or(f.unit.clone()),
            resolution: target_field.resolution.or(f.resolution),
            precision: target_field.precision,
            repeat_index: None,
            repeat_set: 0,
            part_of_primary_key: f.part_of_primary_key.unwrap_or(false),
            bit_offset: Some(bit_offset),
            // For VARIABLE fields, the `-debug` formatter wants the
            // diagnostic to reflect the sub-field's actual width when
            // it has one (so a 3-bit LOOKUP target shows
            // `bits = "010"`). When the sub-field is itself variable-
            // length (e.g. STRING_LAU), fall back to the consumed
            // byte-aligned size so we still emit the bytes annotation.
            bit_length: target_field.bit_length.or(Some(bits_byte_aligned)),
            value: sub.value,
        },
        bits_byte_aligned,
    ))
}

fn decode_number(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
    _offset_k: i64,
) -> FieldValue {
    // canboat.json's `Offset` is in DISPLAY units (e.g. PEUKERT_EXPONENT
    // Offset=1 means "add 1.0 to the displayed exponent"), NOT a raw
    // J1939 Excess-K shift on the integer extraction. canboat C also
    // forces unsigned extraction when `Offset != 0` regardless of the
    // field's nominal Signed flag — see extractNumber's
    // `if (hasSign && field->offset)` path. Replicate both here.
    let display_offset = f.offset.map(|o| o as f64).unwrap_or(0.0);
    let has_display_offset = f.offset.unwrap_or(0) != 0;
    let effective_signed = if has_display_offset { false } else { signed };
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        effective_signed,
        0,
    ) else {
        return FieldValue::NotAvailable;
    };
    if unavailable_with_range(f, ex) {
        return FieldValue::NotAvailable;
    }
    let resolution = f.resolution.unwrap_or(1.0);
    let unit = f.unit.as_deref();
    if resolution == 1.0
        && unit.is_none()
        && f.physical_quantity.is_none()
        && f.unit_offset == 0.0
        && display_offset == 0.0
    {
        FieldValue::Integer(ex.value)
    } else {
        FieldValue::Number(ex.value as f64 * resolution + display_offset + f.unit_offset)
    }
}

fn decode_float(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 32 {
        return FieldValue::Unsupported {
            field_type: "FLOAT (non-32-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 32, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let bits = ex.value as u32;
    FieldValue::Float(f32::from_bits(bits) as f64)
}

fn decode_lookup(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    // canboat allows reserved sentinels in some lookup tables, so don't
    // pre-filter via is_unavailable here — emit the raw value and let
    // the formatter decide.
    let raw = ex.value as u64;
    let name = f
        .lookup_enumeration
        .as_deref()
        .and_then(|n| db.lookup(n))
        .and_then(|t| t.get(raw))
        .map(|v| v.name.clone());
    // canboat: if no name is resolved AND value is in the reserved
    // sentinel range, drop the field (matches print.c:718). The
    // lookup check is one off from `is_unavailable`: canboat uses
    // `>=` against the threshold and a `bits>2 ? 2 : 1` reserved
    // count, both of which include one more sentinel than the NUMBER
    // path would.
    if name.is_none() && is_lookup_unavailable(ex, bit_length as usize) {
        return FieldValue::NotAvailable;
    }
    FieldValue::Lookup { value: raw, name }
}

/// `print.c:718` rule for unknown LOOKUP values: in a `bits>1` field,
/// drop the top `bits>2 ? 2 : 1` raw values (`value >= max - reserved`).
fn is_lookup_unavailable(ex: crate::bits::Extracted, bits: usize) -> bool {
    if bits <= 1 {
        return false;
    }
    let reserved: i64 = if bits > 2 { 2 } else { 1 };
    ex.value >= ex.max - reserved
}

/// INDIRECT_LOOKUP: resolve `(value1, value2)` where `value1` is
/// pulled from another field within the same PGN, identified by
/// `LookupIndirectEnumerationFieldOrder`.
fn decode_indirect_lookup(
    f: &FieldInfo,
    info: &PgnInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    let name = (|| -> Option<String> {
        let table_name = f.lookup_indirect_enumeration.as_deref()?;
        let val1_order = f.lookup_indirect_enumeration_field_order?;
        let val1_field = info.fields.iter().find(|x| x.order == val1_order)?;
        let val1_off = val1_field.bit_offset?;
        let val1_len = val1_field.bit_length?;
        let val1 = extract_bits(data, val1_off as usize, val1_len as usize, false, 0)?;
        let resolved = db.indirect_lookup(table_name, val1.value as u64, raw)?;
        Some(resolved.to_string())
    })();
    // Same print.c:718 rule we apply to plain LOOKUP — unknown values
    // in the top sentinel range drop the field rather than emitting a
    // bare integer. Without this, PGN 60928's Device Function comes
    // through as `"Device Function":255` where canboat C drops it.
    if name.is_none() && is_lookup_unavailable(ex, bit_length as usize) {
        return FieldValue::NotAvailable;
    }
    FieldValue::Lookup { value: raw, name }
}

fn decode_bitlookup(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    db: &PgnDatabase,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    // Keep the BitField even when no bits are set — formatters
    // handle the empty case themselves: JSON drops it, text emits
    // "None" (matches canboat).
    let mut bits = Vec::new();
    if let Some(t) = f
        .lookup_bit_enumeration
        .as_deref()
        .and_then(|n| db.bit_lookup(n))
    {
        for v in &t.values {
            if raw & (1u64 << v.bit) != 0 {
                bits.push((1u64 << v.bit, v.name.clone()));
            }
        }
    }
    FieldValue::BitField { value: raw, bits }
}

fn decode_reserved(
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
    offset_k: i64,
    is_reserved: bool,
) -> FieldValue {
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        signed,
        offset_k,
    ) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    // canboat skips Reserved fields whose value is all-ones (the
    // default "this is unused" state). Surface that here too — but
    // formatters do the actual omission so the `-debug` byte/bit
    // diagnostic survives in callers that care.
    if is_reserved && ex.value == ex.max {
        return FieldValue::Reserved {
            value: raw,
            bytes: Vec::new(),
            bit_length,
        };
    }
    // Pack just the field's value into bytes (little-endian), one byte
    // per `ceil(bit_length / 8)`. This avoids leaking neighboring
    // fields' bits when the reserved span shares a byte with adjacent
    // payload (which slicing `data[start..end]` would do).
    let n_bytes = bit_length.div_ceil(8).max(1) as usize;
    let mut bytes = Vec::with_capacity(n_bytes);
    for i in 0..n_bytes {
        bytes.push(((raw >> (i * 8)) & 0xff) as u8);
    }
    if is_reserved {
        FieldValue::Reserved {
            value: raw,
            bytes,
            bit_length,
        }
    } else {
        FieldValue::Spare {
            value: raw,
            bytes,
            bit_length,
        }
    }
}

/// ISO_NAME: 64-bit packed identifier. The same 8 bytes also form a
/// valid PGN 60928 (ISO Address Claim) payload, so the structured form
/// is built by re-running the decoder against PGN 60928's field list
/// on those 8 bytes — matching `fieldPrintName` in `analyzer/print.c`.
fn decode_iso_name(data: &[u8], bit_offset: u32, bit_length: u32, db: &PgnDatabase) -> FieldValue {
    if bit_length != 64 || (bit_offset & 7) != 0 {
        return FieldValue::Unsupported {
            field_type: "ISO_NAME (unaligned or non-64-bit)",
        };
    }
    let byte_off = (bit_offset / 8) as usize;
    if byte_off + 8 > data.len() {
        return FieldValue::NotAvailable;
    }
    let mut value: u64 = 0;
    for i in 0..8 {
        value |= (data[byte_off + i] as u64) << (i * 8);
    }
    let sub = &data[byte_off..byte_off + 8];
    let subfields = match db.first_pgn(60928) {
        Some(pgn) => decode_fields(pgn, sub, db).map(|x| x.0).unwrap_or_default(),
        None => Vec::new(),
    };
    FieldValue::IsoName { value, subfields }
}

fn decode_binary(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bit_offset = bit_offset as usize;
    let bit_length = bit_length as usize;
    // Whole-byte aligned: take a clean slice. Fallback PGNs like the
    // proprietary catch-alls declare BINARY widths well past the
    // actual payload (e.g. 1768 bits for `Data` in PGN 126720) —
    // canboat just renders whatever bytes are present, so clamp to
    // the available range rather than emitting NotAvailable.
    if bit_offset & 7 == 0 && bit_length & 7 == 0 {
        let start = bit_offset / 8;
        if start >= data.len() {
            return FieldValue::NotAvailable;
        }
        let declared_end = start + bit_length / 8;
        let end = declared_end.min(data.len());
        return FieldValue::Binary(data[start..end].to_vec());
    }
    // Bit-aligned binary: pack into bytes LSB-first to keep round-trip
    // semantics with extract_bits.
    let bytes = bit_length.div_ceil(8);
    let mut out = vec![0u8; bytes];
    let mut bo = bit_offset;
    let mut remaining = bit_length;
    let mut byte_i = 0usize;
    while remaining > 0 {
        let chunk = remaining.min(8);
        let Some(ex) = extract_bits(data, bo, chunk, false, 0) else {
            return FieldValue::NotAvailable;
        };
        out[byte_i] = ex.value as u8;
        byte_i += 1;
        bo += chunk;
        remaining -= chunk;
    }
    FieldValue::Binary(out)
}

fn decode_mmsi(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 32 {
        return FieldValue::Unsupported {
            field_type: "MMSI (non-32-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 32, false, 0) else {
        return FieldValue::NotAvailable;
    };
    if is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    FieldValue::Mmsi(ex.value as u32)
}

fn decode_pgn_field(data: &[u8], bit_offset: u32, bit_length: u32, db: &PgnDatabase) -> FieldValue {
    if bit_length != 24 {
        return FieldValue::Unsupported {
            field_type: "PGN (non-24-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 24, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u32;
    // PDU1 (PF < 240): low byte of the PGN is the destination address,
    // so it's masked out. PDU2: low byte is the PS and part of the PGN.
    let pf = (raw >> 8) & 0xff;
    let pgn = if pf < 240 {
        raw & 0x00ff_ff00
    } else {
        raw & 0x00ff_ffff
    };
    // canboat only emits a name for the PGN field when there's
    // unambiguously one variant *without* `Match` constraints — that
    // is, the PGN number alone is enough to identify the message. PGN
    // 130820 (42 manufacturer variants, all match-gated) and PGN 65410
    // (one Airmar-only variant gated on Manufacturer Code) both fall
    // back to "value only" because we can't tell which variant applies
    // without actually decoding payload data.
    let variants: Vec<&PgnInfo> = db.pgn_variants(pgn).collect();
    let description =
        if variants.len() == 1 && !variants[0].fields.iter().any(|f| f.match_value.is_some()) {
            Some(variants[0].description.clone())
        } else {
            None
        };
    FieldValue::Pgn {
        value: pgn,
        description,
    }
}

fn decode_date(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    if bit_length != 16 {
        return FieldValue::Unsupported {
            field_type: "DATE (non-16-bit)",
        };
    }
    let Some(ex) = extract_bits(data, bit_offset as usize, 16, false, 0) else {
        return FieldValue::NotAvailable;
    };
    if ex.value == 0xffff {
        return FieldValue::NotAvailable;
    }
    FieldValue::Date(ex.value as u16)
}

fn decode_time(
    f: &FieldInfo,
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
) -> FieldValue {
    let Some(ex) = extract_bits(
        data,
        bit_offset as usize,
        bit_length as usize,
        signed,
        f.offset.unwrap_or(0),
    ) else {
        return FieldValue::NotAvailable;
    };
    if is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    let resolution = f.resolution.unwrap_or(1.0);
    FieldValue::Time {
        raw: ex.value,
        seconds: ex.value as f64 * resolution,
    }
}

fn decode_string_fix(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bo = bit_offset as usize;
    let bl = bit_length as usize;
    if bo & 7 != 0 || bl & 7 != 0 {
        return FieldValue::Unsupported {
            field_type: "STRING_FIX (unaligned)",
        };
    }
    let start = bo / 8;
    let end = start + bl / 8;
    if end > data.len() {
        return FieldValue::NotAvailable;
    }
    // Canboat's `printString` first finds an embedded NUL and shortens
    // the string at that point (matches the C-string convention some
    // devices use to terminate inside a fixed-width buffer — e.g. a
    // Mastervolt Product Information field that has two records
    // separated by NULs), then trims trailing '@' / NUL / space /
    // 0xFF. Apply both passes here so STRING_FIX renders the leading
    // C-string portion only.
    let raw = &data[start..end];
    let mut len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    while len > 0 {
        let b = raw[len - 1];
        if b == 0 || b == b'@' || b == b' ' || b == 0xff {
            len -= 1;
        } else {
            break;
        }
    }
    if len == 0 {
        return FieldValue::NotAvailable;
    }
    let s = String::from_utf8_lossy(&raw[..len]).into_owned();
    FieldValue::String(s)
}

/// STRING_LAU — length + encoding + payload, where the first byte is the
/// total size of the field (`len` including the header), the second byte
/// is an encoding control (`0` = UTF-16LE, `1` = ASCII / UTF-8), and the
/// remaining `len - 2` bytes are the payload.
///
/// Returns the decoded value plus the number of bits this field
/// consumed — variable, so callers must use this to advance the cursor.
fn decode_string_lau(data: &[u8], bit_offset: u32) -> (FieldValue, u32) {
    let bo = bit_offset as usize;
    if bo & 7 != 0 {
        return (
            FieldValue::Unsupported {
                field_type: "STRING_LAU (unaligned)",
            },
            8,
        );
    }
    let start = bo / 8;
    if start + 2 > data.len() {
        return (FieldValue::NotAvailable, 16);
    }
    let total_len = data[start] as usize;
    let encoding = data[start + 1];
    if total_len < 2 {
        return (FieldValue::NotAvailable, (total_len.max(2) * 8) as u32);
    }
    let body_len = total_len - 2;
    let body_end = (start + 2 + body_len).min(data.len());
    let body = &data[start + 2..body_end];

    let bits_consumed = (total_len * 8) as u32;
    let s = match encoding {
        0 => {
            // UTF-16LE: pairs of bytes are LE u16 code units.
            let mut code_units = Vec::with_capacity(body.len() / 2);
            let mut i = 0;
            while i + 1 < body.len() {
                code_units.push(u16::from_le_bytes([body[i], body[i + 1]]));
                i += 2;
            }
            String::from_utf16_lossy(&code_units)
        }
        _ => {
            // 1 = ASCII / UTF-8 (canboat doesn't differentiate).
            String::from_utf8_lossy(body).into_owned()
        }
    };
    // Canboat's `printString` trims trailing 0xff / NUL / '@' / spaces
    // *after* the UTF-16→UTF-8 conversion. If nothing's left, the field
    // is rendered as Unknown via `printEmpty`. Match that — and don't
    // trim raw UTF-16 bytes (the trailing NUL of a single ASCII glyph
    // would lose the char).
    let trimmed = trim_string_padding(&s);
    if trimmed.is_empty() {
        return (FieldValue::NotAvailable, bits_consumed);
    }
    (FieldValue::String(trimmed.to_string()), bits_consumed)
}

/// Strip trailing canboat-padding bytes (`\0`, `'@'`, space, `\xff`)
/// from a string. Matches the trailing-byte loop in `printString` in
/// analyzer/print.c.
fn trim_string_padding(s: &str) -> &str {
    s.trim_end_matches(['\0', '@', ' ', '\u{ff}'])
}

fn decode_string_lz(data: &[u8], bit_offset: u32, bit_length: u32) -> FieldValue {
    let bo = bit_offset as usize;
    let bl = bit_length as usize;
    if bo & 7 != 0 {
        return FieldValue::Unsupported {
            field_type: "STRING_LZ (unaligned)",
        };
    }
    let start = bo / 8;
    if start >= data.len() {
        return FieldValue::NotAvailable;
    }
    // STRING_LZ format (canboat `fieldPrintStringLZ`): first byte is
    // the byte length of the content, then `len` bytes of payload,
    // then a NUL terminator. `bl` here is either the field's
    // declared bit width or 0 (BitLengthVariable → read to payload
    // end). Cap the embedded length to whatever's actually present.
    let region_end = if bl == 0 {
        data.len()
    } else {
        (start + bl / 8).min(data.len())
    };
    let len_byte = data[start] as usize;
    let content_start = start + 1;
    let max_avail = region_end.saturating_sub(content_start);
    let content_end = content_start + len_byte.min(max_avail);
    let raw = String::from_utf8_lossy(&data[content_start..content_end]);
    let trimmed = trim_string_padding(&raw);
    if trimmed.is_empty() {
        FieldValue::NotAvailable
    } else {
        FieldValue::String(trimmed.to_string())
    }
}

/// DYNAMIC_FIELD_KEY: decode the integer raw value and resolve it
/// through the field's `LookupFieldTypeEnumeration`. The resolved
/// entry is parked on the [`DecodeContext`] so the matching
/// DYNAMIC_FIELD_VALUE can read its type / bits / resolution / unit.
/// The output value mirrors a normal Lookup (number + resolved name).
fn decode_dynamic_field_key(
    f: &FieldInfo,
    data: &[u8],
    db: &PgnDatabase,
    bit_offset: u32,
    bit_length: u32,
    ctx: &mut DecodeContext,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let raw = ex.value as u64;
    let entry = f
        .lookup_field_type_enumeration
        .as_deref()
        .and_then(|n| db.field_type_lookup(n, raw));
    let name = entry.map(|e| e.name.clone());
    ctx.dynamic_field_type = entry.cloned();
    // Carry over canboat's "no resolution + reserved sentinel = N/A"
    // semantics so out-of-range keys decode as Unknown.
    if name.is_none() && is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    FieldValue::Lookup { value: raw, name }
}

/// DYNAMIC_FIELD_LENGTH: decode as a plain integer count of bytes
/// that the next DYNAMIC_FIELD_VALUE consumes.
fn decode_dynamic_field_length(
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    ctx: &mut DecodeContext,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, false, 0) else {
        return FieldValue::NotAvailable;
    };
    let len = ex.value as u32;
    ctx.dynamic_length_bytes = Some(len);
    FieldValue::Integer(len as i64)
}

/// DYNAMIC_FIELD_VALUE: read the resolved field-type metadata from
/// the context and decode the value using it. Falls back to a BINARY
/// dump (mirroring `fieldPrintKeyValue`'s `g_ftf == NULL` branch)
/// when the key wasn't resolved. Returns the value plus how many bits
/// it consumed so the iteration walker can advance correctly. Always
/// clears the dynamic-* slots in the context.
fn decode_dynamic_field_value(
    data: &[u8],
    bit_offset: u32,
    db: &PgnDatabase,
    ctx: &mut DecodeContext,
) -> (FieldValue, u32) {
    let entry = ctx.dynamic_field_type.take();
    let length_bits = ctx
        .dynamic_length_bytes
        .take()
        .map(|n| n * 8)
        .or_else(|| entry.as_ref().and_then(|e| e.bit_length()));
    // Mirror canboat's fieldPrintKeyValue: no resolved length and
    // no resolved field type → emit an empty BINARY blob (the
    // `g_length = 0, g_ftf = NULL, fieldPrintBinary(bits=0)` path
    // in print.c). Better than erroring out — this is how PGN
    // 130845 with an unknown SIMNET_KEY_VALUE key renders.
    let bits = length_bits.unwrap_or(0);
    let Some(entry) = entry else {
        // Unresolved key — render as a raw BINARY blob over the
        // declared length (zero bytes is fine, comes out as "").
        return (decode_binary(data, bit_offset, bits), bits);
    };
    let signed =
        entry.signed || matches!(entry.field_type.as_deref(), Some(ft) if ft.starts_with("FIX"));
    let val = match entry.field_type.as_deref() {
        Some(ft) if ft.starts_with("NUMBER") || ft.starts_with("FIX") || ft.starts_with("UFIX") => {
            decode_dynamic_number(data, bit_offset, bits, signed, &entry)
        }
        Some("LOOKUP") => match entry.lookup_enumeration.as_deref() {
            Some(name) => {
                let Some(ex) = extract_bits(data, bit_offset as usize, bits as usize, false, 0)
                else {
                    return (FieldValue::NotAvailable, bits);
                };
                let raw = ex.value as u64;
                let nm = db
                    .lookup(name)
                    .and_then(|t| t.get(raw))
                    .map(|v| v.name.clone());
                FieldValue::Lookup {
                    value: raw,
                    name: nm,
                }
            }
            None => decode_binary(data, bit_offset, bits),
        },
        Some("DURATION") | Some("TIME") => {
            // canboat C's lookup.h is what really decides DURATION
            // signedness: most entries are `DURATION_UFIX*` (unsigned,
            // e.g. Layline Time, Sailing Time to Waypoint, Sailing
            // ETA, Trip Time), with `DURATION_FIX*` (signed) reserved
            // for fields that genuinely carry negative values like
            // Race Timer / Timezone offset. The canboat.json
            // simplifies all of these to `"FieldType":"DURATION"`,
            // so we default to UNSIGNED and only flip to signed when
            // the lookup carries an explicit `Signed:true` or the
            // name is in the small set known to be signed in
            // canboat's pgn.h.
            let known_signed_duration =
                matches!(entry.name.as_str(), "Race Timer" | "Timezone offset");
            let want_signed = signed || known_signed_duration;
            // Always sentinel-check against the unsigned bit pattern,
            // even when the display interpretation is signed — canboat's
            // "all-ones" N/A marker is 0xFF..FF in the raw bytes,
            // regardless of how the value is shown.
            let Some(ex_unsigned) =
                extract_bits(data, bit_offset as usize, bits as usize, false, 0)
            else {
                return (FieldValue::NotAvailable, bits);
            };
            if is_unavailable(ex_unsigned) {
                FieldValue::NotAvailable
            } else {
                let ex = if want_signed {
                    match extract_bits(data, bit_offset as usize, bits as usize, true, 0) {
                        Some(e) => e,
                        None => return (FieldValue::NotAvailable, bits),
                    }
                } else {
                    ex_unsigned
                };
                let res = entry.resolution.unwrap_or(1.0);
                FieldValue::Time {
                    raw: ex.value,
                    seconds: ex.value as f64 * res,
                }
            }
        }
        Some("DATE") => {
            let Some(ex) = extract_bits(data, bit_offset as usize, bits as usize, false, 0) else {
                return (FieldValue::NotAvailable, bits);
            };
            if is_unavailable(ex) {
                FieldValue::NotAvailable
            } else {
                FieldValue::Date(ex.value as u16)
            }
        }
        _ => decode_binary(data, bit_offset, bits),
    };
    (val, bits)
}

fn decode_dynamic_number(
    data: &[u8],
    bit_offset: u32,
    bit_length: u32,
    signed: bool,
    entry: &crate::types::LookupFieldTypeValue,
) -> FieldValue {
    let Some(ex) = extract_bits(data, bit_offset as usize, bit_length as usize, signed, 0) else {
        return FieldValue::NotAvailable;
    };
    if is_unavailable(ex) {
        return FieldValue::NotAvailable;
    }
    let raw = ex.value as f64;
    let res = entry.resolution.unwrap_or(1.0);
    if res == 1.0 && entry.unit.is_none() {
        FieldValue::Integer(ex.value)
    } else {
        FieldValue::Number(raw * res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PgnDatabase;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn db() -> &'static PgnDatabase {
        static DB: OnceLock<PgnDatabase> = OnceLock::new();
        DB.get_or_init(|| {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let path = manifest
                .parent()
                .and_then(|p| p.parent())
                .unwrap()
                .join("data")
                .join("canboat.json");
            PgnDatabase::load(path).expect("load canboat.json")
        })
    }

    #[test]
    fn decodes_iso_address_claim() {
        // From canboat/analyzer/tests/pgn-test.in:
        //   2022-09-10T12:10:16.614Z,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0
        // Expected (per pgn-test.out): Unique Number=1088507,
        // Manufacturer Code=Navico (275), Device Function=Rudder (155).
        let data = smallvec::smallvec![0xfb, 0x9b, 0x70, 0x22, 0x00, 0x9b, 0x50, 0xc0];
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 60928,
            src: 5,
            dst: 255,
            data,
        };
        let dec = db().decode(&frame).expect("decode");
        assert_eq!(&*dec.id, "isoAddressClaim");
        assert_eq!(dec.fields.len(), 10);

        // Field 1: Unique Number (21-bit unsigned) = 1088507.
        match dec.fields[0].value {
            FieldValue::Integer(v) => assert_eq!(v, 1_088_507),
            ref other => panic!("expected integer, got {other:?}"),
        }
        // Field 2: Manufacturer Code (11-bit LOOKUP) = 275 / Navico.
        match &dec.fields[1].value {
            FieldValue::Lookup { value, name } => {
                assert_eq!(*value, 275);
                assert_eq!(name.as_deref(), Some("Navico"));
            }
            other => panic!("expected lookup, got {other:?}"),
        }
        // Field 5: Device Function (8-bit LOOKUP→INDIRECT) = 155 / Rudder.
        match &dec.fields[4].value {
            FieldValue::Lookup { value, .. } => assert_eq!(*value, 155),
            other => panic!("expected lookup, got {other:?}"),
        }
    }

    #[test]
    fn unknown_pgn_below_any_fallback_returns_error() {
        // PGN 1 is below the lowest Fallback (59392) so no catchall
        // applies — decode must report UnknownPgn.
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 1,
            src: 1,
            dst: 255,
            data: smallvec::smallvec![0u8; 8],
        };
        assert!(matches!(
            db().decode(&frame),
            Err(DecodeError::UnknownPgn { pgn: 1 })
        ));
    }

    #[test]
    fn match_variant_beats_fallback_listed_first() {
        // PGN 126208 has the FALLBACK variant first in JSON, then 7
        // specific variants distinguished by Function Code (field 1,
        // 8 bits at offset 0). Function Code = 3 must select
        // nmeaReadFieldsGroupFunction, NOT the leading fallback.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![
            3, // Function Code = 3 → Read Fields
            0, 0, 0, 0, 0, 0, 0,
        ];
        let frame = RawFrame {
            timestamp: None,
            prio: 3,
            pgn: 126208,
            src: 0,
            dst: 0,
            data,
        };
        let picked = db().pick_variant(&frame).expect("variant");
        assert_eq!(&*picked.id, "nmeaReadFieldsGroupFunction");
    }

    #[test]
    fn fallback_when_no_specific_variant_matches() {
        // PGN 126208 with Function Code = 99 (none of the 0..6
        // specific variants match) → return the listed fallback.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![99, 0, 0, 0, 0, 0, 0, 0];
        let frame = RawFrame {
            timestamp: None,
            prio: 3,
            pgn: 126208,
            src: 0,
            dst: 0,
            data,
        };
        let picked = db().pick_variant(&frame).expect("variant");
        assert!(
            picked.fallback.unwrap_or(false),
            "expected Fallback variant, got id={}",
            picked.id
        );
    }

    #[test]
    fn cross_pgn_catchall_for_unknown_proprietary() {
        // PGN 65500 is not defined in canboat.json. The latest
        // Fallback:true PGN with pgn <= 65500 covers it — that's
        // 65280 / "0xff000xffffManufacturerProprietarySingleFrameNonAddressed".
        let frame = RawFrame {
            timestamp: None,
            prio: 6,
            pgn: 65500,
            src: 0,
            dst: 255,
            data: smallvec::smallvec![0u8; 8],
        };
        let picked = db().pick_variant(&frame).expect("catchall");
        assert!(picked.fallback.unwrap_or(false));
        assert_eq!(picked.pgn, 65280);
    }

    #[test]
    fn not_available_sentinel_on_all_ones() {
        // PGN 127245 Rudder: first field is Instance (8 bits). 0xFF is
        // the unavailable sentinel.
        let data: smallvec::SmallVec<[u8; 8]> = smallvec::smallvec![0xff; 8];
        let frame = RawFrame {
            timestamp: None,
            prio: 2,
            pgn: 127245,
            src: 0,
            dst: 255,
            data,
        };
        let dec = db().decode(&frame).expect("decode");
        let instance = &dec.fields[0];
        assert!(matches!(instance.value, FieldValue::NotAvailable));
    }
}
