//! Canboat PGN database types.
//!
//! These mirror the structure of `canboat.json`. Field names match the
//! JSON (PascalCase) via serde rename. Everything optional in the JSON
//! is `Option<_>` here.

use serde::{Deserialize, Deserializer};

/// Accept either a string or a numeric value as a string.
/// canboat.json occasionally has integer-valued `Description` fields
/// (data-quality wart upstream); coerce them to text rather than failing.
fn de_loose_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    use serde_json::Value;
    let v = Option::<Value>::deserialize(d)?;
    Ok(match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        Some(other) => Some(other.to_string()),
    })
}

/// How a PGN is transmitted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum PacketType {
    Single,
    Fast,
    #[serde(rename = "ISO")]
    Iso,
    Mixed,
}

/// All field types found in `canboat.json`.
///
/// We deserialize from the JSON's screaming-snake names directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum FieldType {
    #[serde(rename = "NUMBER")]
    Number,
    #[serde(rename = "DECIMAL")]
    Decimal,
    #[serde(rename = "FLOAT")]
    Float,
    #[serde(rename = "BINARY")]
    Binary,
    #[serde(rename = "LOOKUP")]
    Lookup,
    #[serde(rename = "BITLOOKUP")]
    BitLookup,
    #[serde(rename = "INDIRECT_LOOKUP")]
    IndirectLookup,
    #[serde(rename = "DATE")]
    Date,
    #[serde(rename = "TIME")]
    Time,
    #[serde(rename = "DURATION")]
    Duration,
    #[serde(rename = "STRING_FIX")]
    StringFix,
    #[serde(rename = "STRING_LZ")]
    StringLz,
    #[serde(rename = "STRING_LAU")]
    StringLau,
    #[serde(rename = "VARIABLE")]
    Variable,
    #[serde(rename = "MMSI")]
    Mmsi,
    #[serde(rename = "PGN")]
    Pgn,
    #[serde(rename = "ISO_NAME")]
    IsoName,
    #[serde(rename = "RESERVED")]
    Reserved,
    #[serde(rename = "SPARE")]
    Spare,
    #[serde(rename = "DYNAMIC_FIELD_KEY")]
    DynamicFieldKey,
    #[serde(rename = "DYNAMIC_FIELD_LENGTH")]
    DynamicFieldLength,
    #[serde(rename = "DYNAMIC_FIELD_VALUE")]
    DynamicFieldValue,
    #[serde(rename = "FIELD_INDEX")]
    FieldIndex,
}

/// A single field within a PGN definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FieldInfo {
    pub order: u8,
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "de_loose_string")]
    pub description: Option<String>,
    pub bit_length: Option<u32>,
    /// Reference to another field whose value carries this field's bit
    /// length at runtime. Upstream encodes this as either the target
    /// field's `Id` (string) or `Order` (integer).
    #[serde(default, deserialize_with = "de_loose_string")]
    pub bit_length_field: Option<String>,
    pub bit_length_variable: Option<bool>,
    /// Absent on conditional alternative fields (`Condition` is set).
    pub bit_offset: Option<u32>,
    pub bit_start: Option<u32>,
    pub resolution: Option<f64>,
    pub signed: Option<bool>,
    pub offset: Option<i64>,
    pub range_min: Option<f64>,
    pub range_max: Option<f64>,
    pub unit: Option<String>,
    pub physical_quantity: Option<String>,
    pub field_type: Option<FieldType>,
    pub lookup_enumeration: Option<String>,
    pub lookup_bit_enumeration: Option<String>,
    pub lookup_indirect_enumeration: Option<String>,
    pub lookup_indirect_enumeration_field_order: Option<u8>,
    pub lookup_field_type_enumeration: Option<String>,
    /// Manufacturer-variant disambiguation: PGNs with multiple definitions
    /// are distinguished by required raw field values.
    #[serde(rename = "Match")]
    pub match_value: Option<i64>,
    pub part_of_primary_key: Option<bool>,
    pub condition: Option<String>,
    /// Additive offset applied at decode time AFTER multiplying by
    /// `resolution`. Set by the load-time unit fix-up (e.g. K → °C
    /// subtracts 273.15). Not present in canboat.json.
    #[serde(skip, default)]
    pub unit_offset: f64,
    /// Explicit decimal precision override, set by the load-time unit
    /// fix-up. `0` means "compute from resolution" (canboat default).
    #[serde(skip, default)]
    pub precision: u8,
}

/// A PGN definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PgnInfo {
    #[serde(rename = "PGN")]
    pub pgn: u32,
    pub id: String,
    pub description: String,
    pub explanation: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "Type")]
    pub packet_type: PacketType,
    pub complete: Option<bool>,
    pub fallback: Option<bool>,
    pub missing: Option<Vec<String>>,
    pub priority: Option<u8>,
    pub transmission_interval: Option<u32>,
    pub transmission_irregular: Option<bool>,
    pub field_count: u32,
    pub length: Option<u32>,
    pub min_length: Option<u32>,
    pub fields: Vec<FieldInfo>,
    pub repeating_field_set1_size: Option<u32>,
    pub repeating_field_set1_start_field: Option<u32>,
    pub repeating_field_set1_count_field: Option<u32>,
    pub repeating_field_set2_size: Option<u32>,
    pub repeating_field_set2_start_field: Option<u32>,
    pub repeating_field_set2_count_field: Option<u32>,
}

/// A value/name pair inside a regular LOOKUP enumeration.
#[derive(Debug, Clone, Deserialize)]
pub struct LookupValue {
    #[serde(rename = "Value")]
    pub value: u64,
    #[serde(rename = "Name")]
    pub name: String,
    /// Optional NMEA-style identifier (machine-readable form).
    #[serde(rename = "Id")]
    pub id: Option<String>,
}

/// A named LOOKUP enumeration (plain value → name).
#[derive(Debug, Clone, Deserialize)]
pub struct LookupTable {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MaxValue")]
    pub max_value: Option<u64>,
    #[serde(rename = "EnumValues")]
    pub values: Vec<LookupValue>,
    /// `value → index into self.values`. Built once after deserialise
    /// so the per-field LOOKUP decode is O(1) instead of a linear
    /// scan through every entry; populated by
    /// [`PgnDatabase::finalize_lookups`].
    #[serde(skip, default)]
    pub(crate) by_value: std::collections::HashMap<u64, u32>,
}

impl LookupTable {
    /// `Some(&LookupValue)` if `value` is in the enum, else `None`.
    /// O(1) average-case lookup via the precomputed index.
    pub fn get(&self, value: u64) -> Option<&LookupValue> {
        let idx = *self.by_value.get(&value)?;
        self.values.get(idx as usize)
    }
}

/// A bit/name pair inside a BITLOOKUP enumeration.
#[derive(Debug, Clone, Deserialize)]
pub struct BitLookupValue {
    #[serde(rename = "Bit")]
    pub bit: u8,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Id")]
    pub id: Option<String>,
}

/// A BITLOOKUP enumeration (each set bit has a name).
#[derive(Debug, Clone, Deserialize)]
pub struct BitLookupTable {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MaxValue")]
    pub max_value: Option<u64>,
    #[serde(rename = "EnumBitValues")]
    pub values: Vec<BitLookupValue>,
    /// `bit → index into self.values`. See [`LookupTable::by_value`].
    #[serde(skip, default)]
    pub(crate) by_bit: std::collections::HashMap<u8, u32>,
}

impl BitLookupTable {
    pub fn get(&self, bit: u8) -> Option<&BitLookupValue> {
        let idx = *self.by_bit.get(&bit)?;
        self.values.get(idx as usize)
    }
}

/// One (Value1, Value2) → Name mapping inside an INDIRECT_LOOKUP table.
#[derive(Debug, Clone, Deserialize)]
pub struct IndirectLookupValue {
    #[serde(rename = "Value1")]
    pub value1: u64,
    #[serde(rename = "Value2")]
    pub value2: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Id")]
    pub id: Option<String>,
}

/// A two-key lookup (INDIRECT_LOOKUP). Resolved by looking up
/// `(value1, value2)` where `value1` is the raw value of the field
/// pointed to by [`FieldInfo::lookup_indirect_enumeration_field_order`].
#[derive(Debug, Clone, Deserialize)]
pub struct IndirectLookupTable {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MaxValue")]
    pub max_value: Option<u64>,
    #[serde(rename = "EnumValues")]
    pub values: Vec<IndirectLookupValue>,
    /// `(value1, value2) → index into self.values`. See
    /// [`LookupTable::by_value`].
    #[serde(skip, default)]
    pub(crate) by_pair: std::collections::HashMap<(u64, u64), u32>,
}

impl IndirectLookupTable {
    pub fn get(&self, value1: u64, value2: u64) -> Option<&IndirectLookupValue> {
        let idx = *self.by_pair.get(&(value1, value2))?;
        self.values.get(idx as usize)
    }
}

/// One key→field-type entry inside a [`LookupFieldTypeTable`]. The
/// upstream `Bits` field is a stringified integer in canboat.json, so
/// parse via [`de_loose_string`] then convert in the accessor.
#[derive(Debug, Clone, Deserialize)]
pub struct LookupFieldTypeValue {
    #[serde(rename = "value")]
    pub value: u64,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "FieldType")]
    pub field_type: Option<String>,
    /// Field width in bits — encoded as a string in canboat.json.
    #[serde(rename = "Bits", default, deserialize_with = "de_loose_string")]
    pub bits: Option<String>,
    #[serde(rename = "Resolution")]
    pub resolution: Option<f64>,
    #[serde(rename = "Unit")]
    pub unit: Option<String>,
    #[serde(rename = "LookupEnumeration")]
    pub lookup_enumeration: Option<String>,
    #[serde(rename = "LookupBitEnumeration")]
    pub lookup_bit_enumeration: Option<String>,
    /// Signedness inferred from the unit at load time. Canboat.json
    /// strips the FIX-vs-UFIX distinction from these table entries
    /// (everything renders as `FieldType: NUMBER`), so we fall back
    /// to a unit-based heuristic: angle / angular-velocity units are
    /// signed; the others default to unsigned. Mirrors canboat C's
    /// ANGLE_FIX16-style underlying type.
    #[serde(skip, default)]
    pub signed: bool,
    /// Display precision override applied at load time by the same
    /// non-SI unit fix-up that updates [`Self::resolution`] and
    /// [`Self::unit`] (e.g. rad → deg pins precision at 1). `0` means
    /// "compute from resolution".
    #[serde(skip, default)]
    pub precision: u8,
}

impl LookupFieldTypeValue {
    /// Field width in bits parsed from `Bits` (stringly typed upstream).
    pub fn bit_length(&self) -> Option<u32> {
        self.bits.as_deref().and_then(|s| s.parse().ok())
    }
}

/// A LookupFieldTypeEnumeration — maps a key value to a field type
/// (and its display metadata). Used by DYNAMIC_FIELD_KEY /
/// DYNAMIC_FIELD_VALUE pairs in PGNs like 130824 ("B&G: key-value
/// data") to resolve a heterogeneous value field at decode time.
#[derive(Debug, Clone, Deserialize)]
pub struct LookupFieldTypeTable {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MaxValue")]
    pub max_value: Option<u64>,
    #[serde(rename = "EnumFieldTypeValues")]
    pub values: Vec<LookupFieldTypeValue>,
    /// `value → index into self.values`. See [`LookupTable::by_value`].
    #[serde(skip, default)]
    pub(crate) by_value: std::collections::HashMap<u64, u32>,
}

impl LookupFieldTypeTable {
    pub fn get(&self, value: u64) -> Option<&LookupFieldTypeValue> {
        let idx = *self.by_value.get(&value)?;
        self.values.get(idx as usize)
    }
}
