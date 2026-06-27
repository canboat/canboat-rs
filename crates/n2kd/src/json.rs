//! Minimal JSON-value extraction by substring scan. Matches the
//! pragmatic style canboat's C `getJSONValue` uses — we never need a
//! real parser because the analyzer's output is line-delimited and
//! has a known shape.
//!
//! Functions here return owned values (or `None`) so the caller can
//! consume them without borrow gymnastics.

/// Pull `"<field>":<value>` out of `msg`. Returns the value as a
/// borrowed slice with any surrounding quotes stripped. Skips
/// whitespace between `:` and the value. Returns `None` if the
/// field isn't present.
pub fn value<'a>(msg: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\":");
    let mut start = msg.find(&needle)? + needle.len();
    let bytes = msg.as_bytes();
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    if start >= bytes.len() {
        return None;
    }
    // Strings are delimited by `"`; numbers / true / false / null
    // end at the first `,` or `}`. Nested objects are bounded by
    // matching braces — `Lookup` shows up as `{"value":N,"name":"…"}`,
    // so we balance.
    let quoted = bytes[start] == b'"';
    if quoted {
        let body_start = start + 1;
        let mut idx = body_start;
        while idx < bytes.len() && bytes[idx] != b'"' {
            // Skip JSON escapes — but escape sequences are rare in
            // analyzer output (no embedded quotes inside strings we
            // care about). Keep it simple.
            if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
                idx += 2;
                continue;
            }
            idx += 1;
        }
        return Some(&msg[body_start..idx]);
    }
    // Object? Walk the brace depth.
    if bytes[start] == b'{' {
        let mut depth = 0;
        let mut idx = start;
        while idx < bytes.len() {
            match bytes[idx] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&msg[start..=idx]);
                    }
                }
                _ => {}
            }
            idx += 1;
        }
        return None;
    }
    // Array? Walk the bracket depth.
    if bytes[start] == b'[' {
        let mut depth = 0;
        let mut idx = start;
        while idx < bytes.len() {
            match bytes[idx] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&msg[start..=idx]);
                    }
                }
                _ => {}
            }
            idx += 1;
        }
        return None;
    }
    // Bare value: number / bool / null. End on `,` or `}` or whitespace.
    let mut idx = start;
    while idx < bytes.len() && !matches!(bytes[idx], b',' | b'}' | b' ' | b'\t' | b'\n' | b'\r') {
        idx += 1;
    }
    Some(&msg[start..idx])
}

/// Like [`value`], but parse the result as an `f64`. `null` / missing
/// → `None`.
pub fn number(msg: &str, field: &str) -> Option<f64> {
    let v = value(msg, field)?;
    if v == "null" || v.is_empty() {
        return None;
    }
    // canboat -nv puts lookup values inside `{"value":N,"name":"…"}`.
    if v.starts_with('{') {
        return number(v, "value");
    }
    v.trim().parse().ok()
}

/// Parse the field as a signed integer.
pub fn int(msg: &str, field: &str) -> Option<i64> {
    let v = value(msg, field)?;
    if v.starts_with('{') {
        return int(v, "value");
    }
    v.trim().parse().ok()
}

/// Resolve a lookup-style field — accepts either the bare string
/// (canboat default JSON) or the `{value,name}` shape from `-nv`.
/// Returns the integer code.
pub fn lookup_int(msg: &str, field: &str) -> Option<i64> {
    // Try the `{value, name}` form first.
    if let Some(obj) = value(msg, field) {
        if obj.starts_with('{') {
            return int(obj, "value");
        }
        // Bare integer?
        if let Ok(n) = obj.trim().parse() {
            return Some(n);
        }
    }
    None
}

/// Pull the rendered text of a field. For `-nv` lookup objects this
/// is the `name`; for plain JSON it's the bare value. Returns the
/// substring unchanged when the analyzer has already rendered it as
/// a string (e.g. dates / times in `-nv` mode are `{"value":N,"name":"…"}`
/// where the canonical text is in `name`).
pub fn value_or_name<'a>(msg: &'a str, field: &str) -> Option<&'a str> {
    let v = value(msg, field)?;
    if v.starts_with('{') {
        return value(v, "name");
    }
    Some(v)
}

/// Resolve `field`'s readable text following canboat C n2kd's
/// secondary-key extraction (`n2kd/main.c:1022-1067`):
///
/// 1. If the field's value is a lookup object `{"value":N,"name":"X"}`,
///    prefer `name`; otherwise fall back to `value` (so `"Instance":
///    {"value":0,"key":true}` resolves to `"0"`).
/// 2. Truncate the result at the first ASCII whitespace — so
///    `"True (ground referenced to North)"` becomes `"True"`. This
///    is how C collapses long readable names into a stable cache
///    suffix and matches its `<src>_<secondary>` snapshot keys.
pub fn lookup_text<'a>(msg: &'a str, field: &str) -> Option<&'a str> {
    let v = value(msg, field)?;
    let raw = if v.starts_with('{') {
        value(v, "name").or_else(|| value(v, "value"))?
    } else {
        v
    };
    let end = raw.find(char::is_whitespace).unwrap_or(raw.len());
    Some(&raw[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_number() {
        let m = r#"{"pgn":127251,"src":7,"fields":{"Rate":-0.357703}}"#;
        assert_eq!(int(m, "pgn"), Some(127251));
        assert_eq!(int(m, "src"), Some(7));
        assert_eq!(number(m, "Rate"), Some(-0.357703));
    }

    #[test]
    fn extracts_string() {
        let m = r#"{"timestamp":"2026-01-01","fields":{"Reference":"Magnetic"}}"#;
        assert_eq!(value(m, "timestamp"), Some("2026-01-01"));
        assert_eq!(value(m, "Reference"), Some("Magnetic"));
    }

    #[test]
    fn handles_nv_lookup_object() {
        let m = r#"{"fields":{"Reference":{"value":1,"name":"Magnetic"}}}"#;
        assert_eq!(int(m, "Reference"), Some(1));
        assert_eq!(lookup_int(m, "Reference"), Some(1));
    }

    #[test]
    fn missing_returns_none() {
        let m = r#"{"foo":1}"#;
        assert_eq!(value(m, "bar"), None);
        assert_eq!(number(m, "bar"), None);
    }

    #[test]
    fn lookup_text_prefers_name() {
        let m = r#"{"Reference":{"value":1,"name":"Magnetic"}}"#;
        assert_eq!(lookup_text(m, "Reference"), Some("Magnetic"));
    }

    #[test]
    fn lookup_text_falls_back_to_value_when_no_name() {
        // PGN 127501 Instance is `{"value":N,"key":true}` — no name.
        let m = r#"{"Instance":{"value":0,"key":true}}"#;
        assert_eq!(lookup_text(m, "Instance"), Some("0"));
    }

    #[test]
    fn lookup_text_truncates_at_first_whitespace() {
        // canboat C collapses long readable names at the first space —
        // see the e=strchr(s,' ') / e2=strchr(s,'"') logic in
        // n2kd/main.c:1064.
        let m = r#"{"Reference":{"value":0,"name":"True (ground referenced to North)","key":true}}"#;
        assert_eq!(lookup_text(m, "Reference"), Some("True"));
    }

    #[test]
    fn lookup_text_returns_bare_value_when_no_object() {
        let m = r#"{"User ID":"244180106"}"#;
        assert_eq!(lookup_text(m, "User ID"), Some("244180106"));
    }
}
