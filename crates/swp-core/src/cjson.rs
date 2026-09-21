//! Canonical JSON: the single serialization that manifest signatures are
//! computed over. Determinism here is a correctness requirement — two builds
//! of SWP-1 must produce byte-identical signed bytes for the same logical
//! manifest, or every release record becomes unverifiable across upgrades.
//!
//! Rules (also stated in docs/SWP-1-SPEC.md):
//! - object keys sorted by UTF-8 byte value, no other reordering;
//! - arrays keep their order;
//! - no insignificant whitespace at all;
//! - integers only — a float anywhere in a signed document is rejected rather
//!   than rounded, because float formatting is the classic cross-platform drift;
//! - strings escaped minimally: `"`, `\`, and control characters below 0x20 as
//!   `\u00XX`; every other code point emitted as raw NFC UTF-8;
//! - no BOM, no trailing newline inside the signed bytes.

use serde_json::{Map, Number, Value};

use crate::error::{ErrorCode, SwpError};
use crate::text::nfc;

/// Serialize a value to canonical JSON bytes.
pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, SwpError> {
    let v = serde_json::to_value(value)
        .map_err(|e| SwpError::internal(format!("value is not JSON-serializable: {e}")))?;
    encode_value(&v)
}

/// Serialize an already-built `Value`.
pub fn encode_value(value: &Value) -> Result<Vec<u8>, SwpError> {
    let mut out = Vec::new();
    write_value(value, &mut out, "$")?;
    Ok(out)
}

/// Parse JSON into a `Value`, then re-encode it and report whether the input
/// was already canonical. Used by `swp inspect` to explain a signature
/// mismatch that is only a formatting difference.
pub fn is_canonical(bytes: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => encode_value(&v).map(|c| c == bytes).unwrap_or(false),
        Err(_) => false,
    }
}

fn write_value(value: &Value, out: &mut Vec<u8>, path: &str) -> Result<(), SwpError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => write_number(n, out, path)?,
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out, &format!("{path}[{i}]"))?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&map[k.as_str()], out, &format!("{path}.{k}"))?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(n: &Number, out: &mut Vec<u8>, path: &str) -> Result<(), SwpError> {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    Err(SwpError::new(
        ErrorCode::InvalidManifest,
        format!(
            "signed documents must not contain non-integer numbers (found {n} at {path}); \
             use an integer count or a string"
        ),
    ))
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn normalize_in_place(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let taken = std::mem::take(map);
            let mut entries: Vec<(String, Value)> = taken.into_iter().collect();
            for (_, val) in entries.iter_mut() {
                normalize_in_place(val);
            }
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            let mut m = Map::new();
            for (k, val) in entries {
                m.insert(nfc(&k), val);
            }
            *map = m;
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_in_place),
        _ => {}
    }
}

/// Sort keys of an object we are about to sign, defensively, when the caller
/// built the document as a `Value` rather than a typed struct.
pub fn normalize_object(v: Value) -> Value {
    let mut v = v;
    normalize_in_place(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn key_order_does_not_change_output() {
        let mut a = Map::new();
        a.insert("z".into(), Value::from(1));
        a.insert("a".into(), Value::from(2));
        let mut b = Map::new();
        b.insert("a".into(), Value::from(2));
        b.insert("z".into(), Value::from(1));
        let ea = encode_value(&Value::Object(a)).unwrap();
        let eb = encode_value(&Value::Object(b)).unwrap();
        assert_eq!(ea, eb);
        assert_eq!(std::str::from_utf8(&ea).unwrap(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn nested_objects_and_arrays_are_canonical_and_compact() {
        let v: Value =
            serde_json::from_str(r#"{ "b": [3, {"y": 1, "x": null}], "a": true }"#).unwrap();
        assert_eq!(
            std::str::from_utf8(&encode_value(&v).unwrap()).unwrap(),
            r#"{"a":true,"b":[3,{"x":null,"y":1}]}"#
        );
    }

    #[test]
    fn floats_are_rejected() {
        let v: Value = serde_json::from_str(r#"{"pi":3.14}"#).unwrap();
        let e = encode_value(&v).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidManifest);
        assert!(e.message().contains("non-integer"));
    }

    #[test]
    fn control_characters_and_unicode_are_encoded() {
        let mut m = Map::new();
        m.insert("k".into(), Value::String("a\u{1}bé＝".into()));
        let out = String::from_utf8(encode_value(&Value::Object(m)).unwrap()).unwrap();
        // Below-0x20 controls are escaped; everything printable, including
        // U+007F and non-ASCII, is emitted as raw UTF-8 (never \u escapes,
        // which would make the same string encode two ways).
        assert_eq!(out, "{\"k\":\"a\\u0001bé＝\"}");
        assert!(is_canonical(out.as_bytes()));
    }

    #[test]
    fn i64_and_negative_numbers_survive() {
        #[derive(Serialize)]
        struct S {
            n: i64,
            u: u64,
        }
        let out = encode(&S {
            n: -9007199254740993,
            u: u64::MAX,
        })
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"n":-9007199254740993,"u":18446744073709551615}"#
        );
    }

    #[test]
    fn canonically_encoded_documents_are_detected_as_such() {
        let good = br#"{"a":1,"b":[2,3]}"#;
        assert!(is_canonical(good));
        assert!(!is_canonical(br#"{"b":[2,3],"a":1}"#));
        assert!(!is_canonical(br#"not json"#));
    }
}
