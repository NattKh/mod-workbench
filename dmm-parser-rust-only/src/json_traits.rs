// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! JSON serialization traits using `serde_json::Value`.
//!
//! Why this exists: Python consumers of crimson-rs use `parse_iteminfo_from_bytes`
//! and `serialize_iteminfo` which round-trip through dicts. Rust consumers (e.g.
//! DMM, a Tauri app with no embedded Python) need the same dict-style mutation
//! shape without paying for a Python interpreter. This module gives them that
//! by mirroring every `ToPyValue` / `WritePyValue` impl with
//! `ToJsonValue` / `WriteJsonValue` against `serde_json::Value`.
//!
//! The `py_binary_struct!` macro generates `to_json_dict()` and
//! `write_from_json_dict()` methods that parallel `to_py_dict()` and
//! `write_from_py_dict()`. Field names match the Python dict spec verbatim so
//! mod authors writing v3 files don't need to know which language a manager
//! uses.
//!
//! All numeric types serialize as JSON numbers. `u64` and `i64` rely on
//! serde_json::Number's full integer range (it stores them losslessly even
//! though JSON proper has no integer type).

use serde_json::{json, Map, Value};
use std::io;

use crate::binary::{CArray, COptional, CString, LocalizableString};

// ── Traits ────────────────────────────────────────────────────────────────────

/// Convert a parsed binary value into a JSON value. Mirrors `ToPyValue`.
/// Output shape matches the Python dict shape so v3 mod files written
/// against the spec resolve identically.
pub trait ToJsonValue {
    fn to_json_value(&self) -> Value;
}

/// Read a JSON value and write the binary form of its underlying type.
/// Mirrors `WritePyValue`. Returns `io::Error` on shape mismatch (wrong
/// type, missing field, out-of-range integer) so callers can surface the
/// failure with a path before bailing out of a whole-record encode.
pub trait WriteJsonValue {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()>;
}

// ── Field lookup helper for generated dict writers ────────────────────────────

/// Pull a field out of a JSON object, returning a clear error if it's
/// missing. The generated `write_from_json_dict` calls this once per
/// declared struct field — matches Python's `get_field` behavior.
pub fn get_field<'a>(d: &'a Map<String, Value>, key: &str) -> io::Result<&'a Value> {
    d.get(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing JSON field '{}'", key),
        )
    })
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn err<T>(msg: String) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, msg))
}

// ── Primitives ────────────────────────────────────────────────────────────────

impl ToJsonValue for u8 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for u8 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let n = v
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                format!("expected u8 number, got {}", type_name(v))))?;
        if n > u8::MAX as u64 {
            return err(format!("value {} out of u8 range", n));
        }
        w.push(n as u8);
        Ok(())
    }
}

impl ToJsonValue for u16 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for u16 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let n = v
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                format!("expected u16 number, got {}", type_name(v))))?;
        if n > u16::MAX as u64 {
            return err(format!("value {} out of u16 range", n));
        }
        w.extend_from_slice(&(n as u16).to_le_bytes());
        Ok(())
    }
}

impl ToJsonValue for u32 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for u32 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let n = v
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                format!("expected u32 number, got {}", type_name(v))))?;
        if n > u32::MAX as u64 {
            return err(format!("value {} out of u32 range", n));
        }
        w.extend_from_slice(&(n as u32).to_le_bytes());
        Ok(())
    }
}

impl ToJsonValue for u64 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for u64 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        // u64 may exceed i64::MAX where JS-side encoders downgrade to
        // string. Accept either form so spec-compliant writers stay
        // compatible with mod files round-tripped through web tooling.
        let n = match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        };
        let n = n.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected u64 number/string, got {}", type_name(v))))?;
        w.extend_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

impl ToJsonValue for i8 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for i8 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let n = v
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                format!("expected i8 number, got {}", type_name(v))))?;
        if !(i8::MIN as i64..=i8::MAX as i64).contains(&n) {
            return err(format!("value {} out of i8 range", n));
        }
        w.extend_from_slice(&(n as i8).to_le_bytes());
        Ok(())
    }
}

impl ToJsonValue for i64 {
    fn to_json_value(&self) -> Value {
        Value::from(*self)
    }
}
impl WriteJsonValue for i64 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let n = match v {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        };
        let n = n.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected i64 number/string, got {}", type_name(v))))?;
        w.extend_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

impl ToJsonValue for f32 {
    fn to_json_value(&self) -> Value {
        Value::from(*self as f64)
    }
}
impl WriteJsonValue for f32 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let f = v
            .as_f64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                format!("expected f32 number, got {}", type_name(v))))?;
        w.extend_from_slice(&(f as f32).to_le_bytes());
        Ok(())
    }
}

// ── Fixed-size arrays ─────────────────────────────────────────────────────────
// [u8; N] base64 impl lives in `binary/arrays.rs` (predates this module).

impl ToJsonValue for [f32; 2] {
    fn to_json_value(&self) -> Value {
        Value::Array(self.iter().map(|x| Value::from(*x as f64)).collect())
    }
}
impl WriteJsonValue for [f32; 2] {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array of 2 f32, got {}", type_name(v))))?;
        if arr.len() != 2 {
            return err(format!("expected 2 elements for [f32; 2], got {}", arr.len()));
        }
        for elem in arr {
            f32::write_from_json(w, elem)?;
        }
        Ok(())
    }
}

impl ToJsonValue for [f32; 3] {
    fn to_json_value(&self) -> Value {
        Value::Array(self.iter().map(|x| Value::from(*x as f64)).collect())
    }
}
impl WriteJsonValue for [f32; 3] {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array of 3 f32, got {}", type_name(v))))?;
        if arr.len() != 3 {
            return err(format!("expected 3 elements for [f32; 3], got {}", arr.len()));
        }
        for elem in arr {
            f32::write_from_json(w, elem)?;
        }
        Ok(())
    }
}

impl ToJsonValue for [f32; 4] {
    fn to_json_value(&self) -> Value {
        Value::Array(self.iter().map(|x| Value::from(*x as f64)).collect())
    }
}
impl WriteJsonValue for [f32; 4] {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array of 4 f32, got {}", type_name(v))))?;
        if arr.len() != 4 {
            return err(format!("expected 4 elements for [f32; 4], got {}", arr.len()));
        }
        for elem in arr {
            f32::write_from_json(w, elem)?;
        }
        Ok(())
    }
}

impl ToJsonValue for [u32; 2] {
    fn to_json_value(&self) -> Value {
        Value::Array(self.iter().map(|x| Value::from(*x)).collect())
    }
}
impl WriteJsonValue for [u32; 2] {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array of 2 u32, got {}", type_name(v))))?;
        if arr.len() != 2 {
            return err(format!("expected 2 elements for [u32; 2], got {}", arr.len()));
        }
        for elem in arr {
            u32::write_from_json(w, elem)?;
        }
        Ok(())
    }
}

impl ToJsonValue for [u32; 4] {
    fn to_json_value(&self) -> Value {
        Value::Array(self.iter().map(|x| Value::from(*x)).collect())
    }
}
impl WriteJsonValue for [u32; 4] {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array of 4 u32, got {}", type_name(v))))?;
        if arr.len() != 4 {
            return err(format!("expected 4 elements for [u32; 4], got {}", arr.len()));
        }
        for elem in arr {
            u32::write_from_json(w, elem)?;
        }
        Ok(())
    }
}

// ── CString ───────────────────────────────────────────────────────────────────

impl ToJsonValue for CString<'_> {
    fn to_json_value(&self) -> Value {
        if std::str::from_utf8(self.raw).is_ok() {
            Value::String(self.data.to_string())
        } else {
            use base64::Engine;
            Value::String(format!("b64:{}", base64::engine::general_purpose::STANDARD.encode(self.raw)))
        }
    }
}
impl WriteJsonValue for CString<'_> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let s = v.as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected string for CString, got {}", type_name(v))))?;
        if let Some(b64) = s.strip_prefix("b64:") {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("bad base64 in CString: {}", e)))?;
            w.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            w.extend_from_slice(&bytes);
        } else {
            let bytes = s.as_bytes();
            if bytes.len() > u32::MAX as usize {
                return err(format!("string too long ({} bytes)", bytes.len()));
            }
            w.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            w.extend_from_slice(bytes);
        }
        Ok(())
    }
}

// ── LocalizableString ─────────────────────────────────────────────────────────
//
// Layout: u8 category, u64 index, u32 default_len, [u8; default_len].
// The Python bridge uses a dict with `category`, `index`, `default` keys —
// same shape here.

impl ToJsonValue for LocalizableString<'_> {
    fn to_json_value(&self) -> Value {
        json!({
            "category": self.category,
            "index": self.index,
            "default": self.default.data,
        })
    }
}
impl WriteJsonValue for LocalizableString<'_> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected object for LocalizableString, got {}", type_name(v))))?;
        let category = get_field(obj, "category")?
            .as_u64().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "LocalizableString.category: expected u8 number"))?;
        if category > u8::MAX as u64 {
            return err(format!("LocalizableString.category {} out of u8 range", category));
        }
        let index = get_field(obj, "index")?
            .as_u64().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "LocalizableString.index: expected u64 number"))?;
        let default = get_field(obj, "default")?
            .as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "LocalizableString.default: expected string"))?;
        w.push(category as u8);
        w.extend_from_slice(&index.to_le_bytes());
        w.extend_from_slice(&(default.len() as u32).to_le_bytes());
        w.extend_from_slice(default.as_bytes());
        Ok(())
    }
}

// ── CArray ────────────────────────────────────────────────────────────────────

impl<T: ToJsonValue> ToJsonValue for CArray<T> {
    fn to_json_value(&self) -> Value {
        Value::Array(self.items.iter().map(|x| x.to_json_value()).collect())
    }
}
impl<T: WriteJsonValue> WriteJsonValue for CArray<T> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            format!("expected array for CArray, got {}", type_name(v))))?;
        if arr.len() > u32::MAX as usize {
            return err(format!("CArray too long ({} elements)", arr.len()));
        }
        w.extend_from_slice(&(arr.len() as u32).to_le_bytes());
        for (i, elem) in arr.iter().enumerate() {
            T::write_from_json(w, elem).map_err(|e| io::Error::new(
                e.kind(), format!("[{}]: {}", i, e),
            ))?;
        }
        Ok(())
    }
}

// ── COptional ─────────────────────────────────────────────────────────────────
//
// Wire format: u8 flag (0 = absent, 1 = present), then T's bytes if flag=1.
// JSON encoding: `null` ↔ absent, anything else ↔ present.

impl<T: ToJsonValue> ToJsonValue for COptional<T> {
    fn to_json_value(&self) -> Value {
        match &self.value {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }
}
impl<T: WriteJsonValue> WriteJsonValue for COptional<T> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            w.push(0);
        } else {
            w.push(1);
            T::write_from_json(w, v)?;
        }
        Ok(())
    }
}
