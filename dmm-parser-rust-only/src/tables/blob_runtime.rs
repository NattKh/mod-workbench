// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Generic JSON runtime for `pabgh_blob_table!` formatted tables.
//!
//! The macro at `binary::variant::pabgh_blob_table!` lays out every entry as
//! `[key:u32][string_key:CString][is_blocked:u8][blob:rest_to_record_end]`.
//! ~120 tables in this crate use that layout (anything not yet given a
//! field-decoded reader). Without this runtime, v3 mods can't target any of
//! them — there's no `parse_X_to_json` per table.
//!
//! This module exposes ONE pair of functions that work uniformly across every
//! blob-format table by reading the wire layout directly. Mod intents can edit
//! `key`, `string_key`, or `is_blocked` by name. The `_blob_b64` field carries
//! the opaque tail as base64 so authors can clone whole records between mods
//! without losing field-decoded fidelity for the parts they don't understand —
//! and so the byte-level round-trip stays exact when no intent touches the blob.
//!
//! Tables with their own JSON parsers (iteminfo, skill, equip_slot_info as of
//! 1.3.4) should bypass this runtime — the dispatcher in DMM picks the
//! specific handler when one exists and falls back here for everything else.

use crate::binary::*;
use crate::binary::variant::{entry_ranges, load_pabgh_offsets_from_bytes};
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::io::{self, Write};

/// Owned mirror of the macro-generated `pabgh_blob_table!` struct shape.
/// Used internally by parse/serialize for any table that fits the layout.
///
/// The `key_width` field captures whether the wire actually stored the key as
/// u32 (pabgh format 1/3) or u16 (pabgh format 2). The same struct holds both
/// so the JSON layer doesn't have to fork — write_to picks the right width
/// from `key_width` and the round-trip is byte-exact for either flavor.
#[derive(Debug)]
pub struct BlobTableRecord {
    pub key: u32,
    pub key_width: u8,
    pub string_key: String,
    pub is_blocked: u8,
    pub blob: Vec<u8>,
}

impl BlobTableRecord {
    /// Read one record from `data` starting at `*offset`, consuming exactly
    /// `entry_size` bytes (matches the macro's read_with_size contract).
    /// `key_width` must be 2 or 4 — caller derives it from the sister pabgh's
    /// detected format (format 2 stores u16 keys; formats 1/3 store u32).
    pub fn read_with_size(
        data: &[u8],
        offset: &mut usize,
        entry_size: usize,
        key_width: u8,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start
            .checked_add(entry_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "BlobTableRecord: entry_size overflow"))?;
        if entry_end > data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                format!("BlobTableRecord: record extends past body ({} > {})", entry_end, data.len())));
        }

        let key: u32 = match key_width {
            2 => u16::read_from(data, offset)? as u32,
            4 => u32::read_from(data, offset)?,
            other => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BlobTableRecord: unsupported key_width {} (expected 2 or 4)", other))),
        };
        let s = CString::read_from(data, offset)?;
        let string_key = std::str::from_utf8(s.data.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("string_key utf8: {}", e)))?
            .to_string();
        let is_blocked = u8::read_from(data, offset)?;
        if *offset > entry_end {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("BlobTableRecord k=0x{:x}: prefix over-consumed", key)));
        }
        let blob = data[*offset..entry_end].to_vec();
        *offset = entry_end;
        Ok(Self { key, key_width, string_key, is_blocked, blob })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self.key_width {
            2 => {
                if self.key > u16::MAX as u32 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("BlobTableRecord: key 0x{:x} doesn't fit u16 (table uses pabgh format 2)", self.key)));
                }
                (self.key as u16).write_to(w)?;
            }
            4 => self.key.write_to(w)?,
            other => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BlobTableRecord: unsupported key_width {} (expected 2 or 4)", other))),
        }
        // CString wire layout = u32 length + bytes. Inline since we hold an owned
        // String rather than the borrowed CString<'a> the macro uses.
        let bytes = self.string_key.as_bytes();
        (bytes.len() as u32).write_to(w)?;
        w.write_all(bytes)?;
        self.is_blocked.write_to(w)?;
        w.write_all(&self.blob)?;
        Ok(())
    }
}

impl ToJsonValue for BlobTableRecord {
    fn to_json_value(&self) -> Value {
        json!({
            "key": self.key,
            // Hidden underscored field captures the wire's key width so
            // round-trip serialization writes the same number of bytes.
            // Without this, a u16-keyed table parsed and re-serialized would
            // come out 2 bytes longer per record and the body would shift.
            "_key_width": self.key_width,
            "string_key": self.string_key,
            "is_blocked": self.is_blocked,
            // Underscored to make it visually distinct from the schema fields —
            // editing it is a "blob clone" operation, not a typed edit. Authors
            // who don't understand the table's binary should leave it alone.
            "_blob_b64": B64.encode(&self.blob),
        })
    }
}

impl WriteJsonValue for BlobTableRecord {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "BlobTableRecord: expected object"))?;
        // key_width may be missing on JSON dicts produced before this field
        // existed (defensive). Default to 4 (u32) to match historical behavior.
        let key_width = obj.get("_key_width")
            .and_then(|v| v.as_u64())
            .map(|x| x as u8)
            .unwrap_or(4);
        let key_val = json_get_field(obj, "key")?
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key: expected integer"))?;
        match key_width {
            2 => {
                if key_val > u16::MAX as u64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("key {} doesn't fit u16 (table uses pabgh format 2)", key_val)));
                }
                w.extend_from_slice(&(key_val as u16).to_le_bytes());
            }
            4 => {
                if key_val > u32::MAX as u64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("key {} doesn't fit u32", key_val)));
                }
                w.extend_from_slice(&(key_val as u32).to_le_bytes());
            }
            other => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BlobTableRecord: unsupported _key_width {} (expected 2 or 4)", other))),
        }
        // string_key as plain JSON string (CString wire format).
        let sk = json_get_field(obj, "string_key")?
            .as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "string_key: expected string"))?;
        let sk_bytes = sk.as_bytes();
        if sk_bytes.len() > u32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("string_key too long ({} bytes)", sk_bytes.len())));
        }
        w.extend_from_slice(&(sk_bytes.len() as u32).to_le_bytes());
        w.extend_from_slice(sk_bytes);
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        // Blob comes as base64 — decode and write raw bytes.
        let blob_str = json_get_field(obj, "_blob_b64")?
            .as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "_blob_b64: expected base64 string"))?;
        let blob = B64.decode(blob_str).map_err(|e| io::Error::new(
            io::ErrorKind::InvalidData, format!("_blob_b64 invalid base64: {}", e)))?;
        w.extend_from_slice(&blob);
        Ok(())
    }
}

/// Detect the wire key width from a sister pabgh by matching the file size
/// against the 3 known formats. Returns 2 (format 2: u16 keys) or 4 (formats
/// 1/3: u32 keys).
fn detect_key_width(pabgh: &[u8]) -> io::Result<u8> {
    if pabgh.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pabgh too small to detect format"));
    }
    let c16 = u16::from_le_bytes(pabgh[0..2].try_into().unwrap()) as usize;
    let c32 = u32::from_le_bytes(pabgh[0..4].try_into().unwrap()) as usize;
    if 2 + c16 * 8 == pabgh.len() {
        Ok(4) // format 1
    } else if 2 + c16 * 6 == pabgh.len() {
        Ok(2) // format 2
    } else if 4 + c32 * 8 == pabgh.len() {
        Ok(4) // format 3
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "pabgh: unrecognized format (cannot detect key width)"))
    }
}

/// Parse any pabgh_blob_table-formatted body using its sister pabgh for record
/// boundaries. Returns one JSON dict per record in pabgh order — same calling
/// convention as `parse_skill_to_json_with_pabgh`.
///
/// Auto-detects whether the table uses u32 keys (pabgh formats 1/3) or u16
/// keys (pabgh format 2) from the pabgh layout. Tables that don't fit the
/// `[key][string_key:CString][is_blocked:u8][...rest...]` prefix shape will
/// fail to parse cleanly — callers should round-trip-check before applying
/// edits.
pub fn parse_blob_table_to_json_with_pabgh(
    data: &[u8],
    pabgh: &[u8],
) -> io::Result<Vec<Value>> {
    let key_width = detect_key_width(pabgh)?;
    let entries = load_pabgh_offsets_from_bytes(pabgh).ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData, "blob_table: pabgh parse failed"))?;
    let ranges = entry_ranges(&entries, data.len());
    let mut out = Vec::with_capacity(ranges.len());
    for (k, s, e) in ranges {
        let mut c = s;
        let rec = BlobTableRecord::read_with_size(data, &mut c, e - s, key_width).map_err(|err| io::Error::new(
            err.kind(), format!("blob_table k=0x{:x}: {}", k, err)))?;
        if c != e {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("blob_table k=0x{:x}: under/over-consumed {}/{}", k, c - s, e - s)));
        }
        out.push(rec.to_json_value());
    }
    Ok(out)
}

/// Serialize a JSON list (as produced by `parse_blob_table_to_json_with_pabgh`)
/// back to pabgb bytes. The caller must rebuild the sister pabgh separately
/// — the offset map shifts whenever any record's `string_key` length changes.
pub fn serialize_blob_table_from_json(items: &[Value]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(items.len() * 256);
    for (i, v) in items.iter().enumerate() {
        BlobTableRecord::write_from_json(&mut out, v).map_err(|e| io::Error::new(
            e.kind(), format!("blob_table[{}]: {}", i, e)))?;
    }
    Ok(out)
}

// ── Typed-prefix runtime (Tier 1.5 tables) ──────────────────────────────────
//
// `pabgh_typed_blob_table!` generates `read_with_size`, `write_to`,
// `to_json_dict`, and `write_from_json_dict` per table. These two helpers
// drive that surface across an entire pabgb body using the sister pabgh for
// entry boundaries — equivalent to `parse_blob_table_to_json_with_pabgh`
// but for tables that decode the typed prefix individually instead of
// folding everything into an opaque blob.

/// Parse a Tier 1.5 typed-prefix-plus-tail pabgb body to JSON.
///
/// The caller supplies the per-table `read_with_size` and `to_json_dict`
/// functions (or a thin closure over them). This indirection keeps the
/// runtime fully generic without monomorphising one copy per table inside
/// dmm-parser — DMM and other consumers can reuse it for any pabgh_typed_blob_table
/// table.
pub fn parse_typed_blob_table_to_json_with_pabgh<F>(
    data: &[u8],
    pabgh: &[u8],
    mut read_one: F,
) -> io::Result<Vec<Value>>
where
    F: FnMut(&[u8], &mut usize, usize) -> io::Result<serde_json::Map<String, Value>>,
{
    let entries = load_pabgh_offsets_from_bytes(pabgh).ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData, "typed_blob_table: pabgh parse failed"))?;
    let ranges = entry_ranges(&entries, data.len());
    let mut out = Vec::with_capacity(ranges.len());
    for (k, s, e) in ranges {
        let entry_size = e - s;
        let mut c = s;
        // Clamp the data slice to the entry boundary to prevent
        // CArray count overflows from allocating unbounded memory.
        let clamped = if e <= data.len() { &data[..e] } else { data };
        match read_one(clamped, &mut c, entry_size) {
            Ok(dict) if c == e => {
                out.push(Value::Object(dict));
            }
            Ok(dict) => {
                // Under/over-consumed — fall back to blob for roundtrip safety
                use base64::Engine;
                let blob = &data[s..e];
                let mut m = serde_json::Map::new();
                m.insert("key".into(), Value::from(k));
                m.insert("_blob_b64".into(), Value::String(
                    base64::engine::general_purpose::STANDARD.encode(blob)));
                out.push(Value::Object(m));
            }
            Err(_) => {
                // Parse failed — fall back to blob
                use base64::Engine;
                let blob = &data[s..e];
                let mut m = serde_json::Map::new();
                m.insert("key".into(), Value::from(k));
                m.insert("_blob_b64".into(), Value::String(
                    base64::engine::general_purpose::STANDARD.encode(blob)));
                out.push(Value::Object(m));
            }
        }
    }
    Ok(out)
}

/// Serialize a list of typed-prefix dicts back to pabgb bytes.
///
/// Mirrors `serialize_blob_table_from_json` but routes each entry through
/// the per-table `write_from_json_dict` (passed in as a closure). The
/// caller rebuilds the sister pabgh separately — every record's tail size
/// is preserved verbatim, so for replace-only edits the vanilla pabgh
/// stays valid byte-for-byte.
pub fn serialize_typed_blob_table_from_json<F>(
    items: &[Value],
    mut write_one: F,
) -> io::Result<Vec<u8>>
where
    F: FnMut(&mut Vec<u8>, &serde_json::Map<String, Value>) -> io::Result<()>,
{
    let mut out = Vec::with_capacity(items.len() * 256);
    for (i, v) in items.iter().enumerate() {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("typed_blob_table[{}]: expected object, got {}",
                i, match v { Value::Null => "null", Value::Bool(_) => "bool",
                    Value::Number(_) => "number", Value::String(_) => "string",
                    Value::Array(_) => "array", Value::Object(_) => "object" })))?;
        // Check for blob-fallback entries
        if let Some(blob_val) = obj.get("_blob_b64").and_then(|b| b.as_str()) {
            use base64::Engine;
            let blob = base64::engine::general_purpose::STANDARD.decode(blob_val)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("typed_blob_table[{}]: bad base64: {}", i, e)))?;
            out.extend_from_slice(&blob);
            continue;
        }
        write_one(&mut out, obj).map_err(|e| io::Error::new(
            e.kind(), format!("typed_blob_table[{}]: {}", i, e)))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a known blob-format table to confirm the runtime preserves
    /// vanilla bytes when no intent touches the data. Uses equip_info — small,
    /// well-behaved, and confirmed pabgh_blob_table! in the source.
    #[test]
    fn blob_table_roundtrip() {
        let pabgb_path = r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\equip_info.pabgb";
        let pabgh_path = r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\equip_info.pabgh";
        // Try several candidates — different game-data dumps may not have every file.
        for (pb, ph) in [
            (pabgb_path, pabgh_path),
            (r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\condition_info.pabgb",
             r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\condition_info.pabgh"),
            (r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\buff_info.pabgb",
             r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\buff_info.pabgh"),
        ] {
            let Ok(body) = std::fs::read(pb) else { continue; };
            let Ok(pabgh) = std::fs::read(ph) else { continue; };
            let json = parse_blob_table_to_json_with_pabgh(&body, &pabgh)
                .unwrap_or_else(|e| panic!("parse failed for {}: {}", pb, e));
            let out = serialize_blob_table_from_json(&json)
                .unwrap_or_else(|e| panic!("serialize failed for {}: {}", pb, e));
            assert_eq!(out, body, "round-trip mismatch for {}", pb);
            // Smoke: at least one record has a non-empty string_key for the
            // typical case; if all are empty we likely picked the wrong layout.
            let any_named = json.iter().any(|v| v.get("string_key").and_then(|s| s.as_str()).map(|s| !s.is_empty()).unwrap_or(false));
            // Don't fail on this — some tables genuinely have empty string_keys.
            // Just log via the test runner if we want to inspect.
            let _ = any_named;
            return; // first successful file is enough
        }
        eprintln!("SKIP blob_table_roundtrip: no input files available");
    }

    /// Round-trip a u16-keyed table (pabgh format 2) to prove the auto
    /// detected key_width path preserves bytes. inventory.pabgb is the
    /// canonical example — without u16 detection this would mis-parse the
    /// key column and serialize-back would shift every record.
    #[test]
    fn blob_table_roundtrip_u16_key() {
        for (pb, ph) in [
            (r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\inventory.pabgb",
             r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\inventory.pabgh"),
            (r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\inventory.pabgb",
             r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\inventory.pabgh"),
        ] {
            let Ok(body) = std::fs::read(pb) else { continue; };
            let Ok(pabgh) = std::fs::read(ph) else { continue; };
            let json = parse_blob_table_to_json_with_pabgh(&body, &pabgh)
                .unwrap_or_else(|e| panic!("parse failed for {}: {}", pb, e));
            let out = serialize_blob_table_from_json(&json)
                .unwrap_or_else(|e| panic!("serialize failed for {}: {}", pb, e));
            assert_eq!(out, body, "u16-key round-trip mismatch for {}", pb);
            // Confirm at least one record actually came back with a useful
            // key value — if the key_width detection silently fell back to
            // u32 we'd see truncated/0 keys and JSON would be useless.
            let max_key = json.iter()
                .filter_map(|v| v.get("key").and_then(|k| k.as_u64()))
                .max()
                .unwrap_or(0);
            assert!(max_key > 0, "no records had non-zero keys — u16 detection probably failed");
            assert!(max_key <= u16::MAX as u64, "key {} exceeds u16 max — wrong width detected", max_key);
            return;
        }
        eprintln!("SKIP blob_table_roundtrip_u16_key: no input files available");
    }
}
