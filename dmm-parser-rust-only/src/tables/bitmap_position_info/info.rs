#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed (no _tail_b64).
//!
//! Reader: `sub_1410D6120` in CrimsonDesert.exe (Win build).
//! Inner `_values` reader: `sub_14112DE30`. Inner per-Value reader:
//! `sub_140F5B8B0` (CArray<u32> + CArray<u16>).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                         (_key)
//!   2. CString string_key              (_stringKey)
//!   3. u8 is_blocked                   (_isBlocked)
//!   4. u8 scale_type                   (_scaleType)
//!   5. _values (sub_14112DE30):
//!        u32 field_a + u32 field_b
//!        + u8 has_a + u8 has_b + u8 has_c   (all 3 flags grouped)
//!        + if has_a: { CArray<u32>, CArray<u16> }
//!        + if has_b: { CArray<u32>, CArray<u16> }
//!        + if has_c: { CArray<u32>, CArray<u16> }
//!   6. _boundaryPositionMin           [u8; 8]
//!   7. _boundaryPositionMax           [u8; 8]
//!   8. _centerPosition                [u8; 8]
//!   9. _scalePerPixel                 u32
//!  10. _maxUsingHeight                u32
//!  11. _exportTextureOnEditing        u8
//!
//! `BitmapPositionValues` is hand-rolled because the wire groups the
//! three presence flags before the conditional payloads — distinct from
//! `COptional<T>` which interleaves flag+payload per field. The outer
//! `BitmapPositionInfo` is hand-rolled because Python bindings live in
//! Snow's lane (we don't generate them here).
//!
//! Position fields are kept as `[u8; 8]` until we confirm whether the
//! game treats them as `(f32, f32)` 2D coords or `(i32, i32)` pixel
//! offsets — the bit pattern round-trips either way.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct BitmapPositionValueData {
        pub array_u32: CArray<u32>,
        pub array_u16: CArray<u16>,
    }
}

#[derive(Debug)]
pub struct BitmapPositionValues {
    pub field_a: u32,
    pub field_b: u32,
    pub value_a: Option<BitmapPositionValueData>,
    pub value_b: Option<BitmapPositionValueData>,
    pub value_c: Option<BitmapPositionValueData>,
}

impl<'a> BinaryRead<'a> for BitmapPositionValues {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let field_a = u32::read_from(data, offset)?;
        let field_b = u32::read_from(data, offset)?;
        let has_a = u8::read_from(data, offset)?;
        let has_b = u8::read_from(data, offset)?;
        let has_c = u8::read_from(data, offset)?;
        let value_a = if has_a != 0 { Some(BitmapPositionValueData::read_from(data, offset)?) } else { None };
        let value_b = if has_b != 0 { Some(BitmapPositionValueData::read_from(data, offset)?) } else { None };
        let value_c = if has_c != 0 { Some(BitmapPositionValueData::read_from(data, offset)?) } else { None };
        Ok(Self { field_a, field_b, value_a, value_b, value_c })
    }
}

impl BinaryWrite for BitmapPositionValues {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.field_a.write_to(w)?;
        self.field_b.write_to(w)?;
        (self.value_a.is_some() as u8).write_to(w)?;
        (self.value_b.is_some() as u8).write_to(w)?;
        (self.value_c.is_some() as u8).write_to(w)?;
        if let Some(v) = &self.value_a { v.write_to(w)?; }
        if let Some(v) = &self.value_b { v.write_to(w)?; }
        if let Some(v) = &self.value_c { v.write_to(w)?; }
        Ok(())
    }
}

impl BitmapPositionValues {
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("field_a".to_string(), self.field_a.to_json_value());
        m.insert("field_b".to_string(), self.field_b.to_json_value());
        m.insert("value_a".to_string(), match &self.value_a {
            Some(v) => Value::Object(v.to_json_dict()),
            None => Value::Null,
        });
        m.insert("value_b".to_string(), match &self.value_b {
            Some(v) => Value::Object(v.to_json_dict()),
            None => Value::Null,
        });
        m.insert("value_c".to_string(), match &self.value_c {
            Some(v) => Value::Object(v.to_json_dict()),
            None => Value::Null,
        });
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "BitmapPositionValues: expected object",
        ))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_b")?)?;
        let has_a = !json_get_field(obj, "value_a")?.is_null();
        let has_b = !json_get_field(obj, "value_b")?.is_null();
        let has_c = !json_get_field(obj, "value_c")?.is_null();
        w.push(has_a as u8);
        w.push(has_b as u8);
        w.push(has_c as u8);
        if has_a {
            <BitmapPositionValueData as WriteJsonValue>::write_from_json(
                w, json_get_field(obj, "value_a")?,
            )?;
        }
        if has_b {
            <BitmapPositionValueData as WriteJsonValue>::write_from_json(
                w, json_get_field(obj, "value_b")?,
            )?;
        }
        if has_c {
            <BitmapPositionValueData as WriteJsonValue>::write_from_json(
                w, json_get_field(obj, "value_c")?,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BitmapPositionInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub scale_type: u8,
    pub values: BitmapPositionValues,
    pub boundary_position_min: [f32; 2],
    pub boundary_position_max: [f32; 2],
    pub center_position: [f32; 2],
    pub scale_per_pixel: u32,
    pub max_using_height: u32,
    pub export_texture_on_editing: u8,
}

impl<'a> BitmapPositionInfo<'a> {
    /// Read with explicit entry size from pabgh (compat shim — Tier 1 means
    /// every byte is consumed by typed reads, so the size is just verified).
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BitmapPositionInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let scale_type = u8::read_from(data, offset)?;
        let values = BitmapPositionValues::read_from(data, offset)?;
        let boundary_position_min = <[f32; 2]>::read_from(data, offset)?;
        let boundary_position_max = <[f32; 2]>::read_from(data, offset)?;
        let center_position = <[f32; 2]>::read_from(data, offset)?;
        let scale_per_pixel = u32::read_from(data, offset)?;
        let max_using_height = u32::read_from(data, offset)?;
        let export_texture_on_editing = u8::read_from(data, offset)?;
        Ok(Self {
            key, string_key, is_blocked, scale_type, values,
            boundary_position_min, boundary_position_max, center_position,
            scale_per_pixel, max_using_height, export_texture_on_editing,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.scale_type.write_to(w)?;
        self.values.write_to(w)?;
        self.boundary_position_min.write_to(w)?;
        self.boundary_position_max.write_to(w)?;
        self.center_position.write_to(w)?;
        self.scale_per_pixel.write_to(w)?;
        self.max_using_height.write_to(w)?;
        self.export_texture_on_editing.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("scale_type".to_string(), self.scale_type.to_json_value());
        m.insert("values".to_string(), self.values.to_json_value());
        m.insert("boundary_position_min".to_string(), self.boundary_position_min.to_json_value());
        m.insert("boundary_position_max".to_string(), self.boundary_position_max.to_json_value());
        m.insert("center_position".to_string(), self.center_position.to_json_value());
        m.insert("scale_per_pixel".to_string(), self.scale_per_pixel.to_json_value());
        m.insert("max_using_height".to_string(), self.max_using_height.to_json_value());
        m.insert("export_texture_on_editing".to_string(), self.export_texture_on_editing.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "scale_type")?)?;
        BitmapPositionValues::write_from_json(w, json_get_field(obj, "values")?)?;
        <[f32; 2] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "boundary_position_min")?)?;
        <[f32; 2] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "boundary_position_max")?)?;
        <[f32; 2] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "center_position")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "scale_per_pixel")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "max_using_height")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "export_texture_on_editing")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\bitmapposition.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\bitmapposition.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = BitmapPositionInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "bitmapposition roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = BitmapPositionInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            BitmapPositionInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }

    /// Smoke test: every typed field surfaces in the JSON dict, including
    /// the formerly-opaque-tail fields. Without this, the Tier 1.5→1
    /// promotion could silently regress to the old shape.
    #[test]
    fn fields_addressable() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let Some((_, s, _)) = ranges.first() else { eprintln!("SKIP: no entries"); return; };
        let mut c = *s;
        let item = BitmapPositionInfo::read_from(&data, &mut c).unwrap();
        let dict = item.to_json_dict();
        for f in [
            "key", "string_key", "is_blocked", "scale_type", "values",
            "boundary_position_min", "boundary_position_max", "center_position",
            "scale_per_pixel", "max_using_height", "export_texture_on_editing",
        ] {
            assert!(dict.contains_key(f), "missing field `{}` in JSON dict", f);
        }
        assert!(!dict.contains_key("_tail_b64"), "Tier 1.5 _tail_b64 field leaked into Tier 1 dict");
        // `values` should expose its inner fields too.
        let values = dict.get("values").and_then(|v| v.as_object()).expect("values dict");
        for f in ["field_a", "field_b", "value_a", "value_b", "value_c"] {
            assert!(values.contains_key(f), "missing values.{} in JSON dict", f);
        }
    }
}
