// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! EffectData per-element decoder.
//!
//! Per Win-IDA `sub_1410DBAF0` (one EffectData element on the wire):
//!
//! ```text
//! 1. byte_a:        u8                                               (1)
//! 2. lookup_b:      u32 hash → u16 (read_u32_lookup_EF18)            (4)
//! 3. core:          254-byte fixed block via sub_1410D4110           (254)
//! 4. lookups_c:     6 × u32 hash → u16 (read_u32_lookup_DA30)        (24)
//! 5. fields_d:      4 × u32                                          (16)
//! 6. byte_e:        u8                                               (1)
//! 7. cstring_list:  CArray<CString> (sub_14106BAC0)                  (4 + Σ)
//! 8. fixed144_list: CArray<EffectDataD3Block> (sub_141117080)        (4 + 144*N)
//! 9. nested_u32_lists: CArray<{u32 key, CArray<u32> values}>
//!    (sub_141116ED0 → sub_141101AB0)                                 (variable)
//! 10. inner_map:    CArray<{u32 key, EffectDataInner}>
//!    (sub_141116CA0 → sub_1410DB840)                                 (variable, recursive)
//! ```
//!
//! `EffectDataInner` (sub_1410DB840) is similar shape and contains
//! nested CArrays; it's the recursive part of the family. Now fully
//! field-typed end-to-end (see EffectDataInner struct below).

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// 144-byte sub-block read by sub_1410D3DC0. Used both as the leading
    /// half of `EffectDataCoreBlock` AND as the per-element type of
    /// `fixed144_list` (sub_141117080 is `CArray<EffectDataD3Block>`).
    ///
    /// Layout per IDA: 7 × Vec3 + 7 × u32 + Vec4(16B) + 2 × u32 + u8 + u8
    /// + u16 + u32 = 144 bytes wire.
    pub struct EffectDataD3Block {
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
        pub vec_c: [f32; 3],
        pub vec_d: [f32; 3],
        pub vec_e: [f32; 3],
        pub vec_f: [f32; 3],
        pub vec_g: [f32; 3],
        pub field_84: u32,
        pub field_88: u32,
        pub field_92: u32,
        pub field_96: u32,
        pub field_100: u32,
        pub field_104: u32,
        pub field_108: u32,
        pub vec4_a: [u32; 4],
        pub field_128: u32,
        pub field_132: u32,
        pub byte_136: u8,
        pub byte_137: u8,
        pub word_138: u16,
        pub field_140: u32,
    }
}

py_binary_struct! {
    /// 254-byte fixed block read by sub_1410D4110: the 144-byte D3 block
    /// followed by 110 more bytes (u32 + 2×Vec3 + u64 + u32 + 4×Vec3 +
    /// 2×u32 + 14 individual u8 fields).
    pub struct EffectDataCoreBlock {
        pub d3: EffectDataD3Block,
        pub field_144: u32,
        pub vec_h: [f32; 3],
        pub vec_i: [f32; 3],
        pub qword_172: u64,
        pub field_180: u32,
        pub vec_j: [f32; 3],
        pub vec_k: [f32; 3],
        pub vec_l: [f32; 3],
        pub vec_m: [f32; 3],
        pub field_232: u32,
        pub field_236: u32,
        // Per IDA sub_1410D4110: 14 individual `read 1 byte` calls into
        // a2+240..a2+253. Split into 14 named u8 fields rather than
        // riding as an opaque [u8; 14].
        pub byte_240: u8, pub byte_241: u8, pub byte_242: u8, pub byte_243: u8,
        pub byte_244: u8, pub byte_245: u8, pub byte_246: u8, pub byte_247: u8,
        pub byte_248: u8, pub byte_249: u8, pub byte_250: u8, pub byte_251: u8,
        pub byte_252: u8, pub byte_253: u8,
    }
}


/// EffectDataInner record (sub_1410DB840). Recursive nested struct that
/// appears as the value type inside EffectDataElement.inner_map. Wire
/// layout from IDA:
///
/// ```text
/// 1.  u32 field_0                                        (4)
/// 2.  EffectDataCoreBlock (sub_1410D4110)                (254)
/// 3.  6 × u32 hash → u16 lookups (read_u32_lookup_DA30)  (24)
/// 4.  list_a:  CArray<CString-style> (sub_141102990 →
///     sub_1410A9D40 — each element is u32 len + len bytes
///     of UTF-8 that get hashed at runtime)               (variable)
/// 5.  list_b:  CArray<u32 / f32-as-u32> (sub_141102A60)  (variable)
/// 6.  4 × Vec3 (12 bytes each)                            (48)
/// 7.  field_after_vecs: u32                               (4)
/// 8.  cstring_list:  CArray<CString> (sub_14106BAC0)     (variable)
/// 9.  fixed144_list: CArray<EffectDataD3Block> (sub_141117080)        (variable)
/// 10. trailing_word: u16                                  (2)
/// ```
///
/// Total fixed = 4 + 254 + 24 + 48 + 4 + 2 = 336 bytes + 4 CArrays.
#[derive(Debug)]
pub struct EffectDataInner<'a> {
    pub field_0: u32,
    pub core_block: EffectDataCoreBlock,
    pub lookups: [u32; 6],
    pub list_a: Vec<CString<'a>>,
    pub list_b: Vec<u32>,
    pub vec_a: [f32; 3],
    pub vec_b: [f32; 3],
    pub vec_c: [f32; 3],
    pub vec_d: [f32; 3],
    pub field_after_vecs: u32,
    pub cstring_list: Vec<CString<'a>>,
    pub fixed144_list: Vec<EffectDataD3Block>,
    pub trailing_word: u16,
}

impl<'a> EffectDataInner<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let field_0 = u32::read_from(data, offset)?;
        let core_block = EffectDataCoreBlock::read_from(data, offset)?;
        let mut lookups = [0u32; 6];
        for x in &mut lookups { *x = u32::read_from(data, offset)?; }

        let list_a_count = u32::read_from(data, offset)? as usize;
        let mut list_a = Vec::with_capacity(list_a_count);
        for _ in 0..list_a_count { list_a.push(CString::read_from(data, offset)?); }

        let list_b_count = u32::read_from(data, offset)? as usize;
        let mut list_b = Vec::with_capacity(list_b_count);
        for _ in 0..list_b_count { list_b.push(u32::read_from(data, offset)?); }

        let vec_a = <[f32; 3]>::read_from(data, offset)?;
        let vec_b = <[f32; 3]>::read_from(data, offset)?;
        let vec_c = <[f32; 3]>::read_from(data, offset)?;
        let vec_d = <[f32; 3]>::read_from(data, offset)?;

        let field_after_vecs = u32::read_from(data, offset)?;

        let cstring_count = u32::read_from(data, offset)? as usize;
        let mut cstring_list = Vec::with_capacity(cstring_count);
        for _ in 0..cstring_count { cstring_list.push(CString::read_from(data, offset)?); }

        let fixed144_count = u32::read_from(data, offset)? as usize;
        let mut fixed144_list = Vec::with_capacity(fixed144_count);
        for _ in 0..fixed144_count {
            fixed144_list.push(EffectDataD3Block::read_from(data, offset)?);
        }

        let trailing_word = u16::read_from(data, offset)?;

        Ok(Self {
            field_0, core_block, lookups, list_a, list_b,
            vec_a, vec_b, vec_c, vec_d,
            field_after_vecs, cstring_list, fixed144_list, trailing_word,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.field_0.write_to(w)?;
        self.core_block.write_to(w)?;
        for x in &self.lookups { x.write_to(w)?; }
        (self.list_a.len() as u32).write_to(w)?;
        for s in &self.list_a { s.write_to(w)?; }
        (self.list_b.len() as u32).write_to(w)?;
        for v in &self.list_b { v.write_to(w)?; }
        self.vec_a.write_to(w)?;
        self.vec_b.write_to(w)?;
        self.vec_c.write_to(w)?;
        self.vec_d.write_to(w)?;
        self.field_after_vecs.write_to(w)?;
        (self.cstring_list.len() as u32).write_to(w)?;
        for s in &self.cstring_list { s.write_to(w)?; }
        (self.fixed144_list.len() as u32).write_to(w)?;
        for blk in &self.fixed144_list { blk.write_to(w)?; }
        self.trailing_word.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("field_0".to_string(), self.field_0.to_json_value());
        m.insert("core_block".to_string(), Value::Object(self.core_block.to_json_dict()));
        m.insert("lookups".to_string(),
            Value::Array(self.lookups.iter().map(|v| v.to_json_value()).collect()));
        m.insert("list_a".to_string(),
            Value::Array(self.list_a.iter().map(|s| s.to_json_value()).collect()));
        m.insert("list_b".to_string(),
            Value::Array(self.list_b.iter().map(|v| v.to_json_value()).collect()));
        m.insert("vec_a".to_string(), self.vec_a.to_json_value());
        m.insert("vec_b".to_string(), self.vec_b.to_json_value());
        m.insert("vec_c".to_string(), self.vec_c.to_json_value());
        m.insert("vec_d".to_string(), self.vec_d.to_json_value());
        m.insert("field_after_vecs".to_string(), self.field_after_vecs.to_json_value());
        m.insert("cstring_list".to_string(),
            Value::Array(self.cstring_list.iter().map(|s| s.to_json_value()).collect()));
        m.insert("fixed144_list".to_string(),
            Value::Array(self.fixed144_list.iter().map(|b| Value::Object(b.to_json_dict())).collect()));
        m.insert("trailing_word".to_string(), self.trailing_word.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_0")?)?;
        let core_obj = json_get_field(obj, "core_block")?.as_object()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: core_block must be object"))?;
        EffectDataCoreBlock::write_from_json_dict(w, core_obj)?;
        let lookups = json_get_field(obj, "lookups")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: lookups must be array"))?;
        if lookups.len() != 6 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("EffectDataInner: lookups must have 6 items, got {}", lookups.len())));
        }
        for v in lookups { <u32 as WriteJsonValue>::write_from_json(w, v)?; }
        let list_a = json_get_field(obj, "list_a")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: list_a must be array"))?;
        (list_a.len() as u32).write_to(w)?;
        for v in list_a { <CString as WriteJsonValue>::write_from_json(w, v)?; }
        let list_b = json_get_field(obj, "list_b")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: list_b must be array"))?;
        (list_b.len() as u32).write_to(w)?;
        for v in list_b { <u32 as WriteJsonValue>::write_from_json(w, v)?; }
        for name in &["vec_a", "vec_b", "vec_c", "vec_d"] {
            <[f32; 3] as WriteJsonValue>::write_from_json(w, json_get_field(obj, name)?)?;
        }
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_after_vecs")?)?;
        let cstrs = json_get_field(obj, "cstring_list")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: cstring_list must be array"))?;
        (cstrs.len() as u32).write_to(w)?;
        for v in cstrs { <CString as WriteJsonValue>::write_from_json(w, v)?; }
        let f144s = json_get_field(obj, "fixed144_list")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInner: fixed144_list must be array"))?;
        (f144s.len() as u32).write_to(w)?;
        for v in f144s {
            let inner = v.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectDataInner: fixed144_list element must be object"))?;
            EffectDataD3Block::write_from_json_dict(w, inner)?;
        }
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "trailing_word")?)?;
        Ok(())
    }
}

/// One entry in `inner_map`: u32 key + EffectDataInner value.
#[derive(Debug)]
pub struct EffectDataInnerMapEntry<'a> {
    pub key: u32,
    pub value: EffectDataInner<'a>,
}

impl<'a> EffectDataInnerMapEntry<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let value = EffectDataInner::read_from(data, offset)?;
        Ok(Self { key, value })
    }
    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.value.write_to(w)
    }
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("value".to_string(), Value::Object(self.value.to_json_dict()));
        m
    }
    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        let val_obj = json_get_field(obj, "value")?.as_object()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataInnerMapEntry: value must be object"))?;
        EffectDataInner::write_from_json_dict(w, val_obj)?;
        Ok(())
    }
}

/// One EffectData element on the wire. Every field is now individually
/// typed — the recursive `inner_map` is no longer opaque.
#[derive(Debug)]
pub struct EffectDataElement<'a> {
    pub byte_a: u8,
    pub lookup_b: u32,
    /// 254-byte fixed block, fully field-level typed.
    pub core_block: EffectDataCoreBlock,
    pub lookups_c: [u32; 6],
    pub fields_d: [u32; 4],
    pub byte_e: u8,
    pub cstring_list: Vec<CString<'a>>,
    pub fixed144_list: Vec<EffectDataD3Block>,
    /// `CArray<CArray<u32>>` — typed in this commit.
    pub nested_u32_lists: Vec<Vec<u32>>,
    /// `CArray<{u32 key, EffectDataInner value}>` — typed in this commit.
    pub inner_map: Vec<EffectDataInnerMapEntry<'a>>,
}

impl<'a> EffectDataElement<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let byte_a = u8::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let core_block = EffectDataCoreBlock::read_from(data, offset)?;
        let mut lookups_c = [0u32; 6];
        for x in &mut lookups_c { *x = u32::read_from(data, offset)?; }
        let mut fields_d = [0u32; 4];
        for x in &mut fields_d { *x = u32::read_from(data, offset)?; }
        let byte_e = u8::read_from(data, offset)?;

        let cstring_count = u32::read_from(data, offset)? as usize;
        let mut cstring_list = Vec::with_capacity(cstring_count);
        for _ in 0..cstring_count {
            cstring_list.push(CString::read_from(data, offset)?);
        }

        let fixed144_count = u32::read_from(data, offset)? as usize;
        let mut fixed144_list = Vec::with_capacity(fixed144_count);
        for _ in 0..fixed144_count {
            fixed144_list.push(EffectDataD3Block::read_from(data, offset)?);
        }

        let nested_count = u32::read_from(data, offset)? as usize;
        let mut nested_u32_lists = Vec::with_capacity(nested_count);
        for _ in 0..nested_count {
            let inner_count = u32::read_from(data, offset)? as usize;
            let mut inner = Vec::with_capacity(inner_count);
            for _ in 0..inner_count { inner.push(u32::read_from(data, offset)?); }
            nested_u32_lists.push(inner);
        }

        let map_count = u32::read_from(data, offset)? as usize;
        let mut inner_map = Vec::with_capacity(map_count);
        for _ in 0..map_count {
            inner_map.push(EffectDataInnerMapEntry::read_from(data, offset)?);
        }

        Ok(Self {
            byte_a, lookup_b, core_block, lookups_c, fields_d, byte_e,
            cstring_list, fixed144_list, nested_u32_lists, inner_map,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.byte_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.core_block.write_to(w)?;
        for x in &self.lookups_c { x.write_to(w)?; }
        for x in &self.fields_d { x.write_to(w)?; }
        self.byte_e.write_to(w)?;
        (self.cstring_list.len() as u32).write_to(w)?;
        for s in &self.cstring_list { s.write_to(w)?; }
        (self.fixed144_list.len() as u32).write_to(w)?;
        for blk in &self.fixed144_list { blk.write_to(w)?; }
        (self.nested_u32_lists.len() as u32).write_to(w)?;
        for inner in &self.nested_u32_lists {
            (inner.len() as u32).write_to(w)?;
            for v in inner { v.write_to(w)?; }
        }
        (self.inner_map.len() as u32).write_to(w)?;
        for entry in &self.inner_map { entry.write_to(w)?; }
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("byte_a".to_string(), self.byte_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("core_block".to_string(), Value::Object(self.core_block.to_json_dict()));
        m.insert(
            "lookups_c".to_string(),
            Value::Array(self.lookups_c.iter().map(|v| v.to_json_value()).collect()),
        );
        m.insert(
            "fields_d".to_string(),
            Value::Array(self.fields_d.iter().map(|v| v.to_json_value()).collect()),
        );
        m.insert("byte_e".to_string(), self.byte_e.to_json_value());
        m.insert(
            "cstring_list".to_string(),
            Value::Array(self.cstring_list.iter().map(|s| s.to_json_value()).collect()),
        );
        m.insert(
            "fixed144_list".to_string(),
            Value::Array(self.fixed144_list.iter()
                .map(|blk| Value::Object(blk.to_json_dict()))
                .collect()),
        );
        m.insert(
            "nested_u32_lists".to_string(),
            Value::Array(self.nested_u32_lists.iter()
                .map(|inner| Value::Array(inner.iter().map(|v| v.to_json_value()).collect()))
                .collect()),
        );
        m.insert(
            "inner_map".to_string(),
            Value::Array(self.inner_map.iter()
                .map(|e| Value::Object(e.to_json_dict()))
                .collect()),
        );
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "byte_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        let core_obj = json_get_field(obj, "core_block")?.as_object().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: core_block must be object")
        })?;
        EffectDataCoreBlock::write_from_json_dict(w, core_obj)?;
        let lookups_c = json_get_field(obj, "lookups_c")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: lookups_c must be array"))?;
        if lookups_c.len() != 6 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("EffectDataElement: lookups_c must have 6 items, got {}", lookups_c.len())));
        }
        for v in lookups_c { <u32 as WriteJsonValue>::write_from_json(w, v)?; }
        let fields_d = json_get_field(obj, "fields_d")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: fields_d must be array"))?;
        if fields_d.len() != 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("EffectDataElement: fields_d must have 4 items, got {}", fields_d.len())));
        }
        for v in fields_d { <u32 as WriteJsonValue>::write_from_json(w, v)?; }
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "byte_e")?)?;
        let cstrs = json_get_field(obj, "cstring_list")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: cstring_list must be array"))?;
        (cstrs.len() as u32).write_to(w)?;
        for v in cstrs { <CString as WriteJsonValue>::write_from_json(w, v)?; }
        let f144s = json_get_field(obj, "fixed144_list")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: fixed144_list must be array"))?;
        (f144s.len() as u32).write_to(w)?;
        for v in f144s {
            let inner = v.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectDataElement: fixed144_list element must be object"))?;
            EffectDataD3Block::write_from_json_dict(w, inner)?;
        }
        let nested = json_get_field(obj, "nested_u32_lists")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: nested_u32_lists must be array"))?;
        (nested.len() as u32).write_to(w)?;
        for inner_v in nested {
            let inner = inner_v.as_array().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectDataElement: nested_u32_lists element must be array"))?;
            (inner.len() as u32).write_to(w)?;
            for v in inner { <u32 as WriteJsonValue>::write_from_json(w, v)?; }
        }
        let inner_map = json_get_field(obj, "inner_map")?.as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectDataElement: inner_map must be array"))?;
        (inner_map.len() as u32).write_to(w)?;
        for entry_v in inner_map {
            let entry = entry_v.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectDataElement: inner_map entry must be object"))?;
            EffectDataInnerMapEntry::write_from_json_dict(w, entry)?;
        }
        Ok(())
    }
}
