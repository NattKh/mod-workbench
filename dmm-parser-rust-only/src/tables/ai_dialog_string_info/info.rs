#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `AIDialogStringInfo.pabgb`.
//!
//! Per IDA sub_1410D5210: 11 fields, fully field-level typed.
//!
//! Wire layout:
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. u8 flag_a
//!   5. u8 flag_b
//!   6. CArray<u16> list_a
//!   7. u16 lookup_a (sub_1410FF220 — wire u16, runtime u16 hash)
//!   8. u32 lookup_b (sub_1410FF2D0 — wire u32, runtime u16 hash)
//!   9. dialog_map: CArray<DialogMapEntry>  (sub_141119210 — 2-level hashmap)
//!  10. trailing_byte: u8
//!  11. extra_data: AIDialogExtraData (COptional via sub_141119080 →
//!       sub_141118B00; CArray<CArray<{u32+u8}>> + u32 + u8)
//!
//! Inner readers from IDA:
//!   sub_141119210: u32 count + N×{ u16 outer_key + sub_141128710 result }
//!   sub_141128710: u32 count + N×{ u16 inner_key (sub_1410FEE90, qword_115F0) +
//!                                  CArray<u32> condition_keys (sub_1410FEF40, qword_DA30
//!                                                              hash per element) +
//!                                  u8 flag +
//!                                  u32 lookup (sub_1410FF050, qword_DA60) +
//!                                  LocalizableString text }
//!   sub_141119080: u8 presence + (if present: sub_141118B00 + u32 + u8)
//!   sub_141118B00: u32 outer + N×{ u32 inner + M×{ u32 condition (sub_1410FF050) +
//!                                                  u8 flag } }

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Per-element of `condition_keys`. Wire is u32 hash key + u8 flag.
    /// (sub_141118B00's inner reader.) Runtime stores hash-resolved u16 +
    /// flag in a single 4-byte slot; wire preserves both.
    pub struct AIDialogConditionFlag {
        pub condition_lookup: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// Inner localized map entry (sub_141128710 per-element).
    /// `inner_key` is u16 wire (qword_115F0 family hash sentinel 0xFFFF).
    /// `condition_keys` are u32 wire each (qword_DA30 hash → u16 stored).
    /// `lookup` is u32 wire (qword_DA60 hash → u16 stored).
    pub struct AIDialogLocalizedEntry<'a> {
        pub inner_key: u16,
        pub condition_keys: CArray<u32>,
        pub flag: u8,
        pub lookup: u32,
        pub text: LocalizableString<'a>,
    }
}

py_binary_struct! {
    /// Outer map entry (sub_141119210 per-element). Each outer key maps to
    /// an inner array of localized entries.
    pub struct AIDialogMapEntry<'a> {
        pub outer_key: u16,
        pub localized_entries: CArray<AIDialogLocalizedEntry<'a>>,
    }
}

py_binary_struct! {
    /// Inner array of `extra_data.nested_lists` (sub_141118B00's inner array).
    pub struct AIDialogExtraInnerList {
        pub conditions: CArray<AIDialogConditionFlag>,
    }
}

#[derive(Debug)]
pub struct AIDialogExtraData {
    pub nested_lists: CArray<AIDialogExtraInnerList>,
    pub extra_dword: u32,
    pub extra_byte: u8,
}

impl<'a> BinaryRead<'a> for AIDialogExtraData {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let nested_lists = CArray::<AIDialogExtraInnerList>::read_from(data, offset)?;
        let extra_dword = u32::read_from(data, offset)?;
        let extra_byte = u8::read_from(data, offset)?;
        Ok(Self { nested_lists, extra_dword, extra_byte })
    }
}

impl BinaryWrite for AIDialogExtraData {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.nested_lists.write_to(w)?;
        self.extra_dword.write_to(w)?;
        self.extra_byte.write_to(w)
    }
}

impl ToJsonValue for AIDialogExtraData {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("nested_lists".into(), self.nested_lists.to_json_value());
        m.insert("extra_dword".into(), self.extra_dword.to_json_value());
        m.insert("extra_byte".into(), self.extra_byte.to_json_value());
        Value::Object(m)
    }
}

impl WriteJsonValue for AIDialogExtraData {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                "AIDialogExtraData: expected object")
        })?;
        <CArray<AIDialogExtraInnerList> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "nested_lists")?,
        )?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "extra_dword")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "extra_byte")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AIDialogStringInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub flag_a: u8,
    pub flag_b: u8,
    pub list_a: CArray<u16>,
    pub lookup_a: u16,
    pub lookup_b: u32,
    pub dialog_map: CArray<AIDialogMapEntry<'a>>,
    pub trailing_byte: u8,
    pub extra_data: COptional<AIDialogExtraData>,
}

impl<'a> AIDialogStringInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let list_a = CArray::<u16>::read_from(data, offset)?;
        let lookup_a = u16::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let dialog_map = CArray::<AIDialogMapEntry>::read_from(data, offset)?;
        let trailing_byte = u8::read_from(data, offset)?;
        let extra_data = COptional::<AIDialogExtraData>::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "AIDialogStringInfo: under/over-read (consumed {} of {} bytes)",
                    *offset - entry_start, entry_size,
                ),
            ));
        }

        Ok(Self {
            key, string_key, is_blocked, flag_a, flag_b,
            list_a, lookup_a, lookup_b,
            dialog_map, trailing_byte, extra_data,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.list_a.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.dialog_map.write_to(w)?;
        self.trailing_byte.write_to(w)?;
        self.extra_data.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("list_a".to_string(), self.list_a.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("dialog_map".to_string(), self.dialog_map.to_json_value());
        m.insert("trailing_byte".to_string(), self.trailing_byte.to_json_value());
        m.insert("extra_data".to_string(), self.extra_data.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_a")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <CArray<AIDialogMapEntry> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "dialog_map")?,
        )?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "trailing_byte")?)?;
        <COptional<AIDialogExtraData> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "extra_data")?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\aidialogstringinfo.pabgb";
    const PABGH_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\aidialogstringinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = AIDialogStringInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x} off=0x{:x} size={}: {}", i, key, start, end-start, e));
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "aidialogstringinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
            eprintln!("SKIP: missing pabgh fixture {}", PABGH_PATH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = AIDialogStringInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            AIDialogStringInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
