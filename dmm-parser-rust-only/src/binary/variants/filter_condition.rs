// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Typed structures for the QuestDialog_FilterData family used by
//! `quest_info::_questDialogFilterDataList`.
//!
//! All sub-readers were decoded from CrimsonDesert.exe IDA decompiles —
//! see the `quest_dialog_filter_data_list_count` field docstring in
//! `tables/quest_info/info.rs` for the full call graph and per-reader
//! wire shapes. Every struct here corresponds 1:1 to a sub-reader:
//!
//!   sub_141D8F740  → FilterCondition          (tag-dispatched variant)
//!   sub_1410F4050  → FilterDataElement        (the 112-byte composite)
//!   sub_1410F3DE0  → FilterDataElementInner   (composite, 7 fields)
//!   sub_1410F41C0  → FilterDataNamed          (CString + 5 hashes + CArray)
//!   sub_1410F3F00  → FilterDataF3F00          (8 fields ending in CString)
//!   sub_1410F3D00  → FilterDataF3D00          (4 fields, fixed 13 bytes)
//!   sub_14110B710  → CArray<FilterDataB710>   (4 fields, fixed 13 bytes)
//!   sub_141103310  → CArray<HashU64Pair>      (12 bytes/elem)
//!
//! The two callers from the top-level QuestDialog_FilterData (sub_1410F42E0)
//! are sub_14110B150 and sub_14110AF20, each `CArray<{u16 + FilterDataElement}>`.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

// ── Leaves ──────────────────────────────────────────────────────────────────

py_binary_struct! {
    /// sub_141103310 element. Wire: u32 hash (sub_1410FF5C0 → u16) + u64 raw.
    pub struct HashU64Pair {
        pub hash: u32,
        pub raw_u64: u64,
    }
}

py_binary_struct! {
    /// sub_14110B710 element. Wire: u32 hash (sub_1410FF340 → u16_DA08) +
    /// u32 + u32 + u8.
    pub struct FilterDataB710 {
        pub hash: u32,
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// sub_1410F3D00. Wire: u32 hash (sub_1410FF340 → u16_DA08) +
    /// u32 + u32 + u8.
    pub struct FilterDataF3D00 {
        pub hash: u32,
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// sub_1410F3F00 element. Wire: 4 hash u32s + FilterDataF3D00 + 2 u32 +
    /// u8 + CString.
    pub struct FilterDataF3F00<'a> {
        pub hash_ff050: u32,         // sub_1410FF050 u32 hash
        pub hash_115e8: u32,         // sub_1410FF2D0 u32→u16 lookup_115E8
        pub hash_da30: u32,          // read_u32_lookup_DA30
        pub block: FilterDataF3D00,  // 13-byte sub-block
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag: u8,
        pub label: CString<'a>,
    }
}

py_binary_struct! {
    /// sub_1410F41C0 element (= sub_14110B8C0's CArray element). Wire:
    /// CString name + 4 hash u32s + CArray<u32→u16 hash_DA28> + 1 hash u32.
    pub struct FilterDataNamed<'a> {
        pub name: CString<'a>,
        pub hash_ff050: u32,                // sub_1410FF050
        pub hash_da30_a: u32,               // read_u32_lookup_DA30
        pub hash_da30_b: u32,               // read_u32_lookup_DA30
        pub hash_15030: u32,                // sub_1411060F0 u32→u16 lookup_15030
        pub hash_da28_list: CArray<u32>,    // sub_141104760 = CArray<u32→u16 hash_DA28>
        pub hash_006d0: u32,                // sub_1411006D0 u32 hash
    }
}

// ── Composites ──────────────────────────────────────────────────────────────

py_binary_struct! {
    /// sub_1410F3DE0. Wire: CArray<u32→u16 lookup_113C8> +
    /// CArray<HashU64Pair> + 2 hash u32s + raw u16 + raw u32 + raw u8.
    pub struct FilterDataElementInner {
        pub hash_113c8_list: CArray<u32>,         // sub_141100510
        pub hash_u64_list: CArray<HashU64Pair>,    // sub_141103310
        pub hash_d2d90: u32,                      // sub_141102D90 u32→u16
        pub raw_u16: u16,
        pub raw_u32: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// sub_1410F4050 (the 112-byte memory composite). Wire (per IDA):
    ///   u32 raw + u32 hash (sub_1411006D0) + u32 raw +
    ///   FilterDataElementInner +
    ///   CArray<FilterDataNamed> (sub_14110B8C0) +
    ///   CArray<FilterDataB710>  (sub_14110B710) +
    ///   CArray<FilterDataF3F00> (sub_14110B570).
    pub struct FilterDataElement<'a> {
        pub raw_a: u32,
        pub hash_006d0: u32,    // sub_1411006D0 u32 hash
        pub raw_b: u32,
        pub inner: FilterDataElementInner,
        pub named_list: CArray<FilterDataNamed<'a>>,
        pub b710_list: CArray<FilterDataB710>,
        pub f3f00_list: CArray<FilterDataF3F00<'a>>,
    }
}

py_binary_struct! {
    /// sub_14110B150 element. Wire: u16-from-u32 (sub_1411006D0) +
    /// FilterDataElement.
    pub struct FilterDataElementWithHash006D0<'a> {
        pub key: u32,                    // sub_1411006D0 u32 hash
        pub element: FilterDataElement<'a>,
    }
}

py_binary_struct! {
    /// sub_14110AF20 element. Wire: u16-from-u32 (read_u32_lookup_DA30) +
    /// FilterDataElement. Same shape as sub_14110B150 but different lookup
    /// table for the leading hash.
    pub struct FilterDataElementWithHashDA30<'a> {
        pub key: u32,                    // read_u32_lookup_DA30
        pub element: FilterDataElement<'a>,
    }
}

// ── FilterCondition (tag-dispatched variant) ────────────────────────────────

/// sub_141D8F740. Wire (in order):
///   1. u8 tag                              at a2+0
///   2. CArray<u16> via sub_1410FFAC0       at a2+8
///   3. CArray<{[u8;12] + u32}> inline      at a2+24 (mem); count u32 + N×16
///   4. CArray<HashU64Pair>                 at a2+40 (sub_141103310)
///   5. variant payload by tag (0-A inclusive):
///        0 / 1 / A: 0 bytes
///        2:         u32 hash (sub_1410FEE90 → u16)
///        3:         u32 hash (sub_1411003E0 → u16)
///        4 / 5:     u32 hash (sub_1410FF430 → u16)
///        6:         u32 hash (sub_141100860 → u16)
///        7:         raw u32
///        8:         u32 count + u32 raw
///        9:         u32 hash (sub_141102D90 → u16)
#[derive(Debug)]
pub struct FilterCondition {
    pub tag: u8,
    pub u16_list: CArray<u16>,
    pub block_list: CArray<FilterConditionBlock>,
    pub hash_u64_list: CArray<HashU64Pair>,
    pub payload: FilterConditionPayload,
}

py_binary_struct! {
    /// 16-byte inline element of the third CArray in FilterCondition.
    /// Wire: 3× u32 dword + u32. Per IDA, written via vmovups (full
    /// 16 bytes). STATUS.md documents the leading 12 bytes as a Vec3
    /// (likely a position/region center); split here as 3 named u32
    /// dwords to preserve any NaN bit patterns and provide JSON
    /// addressability without committing to f32 semantics
    /// (lane-c, 2026-04-30 — same precedent as
    /// CharacterChartEntry.block_a_dword_*).
    pub struct FilterConditionBlock {
        pub raw_block_dword_0: u32,
        pub raw_block_dword_1: u32,
        pub raw_block_dword_2: u32,
        pub raw_u32: u32,
    }
}

#[derive(Debug)]
pub enum FilterConditionPayload {
    /// Tags 0, 1, 10 — empty payload.
    Empty,
    /// Tag 2 — sub_1410FEE90: 2 wire bytes (u16) hashed via 145F115F0.
    Tag2(u16),
    /// Tag 3 — sub_1411003E0: 2 wire bytes (u16) hashed via 145F12668.
    Tag3(u16),
    /// Tags 4, 5 — sub_1410FF430: 4 wire bytes (u32 hash via 145F0E9C0).
    Tag4or5(u32),
    /// Tag 6 — sub_141100860: 4 wire bytes (u32 hash via 145F0DA48).
    Tag6(u32),
    /// Tag 7 — raw u32, 4 wire bytes.
    Tag7(u32),
    /// Tag 8 — u32 count + u32 raw (8 bytes total).
    Tag8 { count: u32, raw: u32 },
    /// Tag 9 — sub_141102D90: 4 wire bytes (u32 hash via 145F0EF00).
    Tag9(u32),
}

impl<'a> BinaryRead<'a> for FilterCondition {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let tag = u8::read_from(data, offset)?;
        let u16_list = CArray::<u16>::read_from(data, offset)?;
        let block_list = CArray::<FilterConditionBlock>::read_from(data, offset)?;
        let hash_u64_list = CArray::<HashU64Pair>::read_from(data, offset)?;
        let payload = match tag {
            0 | 1 | 10 => FilterConditionPayload::Empty,
            2 => FilterConditionPayload::Tag2(u16::read_from(data, offset)?),
            3 => FilterConditionPayload::Tag3(u16::read_from(data, offset)?),
            4 | 5 => FilterConditionPayload::Tag4or5(u32::read_from(data, offset)?),
            6 => FilterConditionPayload::Tag6(u32::read_from(data, offset)?),
            7 => FilterConditionPayload::Tag7(u32::read_from(data, offset)?),
            8 => {
                let count = u32::read_from(data, offset)?;
                let raw = u32::read_from(data, offset)?;
                FilterConditionPayload::Tag8 { count, raw }
            }
            9 => FilterConditionPayload::Tag9(u32::read_from(data, offset)?),
            other => {
                let tag_off = offset.saturating_sub(1);
                let ctx_start = tag_off.saturating_sub(8);
                let ctx_end = (tag_off + 16).min(data.len());
                let ctx = &data[ctx_start..ctx_end];
                let ctx_hex: String = ctx.iter().map(|b| format!("{:02x}", b)).collect();
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    format!("FilterCondition: unknown tag {} at offset {} \
                             (8 bytes before+16 after = {})",
                        other, tag_off, ctx_hex)));
            }
        };
        Ok(Self { tag, u16_list, block_list, hash_u64_list, payload })
    }
}

impl BinaryWrite for FilterCondition {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.tag.write_to(w)?;
        self.u16_list.write_to(w)?;
        self.block_list.write_to(w)?;
        self.hash_u64_list.write_to(w)?;
        match &self.payload {
            FilterConditionPayload::Empty => Ok(()),
            FilterConditionPayload::Tag2(v) | FilterConditionPayload::Tag3(v) => v.write_to(w),
            FilterConditionPayload::Tag4or5(v)
            | FilterConditionPayload::Tag6(v)
            | FilterConditionPayload::Tag7(v)
            | FilterConditionPayload::Tag9(v) => v.write_to(w),
            FilterConditionPayload::Tag8 { count, raw } => {
                count.write_to(w)?;
                raw.write_to(w)
            }
        }
    }
}

impl<'a> BinaryReadTracked<'a> for FilterCondition {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        _path: &mut String,
        _ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        <Self as BinaryRead<'a>>::read_from(data, offset)
    }
}

impl ToJsonValue for FilterCondition {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("tag".into(), self.tag.to_json_value());
        m.insert("u16_list".into(), self.u16_list.to_json_value());
        m.insert("block_list".into(), self.block_list.to_json_value());
        m.insert("hash_u64_list".into(), self.hash_u64_list.to_json_value());
        let payload = match &self.payload {
            FilterConditionPayload::Empty => Value::Null,
            FilterConditionPayload::Tag2(v) | FilterConditionPayload::Tag3(v) => v.to_json_value(),
            FilterConditionPayload::Tag4or5(v)
            | FilterConditionPayload::Tag6(v)
            | FilterConditionPayload::Tag7(v)
            | FilterConditionPayload::Tag9(v) => v.to_json_value(),
            FilterConditionPayload::Tag8 { count, raw } => {
                let mut p = Map::new();
                p.insert("count".into(), count.to_json_value());
                p.insert("raw".into(), raw.to_json_value());
                Value::Object(p)
            }
        };
        m.insert("payload".into(), payload);
        Value::Object(m)
    }
}

impl WriteJsonValue for FilterCondition {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "FilterCondition: expected object"))?;
        let tag = json_get_field(obj, "tag")?.as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "FilterCondition.tag: expected number"))? as u8;
        w.push(tag);
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "u16_list")?)?;
        <CArray<FilterConditionBlock> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "block_list")?)?;
        <CArray<HashU64Pair> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "hash_u64_list")?)?;
        let payload = json_get_field(obj, "payload")?;
        match tag {
            0 | 1 | 10 => Ok(()),
            2 | 3 => <u16 as WriteJsonValue>::write_from_json(w, payload),
            4 | 5 | 6 | 7 | 9 => {
                <u32 as WriteJsonValue>::write_from_json(w, payload)
            }
            8 => {
                let p = payload.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FilterCondition.payload(tag=8): expected object"))?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "count")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "raw")?)
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("FilterCondition: unknown tag {}", other))),
        }
    }
}


py_binary_struct! {
    /// QuestDialog_FilterData — the 144-byte composite that lives in
    /// `quest_info::_questDialogFilterDataList`. Reader: sub_1410F42E0.
    /// 18 wire fields, all field-level addressable.
    pub struct QuestDialogFilterData<'a> {
        pub flag_a: u8,                                       // a2+0
        pub flag_b: u8,                                       // a2+1
        pub raw_a: u32,                                       // a2+4
        pub raw_b: u32,                                       // a2+8
        pub hash_ef20: u32,                                   // sub_141102CB0
        pub raw_c: u32,                                       // a2+16
        pub condition_list_a: CArray<FilterCondition>,        // sub_141107000
        pub condition_list_b: CArray<FilterCondition>,        // sub_141107000
        pub element_list_of_lists:
            CArray<CArray<FilterDataElement<'a>>>,            // sub_141107120 → 14110B380
        pub element_list_a: CArray<FilterDataElement<'a>>,    // sub_14110B380
        pub element_list_b: CArray<FilterDataElement<'a>>,    // sub_14110B380
        pub keyed_element_list_006d0:
            CArray<FilterDataElementWithHash006D0<'a>>,       // sub_14110B150
        pub keyed_element_list_da30:
            CArray<FilterDataElementWithHashDA30<'a>>,        // sub_14110AF20
        pub hash_ff050: u32,                                  // sub_1410FF050
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub flag_f: u8,
    }
}
