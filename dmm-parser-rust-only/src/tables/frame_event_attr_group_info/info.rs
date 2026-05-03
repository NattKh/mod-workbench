// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser for `FrameEventAttrGroupInfo.pabgb`.
//!
//! Per IDA sub_1410E17C0: 4 fields (key, stringKey, isBlocked, dataList).
//! `dataList` is a `CArray<FrameEventAttr>` via sub_1410E14F0 (421 wire
//! bytes / 424 mem bytes per element). Despite the original guess of
//! "deeply nested variant dispatch", sub_1410E14F0 is a fixed-shape
//! reader: u8 + 5× (3× u32) + 5× sub_1410E1250 (9× u32) +
//! 5× sub_1410E13E0 (2× u32 + Vec3 + 2× u32) + 5× (2× u32).

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Inner of FrameEventAttr triplet block (3× u32 per iter, 5 iters).
    pub struct FrameEventAttrTriplet {
        pub a: u32,
        pub b: u32,
        pub c: u32,
    }
}

py_binary_struct! {
    /// Inner of FrameEventAttr secondary block — sub_1410E1250 reads 9× u32
    /// per element (36 wire bytes).
    pub struct FrameEventAttrSecondary {
        pub a: u32, pub b: u32, pub c: u32,
        pub d: u32, pub e: u32, pub f: u32,
        pub g: u32, pub h: u32, pub i: u32,
    }
}

py_binary_struct! {
    /// Inner of FrameEventAttr tertiary block — sub_1410E13E0 reads
    /// u32 + u32 + Vec3 + u32 + u32 (28 wire bytes / 7 fields).
    pub struct FrameEventAttrTertiary {
        pub a: u32,
        pub b: u32,
        pub vec: [f32; 3],
        pub d: u32,
        pub e: u32,
    }
}

py_binary_struct! {
    /// Inner of FrameEventAttr trailing block (2× u32 per iter, 5 iters).
    pub struct FrameEventAttrPair {
        pub a: u32,
        pub b: u32,
    }
}

py_binary_struct! {
    /// `sub_1410E14F0` per-element. Fixed-shape, 421 wire bytes / 424 mem.
    pub struct FrameEventAttr {
        pub flag: u8,
        pub triplet_0: FrameEventAttrTriplet,
        pub triplet_1: FrameEventAttrTriplet,
        pub triplet_2: FrameEventAttrTriplet,
        pub triplet_3: FrameEventAttrTriplet,
        pub triplet_4: FrameEventAttrTriplet,
        pub secondary_0: FrameEventAttrSecondary,
        pub secondary_1: FrameEventAttrSecondary,
        pub secondary_2: FrameEventAttrSecondary,
        pub secondary_3: FrameEventAttrSecondary,
        pub secondary_4: FrameEventAttrSecondary,
        pub tertiary_0: FrameEventAttrTertiary,
        pub tertiary_1: FrameEventAttrTertiary,
        pub tertiary_2: FrameEventAttrTertiary,
        pub tertiary_3: FrameEventAttrTertiary,
        pub tertiary_4: FrameEventAttrTertiary,
        pub pair_0: FrameEventAttrPair,
        pub pair_1: FrameEventAttrPair,
        pub pair_2: FrameEventAttrPair,
        pub pair_3: FrameEventAttrPair,
        pub pair_4: FrameEventAttrPair,
    }
}

#[derive(Debug)]
pub struct FrameEventAttrGroupInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub data_list: CArray<FrameEventAttr>,
}

impl<'a> FrameEventAttrGroupInfo<'a> {
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
        let data_list = <CArray<FrameEventAttr>>::read_from(data, offset)?;
        if *offset != entry_end {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("FrameEventAttrGroupInfo: under/over-read (cursor {} expected {})",
                    *offset, entry_end)));
        }

        Ok(Self { key, string_key, is_blocked, data_list })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.data_list.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("data_list".to_string(), self.data_list.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <CArray<FrameEventAttr> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "data_list")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str =
        r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\frameeventattrgroupinfo.pabgb";
    const PABGH_PATH: &str =
        r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\frameeventattrgroupinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing pabgb fixture {}", PABGB_PATH);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
            eprintln!("SKIP: missing/unparseable pabgh fixture {}", PABGH_PATH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = FrameEventAttrGroupInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| {
                    panic!(
                        "parse failed at entry {} (key=0x{:x}, offset 0x{:x}, size {}): {}",
                        i, key, start, end - start, e
                    )
                });
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "frameeventattrgroupinfo roundtrip bytes mismatch");
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
            let item = FrameEventAttrGroupInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FrameEventAttrGroupInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
