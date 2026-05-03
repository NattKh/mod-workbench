// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `FactionSpawnDataInfo.pabgb`.
//!
//! Per IDA sub_1410DF1D0: 7 fields fully field-level typed.
//!
//! Wire layout:
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. patrol_spawn_data:    COptional<PatrolSpawnData>          (sub_141115560)
//!   5. gimmick_spawn_data_list: CArray<GimmickElement>           (sub_141115390)
//!   6. schedule_spawn_info:   COptional<CArray<u16>>             (inline, sub_1410FF0C0)
//!   7. sequencer_spawn_info:  COptional<CArray<u32>>             (sub_141115190)
//!
//! ## Inner structs (recovered from nested IDA decompilation):
//!
//! `PatrolSpawnData` (sub_141115560 — 32-byte runtime when present):
//!   - patrol_named_list: CArray<PatrolNamedElement>     (sub_1411038D0)
//!   - patrol_element_list: CArray<PatrolElement>        (sub_1411156C0)
//!
//! `PatrolNamedElement` (sub_1411038D0 per element):
//!   - name: CString
//!   - key_hash: u32                                      (sub_1410FF430, qword_E9C0)
//!
//! `PatrolElement` (sub_1410DF020 per element, 33 fixed + 12*N nested):
//!   - field_a: u32
//!   - field_b: u32
//!   - field_c_hash: u32                                  (qword_D9F8 inline lookup)
//!   - nested: CArray<PatrolNestedElement>                (sub_1411037E0)
//!   - field_d_hash: u32                                  (sub_1410FF430, qword_E9C0)
//!   - field_e: u32
//!   - field_f: u32
//!   - flag: u8
//!
//! `PatrolNestedElement` (sub_1410DEF10 per element, 12 wire bytes):
//!   - field_a: u32                                       (sub_1410FF340, qword_DA08)
//!   - field_b: u16                                       (sub_1411003E0, qword_12668)
//!   - field_c: u32                                       (sub_1410FF340)
//!   - field_d: u16                                       (sub_1411003E0)
//!   - flag_a: u8
//!   - flag_b: u8
//!
//! `GimmickElement` (sub_141115390 per element):
//!   - name: CString
//!   - field_a: u16                                       (sub_1411003E0)
//!   - field_b: u32                                       (sub_1410FF430)

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Inner element of `PatrolElement.nested` (sub_1411037E0 →
    /// sub_1410DEF10). 12 wire bytes; runtime stride 10.
    pub struct PatrolNestedElement {
        pub field_a: u32,
        pub field_b: u16,
        pub field_c: u32,
        pub field_d: u16,
        pub flag_a: u8,
        pub flag_b: u8,
    }
}

py_binary_struct! {
    /// Per-element of `PatrolSpawnData.patrol_element_list` (sub_1410DF020,
    /// 33 fixed bytes + 12*N nested).
    pub struct PatrolElement {
        pub field_a: u32,
        pub field_b: u32,
        pub field_c_hash: u32,
        pub nested: CArray<PatrolNestedElement>,
        pub field_d_hash: u32,
        pub field_e: u32,
        pub field_f: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// Per-element of `PatrolSpawnData.patrol_named_list` (sub_1411038D0).
    pub struct PatrolNamedElement<'a> {
        pub name: CString<'a>,
        pub key_hash: u32,
    }
}

py_binary_struct! {
    /// Patrol spawn data inner struct (sub_141115560 inner, 32B runtime).
    pub struct PatrolSpawnData<'a> {
        pub patrol_named_list: CArray<PatrolNamedElement<'a>>,
        pub patrol_element_list: CArray<PatrolElement>,
    }
}

py_binary_struct! {
    /// Per-element of `gimmick_spawn_data_list` (sub_141115390).
    pub struct GimmickElement<'a> {
        pub name: CString<'a>,
        pub field_a: u16,
        pub field_b: u32,
    }
}

#[derive(Debug)]
pub struct FactionSpawnDataInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub patrol_spawn_data: COptional<PatrolSpawnData<'a>>,
    pub gimmick_spawn_data_list: CArray<GimmickElement<'a>>,
    pub schedule_spawn_info: COptional<CArray<u16>>,
    pub sequencer_spawn_info: COptional<CArray<u32>>,
}

impl<'a> FactionSpawnDataInfo<'a> {
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
        let patrol_spawn_data = COptional::<PatrolSpawnData>::read_from(data, offset)?;
        let gimmick_spawn_data_list = CArray::<GimmickElement>::read_from(data, offset)?;
        let schedule_spawn_info = COptional::<CArray<u16>>::read_from(data, offset)?;
        let sequencer_spawn_info = COptional::<CArray<u32>>::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "FactionSpawnDataInfo k=0x{:x}: under/over-read (consumed {} of {} bytes)",
                    key, *offset - entry_start, entry_size,
                ),
            ));
        }

        Ok(Self {
            key, string_key, is_blocked,
            patrol_spawn_data, gimmick_spawn_data_list,
            schedule_spawn_info, sequencer_spawn_info,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.patrol_spawn_data.write_to(w)?;
        self.gimmick_spawn_data_list.write_to(w)?;
        self.schedule_spawn_info.write_to(w)?;
        self.sequencer_spawn_info.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("patrol_spawn_data".to_string(), self.patrol_spawn_data.to_json_value());
        m.insert("gimmick_spawn_data_list".to_string(), self.gimmick_spawn_data_list.to_json_value());
        m.insert("schedule_spawn_info".to_string(), self.schedule_spawn_info.to_json_value());
        m.insert("sequencer_spawn_info".to_string(), self.sequencer_spawn_info.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <COptional<PatrolSpawnData> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "patrol_spawn_data")?,
        )?;
        <CArray<GimmickElement> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "gimmick_spawn_data_list")?,
        )?;
        <COptional<CArray<u16>> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "schedule_spawn_info")?,
        )?;
        <COptional<CArray<u32>> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "sequencer_spawn_info")?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\factionspawndatainfo.pabgb";
    const PABGH_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\factionspawndatainfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = FactionSpawnDataInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x} off=0x{:x} size={}: {}", i, key, start, end-start, e));
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "factionspawndatainfo roundtrip bytes mismatch");
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
            let item = FactionSpawnDataInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FactionSpawnDataInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
