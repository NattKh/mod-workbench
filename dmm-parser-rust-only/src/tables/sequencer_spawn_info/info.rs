// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed.
//!
//! Reader: `sub_1410F6AA0` (outer) + `sub_141DAE6A0` (per-element of
//! _sequencerSpawnDataList). Each element is a 56-mem-byte record with
//! the polymorphic SequencerStageChartDesc embedded inline (now fully
//! decoded by `binary::sequencer_stage_chart_desc::SequencerStageChartDescPartial`).
//!
//! Wire layout (in order):
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. CString description
//!   5. CArray<SequencerSpawnDataElement> sequencer_spawn_data_list
//!   6. u8 stage_type
//!   7. u8 is_random
//!   8. u32 match_tag_hash
//!
//! Per `sub_141DAE6A0` each `SequencerSpawnDataElement` is:
//!     u32 player_condition_info  (sub_1410FF430 → qword_145F0E9C0)
//!     u32 lookup_b               (read_u32_lookup_DA30 → qword_145F0DA30)
//!     SequencerStageChartDescPartial desc  (sub_141D8C6D0 inline)
//!     u64 raw_a, u64 raw_b, u64 raw_c
//!     u8 flag_a
//!     u32 raw_d
//!     u8 flag_b
//!     u8 flag_c

use crate::binary::*;
use crate::binary::variants::sequencer_stage_chart_desc::SequencerStageChartDescPartial;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

/// Per-element of `sequencer_spawn_data_list` — sub_141DAE6A0.
#[derive(Debug)]
pub struct SequencerSpawnDataElement<'a> {
    pub player_condition_info: u32,
    pub lookup_b: u32,
    pub desc: SequencerStageChartDescPartial<'a>,
    pub raw_a: u64,
    pub raw_b: u64,
    pub raw_c: u64,
    pub flag_a: u8,
    pub raw_d: u32,
    pub flag_b: u8,
    pub flag_c: u8,
}

impl<'a> BinaryRead<'a> for SequencerSpawnDataElement<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            player_condition_info: u32::read_from(data, offset)?,
            lookup_b: u32::read_from(data, offset)?,
            desc: SequencerStageChartDescPartial::read_from(data, offset)?,
            raw_a: u64::read_from(data, offset)?,
            raw_b: u64::read_from(data, offset)?,
            raw_c: u64::read_from(data, offset)?,
            flag_a: u8::read_from(data, offset)?,
            raw_d: u32::read_from(data, offset)?,
            flag_b: u8::read_from(data, offset)?,
            flag_c: u8::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for SequencerSpawnDataElement<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.player_condition_info.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.desc.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.raw_c.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.raw_d.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for SequencerSpawnDataElement<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("player_condition_info".to_string(), self.player_condition_info.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("desc".to_string(), self.desc.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("raw_b".to_string(), self.raw_b.to_json_value());
        m.insert("raw_c".to_string(), self.raw_c.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("raw_d".to_string(), self.raw_d.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for SequencerSpawnDataElement<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "SequencerSpawnDataElement: expected object",
        ))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_condition_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <SequencerStageChartDescPartial as WriteJsonValue>::write_from_json(w, json_get_field(obj, "desc")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_d")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SequencerSpawnInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub description: CString<'a>,
    pub sequencer_spawn_data_list: CArray<SequencerSpawnDataElement<'a>>,
    pub stage_type: u8,
    pub is_random: u8,
    pub match_tag_hash: u32,
}

impl<'a> SequencerSpawnInfo<'a> {
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
        let description = CString::read_from(data, offset)?;
        let sequencer_spawn_data_list = CArray::<SequencerSpawnDataElement>::read_from(data, offset)?;
        let stage_type = u8::read_from(data, offset)?;
        let is_random = u8::read_from(data, offset)?;
        let match_tag_hash = u32::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SequencerSpawnInfo: under/over-read (cursor={}, expected={})",
                    *offset, entry_end
                ),
            ));
        }

        Ok(Self {
            key, string_key, is_blocked, description,
            sequencer_spawn_data_list, stage_type, is_random, match_tag_hash,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.description.write_to(w)?;
        self.sequencer_spawn_data_list.write_to(w)?;
        self.stage_type.write_to(w)?;
        self.is_random.write_to(w)?;
        self.match_tag_hash.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("description".to_string(), self.description.to_json_value());
        m.insert("sequencer_spawn_data_list".to_string(), self.sequencer_spawn_data_list.to_json_value());
        m.insert("stage_type".to_string(), self.stage_type.to_json_value());
        m.insert("is_random".to_string(), self.is_random.to_json_value());
        m.insert("match_tag_hash".to_string(), self.match_tag_hash.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "description")?)?;
        <CArray<SequencerSpawnDataElement> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "sequencer_spawn_data_list")?,
        )?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_random")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "match_tag_hash")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\sequencerspawninfo.pabgb";
    const PABGH_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\sequencerspawninfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = SequencerSpawnInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x} off=0x{:x} size={}: {}", i, key, start, end-start, e));
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "sequencerspawninfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = SequencerSpawnInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            SequencerSpawnInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
