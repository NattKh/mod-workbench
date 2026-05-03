// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — every wire byte typed. The polymorphic
//! SequencerStageChartDesc that used to ride as an opaque blob is now
//! fully decoded (26/26 wire fields) by `SequencerStageChartDescPartial`.
//!
//! Reader: `sub_1410E1090` in CrimsonDesert.exe (Win build).
//! Pabgb dump path is `reviepointinfo.pabgb` (typo in filename — game
//! ships it that way).
//!
//! Wire reads, in order:
//!   1. u32 key                                (_key)
//!   2. CString string_key                     (_stringKey)
//!   3. u8 is_blocked                          (_isBlocked)
//!   4. [u8; 12] position                      (_position, vec3 of f32s)
//!   5. u32 rotation_y                         (_rotationY, f32-as-u32)
//!   6. SequencerStageChartDescPartial sequencer_stage_chart_desc
//!      (sub_141D8C6D0; first 20 wire fields typed via partial
//!      wrapper, fields 21-26 ride as `_opaque_tail_b64`. Sized by
//!      `entry_size - 13` from the trailing fixed-size fields below)
//!   7. u32 field_info_key                     (_fieldInfoKey)
//!   8. u32 knowledge_info                     (_knowledgeInfo,
//!      sub_1411006D0 → qword_145F0DA28)
//!   9. u32 knowledge_level                    (_knowledgeLevel)
//!  10. u8 use_default_revive                  (_useDefaultRevive)
//!
//! sequencer_stage_chart_desc is the same polymorphic family used by
//! StageInfo / GlobalStageSequencerInfo; full typing of fields 14-26
//! requires reverse-engineering sub_141D8C6D0's embedded GameCondition
//! and sub_14110C270 (SequencerStageTrackChangeData family). The 13
//! prefix fields (`name`, `raw_a`, `prefab_path`, `position`, `raw_b`,
//! 8× `flag_*`) are individually editable as of this commit.

use crate::binary::*;
use crate::binary::variants::sequencer_stage_chart_desc::SequencerStageChartDescPartial;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct FieldReviveInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    /// Vec3 spawn position (x, y, z) per IDA sub_1006B48A8 — same Vec3
    /// helper as projectileShotSpread in game_global_effect_info.
    pub position: [f32; 3],
    /// f32 yaw rotation (sub_1006B3DE0).
    pub rotation_y: f32,
    /// Polymorphic SequencerStageChartDesc with its 20-field typed
    /// prefix exposed and the unfinished tail (fields 21-26) carried
    /// as a sized opaque blob. Round-trips byte-perfect; field-level
    /// editing for fields 1-20 is available via the partial wrapper.
    pub sequencer_stage_chart_desc: SequencerStageChartDescPartial<'a>,
    pub field_info_key: u32,
    pub knowledge_info: u32,
    pub knowledge_level: u32,
    pub use_default_revive: u8,
}

const TRAILING_BYTES: usize = 4 + 4 + 4 + 1; // field_info_key, knowledge_info, knowledge_level, use_default_revive

impl<'a> FieldReviveInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start
            .checked_add(entry_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "FieldReviveInfo: entry_size overflow"))?;
        if entry_end > data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                format!("FieldReviveInfo: record extends past body ({} > {})", entry_end, data.len())));
        }

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let position = <[f32; 3]>::read_from(data, offset)?;
        let rotation_y = f32::read_from(data, offset)?;

        // Size the opaque sequencer_stage_chart_desc by subtracting the
        // fixed trailing-field width from the remaining bytes.
        if entry_end < TRAILING_BYTES || *offset > entry_end - TRAILING_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("FieldReviveInfo: sequencer_desc bounds invalid (cursor={}, end={})", *offset, entry_end)));
        }
        let desc_end = entry_end - TRAILING_BYTES;
        let desc_size = desc_end - *offset;
        let sequencer_stage_chart_desc =
            SequencerStageChartDescPartial::read_with_size(data, offset, desc_size)?;

        let field_info_key = u32::read_from(data, offset)?;
        let knowledge_info = u32::read_from(data, offset)?;
        let knowledge_level = u32::read_from(data, offset)?;
        let use_default_revive = u8::read_from(data, offset)?;

        Ok(Self {
            key, string_key, is_blocked, position, rotation_y,
            sequencer_stage_chart_desc, field_info_key, knowledge_info,
            knowledge_level, use_default_revive,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.position.write_to(w)?;
        self.rotation_y.write_to(w)?;
        self.sequencer_stage_chart_desc.write_to(w)?;
        self.field_info_key.write_to(w)?;
        self.knowledge_info.write_to(w)?;
        self.knowledge_level.write_to(w)?;
        self.use_default_revive.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("position".to_string(), self.position.to_json_value());
        m.insert("rotation_y".to_string(), self.rotation_y.to_json_value());
        m.insert(
            "sequencer_stage_chart_desc".to_string(),
            self.sequencer_stage_chart_desc.to_json_value(),
        );
        m.insert("field_info_key".to_string(), self.field_info_key.to_json_value());
        m.insert("knowledge_info".to_string(), self.knowledge_info.to_json_value());
        m.insert("knowledge_level".to_string(), self.knowledge_level.to_json_value());
        m.insert("use_default_revive".to_string(), self.use_default_revive.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <[f32; 3] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "position")?)?;
        <f32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "rotation_y")?)?;
        SequencerStageChartDescPartial::write_from_json(
            w,
            json_get_field(obj, "sequencer_stage_chart_desc")?,
        )?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_info_key")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "knowledge_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "knowledge_level")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_default_revive")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\reviepointinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\reviepointinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                FieldReviveInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "fieldreviveinfo (reviepointinfo.pabgb) roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = FieldReviveInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FieldReviveInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }

    #[test]
    fn fields_addressable() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let Some((_, s, e)) = ranges.first() else { eprintln!("SKIP: no entries"); return; };
        let mut c = *s;
        let item = FieldReviveInfo::read_with_size(&data, &mut c, e - s).unwrap();
        let dict = item.to_json_dict();
        for f in [
            "key", "string_key", "is_blocked", "position", "rotation_y",
            "sequencer_stage_chart_desc",
            "field_info_key", "knowledge_info", "knowledge_level",
            "use_default_revive",
        ] {
            assert!(dict.contains_key(f), "missing field `{}` in JSON dict", f);
        }
        assert!(!dict.contains_key("_tail_b64"), "Tier 1.5 _tail_b64 leaked");
        // Verify the SequencerStageChartDesc partial wrapper exposes
        // its 13 typed prefix fields plus the opaque tail.
        let desc = dict.get("sequencer_stage_chart_desc")
            .and_then(|v| v.as_object())
            .expect("sequencer_stage_chart_desc must be an object");
        for f in [
            "name", "raw_a", "prefab_path", "position", "raw_b",
            "flag_a", "flag_b", "flag_c", "flag_d", "flag_e",
            "flag_f", "flag_g", "flag_h", "lookup_a", "cond_a",
            "cstring_a", "cstring_b", "string_pair_list",
            "track_change_list", "spawn_data_lists",
            "list_a", "list_b", "list_c", "list_d", "list_e", "list_f",
            "_opaque_tail_b64",
        ] {
            assert!(desc.contains_key(f),
                "SequencerStageChartDescPartial missing field `{}`", f);
        }
        // Vanilla SequencerStageChartDesc decodes to all-typed fields,
        // so opaque_tail must be empty.
        let tail = desc.get("_opaque_tail_b64")
            .and_then(|v| v.as_str())
            .expect("_opaque_tail_b64 must be a string");
        assert_eq!(tail, "", "vanilla SequencerStageChartDesc should leave opaque_tail empty");
    }
}
