#![allow(clippy::doc_overindented_list_items)]
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
//! Reader: `sub_1410E8BF0` in CrimsonDesert.exe (Win build). All fields
//! reverse-engineered now that SequencerStageChartDesc has a complete
//! decoder.
//!
//! Wire reads, in order:
//!   1. u32 key                            (_key)
//!   2. CString string_key                 (_stringKey)
//!   3. u8 is_blocked                      (_isBlocked)
//!   4. CString group_name                 (_groupName)
//!   5. u32 group_leader_info              (sub_141104340 →
//!                                          qword_145F0E9B8 hash)
//!   6. LoadingTargetInfo loading_target   (sub_141110D30 — u8 presence
//!                                          + Option<{SequencerStage-
//!                                          ChartDesc + CString}>)
//!   7. PlayerBehaviorOptional behavior_optional
//!                                         (sub_1411057F0 — u8 presence
//!                                          + Option<{u8 + 3× u32 lookup}>)
//!   8. u8 use_reserve
//!   9. u8 ignore_player_state
//!  10. u32 player_behavior_space_radius
//!  11. u32 player_behavior_floor_check_distance
//!  12. u32 player_behavior_space_check_offset_y
//!  13. u32 player_behavior_play_condition (sub_1410FF430 →
//!                                          qword_145F0E9C0 hash)
//!  14. CArray<SequencerStageChartDescPartial> sequencer_desc_list
//!                                         (sub_141110B70 — 232-byte
//!                                          stride per element)

use crate::binary::*;
use crate::binary::variants::sequencer_stage_chart_desc::SequencerStageChartDescPartial;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

/// `sub_141110D30` — `Option<{SequencerStageChartDesc + CString}>`.
/// 240 mem bytes when present.
#[derive(Debug)]
pub struct LoadingTargetInfo<'a> {
    pub inner: Option<LoadingTargetInner<'a>>,
}

#[derive(Debug)]
pub struct LoadingTargetInner<'a> {
    pub desc: SequencerStageChartDescPartial<'a>,
    pub trailing_cstring: CString<'a>,
}

impl<'a> BinaryRead<'a> for LoadingTargetInfo<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(LoadingTargetInner {
                desc: SequencerStageChartDescPartial::read_from(data, offset)?,
                trailing_cstring: CString::read_from(data, offset)?,
            })
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl<'a> BinaryWrite for LoadingTargetInfo<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => {
                1u8.write_to(w)?;
                v.desc.write_to(w)?;
                v.trailing_cstring.write_to(w)?;
            }
            None => 0u8.write_to(w)?,
        }
        Ok(())
    }
}

impl<'a> ToJsonValue for LoadingTargetInfo<'a> {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => {
                let mut m = Map::new();
                m.insert("desc".to_string(), v.desc.to_json_value());
                m.insert("trailing_cstring".to_string(), v.trailing_cstring.to_json_value());
                Value::Object(m)
            }
            None => Value::Null,
        }
    }
}

impl<'a> WriteJsonValue for LoadingTargetInfo<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)?;
            return Ok(());
        }
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "LoadingTargetInfo: expected object or null",
        ))?;
        1u8.write_to(w)?;
        <SequencerStageChartDescPartial as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "desc")?,
        )?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "trailing_cstring")?)?;
        Ok(())
    }
}

/// `sub_1411057F0` — Option of (u8 + 3× u32 lookup).
#[derive(Debug)]
pub struct PlayerBehaviorOptional {
    pub inner: Option<PlayerBehaviorInner>,
}

#[derive(Debug)]
pub struct PlayerBehaviorInner {
    pub flag: u8,
    pub lookup_a: u32,
    pub lookup_b: u32,
    pub lookup_c: u32,
}

impl<'a> BinaryRead<'a> for PlayerBehaviorOptional {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(PlayerBehaviorInner {
                flag: u8::read_from(data, offset)?,
                lookup_a: u32::read_from(data, offset)?,
                lookup_b: u32::read_from(data, offset)?,
                lookup_c: u32::read_from(data, offset)?,
            })
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl BinaryWrite for PlayerBehaviorOptional {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => {
                1u8.write_to(w)?;
                v.flag.write_to(w)?;
                v.lookup_a.write_to(w)?;
                v.lookup_b.write_to(w)?;
                v.lookup_c.write_to(w)?;
            }
            None => 0u8.write_to(w)?,
        }
        Ok(())
    }
}

impl ToJsonValue for PlayerBehaviorOptional {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => {
                let mut m = Map::new();
                m.insert("flag".to_string(), v.flag.to_json_value());
                m.insert("lookup_a".to_string(), v.lookup_a.to_json_value());
                m.insert("lookup_b".to_string(), v.lookup_b.to_json_value());
                m.insert("lookup_c".to_string(), v.lookup_c.to_json_value());
                Value::Object(m)
            }
            None => Value::Null,
        }
    }
}

impl WriteJsonValue for PlayerBehaviorOptional {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)?;
            return Ok(());
        }
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "PlayerBehaviorOptional: expected object or null",
        ))?;
        1u8.write_to(w)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GlobalStageSequencerInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub group_name: CString<'a>,
    pub group_leader_info: u32,
    pub loading_target: LoadingTargetInfo<'a>,
    pub behavior_optional: PlayerBehaviorOptional,
    pub use_reserve: u8,
    pub ignore_player_state: u8,
    pub player_behavior_space_radius: u32,
    pub player_behavior_floor_check_distance: u32,
    pub player_behavior_space_check_offset_y: u32,
    pub player_behavior_play_condition: u32,
    pub sequencer_desc_list: CArray<SequencerStageChartDescPartial<'a>>,
}

impl<'a> GlobalStageSequencerInfo<'a> {
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
        let group_name = CString::read_from(data, offset)?;
        let group_leader_info = u32::read_from(data, offset)?;
        let loading_target = LoadingTargetInfo::read_from(data, offset)?;
        let behavior_optional = PlayerBehaviorOptional::read_from(data, offset)?;
        let use_reserve = u8::read_from(data, offset)?;
        let ignore_player_state = u8::read_from(data, offset)?;
        let player_behavior_space_radius = u32::read_from(data, offset)?;
        let player_behavior_floor_check_distance = u32::read_from(data, offset)?;
        let player_behavior_space_check_offset_y = u32::read_from(data, offset)?;
        let player_behavior_play_condition = u32::read_from(data, offset)?;
        let sequencer_desc_list = CArray::<SequencerStageChartDescPartial>::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "GlobalStageSequencerInfo: under/over-read (cursor={}, expected={})",
                    *offset, entry_end
                ),
            ));
        }

        Ok(Self {
            key, string_key, is_blocked, group_name, group_leader_info,
            loading_target, behavior_optional, use_reserve, ignore_player_state,
            player_behavior_space_radius, player_behavior_floor_check_distance,
            player_behavior_space_check_offset_y, player_behavior_play_condition,
            sequencer_desc_list,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.group_name.write_to(w)?;
        self.group_leader_info.write_to(w)?;
        self.loading_target.write_to(w)?;
        self.behavior_optional.write_to(w)?;
        self.use_reserve.write_to(w)?;
        self.ignore_player_state.write_to(w)?;
        self.player_behavior_space_radius.write_to(w)?;
        self.player_behavior_floor_check_distance.write_to(w)?;
        self.player_behavior_space_check_offset_y.write_to(w)?;
        self.player_behavior_play_condition.write_to(w)?;
        self.sequencer_desc_list.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("group_name".to_string(), self.group_name.to_json_value());
        m.insert("group_leader_info".to_string(), self.group_leader_info.to_json_value());
        m.insert("loading_target".to_string(), self.loading_target.to_json_value());
        m.insert("behavior_optional".to_string(), self.behavior_optional.to_json_value());
        m.insert("use_reserve".to_string(), self.use_reserve.to_json_value());
        m.insert("ignore_player_state".to_string(), self.ignore_player_state.to_json_value());
        m.insert("player_behavior_space_radius".to_string(), self.player_behavior_space_radius.to_json_value());
        m.insert("player_behavior_floor_check_distance".to_string(), self.player_behavior_floor_check_distance.to_json_value());
        m.insert("player_behavior_space_check_offset_y".to_string(), self.player_behavior_space_check_offset_y.to_json_value());
        m.insert("player_behavior_play_condition".to_string(), self.player_behavior_play_condition.to_json_value());
        m.insert("sequencer_desc_list".to_string(), self.sequencer_desc_list.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "group_name")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "group_leader_info")?)?;
        <LoadingTargetInfo as WriteJsonValue>::write_from_json(w, json_get_field(obj, "loading_target")?)?;
        <PlayerBehaviorOptional as WriteJsonValue>::write_from_json(w, json_get_field(obj, "behavior_optional")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_reserve")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "ignore_player_state")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_behavior_space_radius")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_behavior_floor_check_distance")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_behavior_space_check_offset_y")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_behavior_play_condition")?)?;
        <CArray<SequencerStageChartDescPartial> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "sequencer_desc_list")?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalstagesequencerinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalstagesequencerinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                GlobalStageSequencerInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "globalstagesequencerinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = GlobalStageSequencerInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            GlobalStageSequencerInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
