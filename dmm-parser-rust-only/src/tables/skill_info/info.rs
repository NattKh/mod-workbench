// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! `Skill.pabgb` (SkillInfo) — fully field-decoded, **1952/1952 (100%) entries
//! round-trip byte-perfect**.
//!
//! Per IDA `sub_1410F8940` (1819 bytes), found via Korean error string
//! `'SkillInfo의 _allowSkillWithLowResource를 읽어들이는데 실패했다.'`.
//! All 34 fields per Mac symbols mapped.
//!
//! BuffData wrapper is `[u8 absent_flag][BuffData if absent_flag == 0]` per
//! sub_1419D9C70 (NO leading u32 like BuffInfo's BuffDataEntry). The 120-variant
//! BuffData family is shared with BuffInfo (same sub_1419D8B50 base reader,
//! same sub_1419D4FC0 allocator) — uses the existing
//! `binary::variants::buff_data::BuffData`. SummonBuffData (tag 10, previously
//! opaque) is now fully typed — see binary/variants/buff_data.rs.
//!
//! Helper sub-readers (decompiled from IDA):
//!   - GraphData (sub_141E2BB80):       8+8+8+4 = 28 stream bytes
//!   - ResourceStat (sub_1410F8830):    1+4+1+8+4+4 = 22 stream bytes
//!   - u32 lookups (sub_1410FF890, sub_1411077F0, sub_141107A20): u32 count + N×u32
//!   - u16 raw (sub_1410FEA90):         u32 count + N×u16
//!   - ResourceStat list (sub_141107900): u32 count + N×ResourceStat
//!   - read_u32_lookup_DA30:            u32 (4 stream bytes)
//!   - read_u32_lookup_DA10:            u32 (4 stream bytes)

use crate::binary::variants::buff_data::BuffData;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{json, Value};
use std::io::{self, Write};

/// `[u8 absent_flag][BuffData if absent_flag == 0]` per sub_1419D9C70.
/// 1 = absent (skip), 0 = present (read BuffData). Inverted from typical COptional.
#[derive(Debug)]
pub struct BuffDataOptional<'a> {
    pub absent_flag: u8,
    pub data: Option<BuffData<'a>>,
}

impl<'a> BinaryRead<'a> for BuffDataOptional<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let absent_flag = u8::read_from(data, offset)?;
        let payload = if absent_flag == 0 {
            Some(BuffData::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { absent_flag, data: payload })
    }
}

impl<'a> BinaryWrite for BuffDataOptional<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.absent_flag.write_to(w)?;
        if let Some(d) = &self.data {
            d.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> ToJsonValue for BuffDataOptional<'a> {
    fn to_json_value(&self) -> Value {
        match &self.data {
            None => json!({"absent_flag": self.absent_flag}),
            Some(d) => {
                let mut m = d.to_json_dict();
                m.insert("absent_flag".into(), self.absent_flag.to_json_value());
                Value::Object(m)
            }
        }
    }
}

impl<'a> WriteJsonValue for BuffDataOptional<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "BuffDataOptional: expected object",
        ))?;
        let absent_flag = json_get_field(obj, "absent_flag")?
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "BuffDataOptional.absent_flag: expected u8"))? as u8;
        absent_flag.write_to(w)?;
        if absent_flag == 0 {
            BuffData::write_from_json_dict(w, obj)?;
        }
        Ok(())
    }
}

/// 28-byte GraphData per sub_141E2BB80: u64 + u64 + u64 + u32.
#[derive(Debug)]
pub struct GraphData {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u32,
}

impl<'a> BinaryRead<'a> for GraphData {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let a = u64::read_from(data, offset)?;
        let b = u64::read_from(data, offset)?;
        let c = u64::read_from(data, offset)?;
        let d = u32::read_from(data, offset)?;
        Ok(Self { a, b, c, d })
    }
}

impl BinaryWrite for GraphData {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.a.write_to(w)?;
        self.b.write_to(w)?;
        self.c.write_to(w)?;
        self.d.write_to(w)?;
        Ok(())
    }
}

/// 22-byte ResourceStat per sub_1410F8830: u8 + u32 + u8 + u64 + u32 + u32.
#[derive(Debug)]
pub struct ResourceStat {
    pub a: u8,
    pub lookup_b: u32,
    pub c: u8,
    pub d: u64,
    pub lookup_e: u32,
    pub lookup_f: u32,
}

impl<'a> BinaryRead<'a> for ResourceStat {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let a = u8::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let c = u8::read_from(data, offset)?;
        let d = u64::read_from(data, offset)?;
        let lookup_e = u32::read_from(data, offset)?;
        let lookup_f = u32::read_from(data, offset)?;
        Ok(Self { a, lookup_b, c, d, lookup_e, lookup_f })
    }
}

impl BinaryWrite for ResourceStat {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.c.write_to(w)?;
        self.d.write_to(w)?;
        self.lookup_e.write_to(w)?;
        self.lookup_f.write_to(w)?;
        Ok(())
    }
}

/// 12-byte ResourceItem per inline loop in sub_1410F8940: u32 lookup + u64.
#[derive(Debug)]
pub struct ResourceItem {
    pub lookup: u32,
    pub value: u64,
}

impl<'a> BinaryRead<'a> for ResourceItem {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let lookup = u32::read_from(data, offset)?;
        let value = u64::read_from(data, offset)?;
        Ok(Self { lookup, value })
    }
}

impl BinaryWrite for ResourceItem {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.lookup.write_to(w)?;
        self.value.write_to(w)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SkillInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub cooltime: u32,
    pub buff_level_list: CArray<CArray<BuffDataOptional<'a>>>,
    pub skill_group_key: u32,
    pub parent_skill: u32,
    pub learn_level: u32,
    pub apply_type: u8,
    pub icon_path: u32,
    pub need_upgrade_item_info: u32,
    pub need_upgrade_item_count_graph: GraphData,
    pub need_upgrade_experience_graph: GraphData,
    pub usable_character_info_list: CArray<u32>,
    pub usable_condition: CArray<u32>,
    pub learn_knowledge_info: u32,
    pub faction_info: u32,
    pub use_resource_stat_list: CArray<ResourceStat>,
    pub use_resource_item_list: CArray<ResourceItem>,
    pub use_driver_resource_stat_list: CArray<ResourceStat>,
    pub use_battery_stat: u64,
    pub is_ui_use_allowed: u8,
    pub is_learn_use_artifact: u8,
    pub allow_skill_with_low_resource: u8,
    pub is_use_child_pattern_description_buff_data: u8,
    pub damage_type: u8,
    pub ui_type: u8,
    pub reserve_slot_info_list: CArray<u32>,
    pub max_level: u32,
    pub skill_group_key_list: CArray<u16>,
    pub buff_sustain_flag: u32,
    pub dev_skill_name: CString<'a>,
    pub dev_skill_desc: CString<'a>,
    pub video_path: u32,
}

impl<'a> SkillInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;
        // Clamp the data slice to the pabgh-declared entry boundary
        // so BuffData parsing can't overrun into adjacent entries.
        let entry_data = &data[..entry_end.min(data.len())];
        let key = u32::read_from(entry_data, offset)?;
        let string_key = CString::read_from(entry_data, offset)?;
        let is_blocked = u8::read_from(entry_data, offset)?;
        let cooltime = u32::read_from(entry_data, offset)?;
        let buff_level_list = CArray::<CArray<BuffDataOptional>>::read_from(entry_data, offset)?;
        let skill_group_key = u32::read_from(entry_data, offset)?;
        let parent_skill = u32::read_from(entry_data, offset)?;
        let learn_level = u32::read_from(entry_data, offset)?;
        let apply_type = u8::read_from(entry_data, offset)?;
        let icon_path = u32::read_from(entry_data, offset)?;
        let need_upgrade_item_info = u32::read_from(entry_data, offset)?;
        let need_upgrade_item_count_graph = GraphData::read_from(entry_data, offset)?;
        let need_upgrade_experience_graph = GraphData::read_from(entry_data, offset)?;
        let usable_character_info_list = CArray::<u32>::read_from(entry_data, offset)?;
        let usable_condition = CArray::<u32>::read_from(entry_data, offset)?;
        let learn_knowledge_info = u32::read_from(entry_data, offset)?;
        let faction_info = u32::read_from(entry_data, offset)?;
        let use_resource_stat_list = CArray::<ResourceStat>::read_from(entry_data, offset)?;
        let use_resource_item_list = CArray::<ResourceItem>::read_from(entry_data, offset)?;
        let use_driver_resource_stat_list = CArray::<ResourceStat>::read_from(entry_data, offset)?;
        let use_battery_stat = u64::read_from(entry_data, offset)?;
        let is_ui_use_allowed = u8::read_from(entry_data, offset)?;
        let is_learn_use_artifact = u8::read_from(entry_data, offset)?;
        let allow_skill_with_low_resource = u8::read_from(entry_data, offset)?;
        let is_use_child_pattern_description_buff_data = u8::read_from(entry_data, offset)?;
        let damage_type = u8::read_from(entry_data, offset)?;
        let ui_type = u8::read_from(entry_data, offset)?;
        let reserve_slot_info_list = CArray::<u32>::read_from(entry_data, offset)?;
        let max_level = u32::read_from(entry_data, offset)?;
        let skill_group_key_list = CArray::<u16>::read_from(entry_data, offset)?;
        let buff_sustain_flag = u32::read_from(entry_data, offset)?;
        let dev_skill_name = CString::read_from(entry_data, offset)?;
        let dev_skill_desc = CString::read_from(entry_data, offset)?;
        let video_path = u32::read_from(entry_data, offset)?;

        // Absorb trailing bytes only when a real pabgh boundary was provided.
        // When entry_size == remaining data (no pabgh), snapping to entry_end
        // jumps to EOF and kills all subsequent entries.
        let has_pabgh_boundary = entry_size < (data.len() - entry_start);
        if has_pabgh_boundary && *offset < entry_end {
            *offset = entry_end;
        }

        Ok(Self {
            key, string_key, is_blocked, cooltime, buff_level_list,
            skill_group_key, parent_skill, learn_level, apply_type,
            icon_path, need_upgrade_item_info,
            need_upgrade_item_count_graph, need_upgrade_experience_graph,
            usable_character_info_list, usable_condition,
            learn_knowledge_info, faction_info,
            use_resource_stat_list, use_resource_item_list, use_driver_resource_stat_list,
            use_battery_stat, is_ui_use_allowed, is_learn_use_artifact,
            allow_skill_with_low_resource, is_use_child_pattern_description_buff_data,
            damage_type, ui_type,
            reserve_slot_info_list, max_level, skill_group_key_list,
            buff_sustain_flag, dev_skill_name, dev_skill_desc, video_path,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.cooltime.write_to(w)?;
        self.buff_level_list.write_to(w)?;
        self.skill_group_key.write_to(w)?;
        self.parent_skill.write_to(w)?;
        self.learn_level.write_to(w)?;
        self.apply_type.write_to(w)?;
        self.icon_path.write_to(w)?;
        self.need_upgrade_item_info.write_to(w)?;
        self.need_upgrade_item_count_graph.write_to(w)?;
        self.need_upgrade_experience_graph.write_to(w)?;
        self.usable_character_info_list.write_to(w)?;
        self.usable_condition.write_to(w)?;
        self.learn_knowledge_info.write_to(w)?;
        self.faction_info.write_to(w)?;
        self.use_resource_stat_list.write_to(w)?;
        self.use_resource_item_list.write_to(w)?;
        self.use_driver_resource_stat_list.write_to(w)?;
        self.use_battery_stat.write_to(w)?;
        self.is_ui_use_allowed.write_to(w)?;
        self.is_learn_use_artifact.write_to(w)?;
        self.allow_skill_with_low_resource.write_to(w)?;
        self.is_use_child_pattern_description_buff_data.write_to(w)?;
        self.damage_type.write_to(w)?;
        self.ui_type.write_to(w)?;
        self.reserve_slot_info_list.write_to(w)?;
        self.max_level.write_to(w)?;
        self.skill_group_key_list.write_to(w)?;
        self.buff_sustain_flag.write_to(w)?;
        self.dev_skill_name.write_to(w)?;
        self.dev_skill_desc.write_to(w)?;
        self.video_path.write_to(w)?;
        Ok(())
    }
}

// ── JSON support ─────────────────────────────────────────────────────────────
//
// SkillInfo's simple fields (key, string_key, is_blocked, etc.) are exposed
// as JSON for direct field editing via v3 mods.
//
// `buff_level_list` (CArray<CArray<BuffDataOptional>>) ships as fully
// typed JSON via the per-variant BuffData ToJsonValue/WriteJsonValue
// impls in `binary::variants::buff_data`. Mod authors can drill into
// any single buff at any level.

impl ToJsonValue for GraphData {
    fn to_json_value(&self) -> Value {
        json!({"a": self.a, "b": self.b, "c": self.c, "d": self.d})
    }
}
impl WriteJsonValue for GraphData {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "GraphData: expected object"))?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "b")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "d")?)?;
        Ok(())
    }
}

impl ToJsonValue for ResourceStat {
    fn to_json_value(&self) -> Value {
        json!({
            "a": self.a, "lookup_b": self.lookup_b, "c": self.c,
            "d": self.d, "lookup_e": self.lookup_e, "lookup_f": self.lookup_f,
        })
    }
}
impl WriteJsonValue for ResourceStat {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "ResourceStat: expected object"))?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "c")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_e")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_f")?)?;
        Ok(())
    }
}

impl ToJsonValue for ResourceItem {
    fn to_json_value(&self) -> Value {
        json!({"lookup": self.lookup, "value": self.value})
    }
}
impl WriteJsonValue for ResourceItem {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "ResourceItem: expected object"))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "value")?)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for SkillInfo<'a> {
    fn to_json_value(&self) -> Value {
        json!({
            "key": self.key,
            "string_key": self.string_key.data,
            "is_blocked": self.is_blocked,
            "cooltime": self.cooltime,
            "buff_level_list": self.buff_level_list.to_json_value(),
            "skill_group_key": self.skill_group_key,
            "parent_skill": self.parent_skill,
            "learn_level": self.learn_level,
            "apply_type": self.apply_type,
            "icon_path": self.icon_path,
            "need_upgrade_item_info": self.need_upgrade_item_info,
            "need_upgrade_item_count_graph": self.need_upgrade_item_count_graph.to_json_value(),
            "need_upgrade_experience_graph": self.need_upgrade_experience_graph.to_json_value(),
            "usable_character_info_list": self.usable_character_info_list.to_json_value(),
            "usable_condition": self.usable_condition.to_json_value(),
            "learn_knowledge_info": self.learn_knowledge_info,
            "faction_info": self.faction_info,
            "use_resource_stat_list": self.use_resource_stat_list.to_json_value(),
            "use_resource_item_list": self.use_resource_item_list.to_json_value(),
            "use_driver_resource_stat_list": self.use_driver_resource_stat_list.to_json_value(),
            "use_battery_stat": self.use_battery_stat,
            "is_ui_use_allowed": self.is_ui_use_allowed,
            "is_learn_use_artifact": self.is_learn_use_artifact,
            "allow_skill_with_low_resource": self.allow_skill_with_low_resource,
            "is_use_child_pattern_description_buff_data": self.is_use_child_pattern_description_buff_data,
            "damage_type": self.damage_type,
            "ui_type": self.ui_type,
            "reserve_slot_info_list": self.reserve_slot_info_list.to_json_value(),
            "max_level": self.max_level,
            "skill_group_key_list": self.skill_group_key_list.to_json_value(),
            "buff_sustain_flag": self.buff_sustain_flag,
            "dev_skill_name": self.dev_skill_name.data,
            "dev_skill_desc": self.dev_skill_desc.data,
            "video_path": self.video_path,
        })
    }
}

impl<'a> WriteJsonValue for SkillInfo<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "SkillInfo: expected object"))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cooltime")?)?;
        <CArray<CArray<BuffDataOptional>> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "buff_level_list")?,
        )?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "skill_group_key")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "parent_skill")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "learn_level")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "apply_type")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "icon_path")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "need_upgrade_item_info")?)?;
        <GraphData as WriteJsonValue>::write_from_json(w, json_get_field(obj, "need_upgrade_item_count_graph")?)?;
        <GraphData as WriteJsonValue>::write_from_json(w, json_get_field(obj, "need_upgrade_experience_graph")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "usable_character_info_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "usable_condition")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "learn_knowledge_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "faction_info")?)?;
        <CArray<ResourceStat> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_resource_stat_list")?)?;
        <CArray<ResourceItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_resource_item_list")?)?;
        <CArray<ResourceStat> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_driver_resource_stat_list")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_battery_stat")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_ui_use_allowed")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_learn_use_artifact")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "allow_skill_with_low_resource")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_use_child_pattern_description_buff_data")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "damage_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "ui_type")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "reserve_slot_info_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "max_level")?)?;
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "skill_group_key_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "buff_sustain_flag")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dev_skill_name")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dev_skill_desc")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "video_path")?)?;
        Ok(())
    }
}

/// Parse a skill.pabgb body into a Vec of skill JSON dicts. Mirror of
/// `parse_iteminfo_to_json`. Used by DMM for v3 SkillInfo mod application.
///
/// Each SkillInfo entry is self-delimiting (its fields self-describe their
/// own length), so this function iterates the body without needing pabgh
/// boundaries — same calling convention as `parse_iteminfo_to_json`.
///
/// If a pabgh is available, prefer `parse_skill_to_json_with_pabgh` for
/// per-entry boundary verification.
pub fn parse_skill_to_json(data: &[u8]) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let item = SkillInfo::read_with_size(data, &mut offset, remaining)?;
        items.push(item.to_json_value());
    }
    Ok(items)
}

/// Variant of `parse_skill_to_json` that uses the pabgh sister file to
/// verify each entry's byte boundaries. Useful for mod-time validation.
pub fn parse_skill_to_json_with_pabgh(data: &[u8], pabgh: &[u8]) -> io::Result<Vec<Value>> {
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets_from_bytes};
    let entries = load_pabgh_offsets_from_bytes(pabgh).ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData, "pabgh parse failed"))?;
    let ranges = entry_ranges(&entries, data.len());
    let mut items = Vec::with_capacity(ranges.len());
    for (_k, s, e) in ranges {
        let mut c = s;
        match SkillInfo::read_with_size(data, &mut c, e - s) {
            Ok(item) => {
                items.push(item.to_json_value());
            }
            Err(_) => {
                // BuffData variant changed in game update — fall back to
                // blob representation so the entry roundtrips even if we
                // can't decode every field.
                use base64::Engine;
                let blob = &data[s..e];
                let key = u32::from_le_bytes(blob[..4].try_into().unwrap_or([0;4]));
                let mut m = serde_json::Map::new();
                m.insert("key".into(), Value::from(key));
                m.insert("_blob_b64".into(), Value::String(
                    base64::engine::general_purpose::STANDARD.encode(blob)));
                items.push(Value::Object(m));
            }
        }
    }
    Ok(items)
}

/// Inverse of `parse_skill_to_json`: write a sequence of skill dicts back
/// to pabgb bytes.
pub fn serialize_skill_from_json(items: &[Value]) -> io::Result<Vec<u8>> {
    use base64::Engine;
    let mut out = Vec::with_capacity(items.len() * 512);
    for (i, v) in items.iter().enumerate() {
        // Check if this is a blob-fallback entry
        if let Some(blob_b64) = v.get("_blob_b64").and_then(|b| b.as_str()) {
            let blob = base64::engine::general_purpose::STANDARD.decode(blob_b64)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("skill[{}]: bad base64: {}", i, e)))?;
            out.extend_from_slice(&blob);
        } else {
            SkillInfo::write_from_json(&mut out, v).map_err(|e| io::Error::new(
                e.kind(), format!("skill[{}]: {}", i, e)))?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skill.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skill.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        let mut pass = 0;
        let mut fails: Vec<String> = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            match SkillInfo::read_with_size(&data, &mut c, e - s) {
                Ok(item) => {
                    if c == *e {
                        items.push(item);
                        pass += 1;
                    } else {
                        fails.push(format!("e{} k=0x{:x}: under/over-consumed {}/{}", i, k, c - *s, e - *s));
                    }
                }
                Err(err) => {
                    fails.push(format!("e{} k=0x{:x}: {}", i, k, err));
                }
            }
        }
        if !fails.is_empty() {
            panic!("SkillInfo roundtrip: {} pass, {} fail (total {}).\nFailures:\n  {}",
                pass, fails.len(), ranges.len(), fails.join("\n  "));
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "SkillInfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = SkillInfo::read_with_size(&data, &mut c, e - s).unwrap();
            assert_eq!(c, *e);
            let json = item.to_json_value();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            <SkillInfo as WriteJsonValue>::write_from_json(&mut from_json, &json)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: write_from_json: {}", i, k, er));
            assert_eq!(from_json, from_typed,
                "e{} k=0x{:x}: JSON roundtrip diverges from typed write", i, k);
        }
    }
}
