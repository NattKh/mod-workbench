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
//! Reader: `sub_1410F5140` in CrimsonDesert.exe (Win build).
//! Tail readers (decoded for the Tier 1.5 → 1 promotion):
//!   - sub_1411043B0 → CArray<RegionGimmickAliasItem>
//!     (each element: u32 lookup_a + u32 value, 8 wire bytes)
//!   - sub_14110A900 → CArray<RegionDomainFactionItem>
//!     (each element: u32 condition_info + u32 faction_info + u32
//!      mission_info, 12 wire bytes)
//!   - sub_1410FEF40 → CArray<u32> (tag_list)
//!
//! Wire reads, in order (canonical names from Mac Korean error strings
//! / docs/449_TABLE_CATALOG.md):
//!   1.  u16 key                              (_key, pabgh format 2)
//!   2.  CString string_key                   (_stringKey)
//!   3.  u8 is_blocked                        (_isBlocked)
//!   4.  LocalizableString display_region_name (_displayRegionName)
//!   5.  u32 knowledge_info                   (_knowledgeInfo,
//!       sub_1411006D0 → qword_145F0DA28)
//!   6.  CArray<RegionSubA> region_enter_knowledge_info_list
//!       (_regionEnterknowledgeInfoList, sub_141104230)
//!   7.  u16 parent_region_info               (_parentRegionInfo,
//!       sub_1410FF220 → qword_145F0DA80, u16 wire)
//!   8.  CArray<u16> child_region_info_list   (_childRegionInfoList,
//!       sub_1410FFAC0)
//!   9.  u8 bitmap_color                      (_bitmapColor)
//!  10.  u8 overrided_max_height              (_overriedMaxHeight, sic)
//!  11.  u32 region_type                      (_regionType)
//!  12.  u8 fog_clear_condition               (_fogClearCondition)
//!  13.  u32 limit_vehicle_run                (_limitVehicleRun,
//!       sub_1410FF430 → qword_145F0E9C0)
//!  14.  u8 is_town
//!  15.  u8 is_wild
//!  16.  u8 is_ui_map_disable
//!  17.  u8 is_housing_region
//!  18.  u8 is_none_play_zone
//!  19.  u8 vehicle_mercenary_allow_type
//!  20.  u8 is_world_map_road_path_findable
//!  21.  u8 u8_123  (no matching canonical name — extra byte at wire
//!       offset 123 preserved for byte-perfect round-trip)
//!  22.  CArray<RegionGimmickAliasItem> gimmick_alias_pointer_list
//!       (_gimmickAliasPointerList, sub_1411043B0)
//!  23.  CArray<RegionDomainFactionItem> domain_faction_list
//!       (_domainFactionList, sub_14110A900)
//!  24.  CArray<u32> tag_list                 (_tagList, sub_1410FEF40)

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct RegionSubA {
        pub lookup_a: u32,
        pub raw_b: u32,
    }
}

py_binary_struct! {
    pub struct RegionGimmickAliasItem {
        pub lookup_a: u32,
        pub value: u32,
    }
}

py_binary_struct! {
    pub struct RegionDomainFactionItem {
        pub condition_info: u32,
        pub faction_info: u32,
        pub mission_info: u32,
    }
}

#[derive(Debug)]
pub struct RegionInfo<'a> {
    pub key: u16,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub display_region_name: LocalizableString<'a>,
    pub knowledge_info: u32,
    pub region_enter_knowledge_info_list: CArray<RegionSubA>,
    pub parent_region_info: u16,
    pub child_region_info_list: CArray<u16>,
    pub bitmap_color: u8,
    pub overrided_max_height: u8,
    pub region_type: u32,
    pub fog_clear_condition: u8,
    pub limit_vehicle_run: u32,
    pub is_town: u8,
    pub is_wild: u8,
    pub is_ui_map_disable: u8,
    pub is_housing_region: u8,
    pub is_none_play_zone: u8,
    pub vehicle_mercenary_allow_type: u8,
    pub is_world_map_road_path_findable: u8,
    pub u8_123: u8,
    pub gimmick_alias_pointer_list: CArray<RegionGimmickAliasItem>,
    pub domain_faction_list: CArray<RegionDomainFactionItem>,
    pub tag_list: CArray<u32>,
}

impl<'a> RegionInfo<'a> {
    /// Read with explicit entry size from pabgh (compat shim — Tier 1 means
    /// every byte is consumed by typed reads, so the size is just verified).
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("RegionInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u16::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let display_region_name = LocalizableString::read_from(data, offset)?;
        let knowledge_info = u32::read_from(data, offset)?;
        let region_enter_knowledge_info_list = CArray::<RegionSubA>::read_from(data, offset)?;
        let parent_region_info = u16::read_from(data, offset)?;
        let child_region_info_list = CArray::<u16>::read_from(data, offset)?;
        let bitmap_color = u8::read_from(data, offset)?;
        let overrided_max_height = u8::read_from(data, offset)?;
        let region_type = u32::read_from(data, offset)?;
        let fog_clear_condition = u8::read_from(data, offset)?;
        let limit_vehicle_run = u32::read_from(data, offset)?;
        let is_town = u8::read_from(data, offset)?;
        let is_wild = u8::read_from(data, offset)?;
        let is_ui_map_disable = u8::read_from(data, offset)?;
        let is_housing_region = u8::read_from(data, offset)?;
        let is_none_play_zone = u8::read_from(data, offset)?;
        let vehicle_mercenary_allow_type = u8::read_from(data, offset)?;
        let is_world_map_road_path_findable = u8::read_from(data, offset)?;
        let u8_123 = u8::read_from(data, offset)?;
        let gimmick_alias_pointer_list = CArray::<RegionGimmickAliasItem>::read_from(data, offset)?;
        let domain_faction_list = CArray::<RegionDomainFactionItem>::read_from(data, offset)?;
        let tag_list = CArray::<u32>::read_from(data, offset)?;
        Ok(Self {
            key, string_key, is_blocked, display_region_name, knowledge_info,
            region_enter_knowledge_info_list, parent_region_info,
            child_region_info_list, bitmap_color, overrided_max_height,
            region_type, fog_clear_condition, limit_vehicle_run, is_town,
            is_wild, is_ui_map_disable, is_housing_region, is_none_play_zone,
            vehicle_mercenary_allow_type, is_world_map_road_path_findable,
            u8_123, gimmick_alias_pointer_list, domain_faction_list, tag_list,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.display_region_name.write_to(w)?;
        self.knowledge_info.write_to(w)?;
        self.region_enter_knowledge_info_list.write_to(w)?;
        self.parent_region_info.write_to(w)?;
        self.child_region_info_list.write_to(w)?;
        self.bitmap_color.write_to(w)?;
        self.overrided_max_height.write_to(w)?;
        self.region_type.write_to(w)?;
        self.fog_clear_condition.write_to(w)?;
        self.limit_vehicle_run.write_to(w)?;
        self.is_town.write_to(w)?;
        self.is_wild.write_to(w)?;
        self.is_ui_map_disable.write_to(w)?;
        self.is_housing_region.write_to(w)?;
        self.is_none_play_zone.write_to(w)?;
        self.vehicle_mercenary_allow_type.write_to(w)?;
        self.is_world_map_road_path_findable.write_to(w)?;
        self.u8_123.write_to(w)?;
        self.gimmick_alias_pointer_list.write_to(w)?;
        self.domain_faction_list.write_to(w)?;
        self.tag_list.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("display_region_name".to_string(), self.display_region_name.to_json_value());
        m.insert("knowledge_info".to_string(), self.knowledge_info.to_json_value());
        m.insert("region_enter_knowledge_info_list".to_string(), self.region_enter_knowledge_info_list.to_json_value());
        m.insert("parent_region_info".to_string(), self.parent_region_info.to_json_value());
        m.insert("child_region_info_list".to_string(), self.child_region_info_list.to_json_value());
        m.insert("bitmap_color".to_string(), self.bitmap_color.to_json_value());
        m.insert("overrided_max_height".to_string(), self.overrided_max_height.to_json_value());
        m.insert("region_type".to_string(), self.region_type.to_json_value());
        m.insert("fog_clear_condition".to_string(), self.fog_clear_condition.to_json_value());
        m.insert("limit_vehicle_run".to_string(), self.limit_vehicle_run.to_json_value());
        m.insert("is_town".to_string(), self.is_town.to_json_value());
        m.insert("is_wild".to_string(), self.is_wild.to_json_value());
        m.insert("is_ui_map_disable".to_string(), self.is_ui_map_disable.to_json_value());
        m.insert("is_housing_region".to_string(), self.is_housing_region.to_json_value());
        m.insert("is_none_play_zone".to_string(), self.is_none_play_zone.to_json_value());
        m.insert("vehicle_mercenary_allow_type".to_string(), self.vehicle_mercenary_allow_type.to_json_value());
        m.insert("is_world_map_road_path_findable".to_string(), self.is_world_map_road_path_findable.to_json_value());
        m.insert("u8_123".to_string(), self.u8_123.to_json_value());
        m.insert("gimmick_alias_pointer_list".to_string(), self.gimmick_alias_pointer_list.to_json_value());
        m.insert("domain_faction_list".to_string(), self.domain_faction_list.to_json_value());
        m.insert("tag_list".to_string(), self.tag_list.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "display_region_name")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "knowledge_info")?)?;
        <CArray<RegionSubA> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "region_enter_knowledge_info_list")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "parent_region_info")?)?;
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "child_region_info_list")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "bitmap_color")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "overrided_max_height")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "region_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "fog_clear_condition")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "limit_vehicle_run")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_town")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_wild")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_ui_map_disable")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_housing_region")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_none_play_zone")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "vehicle_mercenary_allow_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_world_map_road_path_findable")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "u8_123")?)?;
        <CArray<RegionGimmickAliasItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "gimmick_alias_pointer_list")?)?;
        <CArray<RegionDomainFactionItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "domain_faction_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tag_list")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\regioninfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\regioninfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = RegionInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "regioninfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = RegionInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            RegionInfo::write_from_json_dict(&mut from_json, &dict)
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
        let Some((_, s, _)) = ranges.first() else { eprintln!("SKIP: no entries"); return; };
        let mut c = *s;
        let item = RegionInfo::read_from(&data, &mut c).unwrap();
        let dict = item.to_json_dict();
        for f in [
            "key", "string_key", "is_blocked", "display_region_name",
            "knowledge_info", "region_enter_knowledge_info_list",
            "parent_region_info", "child_region_info_list", "bitmap_color",
            "overrided_max_height", "region_type", "fog_clear_condition",
            "limit_vehicle_run", "is_town", "is_wild", "is_ui_map_disable",
            "is_housing_region", "is_none_play_zone",
            "vehicle_mercenary_allow_type", "is_world_map_road_path_findable",
            "u8_123", "gimmick_alias_pointer_list", "domain_faction_list",
            "tag_list",
        ] {
            assert!(dict.contains_key(f), "missing field `{}` in JSON dict", f);
        }
        assert!(!dict.contains_key("_tail_b64"), "Tier 1.5 _tail_b64 leaked into Tier 1 dict");
    }
}
