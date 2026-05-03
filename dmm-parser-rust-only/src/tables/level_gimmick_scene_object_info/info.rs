// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser for `LevelGimmickSceneObjectInfo.pabgb`.
//!
//! Per IDA sub_1410EB480: 25 fields. `_levelGimmickSceneObjectDataList`
//! is a `CArray<LevelGimmickSceneObjectData>` via sub_14110ECD0 +
//! sub_1410EB270. Despite the original "polymorphic" label, sub_1410EB270
//! is a fixed-shape reader: 4× u32 (raw + 3 hash lookups) + CString +
//! u32 + u32-hash + 16 raw + u32 + CString + 2× SceneObjectAA1B0Block
//! (each = Vec3 + [u32;4] + Vec3) + 12 raw bytes. Mem stride 160.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// `sub_1410AA1B0` per-call. 40 wire bytes / 40 mem bytes.
    /// Wire ORDER (mem-out-of-order in IDA): vec_a (12 bytes, written to
    /// mem +28), block (16 bytes via sub_1410AA0D0, written to mem +12),
    /// vec_b (12 bytes, written to mem +0).
    pub struct SceneObjectAA1B0Block {
        pub vec_a: [f32; 3],
        pub block: [u32; 4],
        pub vec_b: [f32; 3],
    }
}

py_binary_struct! {
    /// `sub_1410EB270` per-element. 144 wire bytes (excluding two CStrings)
    /// / 160 mem bytes.
    pub struct LevelGimmickSceneObjectData<'a> {
        pub raw_a: u32,            // sub_141106210 (u32 wire / u32 mem)
        pub raw_b: u32,            // sub_141100740 (u32 wire / u16 mem)
        pub raw_c: u32,            // sub_1410FF5C0 (u32 wire / u16 mem)
        pub raw_d: u32,            // u32 raw → hash via 145F169C0
        pub name: CString<'a>,
        pub raw_e: u32,            // sub_141103530 (u32 wire / u32 mem)
        pub raw_f: u32,            // read_u32_lookup_DA30 (u32 wire / u16 mem)
        pub block_32: [u32; 4],    // 16 raw bytes
        pub raw_g: u32,            // 4 raw bytes
        pub texture_id: CString<'a>,
        pub block_a: SceneObjectAA1B0Block,  // sub_1410AA1B0 #1
        pub block_b: SceneObjectAA1B0Block,  // sub_1410AA1B0 #2
        pub trail_a: u32,
        pub trail_b: u32,
        pub trail_c: u32,
    }
}

#[derive(Debug)]
pub struct LevelGimmickSceneObjectInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub level_name: CString<'a>,
    pub data_list: CArray<LevelGimmickSceneObjectData<'a>>,
    pub map_icon_texture_info: u32,
    pub discover_near_fog: u8,
    pub fog_map_icon_texture_info: u32,
    pub fog_distance: u32,
    pub over_abyss_icon_texture_info: u32,
    pub over_abyss_fog_map_icon_texture_info: u32,
    pub over_abyss_fog_distance: u32,
    pub discover_distance: u32,
    pub show_icon_condition_type: u8,
    pub use_teleport: u8,
    pub use_guide_effect: u8,
    pub is_sub_inner_gimmick: u8,
    pub check_game_level_load_state: u8,
    pub completed_discover_map_icon_texture_info: u32,
    pub over_abyss_completed_discover_map_icon_texture_info: u32,
    pub guide_effect_socket_name: CString<'a>,
    pub ore_vein_index: u32,
    pub discover_type: u32,
    pub ignore_same_gimmick_discover_distance: u32,
    pub discover_gimmick_state_hash: u32,
}

impl<'a> LevelGimmickSceneObjectInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let _ = entry_size; // typed reader is byte-perfect; size is informational

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let level_name = CString::read_from(data, offset)?;

        let data_list = <CArray<LevelGimmickSceneObjectData>>::read_from(data, offset)?;

        let map_icon_texture_info = u32::read_from(data, offset)?;
        let discover_near_fog = u8::read_from(data, offset)?;
        let fog_map_icon_texture_info = u32::read_from(data, offset)?;
        let fog_distance = u32::read_from(data, offset)?;
        let over_abyss_icon_texture_info = u32::read_from(data, offset)?;
        let over_abyss_fog_map_icon_texture_info = u32::read_from(data, offset)?;
        let over_abyss_fog_distance = u32::read_from(data, offset)?;
        let discover_distance = u32::read_from(data, offset)?;
        let show_icon_condition_type = u8::read_from(data, offset)?;
        let use_teleport = u8::read_from(data, offset)?;
        let use_guide_effect = u8::read_from(data, offset)?;
        let is_sub_inner_gimmick = u8::read_from(data, offset)?;
        let check_game_level_load_state = u8::read_from(data, offset)?;
        let completed_discover_map_icon_texture_info = u32::read_from(data, offset)?;
        let over_abyss_completed_discover_map_icon_texture_info = u32::read_from(data, offset)?;
        let guide_effect_socket_name = CString::read_from(data, offset)?;
        let ore_vein_index = u32::read_from(data, offset)?;
        let discover_type = u32::read_from(data, offset)?;
        let ignore_same_gimmick_discover_distance = u32::read_from(data, offset)?;
        let discover_gimmick_state_hash = u32::read_from(data, offset)?;

        Ok(Self {
            key, string_key, is_blocked, level_name, data_list,
            map_icon_texture_info, discover_near_fog, fog_map_icon_texture_info,
            fog_distance, over_abyss_icon_texture_info, over_abyss_fog_map_icon_texture_info,
            over_abyss_fog_distance, discover_distance,
            show_icon_condition_type, use_teleport, use_guide_effect,
            is_sub_inner_gimmick, check_game_level_load_state,
            completed_discover_map_icon_texture_info, over_abyss_completed_discover_map_icon_texture_info,
            guide_effect_socket_name, ore_vein_index, discover_type,
            ignore_same_gimmick_discover_distance, discover_gimmick_state_hash,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.level_name.write_to(w)?;
        self.data_list.write_to(w)?;
        self.map_icon_texture_info.write_to(w)?;
        self.discover_near_fog.write_to(w)?;
        self.fog_map_icon_texture_info.write_to(w)?;
        self.fog_distance.write_to(w)?;
        self.over_abyss_icon_texture_info.write_to(w)?;
        self.over_abyss_fog_map_icon_texture_info.write_to(w)?;
        self.over_abyss_fog_distance.write_to(w)?;
        self.discover_distance.write_to(w)?;
        self.show_icon_condition_type.write_to(w)?;
        self.use_teleport.write_to(w)?;
        self.use_guide_effect.write_to(w)?;
        self.is_sub_inner_gimmick.write_to(w)?;
        self.check_game_level_load_state.write_to(w)?;
        self.completed_discover_map_icon_texture_info.write_to(w)?;
        self.over_abyss_completed_discover_map_icon_texture_info.write_to(w)?;
        self.guide_effect_socket_name.write_to(w)?;
        self.ore_vein_index.write_to(w)?;
        self.discover_type.write_to(w)?;
        self.ignore_same_gimmick_discover_distance.write_to(w)?;
        self.discover_gimmick_state_hash.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("level_name".to_string(), self.level_name.to_json_value());
        m.insert("data_list".to_string(), self.data_list.to_json_value());
        m.insert("map_icon_texture_info".to_string(), self.map_icon_texture_info.to_json_value());
        m.insert("discover_near_fog".to_string(), self.discover_near_fog.to_json_value());
        m.insert("fog_map_icon_texture_info".to_string(), self.fog_map_icon_texture_info.to_json_value());
        m.insert("fog_distance".to_string(), self.fog_distance.to_json_value());
        m.insert("over_abyss_icon_texture_info".to_string(), self.over_abyss_icon_texture_info.to_json_value());
        m.insert("over_abyss_fog_map_icon_texture_info".to_string(), self.over_abyss_fog_map_icon_texture_info.to_json_value());
        m.insert("over_abyss_fog_distance".to_string(), self.over_abyss_fog_distance.to_json_value());
        m.insert("discover_distance".to_string(), self.discover_distance.to_json_value());
        m.insert("show_icon_condition_type".to_string(), self.show_icon_condition_type.to_json_value());
        m.insert("use_teleport".to_string(), self.use_teleport.to_json_value());
        m.insert("use_guide_effect".to_string(), self.use_guide_effect.to_json_value());
        m.insert("is_sub_inner_gimmick".to_string(), self.is_sub_inner_gimmick.to_json_value());
        m.insert("check_game_level_load_state".to_string(), self.check_game_level_load_state.to_json_value());
        m.insert("completed_discover_map_icon_texture_info".to_string(), self.completed_discover_map_icon_texture_info.to_json_value());
        m.insert("over_abyss_completed_discover_map_icon_texture_info".to_string(), self.over_abyss_completed_discover_map_icon_texture_info.to_json_value());
        m.insert("guide_effect_socket_name".to_string(), self.guide_effect_socket_name.to_json_value());
        m.insert("ore_vein_index".to_string(), self.ore_vein_index.to_json_value());
        m.insert("discover_type".to_string(), self.discover_type.to_json_value());
        m.insert("ignore_same_gimmick_discover_distance".to_string(), self.ignore_same_gimmick_discover_distance.to_json_value());
        m.insert("discover_gimmick_state_hash".to_string(), self.discover_gimmick_state_hash.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "level_name")?)?;
        <CArray<LevelGimmickSceneObjectData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "data_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "map_icon_texture_info")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "discover_near_fog")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "fog_map_icon_texture_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "fog_distance")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "over_abyss_icon_texture_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "over_abyss_fog_map_icon_texture_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "over_abyss_fog_distance")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "discover_distance")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "show_icon_condition_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_teleport")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_guide_effect")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_sub_inner_gimmick")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "check_game_level_load_state")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "completed_discover_map_icon_texture_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "over_abyss_completed_discover_map_icon_texture_info")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "guide_effect_socket_name")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "ore_vein_index")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "discover_type")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "ignore_same_gimmick_discover_distance")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "discover_gimmick_state_hash")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\levelgimmicksceneobjectinfo.pabgb";
    const PABGH_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\levelgimmicksceneobjectinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = LevelGimmickSceneObjectInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x} off=0x{:x} size={}: {}", i, key, start, end-start, e));
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "levelgimmicksceneobjectinfo roundtrip bytes mismatch");
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
            let item = LevelGimmickSceneObjectInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            LevelGimmickSceneObjectInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
