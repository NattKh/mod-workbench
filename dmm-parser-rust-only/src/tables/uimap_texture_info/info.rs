// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `UIMapTextureInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct UIMapTextureInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub world_position: [f32; 3],
        pub ui_template_name: u32,
        pub ui_texture_name: u32,
        pub ui_small_texture_name: u32,
        pub ui_filter_group_component_name: u32,
        pub ui_filter_texture_name: u32,
        pub ui_map_layer_type: u8,
        pub map_icon_type: u32,
        pub knowledge_info: u32,
        pub gameplay_trigger_info: u32,
        pub filter_group_name: LocalizableString<'a>,
        pub filter_group_parent_info: u32,
        pub z_index: u32,
        pub is_flexible_size: u8,
        pub is_flexible_icon: u8,
        pub is_simple_material: u8,
        pub tooltip_text: LocalizableString<'a>,
        pub auto_remove_distance: u32,
        pub max_scale: u32,
        pub min_scale: u32,
        pub lerp_icon_min_size: u32,
        pub lerp_min_zoom: u32,
        pub lerp_max_zoom: u32,
        pub lerp_size: u32,
        pub change_scale_ratio: u32,
        pub filter_type: u8,
        pub is_show_tooltip: u8,
        pub is_region_knowledge_icon: u8,
        pub is_uimap_quest_type: u8,
        pub is_uimap_debug_quest_type: u8,
        pub is_uimap_debug_quest_area_type: u8,
        pub is_uimap_npctype: u8,
        pub is_uimap_mission_type: u8,
        pub is_actor_type: u8,
        pub is_perspective_icon: u8,
        pub is_alway_show_minimap: u8,
        pub check_has_owner_actor_icon: u8,
        pub is_fix_scale_icon_image: u8,
        pub use_change_scale: u8,
        pub use_change_scale_when_zoom_out: u8,
        pub use_auto_abyss_layer: u8,
        pub minimap_force_update_icon: u8,
        pub indoor_state_force_show: u8,
        pub other_space_force_show: u8,
        pub is_keep_show_by_character_info: u8,
        pub is_discover_gimmick_icon: u8,
        pub ui_filter_group_by_info: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\uimaptextureinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(UIMapTextureInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "uimaptextureinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(UIMapTextureInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            UIMapTextureInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
