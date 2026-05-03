#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser.
//!
//! Reader (Mac CrimsonDesert_Steam): `sub_101857BC0` at 0x101857BC0.
//! 28 KB pabgb / 31 records. Round-trips byte-perfect with the
//! fully-typed body.
//!
//! ## History
//!
//! A prior session attempted Tier 1 but got 28/31 round-tripping; 3
//! entries diverged by ~30 bytes. Mac IDB analysis (2026-04-28)
//! identified two bugs in that attempt:
//!   1. CArray order was swapped — `_skillNodeList` is FIRST, then
//!      `_statNodeList` (Mac error strings prove the wire order).
//!   2. StatNode element is variable-sized — contains a CString
//!      `_uiCommand` field (sub_1006B40F4 = u32 length + bytes).
//!      The 3 diverging entries had non-empty uiCommand strings
//!      totaling ~30 extra bytes. Prior code assumed fixed 45-byte
//!      stride.
//!
//! Both bugs fixed in this implementation.
//!
//! ## Wire layout
//!
//! TYPED PREFIX (10 fields):
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. u32 character_info       (CharacterKey lookup, wire 4)
//!   5. u32 faction_info         (FactionNodeKey lookup)
//!   6. u32 item_info            (ItemKey lookup)
//!   7. u32 ui_grid_size_x       (sub_1006B3D80, raw u32)
//!   8. u32 ui_grid_size_y
//!   9. u32 ui_texture_icon_path (sub_100C93428)
//!  10. LocalizableString ui_page_name
//!
//! TYPED BODY (6 fields):
//!  11. CArray<SkillTreeSkillNode> skill_node_list
//!  12. CArray<SkillTreeStatNode> stat_node_list
//!  13. u32 first_focus_skill_info (SkillKey lookup, wire 4)
//!  14. f32 first_focus_zoom
//!  15. [f32;2] first_focus_position (Vec2)
//!  16. [u8;8] skill_tree_area
//!
//! ## Helper map (Mac)
//!
//! - `sub_1006B3D80` = u32 read (vtable[2] width=4)
//! - `sub_1006B3D60` = u32 read (vtable[2] width=4)
//! - `sub_1006B3DE0` = u32/f32 read (vtable[2] width=4)
//! - `sub_1006B3CC0` = u8 read (vtable[2] width=1)
//! - `sub_1006B4C60` = 8-byte raw (vtable[2] width=8)
//! - `sub_1006B40F4` = CString-like reader (u32 length + bytes)
//! - `sub_1005FFBFC` = LinearColor (4× f32 RGBA = 16 bytes)
//! - `sub_100C52EA4` = CArray<u32> (u32 count + N×u32)
//! - `sub_100F2893C` = u32 read (raw u32 storage)
//! - `sub_101887514` = SkillTreeParentDataEntry CArray (u32 count +
//!    N×(u32 key + sub_1018876B0 value))
//! - `sub_1018876B0` = CArray<u64> (u32 count + N×8 bytes)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    /// Single entry in SkillNode's `_uiParentDataList` hash map.
    ///
    /// Wire = u32 key + CArray<u64> values. The values are read via
    /// sub_1018876B0 in the Mac binary; we treat them as u64 here for
    /// byte-exact round-trip (the game uses them as 8-byte handles).
    pub struct SkillTreeParentDataEntry {
        pub key: u32,
        pub values: CArray<u64>,
    }
}

py_binary_struct! {
    /// Element of `_statNodeList` in SkillTreeInfo.
    ///
    /// 8 wire fields totaling 45+N bytes (where N = ui_command string
    /// length). The variable-CString `ui_command` is the field that
    /// caused the prior session's 3-entry divergence.
    pub struct SkillTreeStatNode<'a> {
        pub id: u32,
        pub item_info: u32,
        pub sub_level_info: u32,
        pub ui_command: CString<'a>,
        pub ui_position: [f32; 2],
        pub node_type: u8,
        pub deco_line_node_id: u32,
        pub color: [f32; 4],
    }
}

py_binary_struct! {
    /// Element of `_skillNodeList` in SkillTreeInfo.
    ///
    /// 17 wire fields, variable-sized due to multiple CArray fields.
    /// No lifetime parameter — none of the fields borrow from the
    /// source data (all are owned scalars / owned CArrays).
    pub struct SkillTreeSkillNode {
        pub id: u32,
        pub skill_info_wrapper: u32,
        pub skill_level: u32,
        pub knowledge_info: u32,
        pub condition_info: u32,
        pub ui_position_x: u32,
        pub ui_position_y: u32,
        pub deco_line_node_id: u32,
        pub ui_position: [f32; 2],
        pub parent_id: u32,
        pub child_id_list: CArray<u32>,
        pub ui_parent_data_list: CArray<SkillTreeParentDataEntry>,
        pub ui_child_id_for_guideline: CArray<u32>,
        pub node_type: u8,
        pub ui_learn_need_node_list: CArray<u32>,
        pub color: [f32; 4],
        pub faction_research_key: u32,
    }
}

py_binary_struct! {
    pub struct SkillTreeInfo<'a> {
        // Prefix (10 fields)
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub character_info: u32,
        pub faction_info: u32,
        pub item_info: u32,
        pub ui_grid_size_x: u32,
        pub ui_grid_size_y: u32,
        pub ui_texture_icon_path: u32,
        pub ui_page_name: LocalizableString<'a>,
        // Body (6 fields)
        pub skill_node_list: CArray<SkillTreeSkillNode>,
        pub stat_node_list: CArray<SkillTreeStatNode<'a>>,
        pub first_focus_skill_info: u32,
        pub first_focus_zoom: f32,
        pub first_focus_position: [f32; 2],
        pub skill_tree_area: u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skilltreeinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skilltreeinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = SkillTreeInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "entry {} k=0x{:x} consumed {} of {} bytes", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "skilltreeinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP: missing fixture {}", PABGB);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP: missing pabgh fixture {}", PABGH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut c = *start;
            let item = SkillTreeInfo::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            SkillTreeInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
