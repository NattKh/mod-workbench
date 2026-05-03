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
//! Reader: `sub_1410DA3D0` in CrimsonDesert.exe (Win build).
//! Inner readers (decoded for full Tier 1):
//!   - sub_141117AC0: CArray<FactionUiCardEntry>
//!   - sub_141117920: CArray<StealthOption>
//!   - sub_141128990: CArray<FactionEventData> (288-byte composite per
//!     element; built by sub_1410DD2A0 + sub_1410DD420 with sub_1410DD140
//!     nested for the FactionEventNestedData sub-struct)
//!   - 13 fixed slots of CArray<FactionEventData> at struct +88..296
//!     (loop `for i in 0..13` calling sub_141128990(a2+88+16*i))
//!
//! Wire reads, in order (canonical names from Mac Korean error strings
//! / `docs/449_TABLE_CATALOG.md` FactionInfo section, 19 fields + 2
//! catalog-unnamed sub-lookups for represent_faction_info):
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. CString memo
//!   5. u8 category_type
//!   6. u32 flag_component_name              (read_u32_lookup_DA30)
//!   7. u32 knowledge_info                   (sub_1411006D0)
//!   8. u32 contribution_sub_level_info      (inline → qword_145F0EF10)
//!   9. u32 contribution_worker_info         (inline → qword_145F0EF10)
//!  10. u32 trade_reward_dropset_info        (inline → qword_145F0DA08)
//!  11. u32 faction_relation_group_info      (inline → qword_145F0DA08)
//!  12. u32 faction_group_info               (sub_141100370)
//!  13. u16 represent_faction_info_lookup_a  (sub_141102410)
//!  14. u16 represent_faction_info_lookup_b  (sub_1411024C0)
//!  15. u32 represent_faction_info           (sub_141100860)
//!  16. u32 stage_icon_path                  (read_u32_lookup_DA30)
//!  17. CArray<FactionUiCardEntry> faction_ui_card_list (sub_141117AC0)
//!  18. CArray<StealthOption> stealth_option_list (sub_141117920)
//!  19. faction_event_data_list: 13 fixed CArray<FactionEventData> slots
//!      (sub_141128990 called 13× with mem offsets +88, +104, ... +280;
//!      each slot is independent, semantics likely event-type-keyed)
//!  20. u8 is_empty_misc                     (a2+296)
//!  21. u32 faction_color                    (a2+300, 4 raw wire bytes —
//!      probably packed RGBA)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct FactionUiCardEntry {
        pub knowledge_info: u32,
        pub list: CArray<u32>,
    }
}

py_binary_struct! {
    pub struct StealthOption<'a> {
        pub tag: CString<'a>,
        pub condition_logic: u32,
        pub flag: u8,
    }
}

// Inner sub_1410DD140 — 32 mem bytes / 8 wire fields.
// Wire: u32 + u32 + u8 + u8 + u8 + u32 + u32 + CArray<u32> = 23 + 4N bytes.
py_binary_struct! {
    pub struct FactionEventNestedData {
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub raw_a: u32,
        pub raw_b: u32,
        pub list_a: CArray<u32>,
    }
}

// FactionEventData — 288 mem bytes per element via sub_141128990.
// Built from sub_1410DD2A0 (10 wire fields → 24 mem bytes) +
// sub_1410DD420 (37 outer wire fields with FactionEventNestedData
// nested → 264 mem bytes). 36 catalog field count includes some
// composite mappings; this layout preserves the wire shape exactly
// and is what round-trips. Names follow catalog where confident,
// generic flag_/raw_/lookup_ otherwise.
py_binary_struct! {
    pub struct FactionEventData<'a> {
        // sub_1410DD2A0 part (10 fields)
        pub event_data_type: u8,
        pub faction_info: u32,
        pub faction_node_info: u32,
        pub leader_character_info: u32,
        pub target_faction_node_info: u32,
        pub target_faction_info: u32,
        pub faction_relation: u32,
        pub due_date_in_seconds: u32,
        pub relation_group_info: u8,
        pub conquered_node_info: u8,
        // sub_1410DD420 part
        pub is_conquer_enable: u8,
        pub is_capital_lookup_a: u32,
        pub is_capital_lookup_b: u32,
        pub block_data_a: u32,
        pub block_data_b: u32,
        pub block_data_c: u32,
        pub is_block_enable: u8,
        pub daily_delivery_item_pair: u32,
        pub range_value: u16,
        pub spawn_rate: u32,
        pub flag_d: u8,
        pub flag_e: u8,
        pub nested: FactionEventNestedData,
        pub flag_f: u8,
        pub is_revive_enable_lookup: u32,
        pub is_save_enable_raw: u64,
        pub is_sub_inner_enable_raw: u32,
        pub is_node_enable_raw: u64,
        pub apply_skill_data_list: CArray<u32>,
        pub fire_arm_range_type: u32,
        pub target_faction_type_list: CArray<u32>,
        pub level_name_raw: u64,
        pub alias_name_list: CArray<u32>,
        pub desc_list: CArray<u16>,
        pub target_position: [f32; 3],
        pub flag_g: u8,
        pub flag_h: u8,
        pub flag_i: u8,
        pub flag_j: u8,
        pub flag_k: u8,
        pub event_data_file_line_number: u32,
        pub flag_l: u8,
        pub lookup_x: u32,
        pub lookup_y: u32,
        pub event_data_file_name_loc: LocalizableString<'a>,
        pub event_data_file_name: CString<'a>,
        pub raw_tail: u32,
    }
}

// 13 fixed slots of CArray<FactionEventData>. The reader (sub_1410DA3D0)
// loops `for (i = 0; i < 13; ++i) sub_141128990(a2 + 88 + 16*i)` —
// each slot is read independently. Semantic naming TBD when event-type
// enum is decoded; using slot_NN for now.
py_binary_struct! {
    pub struct FactionEventDataSlots<'a> {
        pub slot_00: CArray<FactionEventData<'a>>,
        pub slot_01: CArray<FactionEventData<'a>>,
        pub slot_02: CArray<FactionEventData<'a>>,
        pub slot_03: CArray<FactionEventData<'a>>,
        pub slot_04: CArray<FactionEventData<'a>>,
        pub slot_05: CArray<FactionEventData<'a>>,
        pub slot_06: CArray<FactionEventData<'a>>,
        pub slot_07: CArray<FactionEventData<'a>>,
        pub slot_08: CArray<FactionEventData<'a>>,
        pub slot_09: CArray<FactionEventData<'a>>,
        pub slot_10: CArray<FactionEventData<'a>>,
        pub slot_11: CArray<FactionEventData<'a>>,
        pub slot_12: CArray<FactionEventData<'a>>,
    }
}

py_binary_struct! {
    pub struct FactionInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub memo: CString<'a>,
        pub category_type: u8,
        pub flag_component_name: u32,
        pub knowledge_info: u32,
        pub contribution_sub_level_info: u32,
        pub contribution_worker_info: u32,
        pub trade_reward_dropset_info: u32,
        pub faction_relation_group_info: u32,
        pub faction_group_info: u32,
        pub represent_faction_info_lookup_a: u16,
        pub represent_faction_info_lookup_b: u16,
        pub represent_faction_info: u32,
        pub stage_icon_path: u32,
        pub faction_ui_card_list: CArray<FactionUiCardEntry>,
        pub stealth_option_list: CArray<StealthOption<'a>>,
        pub faction_event_data_list: FactionEventDataSlots<'a>,
        pub is_empty_misc: u8,
        pub faction_color: u32,
    }
}

impl<'a> FactionInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("FactionInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\faction.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\faction.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = FactionInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "faction roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = FactionInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FactionInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
