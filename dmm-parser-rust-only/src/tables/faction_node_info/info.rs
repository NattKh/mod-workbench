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
//! Reader: `sub_1410DE7A0` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings
//! / `docs/449_TABLE_CATALOG.md` FactionNodeInfo section):
//!   1. u32 key                                      (_key)
//!   2. CString string_key                           (_stringKey)
//!   3. u8 is_blocked                                (_isBlocked)
//!   4. u32 knowledge_info                           (_knowledgeInfo,
//!      sub_1411006D0 wire u32)
//!   5. u32 skill_tree_info                          (_skillTreeInfo,
//!      sub_1411035A0 wire u32)
//!   6. u32 connect_research_node_info               (_connectResearchNodeInfo,
//!      sub_141101D50 wire u32)
//!   7. u16 store_info                               (_storeInfo,
//!      sub_141103610 — wire u16)
//!   8. u16 royal_supply_info                        (_royalSupplyInfo,
//!      sub_1411036C0 — wire u16)
//!   9. CString memo                                 (_memo)
//!  10. CArray<u32> child_faction_info_list          (_childFactionInfoList,
//!      sub_141102FF0 wire u32)
//!  11. CArray<u32> node_line_main_faction_info_list (_nodeLineMainFactionInfoList,
//!      sub_141102FF0)
//!  12. [f32; 3] world_position                      (_worldPosition, Vec3)
//!  13. f32 node_radius                              (_nodeRadius)
//!  14. CArray<ApplySkillData> apply_skill_data_list (_applySkillDataList,
//!      sub_141115FD0; per element: u32 lookup + u64 raw +
//!      FactionNodeRawDataExt — 40 mem bytes)
//!  15. CArray<ResourceItemData> resource_item_list  (_resourceItemList,
//!      sub_141115D90; per element: u32 + u32 + u64 + u64 +
//!      FactionNodeRawDataExt — 48 mem bytes)
//!  16. CArray<u32> revival_stage_info_list          (_revivalStageInfoList,
//!      sub_141101610 wire u32)
//!  17. CArray<WayPointDeprData> way_point_data_list_deprecated
//!      (_wayPointDataList_deprecated, sub_141115BA0; per element:
//!      u16 + u16 + CArray<[f32; 3]> — 24 mem bytes)
//!  18. CArray<FactionSchedule> faction_schedule_list (sub_1410DDE60
//!      via inline CArray; per element 280 mem bytes / 31 wire fields)
//!  19. u8 unknown_a                                (mem a2+168)
//!  20. CString key_str_after                       (sub_1410A9D40 wire
//!      CString — mem a2+172 stores u32 hash)
//!  21. u8 unknown_b                                (mem a2+176)
//!  22. u32 lookup_after                            (sub_1410FF430 wire
//!      u32 — mem a2+178)
//!  23. u8 unknown_c                                (mem a2+180)
//!  24. u8 unknown_d                                (mem a2+181)
//!  25. CArray<FactionAdjacencyEntry> adjacency_list (sub_141115A30 →
//!      sub_1410DE350; per element 144 mem bytes / 10+ wire fields:
//!      u32 raw_a + FactionAdjacencyData inner with 2 LocalizableStrings,
//!      3 u32 lookups, FactionScheduleU64Triple list, u32 lookup+raw
//!      pair list, FactionAdjacencyMobItem list, trailing u32)
//!  26. FactionNodeBigCompositeSlots big_composite_slots (13 fixed
//!      CArray<FactionNodeBigComposite> slots via sub_141128990 →
//!      sub_1410DD2A0 (24-byte/10-field header) + sub_1410DD420
//!      (296-byte/37-field body with FactionNodeDD140Inner inner)
//!  27. u8 flag_after_slots                           (mem a2+408)
//!  28. FactionNodeDE690 de690_data                   (sub_1410DE690 —
//!      28-byte fixed: Vec3 + 4× u32, mem a2+412)
//!  29. u32 raw_after_de690                           (mem a2+440)
//!  30. CArray<u32> final_list_u32                    (sub_141100510 wire
//!      u32 — mem a2+448)
//!  31. CArray<u16> final_list_u16                    (sub_1410FFAC0 wire
//!      u16 — mem a2+464)
//!  32. u32 final_lookup                              (sub_141103770 wire
//!      u32 — mem a2+480)
//!
//! All 32 wire fields typed. JSON-addressable for full mod-editing.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct FactionNodeRawDataExt {
        pub raw_bytes: CArray<u8>,
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    pub struct ApplySkillData {
        pub lookup: u32,
        pub raw: u64,
        pub ext: FactionNodeRawDataExt,
    }
}

py_binary_struct! {
    pub struct ResourceItemData {
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub raw_a: u64,
        pub raw_b: u64,
        pub ext: FactionNodeRawDataExt,
    }
}

py_binary_struct! {
    pub struct WayPointTriplet {
        pub xyz: [f32; 3],
    }
}

py_binary_struct! {
    pub struct WayPointDeprData {
        pub lookup_a: u16,
        pub lookup_b: u16,
        pub points: CArray<WayPointTriplet>,
    }
}

// sub_1410DDD40 — FactionScheduleEntry48 inner: 48 mem / 6 wire fields.
// Trailing CArray<u64> per sub_141103200: each u64 is u32 lookup
// (sub_1410FF340 wire u32) + u32 raw, packed LE so wire matches u64.
py_binary_struct! {
    pub struct FactionScheduleEntry48 {
        pub flag_a: u8,
        pub raw_a: u32,
        pub raw_b: u32,
        pub vec3: [f32; 3],
        pub flag_b: u8,
        pub list_u64: CArray<u64>,
    }
}

// sub_141103310 inner — 16 mem bytes / 2 wire fields packed as u128.
// Wire: sub_1410FF5C0 (u32 lookup) + u64 raw = 12 wire bytes per element.
py_binary_struct! {
    pub struct FactionScheduleU128Pair {
        pub lookup: u32,
        pub raw: u64,
    }
}

// sub_141103420 → sub_1410ED8F0 inner — 32 mem / 6 wire fields = 30 wire.
py_binary_struct! {
    pub struct FactionScheduleSlotInner {
        pub lookup_a: u32, // sub_1410FF5C0 wire u32
        pub lookup_b: u32, // sub_141100740 wire u32
        pub lookup_c: u32, // sub_1410FF340 wire u32
        pub raw_a: u64,
        pub raw_b: u64,
        pub raw_c: u16,
    }
}

// sub_141116370 inner — 13 wire bytes per element.
py_binary_struct! {
    pub struct FactionScheduleU64Triple {
        pub lookup_a: u32,  // sub_1410FF430 wire u32
        pub flag: u8,
        pub lookup_b: u32,  // sub_1410FF050 wire u32
        pub lookup_c: u32,  // sub_1410FF050 wire u32
    }
}

// sub_1411161C0 inner — 12 wire bytes per element.
py_binary_struct! {
    pub struct FactionScheduleU32Triple {
        pub lookup: u32,  // sub_1411006D0 wire u32
        pub raw_a: u32,
        pub raw_b: u32,
    }
}

// sub_141100E90 inner — 32 mem bytes / 4 wire fields = 28 wire bytes.
// Wire: f32 + 8 raw bytes + 8 raw bytes + 8 raw bytes (assembled into
// 32-byte mem with 4-byte gap after the f32). Used by FactionAdjacencyData
// at slot +112 (and similarly elsewhere — gimmick_info field 7,
// interaction_info field 21).
py_binary_struct! {
    pub struct FactionAdjacencyMobItem {
        pub raw_a: u32,
        pub raw_b: u64,
        pub raw_c: u64,
        pub raw_d: u64,
    }
}

// sub_1410DE350 — FactionAdjacencyData inner, 128 mem bytes / 10 wire fields.
// Inner CArray<u64> at +96: per element u32 lookup (sub_1410FF430) + u32 raw
// = 8 wire bytes packed LE.
py_binary_struct! {
    pub struct FactionAdjacencyData<'a> {
        pub raw_a: u32,
        pub label_a: LocalizableString<'a>,
        pub label_b: LocalizableString<'a>,
        pub lookup_a: u32,                     // read_u32_lookup_DA30 wire u32
        pub lookup_b: u32,                     // sub_141100370 wire u32
        pub lookup_c: u32,                     // sub_141101D50 wire u32
        pub triple_u64_list: CArray<FactionScheduleU64Triple>,
        pub lookup_raw_pair_list: CArray<u64>, // u32 lookup + u32 raw per element
        pub mob_item_list: CArray<FactionAdjacencyMobItem>,
        pub trailing_raw: u32,
    }
}

// sub_141115A30 inner — FactionAdjacencyEntry, 144 mem bytes.
// Wire: u32 raw_a (4 wire) + FactionAdjacencyData (variable wire).
py_binary_struct! {
    pub struct FactionAdjacencyEntry<'a> {
        pub raw_a: u32,
        pub data: FactionAdjacencyData<'a>,
    }
}

// sub_1410DD2A0 — FactionNodeBigCompositeHeader, 24 mem / 31 wire bytes.
py_binary_struct! {
    pub struct FactionNodeBigCompositeHeader {
        pub flag_a: u8,
        pub lookup_a: u32,    // sub_1410FF430 wire u32
        pub lookup_b: u32,    // sub_141102CB0 wire u32
        pub lookup_c: u32,    // sub_141102D20 wire u32
        pub lookup_d: u32,    // sub_141102D90 wire u32
        pub lookup_e: u32,    // sub_141101D50 wire u32
        pub lookup_f: u32,    // sub_141100860 wire u32
        pub lookup_g: u32,    // sub_141102E00 wire u32
        pub flag_b: u8,
        pub flag_c: u8,
    }
}

// sub_1410DD140 — FactionNodeDD140Inner, 32 mem / 8 wire fields = 23 wire.
py_binary_struct! {
    pub struct FactionNodeDD140Inner {
        pub lookup_a: u32,             // sub_141100860 wire u32
        pub lookup_b: u32,             // sub_141101D50 wire u32
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub raw_a: u32,
        pub raw_b: u32,
        pub list_lookup: CArray<u32>,  // sub_1410FFC20 wire u32 per element
    }
}

// sub_1410DD420 — FactionNodeBigCompositeBody, 296 mem / 37 wire fields.
py_binary_struct! {
    pub struct FactionNodeBigCompositeBody<'a> {
        pub flag_a: u8,
        pub lookup_a: u32,                     // sub_141100860 wire u32
        pub lookup_b: u32,                     // sub_141101D50 wire u32
        pub lookup_c: u32,                     // sub_1410FF340 wire u32
        pub lookup_d: u32,                     // sub_141101D50 wire u32
        pub lookup_e: u32,                     // sub_141100860 wire u32
        pub flag_b: u8,
        pub raw_a: u32,
        pub lookup_f: u16,                     // sub_141102410 wire u16
        pub lookup_g: u32,                     // sub_141101D50 wire u32
        pub flag_c: u8,
        pub flag_d: u8,
        pub dd140_inner: FactionNodeDD140Inner,
        pub flag_e: u8,
        pub lookup_h: u32,                     // sub_1410FF5C0 wire u32
        pub raw_b: u64,
        pub raw_c: u32,
        pub raw_d: u64,
        pub list_u32: CArray<u32>,             // sub_141102EF0 wire u32
        pub lookup_i: u32,                     // sub_141102D20 wire u32
        pub list_u32_b: CArray<u32>,           // sub_1410FFC20 wire u32
        pub raw_e: u64,
        pub list_u32_c: CArray<u32>,           // sub_141102FF0 wire u32
        pub list_u16: CArray<u16>,             // sub_1410FFAC0 wire u16
        pub vec3: [f32; 3],
        pub flag_f: u8,
        pub flag_g: u8,
        pub flag_h: u8,
        pub flag_i: u8,
        pub flag_j: u8,
        pub raw_f: u32,
        pub flag_k: u8,
        pub lookup_j: u32,                     // read_u32_lookup_DA30 wire u32
        pub lookup_k: u32,                     // read_u32_lookup_DA30 wire u32
        pub label: LocalizableString<'a>,
        pub name: CString<'a>,
        pub trailing_raw: u32,
    }
}

// sub_141128990 inner — FactionNodeBigComposite, 288 mem bytes.
// Wire: FactionNodeBigCompositeHeader + FactionNodeBigCompositeBody.
py_binary_struct! {
    pub struct FactionNodeBigComposite<'a> {
        pub header: FactionNodeBigCompositeHeader,
        pub body: FactionNodeBigCompositeBody<'a>,
    }
}

// 13 fixed CArray slots used by faction_node_info field 26 (a2+200..408
// stride 16 mem). Each is a CArray<FactionNodeBigComposite>.
py_binary_struct! {
    pub struct FactionNodeBigCompositeSlots<'a> {
        pub slot_00: CArray<FactionNodeBigComposite<'a>>,
        pub slot_01: CArray<FactionNodeBigComposite<'a>>,
        pub slot_02: CArray<FactionNodeBigComposite<'a>>,
        pub slot_03: CArray<FactionNodeBigComposite<'a>>,
        pub slot_04: CArray<FactionNodeBigComposite<'a>>,
        pub slot_05: CArray<FactionNodeBigComposite<'a>>,
        pub slot_06: CArray<FactionNodeBigComposite<'a>>,
        pub slot_07: CArray<FactionNodeBigComposite<'a>>,
        pub slot_08: CArray<FactionNodeBigComposite<'a>>,
        pub slot_09: CArray<FactionNodeBigComposite<'a>>,
        pub slot_10: CArray<FactionNodeBigComposite<'a>>,
        pub slot_11: CArray<FactionNodeBigComposite<'a>>,
        pub slot_12: CArray<FactionNodeBigComposite<'a>>,
    }
}

// sub_1410DE690 — 28-byte fixed struct: Vec3 + 4× u32.
py_binary_struct! {
    pub struct FactionNodeDE690 {
        pub vec3: [f32; 3],
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u32,
    }
}

// sub_1410DDE60 — FactionSchedule, 280 mem bytes / 31 wire fields.
py_binary_struct! {
    pub struct FactionSchedule<'a> {
        pub flag_a: u8,
        pub schedule_entries: CArray<FactionScheduleEntry48>,
        pub raw_data_ext: FactionNodeRawDataExt,
        pub list_u128: CArray<FactionScheduleU128Pair>,
        pub player_list: CArray<u32>,        // sub_1410FF890 wire u32
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub flag_b: u8,
        pub flag_c: u8,
        pub raw_d: u32,
        pub memo: CString<'a>,
        pub label: LocalizableString<'a>,
        pub slot_inner_list: CArray<FactionScheduleSlotInner>,
        pub lookup_a: u32,                   // sub_141100370 wire u32
        pub lookup_b: u32,                   // sub_141100370 wire u32
        pub lookup_c: u32,                   // sub_1410FF5C0 wire u32
        pub lookup_d: u32,                   // sub_141103530 wire u32
        pub name: CString<'a>,
        pub raw_e: u32,
        pub raw_f: u32,
        pub raw_g: u32,
        pub raw_h: u32,
        pub key_str: CString<'a>,            // sub_1410A9D40 wire CString
        pub lookup_e: u32,                   // read_u32_lookup_DA10 wire u32
        pub lookup_f: u32,                   // sub_1410FEBE0 wire u32
        pub raw_i: u64,
        pub vec3: [f32; 3],
        pub triple_u64_list: CArray<FactionScheduleU64Triple>,
        pub triple_u32_list: CArray<FactionScheduleU32Triple>,
        pub flag_d: u8,
    }
}

py_binary_struct! {
    pub struct FactionNodeInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub knowledge_info: u32,
        pub skill_tree_info: u32,
        pub connect_research_node_info: u32,
        pub store_info: u16,
        pub royal_supply_info: u16,
        pub memo: CString<'a>,
        pub child_faction_info_list: CArray<u32>,
        pub node_line_main_faction_info_list: CArray<u32>,
        pub world_position: [f32; 3],
        pub node_radius: f32,
        pub apply_skill_data_list: CArray<ApplySkillData>,
        pub resource_item_list: CArray<ResourceItemData>,
        pub revival_stage_info_list: CArray<u32>,
        pub way_point_data_list_deprecated: CArray<WayPointDeprData>,
        pub faction_schedule_list: CArray<FactionSchedule<'a>>,
        pub unknown_a: u8,
        pub key_str_after: CString<'a>,
        pub unknown_b: u8,
        pub lookup_after: u32,
        pub unknown_c: u8,
        pub unknown_d: u8,
        pub adjacency_list: CArray<FactionAdjacencyEntry<'a>>,
        pub big_composite_slots: FactionNodeBigCompositeSlots<'a>,
        pub flag_after_slots: u8,
        pub de690_data: FactionNodeDE690,
        pub raw_after_de690: u32,
        pub final_list_u32: CArray<u32>,    // sub_141100510 wire u32
        pub final_list_u16: CArray<u16>,    // sub_1410FFAC0 wire u16
        pub final_lookup: u32,              // sub_141103770 wire u32
    }
}

impl<'a> FactionNodeInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("FactionNodeInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\factionnode.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\factionnode.pabgh";


    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                FactionNodeInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "factionnode roundtrip mismatch");
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
            let mut cursor = *start;
            let item = FactionNodeInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FactionNodeInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
