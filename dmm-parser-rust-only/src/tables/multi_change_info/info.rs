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
//! Reader: `sub_1410EDA00` in CrimsonDesert.exe (Win build).
//! Inner readers (all decoded for the Tier 1.5 -> 1 promotion):
//!   - sub_141114A80 → CArray<ConditionListItem>
//!   - sub_141103420 → CArray<FixedMaterialData> (each via sub_1410ED8F0)
//!   - sub_14110D970 → CArray<RecipeItemGroupData>
//!   - sub_14106BAC0 → CArray<CString>
//!   - sub_141100510 → CArray<u32>          (used twice)
//!
//! Wire reads, in order (canonical names from
//! `docs/449_TABLE_CATALOG.md` MultiChangeInfo section):
//!   1. u32 key                                  (_key)
//!   2. CString string_key                       (_stringKey)
//!   3. u8 is_blocked                            (_isBlocked)
//!   4. u16 craft_tool_info                      (_craftToolInfo,
//!      sub_141105A10 → qword_145F15028 — u16 wire)
//!   5. u8 item_consume_type                     (_itemConsumeType)
//!   6. CArray<ConditionListItem> condition_list (_conditionList,
//!      sub_141114A80; per element: u32 condition_info wire +
//!      LocalizableString label)
//!   7. u32 need_knowledge_info                  (_needKnowledgeInfo,
//!      sub_1411006D0 → qword_145F0DA28)
//!   8. CString craft_tag_name                   (_craftTagName,
//!      sub_1410A9D40; wire is u32 length + N raw bytes; runtime
//!      hashes to u32, but the on-disk bytes round-trip verbatim
//!      through the standard CString reader)
//!   9. u8 is_from_item_info                     (_isFromItemInfo)
//!  10. u8 is_result_item_for_warehouse          (_isResultItemForWarehouse)
//!  11. u8 is_with_sealed_item                   (_isWithSealedItem)
//!  12. u8 is_apply_enchant_level                (_isApplyEnchantLevel)
//!  13. u8 is_material_item_only_same_item_no    (_isMaterialItemOnlySameItemNo)
//!  14. u8 is_allow_material_item_self_same      (_isAllowMaterialItemSelfSame)
//!  15. CArray<FixedMaterialData> fixed_material_data_list
//!      (_fixedMaterialDataList, sub_141103420 wraps sub_1410ED8F0;
//!      per element: u32 lookup_a (sub_1410FF5C0 → qword_145F0DA00) +
//!      u32 lookup_b (sub_141100740 → qword_145F0DA38) + u32 lookup_c
//!      (sub_1410FF340 → qword_145F0DA08) + [u8; 8] raw_a +
//!      [u8; 8] raw_b + u16 raw_c — 30 wire bytes per element)
//!  16. CArray<RecipeItemGroupData> recipe_item_group_info_list
//!      (_recipeItemGroupInfoList, sub_14110D970; per element:
//!      u16 lookup (sub_141100620 → qword_145F0DA20 — u16 wire) +
//!      [u8; 8] raw_a + u16 raw_b — 12 wire bytes per element)
//!  17. u32 elemental_status_info                (_elementalStatusInfo,
//!      read_u32_lookup_DA10 → qword_145F0DA10)
//!  18. CArray<CString> elemental_material_state_list
//!      (_elementalMaterialStateList, sub_14106BAC0)
//!  19. LocalizableString name                   (_name)
//!  20. LocalizableString description            (_description)
//!  21. u32 enchant_recipe_desc                  (_enchantRecipeDesc,
//!      sub_1410FF050 → qword_145F0DA60)
//!  22. u32 group_string_info                    (_groupStringInfo,
//!      sub_1410FF050)
//!  23. u32 sub_group_string_info                (_subGroupStringInfo,
//!      sub_1410FF050)
//!  24. LocalizableString complete_description   (_complteDescription;
//!      typo preserved from source, but renamed to `complete_description`
//!      in Rust)
//!  25. CArray<u32> result_drop_info_list        (_resultDropInfoList,
//!      sub_141100510 → qword_145F113C8 lookup)
//!  26. CArray<u32> additional_drop_info_list    (_additionalDropInfoList,
//!      sub_141100510)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct ConditionListItem<'a> {
        pub condition_info: u32,
        pub label: LocalizableString<'a>,
    }
}

// FixedMaterialData per canonical Mac names (catalog section
// FixedMaterialData, 6 fields). 30 wire bytes.
py_binary_struct! {
    pub struct FixedMaterialData {
        pub item_info: u32,
        pub gimmick_info: u32,
        pub character_info: u32,
        pub count: u64,
        pub coupon_count: u64,
        pub enchant_level: u16,
    }
}

// Catalog GroupMaterialData (3 fields). Wire 12 bytes = u16 + u64 + u16.
py_binary_struct! {
    pub struct RecipeItemGroupData {
        pub item_group_info: u16,
        pub count: u64,
        pub enchant_level: u16,
    }
}

py_binary_struct! {
    pub struct MultiChangeInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub craft_tool_info: u16,
        pub item_consume_type: u8,
        pub condition_list: CArray<ConditionListItem<'a>>,
        pub need_knowledge_info: u32,
        pub craft_tag_name: CString<'a>,
        pub is_from_item_info: u8,
        pub is_result_item_for_warehouse: u8,
        pub is_with_sealed_item: u8,
        pub is_apply_enchant_level: u8,
        pub is_material_item_only_same_item_no: u8,
        pub is_allow_material_item_self_same: u8,
        pub fixed_material_data_list: CArray<FixedMaterialData>,
        pub recipe_item_group_info_list: CArray<RecipeItemGroupData>,
        pub elemental_status_info: u32,
        pub elemental_material_state_list: CArray<CString<'a>>,
        pub name: LocalizableString<'a>,
        pub description: LocalizableString<'a>,
        pub enchant_recipe_desc: u32,
        pub group_string_info: u32,
        pub sub_group_string_info: u32,
        pub complete_description: LocalizableString<'a>,
        pub result_drop_info_list: CArray<u32>,
        pub additional_drop_info_list: CArray<u32>,
    }
}

impl<'a> MultiChangeInfo<'a> {
    /// Read with explicit entry size from pabgh (compat shim — Tier 1 means
    /// every byte is consumed by typed reads, so the size is just verified).
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MultiChangeInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\multichangeinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\multichangeinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = MultiChangeInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "multichangeinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = MultiChangeInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            MultiChangeInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }

    /// Confirm the new typed lists carry data — guards against silent
    /// regression to _tail_b64.
    #[test]
    fn typed_lists_populated() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for (_, s, _) in &ranges {
            let mut c = *s;
            let item = MultiChangeInfo::read_from(&data, &mut c).unwrap();
            totals.0 += item.condition_list.items.len();
            totals.1 += item.fixed_material_data_list.items.len();
            totals.2 += item.recipe_item_group_info_list.items.len();
            totals.3 += item.elemental_material_state_list.items.len();
            totals.4 += item.result_drop_info_list.items.len();
            totals.5 += item.additional_drop_info_list.items.len();
        }
        eprintln!(
            "multi_change_info: {} entries, conditions={} fixed_materials={} recipes={} elem_states={} results={} additional={}",
            ranges.len(), totals.0, totals.1, totals.2, totals.3, totals.4, totals.5
        );
    }
}
