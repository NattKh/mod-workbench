// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

use super::keys::*;
use super::structs::*;
use crate::binary::*;
use crate::json_traits::ToJsonValue;
use crate::py_binary_struct;
use std::io;

/// Parse the entire iteminfo binary into a `Vec<serde_json::Value>` of
/// item dicts. Mirrors the Python `parse_iteminfo_from_bytes(data)` function
/// but runs without a Python interpreter — used by Rust mod managers (DMM)
/// for v3 mod application.
///
/// Each dict's shape matches `ItemInfo::to_json_dict()`. Field names match
/// the v3 mod format spec verbatim.
pub fn parse_iteminfo_to_json(data: &[u8]) -> io::Result<Vec<::serde_json::Value>> {
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let item = ItemInfo::read_from(data, &mut offset)?;
        items.push(item.to_json_value());
    }
    Ok(items)
}

/// Inverse of `parse_iteminfo_to_json`: write a sequence of item dicts back
/// to bytes. Each value must be an object whose shape matches what
/// `ItemInfo::to_json_dict()` produces.
pub fn serialize_iteminfo_from_json(items: &[::serde_json::Value]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(items.len() * 256);
    for (i, v) in items.iter().enumerate() {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("item[{}]: expected object, got {:?}", i, v),
        ))?;
        ItemInfo::write_from_json_dict(&mut out, obj).map_err(|e| io::Error::new(
            e.kind(),
            format!("item[{}]: {}", i, e),
        ))?;
    }
    Ok(out)
}

py_binary_struct! {
    pub struct ItemInfo<'a> {
        pub key: ItemKey,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub max_stack_count: u64,
        pub item_name: LocalizableString<'a>,
        pub broken_item_prefix_string: LocalStringInfoKey,
        pub inventory_info: InventoryKey,
        pub equip_type_info: EquipTypeKey,
        pub occupied_equip_slot_data_list: CArray<OccupiedEquipSlotData>,
        pub item_tag_list: CArray<u32>,
        pub equipable_hash: u32,
        pub consumable_type_list: CArray<u32>,
        pub item_use_info_list: CArray<ItemUseKey>,
        pub item_icon_list: CArray<ItemIconData>,
        pub map_icon_path: StringInfoKey,
        pub money_icon_path: StringInfoKey,
        pub use_map_icon_alert: u8,
        pub item_type: u8,
        pub material_key: u32,
        pub material_match_info: MaterialMatchKey,
        pub item_desc: LocalizableString<'a>,
        pub item_desc2: LocalizableString<'a>,
        pub equipable_level: u32,
        pub category_info: CategoryKey,
        pub knowledge_info: KnowledgeKey,
        pub knowledge_obtain_type: u8,
        pub destroy_effec_info: EffectKey,
        pub equip_passive_skill_list: CArray<PassiveSkillLevel>,
        pub use_immediately: u8,
        pub apply_max_stack_cap: u8,
        pub extract_multi_change_info: MultiChangeKey,
        pub extract_additional_drop_set_info: u32,
        pub minimum_extract_enchant_level: u16,
        pub item_memo: CString<'a>,
        pub filter_type: CString<'a>,
        pub gimmick_info: GimmickInfoKey,
        pub gimmick_tag_list: CArray<CString<'a>>,
        pub max_drop_result_sub_item_count: u32,
        pub use_drop_set_target: u8,
        pub is_all_gimmick_sealable: u8,
        pub sealable_item_info_list: CArray<SealableItemInfo<'a>>,
        pub sealable_character_info_list: CArray<SealableItemInfo<'a>>,
        pub sealable_gimmick_info_list: CArray<SealableItemInfo<'a>>,
        pub sealable_gimmick_tag_list: CArray<SealableItemInfo<'a>>,
        pub sealable_tribe_info_list: CArray<SealableItemInfo<'a>>,
        pub sealable_money_info_list: CArray<ItemKey>,
        pub delete_by_gimmick_unlock: u8,
        pub gimmick_unlock_message_local_string_info: LocalStringInfoKey,
        pub can_disassemble: u8,
        pub transmutation_material_gimmick_list: CArray<GimmickInfoKey>,
        pub transmutation_material_item_list: CArray<ItemKey>,
        pub transmutation_material_item_group_list: CArray<ItemGroupKey>,
        pub is_register_trade_market: u8,
        pub multi_change_info_list: CArray<MultiChangeKey>,
        pub is_editor_usable: u8,
        pub discardable: u8,
        pub is_dyeable: u8,
        pub is_editable_grime: u8,
        pub is_destroy_when_broken: u8,
        pub is_housing_only: u8,
        pub quick_slot_index: u8,
        pub reserve_slot_target_data_list: CArray<ReserveSlotTargetData>,
        pub item_tier: u8,
        pub is_important_item: u8,
        pub apply_drop_stat_type: u8,
        pub drop_default_data: DropDefaultData,
        pub prefab_data_list: CArray<PrefabData>,
        pub enchant_data_list: CArray<EnchantData>,
        pub gimmick_visual_prefab_data_list: CArray<GimmickVisualPrefabData>,
        pub price_list: CArray<ItemPriceInfo>,
        pub docking_child_data: COptional<DockingChildData<'a>>,
        pub inventory_change_data: COptional<InventoryChangeData>,
        pub unk_texture_path: CString<'a>,
        pub fixed_page_data_list: CArray<PageData<'a>>,
        pub dynamic_page_data_list: CArray<PageData<'a>>,
        pub inspect_data_list: CArray<InspectData<'a>>,
        pub inspect_action: InspectAction<'a>,
        pub default_sub_item: SubItem,
        pub cooltime: i64,
        pub unk_post_cooltime_a: i64,
        pub unk_post_cooltime_b: i64,
        pub item_charge_type: u8,
        pub usable_alert_type: u8,
        pub sharpness_data: ItemInfoSharpnessData,
        pub max_charged_useable_count: u32,
        pub unk_post_max_charged_a: u32,
        pub unk_post_max_charged_b: u32,
        pub hackable_character_group_info_list: CArray<CharacterGroupKey>,
        pub item_group_info_list: CArray<ItemGroupKey>,
        pub discard_offset_y: f32,
        pub discard_attach_terrain: u8,
        pub hide_from_inventory_on_pop_item: u8,
        pub is_shield_item: u8,
        pub is_tower_shield_item: u8,
        pub is_wild: u8,
        pub packed_item_info: ItemKey,
        pub unpacked_item_info: ItemKey,
        pub convert_item_info_by_drop_npc: ItemKey,
        pub stage_info: u32,
        pub pattern_description_data_list: CArray<PatternDescriptionData<'a>>,
        pub look_detail_game_advice_info_wrapper: GameAdviceInfoKey,
        pub look_detail_mission_info: MissionKey,
        pub enable_alert_system_to_ui: u8,
        pub is_save_game_data_at_use_item: u8,
        pub is_logout_at_use_item: u8,
        pub shared_cool_time_group_name_hash: u32,
        pub item_bundle_data_list: CArray<ItemBundleData>,
        pub money_type_define: COptional<MoneyTypeDefine<'a>>,
        pub emoji_texture_id: CString<'a>,
        pub enable_equip_in_clone_actor: u8,
        pub is_blocked_store_sell: u8,
        pub is_preorder_item: u8,
        pub is_has_item_use_data_inventory_buff: u8,
        pub is_preserved_on_extract: u8,
        pub respawn_time_seconds: i64,
        pub max_endurance: u16,
        pub repair_data_list: CArray<RepairData>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-platform fixture resolution. Tries env var first, then known paths.
    // Returns None (test SKIPs) if no fixture found anywhere.
    fn find_iteminfo() -> Option<Vec<u8>> {
        let candidates: &[&str] = &[
            "/mnt/e/OpensourceGame/CrimsonDesert/Godmod/backups/iteminfo_1.0.4.0.pabgb",
            r"C:\Users\corin\Desktop\CD DUMPING TOOLS\1.0.4 PABGB_PABGH\iteminfo.pabgb",
            r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\iteminfo.pabgb",
        ];
        if let Ok(p) = std::env::var("DMM_PARSER_ITEMINFO_PATH") {
            if let Ok(d) = std::fs::read(&p) {
                return Some(d);
            }
        }
        for c in candidates {
            if let Ok(d) = std::fs::read(c) {
                return Some(d);
            }
        }
        None
    }

    macro_rules! load_or_skip {
        () => {
            match find_iteminfo() {
                Some(d) => d,
                None => {
                    eprintln!("SKIP: iteminfo_1.0.4.0.pabgb fixture not found");
                    return;
                }
            }
        };
    }

    #[test]
    fn test_parse_first_item() {
        let data = load_or_skip!();
        let mut offset = 0;
        let item = ItemInfo::read_from(&data, &mut offset).unwrap();
        assert_eq!(item.key, ItemKey(2200));
        assert_eq!(item.string_key.data, "Pyeonjeon_Arrow");
        assert_eq!(offset, 0x00000270, "unexpected size for first item");
    }

    #[test]
    fn test_parse_second_item() {
        let data = load_or_skip!();
        let mut offset = 0x00000270;
        let item = ItemInfo::read_from(&data, &mut offset).unwrap();
        assert_ne!(item.key, ItemKey(0));
        println!(
            "Second item: key={}, name={}",
            item.key.0, item.string_key.data
        );
    }

    #[test]
    fn test_first_item_roundtrip() {
        let data = load_or_skip!();
        let mut offset = 0;
        let item = ItemInfo::read_from(&data, &mut offset).unwrap();
        let end = offset;

        let mut out = Vec::new();
        item.write_to(&mut out).unwrap();
        assert_eq!(out.len(), end, "written size mismatch");
        assert_eq!(&out[..], &data[..end], "roundtrip bytes mismatch");
    }
}
