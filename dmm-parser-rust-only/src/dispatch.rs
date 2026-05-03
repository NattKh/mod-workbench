// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Generic table dispatch — pure-Rust API.
//!
//! This module exposes the 122-table dispatch with `io::Result<...>`
//! so Rust callers (DMM, CLI tools) can use it directly.
//!
//! This keeps a single source of truth for the
//! match arms — adding a new table = one entry here, the Python side picks it
//! up automatically.
//!
//! ## Public API
//!
//! ```ignore
//! use dmm_parser::dispatch::{parse_table_to_json, serialize_table_from_json};
//!
//! let items: Vec<serde_json::Value> = parse_table_to_json(
//!     "gimmick_info",
//!     &pabgb_bytes,
//!     Some(&pabgh_bytes),
//! )?;
//!
//! let raw: Vec<u8> = serialize_table_from_json("gimmick_info", &items)?;
//! ```
//!
//! See `FIELD_JSON_V3_1_SPEC.md` (in CrimsonGameMods repo) for the format these
//! functions support.

use std::io;

/// Parse a `.pabgb` body to a list of typed JSON dicts.
///
/// `table_name`: snake_case identifier matching `src/tables/<name>/`.
/// E.g. `"gimmick_info"`, `"condition_info"`, `"vehicle_info"`.
///
/// `pabgb`: the raw `.pabgb` bytes.
///
/// `pabgh`: optional `.pabgh` companion bytes. Required for ~47 tables that
/// use the pabgh_blob_table layout (entries are size-delimited via offsets in
/// the .pabgh file). Ignored for ~73 sequential tables (which self-delimit).
///
/// Returns one `serde_json::Value::Object` per record.
///
/// Errors:
/// - `InvalidInput`: `table_name` is unknown
/// - `InvalidInput`: pabgh missing for a pabgh-bounded table
/// - `InvalidData`: parse error mid-record (table-specific message)
pub fn parse_table_to_json(
    table_name: &str,
    pabgb: &[u8],
    pabgh: Option<&[u8]>,
) -> io::Result<Vec<serde_json::Value>> {
    use crate::binary::BinaryRead;
    use crate::tables::blob_runtime::parse_typed_blob_table_to_json_with_pabgh;

    macro_rules! p {
        ($ty:path) => {{
            let ph = pabgh.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                format!("table '{}' requires a pabgh file", table_name)))?;
            parse_typed_blob_table_to_json_with_pabgh(pabgb, ph, |data, offset, size| {
                <$ty>::read_with_size(data, offset, size).map(|t| t.to_json_dict())
            })?
        }};
    }

    macro_rules! s {
        ($ty:path) => {{
            let mut offset = 0usize;
            let mut out: Vec<serde_json::Value> = Vec::new();
            while offset < pabgb.len() {
                let item = <$ty>::read_from(pabgb, &mut offset)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                        format!("offset 0x{:08x}: {}", offset, e)))?;
                out.push(serde_json::Value::Object(item.to_json_dict()));
            }
            out
        }};
    }

    Ok(match table_name {
        // ── pabgh-bounded tables ──────────────────────────────────────────
        "ai_dialog_string_info"          => p!(crate::tables::ai_dialog_string_info::AIDialogStringInfo),
        "bitmap_position_info"           => p!(crate::tables::bitmap_position_info::BitmapPositionInfo),
        "buff_info"                      => p!(crate::tables::buff_info::BuffInfo),
        "character_change_info"          => p!(crate::tables::character_change_info::CharacterChangeInfo),
        "character_info"                 => p!(crate::tables::character_info::CharacterInfo),
        "condition_info"                 => p!(crate::tables::condition_info::ConditionInfo),
        "drop_set_info"                  => p!(crate::tables::drop_set_info::DropSetInfo),
        "effect_info"                    => p!(crate::tables::effect_info::EffectInfo),
        "elemental_material_info"        => p!(crate::tables::elemental_material_info::ElementalMaterialInfo),
        "equip_info"                     => p!(crate::tables::equip_info::EquipInfo),
        "equip_slot_info"                => {
            let ph = pabgh.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                "table 'equip_slot_info' requires a pabgh file"))?;
            crate::tables::equip_slot_info::parse_equip_slot_info_to_json_with_pabgh(pabgb, ph)?
        },
        "faction_info"                   => p!(crate::tables::faction_info::FactionInfo),
        "faction_node_info"              => p!(crate::tables::faction_node_info::FactionNodeInfo),
        "faction_node_spawn_info"        => p!(crate::tables::faction_node_spawn_info::FactionNodeSpawnInfo),
        "faction_spawn_data_info"        => p!(crate::tables::faction_spawn_data_info::FactionSpawnDataInfo),
        "field_revive_info"              => p!(crate::tables::field_revive_info::FieldReviveInfo),
        "frame_event_attr_group_info"    => p!(crate::tables::frame_event_attr_group_info::FrameEventAttrGroupInfo),
        "game_event_handler_info"        => p!(crate::tables::game_event_handler_info::GameEventHandlerInfo),
        "game_global_effect_info"        => p!(crate::tables::game_global_effect_info::GameGlobalEffectInfo),
        "game_level_info"                => p!(crate::tables::game_level_info::GameLevelInfo),
        "game_play_trigger_info"         => p!(crate::tables::game_play_trigger_info::GamePlayTriggerInfo),
        "gimmick_group_info"             => p!(crate::tables::gimmick_group_info::GimmickGroupInfo),
        "gimmick_info"                   => p!(crate::tables::gimmick_info::GimmickInfo),
        "global_game_event_info"         => p!(crate::tables::global_game_event_info::GlobalGameEventInfo),
        "global_stage_sequencer_info"    => p!(crate::tables::global_stage_sequencer_info::GlobalStageSequencerInfo),
        "interaction_info"               => p!(crate::tables::interaction_info::InteractionInfo),
        "inventory_info"                 => p!(crate::tables::inventory_info::InventoryInfo),
        "item_use_info"                  => p!(crate::tables::item_use_info::ItemUseInfo),
        "knowledge_info"                 => p!(crate::tables::knowledge_info::KnowledgeInfo),
        "level_gimmick_scene_object_info" => p!(crate::tables::level_gimmick_scene_object_info::LevelGimmickSceneObjectInfo),
        "mini_game_data_info"            => p!(crate::tables::mini_game_data_info::MiniGameDataInfo),
        "mission_info"                   => p!(crate::tables::mission_info::MissionInfo),
        "multi_change_info"              => p!(crate::tables::multi_change_info::MultiChangeInfo),
        "npc_info"                       => p!(crate::tables::npc_info::NpcInfo),
        "platform_entitlement_info"      => p!(crate::tables::platform_entitlement_info::PlatformEntitlementInfo),
        "quest_info"                     => p!(crate::tables::quest_info::QuestInfo),
        "region_info"                    => p!(crate::tables::region_info::RegionInfo),
        "royal_supply_info"              => p!(crate::tables::royal_supply_info::RoyalSupplyInfo),
        "sequencer_spawn_info"           => p!(crate::tables::sequencer_spawn_info::SequencerSpawnInfo),
        "skill_info"                     => {
            let ph = pabgh.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                "table 'skill_info' requires a pabgh file"))?;
            crate::tables::skill_info::parse_skill_to_json_with_pabgh(pabgb, ph)?
        },
        "spawning_pool_auto_spawn_info"  => p!(crate::tables::spawning_pool_auto_spawn_info::SpawningPoolAutoSpawnInfo),
        "special_mode_info"              => p!(crate::tables::special_mode_info::SpecialModeInfo),
        "stage_info"                     => p!(crate::tables::stage_info::StageInfo),
        "store_info"                     => p!(crate::tables::store_info::StoreInfo),
        "sub_level_info"                 => p!(crate::tables::sub_level_info::SubLevelInfo),
        "terrain_region_auto_spawn_info" => p!(crate::tables::terrain_region_auto_spawn_info::TerrainRegionAutoSpawnInfo),

        // ── sequential tables ─────────────────────────────────────────────
        "action_point_info"              => s!(crate::tables::action_point_info::ActionPointInfo),
        "action_restriction_order_info"  => s!(crate::tables::action_restriction_order_info::ActionRestrictionOrderInfo),
        "aiaction_attribute_info"        => s!(crate::tables::aiaction_attribute_info::AIActionAttributeInfo),
        "aidialog_type_info"             => s!(crate::tables::aidialog_type_info::AIDialogTypeInfo),
        "aievent_table_info"             => s!(crate::tables::aievent_table_info::AIEventTableInfo),
        "aimemory_info"                  => s!(crate::tables::aimemory_info::AIMemoryInfo),
        "aimove_speed_info"              => s!(crate::tables::aimove_speed_info::AIMoveSpeedInfo),
        "ally_group_info"                => s!(crate::tables::ally_group_info::AllyGroupInfo),
        "auto_spawn_filter_info"         => s!(crate::tables::auto_spawn_filter_info::AutoSpawnFilterInfo),
        "board_info"                     => s!(crate::tables::board_info::BoardInfo),
        "breakable_object_info"          => s!(crate::tables::breakable_object_info::BreakableObjectInfo),
        "category_group_info"            => s!(crate::tables::category_group_info::CategoryGroupInfo),
        "category_info"                  => s!(crate::tables::category_info::CategoryInfo),
        "character_appearance_index_info" => s!(crate::tables::character_appearance_index_info::CharacterAppearanceIndexInfo),
        "character_group_info"           => s!(crate::tables::character_group_info::CharacterGroupInfo),
        "craft_tool_group_info"          => s!(crate::tables::craft_tool_group_info::CraftToolGroupInfo),
        "craft_tool_info"                => s!(crate::tables::craft_tool_info::CraftToolInfo),
        "detect_detail_info"             => s!(crate::tables::detect_detail_info::DetectDetailInfo),
        "detect_info"                    => s!(crate::tables::detect_info::DetectInfo),
        "detect_reaction_info"           => s!(crate::tables::detect_reaction_info::DetectReactionInfo),
        "dialog_voice_info"              => s!(crate::tables::dialog_voice_info::DialogVoiceInfo),
        "dye_color_group_info"           => s!(crate::tables::dye_color_group_info::DyeColorGroupInfo),
        "equip_type_info"                => s!(crate::tables::equip_type_info::EquipTypeInfo),
        "faction_group_info"             => s!(crate::tables::faction_group_info::FactionGroupInfo),
        "faction_relation_group_info"    => s!(crate::tables::faction_relation_group_info::FactionRelationGroupInfo),
        "faction_waypoint_info"          => s!(crate::tables::faction_waypoint_info::FactionWaypointInfo),
        "fail_message_info"              => s!(crate::tables::fail_message_info::FailMessageInfo),
        "field_info"                     => s!(crate::tables::field_info::FieldInfo),
        "field_level_name_table_info"    => s!(crate::tables::field_level_name_table_info::FieldLevelNameTableInfo),
        "formation_info"                 => s!(crate::tables::formation_info::FormationInfo),
        "game_advice_group_info"         => s!(crate::tables::game_advice_group_info::GameAdviceGroupInfo),
        "game_advice_info"               => s!(crate::tables::game_advice_info::GameAdviceInfo),
        "game_play_variable_info"        => s!(crate::tables::game_play_variable_info::GamePlayVariableInfo),
        "gimmick_event_table_info"       => s!(crate::tables::gimmick_event_table_info::GimmickEventTableInfo),
        "gimmick_gate_connection_info"   => s!(crate::tables::gimmick_gate_connection_info::GimmickGateConnectionInfo),
        "gimmick_gate_info"              => s!(crate::tables::gimmick_gate_info::GimmickGateInfo),
        "global_game_event_group_info"   => s!(crate::tables::global_game_event_group_info::GlobalGameEventGroupInfo),
        "house_info"                     => s!(crate::tables::house_info::HouseInfo),
        "item_group_info"                => s!(crate::tables::item_group_info::ItemGroupInfo),
        "job_info"                       => s!(crate::tables::job_info::JobInfo),
        "key_map_setting_list_info"      => s!(crate::tables::key_map_setting_list_info::KeyMapSettingListInfo),
        "knowledge_group_info"           => s!(crate::tables::knowledge_group_info::KnowledgeGroupInfo),
        "level_action_point_info"        => s!(crate::tables::level_action_point_info::LevelActionPointInfo),
        "local_string_info"              => s!(crate::tables::local_string_info::LocalStringInfo),
        "material_blood_decal_info"      => s!(crate::tables::material_blood_decal_info::MaterialBloodDecalInfo),
        "material_match_info"            => s!(crate::tables::material_match_info::MaterialMatchInfo),
        "material_relation_info"         => s!(crate::tables::material_relation_info::MaterialRelationInfo),
        "mercenary_group_info"           => s!(crate::tables::mercenary_group_info::MercenaryGroupInfo),
        "mercenary_info"                 => s!(crate::tables::mercenary_info::MercenaryInfo),
        "part_prefab_dye_slot_info"      => s!(crate::tables::part_prefab_dye_slot_info::PartPrefabDyeSlotInfo),
        "part_prefab_dye_texture_pallete_info" => s!(crate::tables::part_prefab_dye_texture_pallete_info::PartPrefabDyeTexturePalleteInfo),
        "pattern_description_info"       => s!(crate::tables::pattern_description_info::PatternDescriptionInfo),
        "platform_achievement_info"      => s!(crate::tables::platform_achievement_info::PlatformAchievementInfo),
        "quest_gauge_info"               => s!(crate::tables::quest_gauge_info::QuestGaugeInfo),
        "quest_group_info"               => s!(crate::tables::quest_group_info::QuestGroupInfo),
        "quick_time_event_info"          => s!(crate::tables::quick_time_event_info::QuickTimeEventInfo),
        "relation_info"                  => s!(crate::tables::relation_info::RelationInfo),
        "reserve_slot_info"              => s!(crate::tables::reserve_slot_info::ReserveSlotInfo),
        "skill_group_info"               => s!(crate::tables::skill_group_info::SkillGroupInfo),
        "skill_tree_group_info"          => s!(crate::tables::skill_tree_group_info::SkillTreeGroupInfo),
        "skill_tree_info"                => s!(crate::tables::skill_tree_info::SkillTreeInfo),
        "socket_group_info"              => s!(crate::tables::socket_group_info::SocketGroupInfo),
        "socket_info"                    => s!(crate::tables::socket_info::SocketInfo),
        "status_group_info"              => s!(crate::tables::status_group_info::StatusGroupInfo),
        "status_info"                    => s!(crate::tables::status_info::StatusInfo),
        "string_info"                    => s!(crate::tables::string_info::StringInfo),
        "terrain_region_navi_info"       => s!(crate::tables::terrain_region_navi_info::TerrainRegionNaviInfo),
        "tribe_info"                     => s!(crate::tables::tribe_info::TribeInfo),
        "trigger_region_info"            => s!(crate::tables::trigger_region_info::TriggerRegionInfo),
        "ui_social_action_info"          => s!(crate::tables::ui_social_action_info::UISocialActionInfo),
        "uifilter_group_info"            => s!(crate::tables::uifilter_group_info::UIFilterGroupInfo),
        "uimap_texture_info"             => s!(crate::tables::uimap_texture_info::UIMapTextureInfo),
        "valid_schedule_action_info"     => s!(crate::tables::valid_schedule_action_info::ValidScheduleActionInfo),
        "vehicle_info"                   => s!(crate::tables::vehicle_info::VehicleInfo),
        "vibrate_pattern_info"           => s!(crate::tables::vibrate_pattern_info::VibratePatternInfo),
        "wanted_info"                    => s!(crate::tables::wanted_info::WantedInfo),

        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput,
            format!("unknown table: '{}'", table_name))),
    })
}

/// Serialize a list of typed JSON dicts back to `.pabgb` bytes.
///
/// `table_name`: same set as `parse_table_to_json`.
///
/// `json_items`: typically the output of `parse_table_to_json` after edits,
/// but can also be hand-constructed JSON values matching the table's schema.
///
/// Returns the raw `.pabgb` bytes. The caller is responsible for rebuilding
/// the companion `.pabgh` (offsets file) for pabgh-bounded tables — see
/// `dmm_parser::binary::variant::build_pabgh_for_modified_body` (TODO: rename)
/// or DMM's `iteminfo/v3_overlay::build_pabgh_for_modified_body`.
pub fn serialize_table_from_json(
    table_name: &str,
    json_items: &[serde_json::Value],
) -> io::Result<Vec<u8>> {
    use crate::tables::blob_runtime::serialize_typed_blob_table_from_json;

    macro_rules! d {
        ($ty:path) => {
            serialize_typed_blob_table_from_json(json_items, |w, map| {
                <$ty>::write_from_json_dict(w, map)
            })?
        };
    }

    Ok(match table_name {
        // ── pabgh-bounded tables ──────────────────────────────────────────
        "ai_dialog_string_info"          => d!(crate::tables::ai_dialog_string_info::AIDialogStringInfo),
        "bitmap_position_info"           => d!(crate::tables::bitmap_position_info::BitmapPositionInfo),
        "buff_info"                      => d!(crate::tables::buff_info::BuffInfo),
        "character_change_info"          => d!(crate::tables::character_change_info::CharacterChangeInfo),
        "character_info"                 => d!(crate::tables::character_info::CharacterInfo),
        "condition_info"                 => d!(crate::tables::condition_info::ConditionInfo),
        "drop_set_info"                  => d!(crate::tables::drop_set_info::DropSetInfo),
        "effect_info"                    => d!(crate::tables::effect_info::EffectInfo),
        "elemental_material_info"        => d!(crate::tables::elemental_material_info::ElementalMaterialInfo),
        "equip_info"                     => d!(crate::tables::equip_info::EquipInfo),
        "equip_slot_info"                => {
            crate::tables::equip_slot_info::serialize_equip_slot_info_from_json(json_items)?
        },
        "faction_info"                   => d!(crate::tables::faction_info::FactionInfo),
        "faction_node_info"              => d!(crate::tables::faction_node_info::FactionNodeInfo),
        "faction_node_spawn_info"        => d!(crate::tables::faction_node_spawn_info::FactionNodeSpawnInfo),
        "faction_spawn_data_info"        => d!(crate::tables::faction_spawn_data_info::FactionSpawnDataInfo),
        "field_revive_info"              => d!(crate::tables::field_revive_info::FieldReviveInfo),
        "frame_event_attr_group_info"    => d!(crate::tables::frame_event_attr_group_info::FrameEventAttrGroupInfo),
        "game_event_handler_info"        => d!(crate::tables::game_event_handler_info::GameEventHandlerInfo),
        "game_global_effect_info"        => d!(crate::tables::game_global_effect_info::GameGlobalEffectInfo),
        "game_level_info"                => d!(crate::tables::game_level_info::GameLevelInfo),
        "game_play_trigger_info"         => d!(crate::tables::game_play_trigger_info::GamePlayTriggerInfo),
        "gimmick_group_info"             => d!(crate::tables::gimmick_group_info::GimmickGroupInfo),
        "gimmick_info"                   => d!(crate::tables::gimmick_info::GimmickInfo),
        "global_game_event_info"         => d!(crate::tables::global_game_event_info::GlobalGameEventInfo),
        "global_stage_sequencer_info"    => d!(crate::tables::global_stage_sequencer_info::GlobalStageSequencerInfo),
        "interaction_info"               => d!(crate::tables::interaction_info::InteractionInfo),
        "inventory_info"                 => d!(crate::tables::inventory_info::InventoryInfo),
        "item_use_info"                  => d!(crate::tables::item_use_info::ItemUseInfo),
        "knowledge_info"                 => d!(crate::tables::knowledge_info::KnowledgeInfo),
        "level_gimmick_scene_object_info" => d!(crate::tables::level_gimmick_scene_object_info::LevelGimmickSceneObjectInfo),
        "mini_game_data_info"            => d!(crate::tables::mini_game_data_info::MiniGameDataInfo),
        "mission_info"                   => d!(crate::tables::mission_info::MissionInfo),
        "multi_change_info"              => d!(crate::tables::multi_change_info::MultiChangeInfo),
        "npc_info"                       => d!(crate::tables::npc_info::NpcInfo),
        "platform_entitlement_info"      => d!(crate::tables::platform_entitlement_info::PlatformEntitlementInfo),
        "quest_info"                     => d!(crate::tables::quest_info::QuestInfo),
        "region_info"                    => d!(crate::tables::region_info::RegionInfo),
        "royal_supply_info"              => d!(crate::tables::royal_supply_info::RoyalSupplyInfo),
        "sequencer_spawn_info"           => d!(crate::tables::sequencer_spawn_info::SequencerSpawnInfo),
        "skill_info"                     => {
            crate::tables::skill_info::serialize_skill_from_json(json_items)?
        },
        "spawning_pool_auto_spawn_info"  => d!(crate::tables::spawning_pool_auto_spawn_info::SpawningPoolAutoSpawnInfo),
        "special_mode_info"              => d!(crate::tables::special_mode_info::SpecialModeInfo),
        "stage_info"                     => d!(crate::tables::stage_info::StageInfo),
        "store_info"                     => d!(crate::tables::store_info::StoreInfo),
        "sub_level_info"                 => d!(crate::tables::sub_level_info::SubLevelInfo),
        "terrain_region_auto_spawn_info" => d!(crate::tables::terrain_region_auto_spawn_info::TerrainRegionAutoSpawnInfo),

        // ── sequential tables ─────────────────────────────────────────────
        "action_point_info"              => d!(crate::tables::action_point_info::ActionPointInfo),
        "action_restriction_order_info"  => d!(crate::tables::action_restriction_order_info::ActionRestrictionOrderInfo),
        "aiaction_attribute_info"        => d!(crate::tables::aiaction_attribute_info::AIActionAttributeInfo),
        "aidialog_type_info"             => d!(crate::tables::aidialog_type_info::AIDialogTypeInfo),
        "aievent_table_info"             => d!(crate::tables::aievent_table_info::AIEventTableInfo),
        "aimemory_info"                  => d!(crate::tables::aimemory_info::AIMemoryInfo),
        "aimove_speed_info"              => d!(crate::tables::aimove_speed_info::AIMoveSpeedInfo),
        "ally_group_info"                => d!(crate::tables::ally_group_info::AllyGroupInfo),
        "auto_spawn_filter_info"         => d!(crate::tables::auto_spawn_filter_info::AutoSpawnFilterInfo),
        "board_info"                     => d!(crate::tables::board_info::BoardInfo),
        "breakable_object_info"          => d!(crate::tables::breakable_object_info::BreakableObjectInfo),
        "category_group_info"            => d!(crate::tables::category_group_info::CategoryGroupInfo),
        "category_info"                  => d!(crate::tables::category_info::CategoryInfo),
        "character_appearance_index_info" => d!(crate::tables::character_appearance_index_info::CharacterAppearanceIndexInfo),
        "character_group_info"           => d!(crate::tables::character_group_info::CharacterGroupInfo),
        "craft_tool_group_info"          => d!(crate::tables::craft_tool_group_info::CraftToolGroupInfo),
        "craft_tool_info"                => d!(crate::tables::craft_tool_info::CraftToolInfo),
        "detect_detail_info"             => d!(crate::tables::detect_detail_info::DetectDetailInfo),
        "detect_info"                    => d!(crate::tables::detect_info::DetectInfo),
        "detect_reaction_info"           => d!(crate::tables::detect_reaction_info::DetectReactionInfo),
        "dialog_voice_info"              => d!(crate::tables::dialog_voice_info::DialogVoiceInfo),
        "dye_color_group_info"           => d!(crate::tables::dye_color_group_info::DyeColorGroupInfo),
        "equip_type_info"                => d!(crate::tables::equip_type_info::EquipTypeInfo),
        "faction_group_info"             => d!(crate::tables::faction_group_info::FactionGroupInfo),
        "faction_relation_group_info"    => d!(crate::tables::faction_relation_group_info::FactionRelationGroupInfo),
        "faction_waypoint_info"          => d!(crate::tables::faction_waypoint_info::FactionWaypointInfo),
        "fail_message_info"              => d!(crate::tables::fail_message_info::FailMessageInfo),
        "field_info"                     => d!(crate::tables::field_info::FieldInfo),
        "field_level_name_table_info"    => d!(crate::tables::field_level_name_table_info::FieldLevelNameTableInfo),
        "formation_info"                 => d!(crate::tables::formation_info::FormationInfo),
        "game_advice_group_info"         => d!(crate::tables::game_advice_group_info::GameAdviceGroupInfo),
        "game_advice_info"               => d!(crate::tables::game_advice_info::GameAdviceInfo),
        "game_play_variable_info"        => d!(crate::tables::game_play_variable_info::GamePlayVariableInfo),
        "gimmick_event_table_info"       => d!(crate::tables::gimmick_event_table_info::GimmickEventTableInfo),
        "gimmick_gate_connection_info"   => d!(crate::tables::gimmick_gate_connection_info::GimmickGateConnectionInfo),
        "gimmick_gate_info"              => d!(crate::tables::gimmick_gate_info::GimmickGateInfo),
        "global_game_event_group_info"   => d!(crate::tables::global_game_event_group_info::GlobalGameEventGroupInfo),
        "house_info"                     => d!(crate::tables::house_info::HouseInfo),
        "item_group_info"                => d!(crate::tables::item_group_info::ItemGroupInfo),
        "job_info"                       => d!(crate::tables::job_info::JobInfo),
        "key_map_setting_list_info"      => d!(crate::tables::key_map_setting_list_info::KeyMapSettingListInfo),
        "knowledge_group_info"           => d!(crate::tables::knowledge_group_info::KnowledgeGroupInfo),
        "level_action_point_info"        => d!(crate::tables::level_action_point_info::LevelActionPointInfo),
        "local_string_info"              => d!(crate::tables::local_string_info::LocalStringInfo),
        "material_blood_decal_info"      => d!(crate::tables::material_blood_decal_info::MaterialBloodDecalInfo),
        "material_match_info"            => d!(crate::tables::material_match_info::MaterialMatchInfo),
        "material_relation_info"         => d!(crate::tables::material_relation_info::MaterialRelationInfo),
        "mercenary_group_info"           => d!(crate::tables::mercenary_group_info::MercenaryGroupInfo),
        "mercenary_info"                 => d!(crate::tables::mercenary_info::MercenaryInfo),
        "part_prefab_dye_slot_info"      => d!(crate::tables::part_prefab_dye_slot_info::PartPrefabDyeSlotInfo),
        "part_prefab_dye_texture_pallete_info" => d!(crate::tables::part_prefab_dye_texture_pallete_info::PartPrefabDyeTexturePalleteInfo),
        "pattern_description_info"       => d!(crate::tables::pattern_description_info::PatternDescriptionInfo),
        "platform_achievement_info"      => d!(crate::tables::platform_achievement_info::PlatformAchievementInfo),
        "quest_gauge_info"               => d!(crate::tables::quest_gauge_info::QuestGaugeInfo),
        "quest_group_info"               => d!(crate::tables::quest_group_info::QuestGroupInfo),
        "quick_time_event_info"          => d!(crate::tables::quick_time_event_info::QuickTimeEventInfo),
        "relation_info"                  => d!(crate::tables::relation_info::RelationInfo),
        "reserve_slot_info"              => d!(crate::tables::reserve_slot_info::ReserveSlotInfo),
        "skill_group_info"               => d!(crate::tables::skill_group_info::SkillGroupInfo),
        "skill_tree_group_info"          => d!(crate::tables::skill_tree_group_info::SkillTreeGroupInfo),
        "skill_tree_info"                => d!(crate::tables::skill_tree_info::SkillTreeInfo),
        "socket_group_info"              => d!(crate::tables::socket_group_info::SocketGroupInfo),
        "socket_info"                    => d!(crate::tables::socket_info::SocketInfo),
        "status_group_info"              => d!(crate::tables::status_group_info::StatusGroupInfo),
        "status_info"                    => d!(crate::tables::status_info::StatusInfo),
        "string_info"                    => d!(crate::tables::string_info::StringInfo),
        "terrain_region_navi_info"       => d!(crate::tables::terrain_region_navi_info::TerrainRegionNaviInfo),
        "tribe_info"                     => d!(crate::tables::tribe_info::TribeInfo),
        "trigger_region_info"            => d!(crate::tables::trigger_region_info::TriggerRegionInfo),
        "ui_social_action_info"          => d!(crate::tables::ui_social_action_info::UISocialActionInfo),
        "uifilter_group_info"            => d!(crate::tables::uifilter_group_info::UIFilterGroupInfo),
        "uimap_texture_info"             => d!(crate::tables::uimap_texture_info::UIMapTextureInfo),
        "valid_schedule_action_info"     => d!(crate::tables::valid_schedule_action_info::ValidScheduleActionInfo),
        "vehicle_info"                   => d!(crate::tables::vehicle_info::VehicleInfo),
        "vibrate_pattern_info"           => d!(crate::tables::vibrate_pattern_info::VibratePatternInfo),
        "wanted_info"                    => d!(crate::tables::wanted_info::WantedInfo),

        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput,
            format!("unknown table: '{}'", table_name))),
    })
}

/// True if `table_name` is supported by `parse_table_to_json`/`serialize_table_from_json`.
///
/// Useful for callers that want to detect supported targets without triggering
/// a parse error. Cheaper than a real parse: just dispatches the match arm.
pub fn is_supported_table(table_name: &str) -> bool {
    // Cheapest test: try a parse on empty bytes. If the table is recognized
    // but pabgh is missing, we get InvalidInput("requires a pabgh"). If the
    // table is unknown we get InvalidInput("unknown table"). Distinguish via
    // the message. Both errors are no-ops (no allocation, no real parse).
    match parse_table_to_json(table_name, &[], None) {
        Ok(_) => true,  // empty body parsed OK (sequential tables)
        Err(e) => !e.to_string().starts_with("unknown table:"),
    }
}

/// List every table_name supported by this dispatcher.
///
/// Order: `pabgh-bounded` first (alphabetical), then `sequential` (alphabetical).
/// Stable across releases — adding a new table appends to one of the two
/// halves. Useful for tooling/UI dropdowns.
pub fn supported_tables() -> &'static [&'static str] {
    &[
        // pabgh-bounded
        "ai_dialog_string_info", "bitmap_position_info", "buff_info",
        "character_change_info", "character_info", "condition_info",
        "drop_set_info", "effect_info", "elemental_material_info",
        "equip_info", "equip_slot_info", "faction_info", "faction_node_info",
        "faction_node_spawn_info", "faction_spawn_data_info",
        "field_revive_info", "frame_event_attr_group_info",
        "game_event_handler_info", "game_global_effect_info",
        "game_level_info", "game_play_trigger_info", "gimmick_group_info",
        "gimmick_info", "global_game_event_info", "global_stage_sequencer_info",
        "interaction_info", "inventory_info", "item_use_info",
        "knowledge_info", "level_gimmick_scene_object_info",
        "mini_game_data_info", "mission_info", "multi_change_info",
        "npc_info", "platform_entitlement_info", "quest_info", "region_info",
        "royal_supply_info", "sequencer_spawn_info", "skill_info",
        "spawning_pool_auto_spawn_info", "special_mode_info", "stage_info",
        "store_info", "sub_level_info", "terrain_region_auto_spawn_info",
        // sequential
        "action_point_info", "action_restriction_order_info",
        "aiaction_attribute_info", "aidialog_type_info", "aievent_table_info",
        "aimemory_info", "aimove_speed_info", "ally_group_info",
        "auto_spawn_filter_info", "board_info", "breakable_object_info",
        "category_group_info", "category_info", "character_appearance_index_info",
        "character_group_info", "craft_tool_group_info", "craft_tool_info",
        "detect_detail_info", "detect_info", "detect_reaction_info",
        "dialog_voice_info", "dye_color_group_info", "equip_type_info",
        "faction_group_info", "faction_relation_group_info",
        "faction_waypoint_info", "fail_message_info", "field_info",
        "field_level_name_table_info", "formation_info",
        "game_advice_group_info", "game_advice_info", "game_play_variable_info",
        "gimmick_event_table_info", "gimmick_gate_connection_info",
        "gimmick_gate_info", "global_game_event_group_info", "house_info",
        "item_group_info", "job_info", "key_map_setting_list_info",
        "knowledge_group_info", "level_action_point_info", "local_string_info",
        "material_blood_decal_info", "material_match_info",
        "material_relation_info", "mercenary_group_info", "mercenary_info",
        "part_prefab_dye_slot_info", "part_prefab_dye_texture_pallete_info",
        "pattern_description_info", "platform_achievement_info",
        "quest_gauge_info", "quest_group_info", "quick_time_event_info",
        "relation_info", "reserve_slot_info", "skill_group_info",
        "skill_tree_group_info", "skill_tree_info", "socket_group_info",
        "socket_info", "status_group_info", "status_info", "string_info",
        "terrain_region_navi_info", "tribe_info", "trigger_region_info",
        "ui_social_action_info", "uifilter_group_info", "uimap_texture_info",
        "valid_schedule_action_info", "vehicle_info", "vibrate_pattern_info",
        "wanted_info",
    ]
}
