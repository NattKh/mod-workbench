// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Round-trip every pabgh_typed_blob_table! Tier 1.5 table through the new
//! JSON methods. Reports per-table pass/fail across all 28 tables.

use dmm_parser::tables::blob_runtime::{
    parse_typed_blob_table_to_json_with_pabgh,
    serialize_typed_blob_table_from_json,
};
use std::path::Path;

const VANILLA_DIR: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps";

macro_rules! check {
    ($pabgb:expr, $pabgh:expr, $T:ty) => {{
        let pabgb_path = Path::new(VANILLA_DIR).join($pabgb);
        let pabgh_path = Path::new(VANILLA_DIR).join($pabgh);
        let Ok(body) = std::fs::read(&pabgb_path) else {
            println!("  SKIP {} (no vanilla file)", $pabgb);
            return;
        };
        let Ok(pabgh) = std::fs::read(&pabgh_path) else {
            println!("  SKIP {} (no vanilla pabgh)", $pabgb);
            return;
        };
        let dicts = match parse_typed_blob_table_to_json_with_pabgh(&body, &pabgh, |d, o, s| {
            Ok(<$T>::read_with_size(d, o, s)?.to_json_dict())
        }) {
            Ok(d) => d,
            Err(e) => { println!("  ❌ {} parse: {}", $pabgb, e); return; }
        };
        let out = match serialize_typed_blob_table_from_json(&dicts, |w, obj| {
            <$T>::write_from_json_dict(w, obj)
        }) {
            Ok(o) => o,
            Err(e) => { println!("  ❌ {} serialize: {}", $pabgb, e); return; }
        };
        if out == body {
            println!("  ✅ {} ({} entries, {} bytes)", $pabgb, dicts.len(), body.len());
        } else {
            let diff_at = out.iter().zip(body.iter()).position(|(a, b)| a != b)
                .unwrap_or(out.len().min(body.len()));
            println!("  ❌ {} MISMATCH at byte 0x{:X} (out_len={}, vanilla_len={})", $pabgb, diff_at, out.len(), body.len());
        }
    }};
}

fn main() {
    println!("=== Tier 1.5 typed-blob-table JSON round-trip ===\n");

    // Run each table inside its own closure so SKIP/early-return doesn't break the rest.
    macro_rules! test_table {
        ($pabgb:expr, $pabgh:expr, $T:ty) => {
            (|| { check!($pabgb, $pabgh, $T); })();
        };
    }

    use dmm_parser::tables::sub_level_info::SubLevelInfo;
    test_table!("sublevelinfo.pabgb", "sublevelinfo.pabgh", SubLevelInfo);

    use dmm_parser::tables::inventory_info::InventoryInfo;
    test_table!("inventory.pabgb", "inventory.pabgh", InventoryInfo);

    use dmm_parser::tables::knowledge_info::KnowledgeInfo;
    test_table!("knowledgeinfo.pabgb", "knowledgeinfo.pabgh", KnowledgeInfo);

    use dmm_parser::tables::mission_info::MissionInfo;
    test_table!("missioninfo.pabgb", "missioninfo.pabgh", MissionInfo);

    use dmm_parser::tables::store_info::StoreInfo;
    test_table!("storeinfo.pabgb", "storeinfo.pabgh", StoreInfo);

    use dmm_parser::tables::elemental_material_info::ElementalMaterialInfo;
    test_table!("elementalmaterialinfo.pabgb", "elementalmaterialinfo.pabgh", ElementalMaterialInfo);

    // QuestInfo is hand-rolled (not macro-generated), skip — needs separate
    // JSON method work.

    use dmm_parser::tables::region_info::RegionInfo;
    test_table!("regioninfo.pabgb", "regioninfo.pabgh", RegionInfo);

    use dmm_parser::tables::equip_info::EquipInfo;
    test_table!("equipinfo.pabgb", "equipinfo.pabgh", EquipInfo);

    use dmm_parser::tables::royal_supply_info::RoyalSupplyInfo;
    test_table!("royalsupplyinfo.pabgb", "royalsupplyinfo.pabgh", RoyalSupplyInfo);

    use dmm_parser::tables::game_play_trigger_info::GamePlayTriggerInfo;
    test_table!("gameplaytriggerinfo.pabgb", "gameplaytriggerinfo.pabgh", GamePlayTriggerInfo);

    use dmm_parser::tables::gimmick_info::GimmickInfo;
    test_table!("gimmickinfo.pabgb", "gimmickinfo.pabgh", GimmickInfo);

    use dmm_parser::tables::character_info::CharacterInfo;
    test_table!("characterinfo.pabgb", "characterinfo.pabgh", CharacterInfo);

    use dmm_parser::tables::npc_info::NpcInfo;
    test_table!("npcinfo.pabgb", "npcinfo.pabgh", NpcInfo);

    use dmm_parser::tables::faction_info::FactionInfo;
    test_table!("factioninfo.pabgb", "factioninfo.pabgh", FactionInfo);
}
