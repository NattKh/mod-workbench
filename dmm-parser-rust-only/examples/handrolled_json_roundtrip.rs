// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Verify hand-rolled tables that just got JSON exposure round-trip clean.
//! Add a check! line per table as it gains JSON methods.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use serde_json::{Map, Value};
use std::path::Path;

const VANILLA_DIR: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps";

macro_rules! check {
    ($pabgb:expr, $pabgh:expr, $T:ty) => {{
        let pabgb_path = Path::new(VANILLA_DIR).join($pabgb);
        let pabgh_path = Path::new(VANILLA_DIR).join($pabgh);
        let Ok(body) = std::fs::read(&pabgb_path) else { println!("  SKIP {} (missing)", $pabgb); return; };
        let Some(entries) = load_pabgh_offsets(pabgh_path.to_str().unwrap()) else { println!("  SKIP {} (pabgh)", $pabgb); return; };
        let ranges = entry_ranges(&entries, body.len());

        // Read all → JSON dicts.
        let mut dicts: Vec<Map<String, Value>> = Vec::with_capacity(ranges.len());
        for (k, s, e) in &ranges {
            let mut c = *s;
            let item = match <$T>::read_with_size(&body, &mut c, e - s) {
                Ok(it) => it,
                Err(err) => { println!("  ❌ {} parse k=0x{:x}: {}", $pabgb, k, err); return; }
            };
            if c != *e {
                println!("  ❌ {} k=0x{:x} under/over-consumed: {}/{}", $pabgb, k, c - s, e - s);
                return;
            }
            dicts.push(item.to_json_dict());
        }

        // Re-serialize from JSON dicts.
        let mut out = Vec::with_capacity(body.len());
        for (i, d) in dicts.iter().enumerate() {
            if let Err(e) = <$T>::write_from_json_dict(&mut out, d) {
                println!("  ❌ {} write[{}]: {}", $pabgb, i, e); return;
            }
        }

        if out == body {
            println!("  ✅ {} ({} entries, {} bytes)", $pabgb, dicts.len(), body.len());
        } else {
            let diff = out.iter().zip(body.iter()).position(|(a, b)| a != b).unwrap_or(out.len().min(body.len()));
            println!("  ❌ {} byte mismatch at 0x{:X} (out={}, vanilla={})", $pabgb, diff, out.len(), body.len());
        }
    }};
}

fn main() {
    println!("=== Hand-rolled tables JSON round-trip ===\n");

    macro_rules! test_table {
        ($pabgb:expr, $pabgh:expr, $T:ty) => {
            (|| { check!($pabgb, $pabgh, $T); })();
        };
    }

    use dmm_parser::tables::buff_info::BuffInfo;
    test_table!("buffinfo.pabgb", "buffinfo.pabgh", BuffInfo);

    use dmm_parser::tables::ai_dialog_string_info::AIDialogStringInfo;
    test_table!("aidialogstringinfo.pabgb", "aidialogstringinfo.pabgh", AIDialogStringInfo);

    use dmm_parser::tables::character_change_info::CharacterChangeInfo;
    test_table!("characterchange.pabgb", "characterchange.pabgh", CharacterChangeInfo);

    use dmm_parser::tables::condition_info::ConditionInfo;
    test_table!("conditioninfo.pabgb", "conditioninfo.pabgh", ConditionInfo);

    use dmm_parser::tables::drop_set_info::DropSetInfo;
    test_table!("dropsetinfo.pabgb", "dropsetinfo.pabgh", DropSetInfo);

    use dmm_parser::tables::effect_info::EffectInfo;
    test_table!("effectinfo.pabgb", "effectinfo.pabgh", EffectInfo);

    use dmm_parser::tables::faction_node_spawn_info::FactionNodeSpawnInfo;
    test_table!("factionnodespawninfo.pabgb", "factionnodespawninfo.pabgh", FactionNodeSpawnInfo);

    use dmm_parser::tables::faction_spawn_data_info::FactionSpawnDataInfo;
    test_table!("factionspawndatainfo.pabgb", "factionspawndatainfo.pabgh", FactionSpawnDataInfo);

    use dmm_parser::tables::frame_event_attr_group_info::FrameEventAttrGroupInfo;
    test_table!("frameeventattrgroupinfo.pabgb", "frameeventattrgroupinfo.pabgh", FrameEventAttrGroupInfo);

    use dmm_parser::tables::level_gimmick_scene_object_info::LevelGimmickSceneObjectInfo;
    test_table!("levelgimmicksceneobjectinfo.pabgb", "levelgimmicksceneobjectinfo.pabgh", LevelGimmickSceneObjectInfo);

    use dmm_parser::tables::mini_game_data_info::MiniGameDataInfo;
    test_table!("minigamedatainfo.pabgb", "minigamedatainfo.pabgh", MiniGameDataInfo);

    use dmm_parser::tables::sequencer_spawn_info::SequencerSpawnInfo;
    test_table!("sequencerspawninfo.pabgb", "sequencerspawninfo.pabgh", SequencerSpawnInfo);

    use dmm_parser::tables::spawning_pool_auto_spawn_info::SpawningPoolAutoSpawnInfo;
    test_table!("spawningpoolautospawninfo.pabgb", "spawningpoolautospawninfo.pabgh", SpawningPoolAutoSpawnInfo);

    use dmm_parser::tables::terrain_region_auto_spawn_info::TerrainRegionAutoSpawnInfo;
    test_table!("terrainregionautospawninfo.pabgb", "terrainregionautospawninfo.pabgh", TerrainRegionAutoSpawnInfo);

    // detect_detail_info has no pabgh (fixed-size 59-entry stride per record).
    // We exercise it via a separate inline check.
    {
        use dmm_parser::tables::detect_detail_info::DetectDetailInfo;
        let pabgb = std::path::Path::new(VANILLA_DIR).join("detectdetailinfo.pabgb");
        match std::fs::read(&pabgb) {
            Err(_) => println!("  SKIP detectdetailinfo.pabgb (missing)"),
            Ok(body) => {
                let mut off = 0;
                let mut dicts = Vec::new();
                while off < body.len() {
                    match DetectDetailInfo::read_from(&body, &mut off) {
                        Ok(it) => dicts.push(it.to_json_dict()),
                        Err(e) => { println!("  ❌ detectdetailinfo parse @ 0x{:x}: {}", off, e); break; }
                    }
                }
                if off == body.len() {
                    let mut out = Vec::with_capacity(body.len());
                    let mut ok = true;
                    for (i, d) in dicts.iter().enumerate() {
                        if let Err(e) = DetectDetailInfo::write_from_json_dict(&mut out, d) {
                            println!("  ❌ detectdetailinfo write[{}]: {}", i, e); ok = false; break;
                        }
                    }
                    if ok {
                        if out == body {
                            println!("  ✅ detectdetailinfo.pabgb ({} entries, {} bytes)", dicts.len(), body.len());
                        } else {
                            let diff = out.iter().zip(body.iter()).position(|(a, b)| a != b)
                                .unwrap_or(out.len().min(body.len()));
                            println!("  ❌ detectdetailinfo byte mismatch at 0x{:X} (out={}, vanilla={})",
                                diff, out.len(), body.len());
                        }
                    }
                }
            }
        }
    }
}
