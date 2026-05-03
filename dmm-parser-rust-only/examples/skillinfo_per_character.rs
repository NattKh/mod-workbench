// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Per-character SkillInfo cross-reference. Empirically tests the
//! hypothesis: "Damian and Kliff feel different with the same weapon
//! because they have different SkillInfo entries gating which moves
//! they can execute."
//!
//! Walks all 1952 SkillInfo entries and groups by `usable_character_info_list`
//! to show: which skills are unique to which character, which are shared.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::character_info::info::CharacterInfo;
use dmm_parser::tables::skill_info::info::SkillInfo;
use std::collections::{BTreeMap, BTreeSet};

const CHAR_PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgb";
const CHAR_PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgh";
const SKILL_PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skill.pabgb";
const SKILL_PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\skill.pabgh";

fn main() {
    // Load CharacterInfo to map keys → string_keys
    let char_pabgb = std::fs::read(CHAR_PABGB).expect("read char pabgb");
    let char_entries = load_pabgh_offsets(CHAR_PABGH).expect("char pabgh");
    let char_ranges = entry_ranges(&char_entries, char_pabgb.len());

    let mut key_to_name: BTreeMap<u32, String> = BTreeMap::new();
    let mut player_keys: Vec<(u32, String)> = vec![];
    for (_key, start, end) in &char_ranges {
        let mut cur = *start;
        if let Ok(c) = CharacterInfo::read_with_size(&char_pabgb, &mut cur, end - start) {
            let sk: &str = c.string_key.data;
            key_to_name.insert(c.key, sk.to_string());
            if matches!(sk, "Kliff" | "Damian" | "Yahn" | "Yann" | "Oongka" | "PlayerAll") {
                player_keys.push((c.key, sk.to_string()));
            }
        }
    }
    println!("Loaded {} CharacterInfo entries", key_to_name.len());
    println!("Player records:");
    for (k, n) in &player_keys {
        println!("  key={:>6} string_key={}", k, n);
    }

    // Load SkillInfo
    let skill_pabgb = std::fs::read(SKILL_PABGB).expect("read skill pabgb");
    let skill_entries = load_pabgh_offsets(SKILL_PABGH).expect("skill pabgh");
    let skill_ranges = entry_ranges(&skill_entries, skill_pabgb.len());
    println!("\nLoaded {} SkillInfo entries\n", skill_ranges.len());

    // Cross-ref: for each character key, count how many skills include them
    let mut skills_per_char: BTreeMap<u32, Vec<(u32, String)>> = BTreeMap::new();
    let mut total_with_user_list = 0;
    let mut total_empty_user_list = 0;

    for (_key, start, end) in &skill_ranges {
        let mut cur = *start;
        let skill = match SkillInfo::read_with_size(&skill_pabgb, &mut cur, end - start) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if skill.usable_character_info_list.items.is_empty() {
            total_empty_user_list += 1;
        } else {
            total_with_user_list += 1;
        }
        for ck in &skill.usable_character_info_list.items {
            skills_per_char.entry(*ck).or_default().push((skill.key, skill.string_key.data.to_string()));
        }
    }

    println!("=== Skill access summary ===");
    println!("  Skills with empty usable_character_info_list:  {}",
        total_empty_user_list);
    println!("  Skills with at least one character key:        {}",
        total_with_user_list);
    println!();

    // Top character keys by skill access count
    let mut sorted: Vec<_> = skills_per_char.iter().collect();
    sorted.sort_by_key(|(_, skills)| std::cmp::Reverse(skills.len()));

    println!("=== Top 20 character keys by skill access count ===");
    for (ck, skills) in sorted.iter().take(20) {
        let name = key_to_name.get(ck).cloned().unwrap_or_else(|| format!("key=0x{:x}", ck));
        println!("  {:<32}  {} skills", name, skills.len());
    }

    // Compare Kliff vs Damian
    println!("\n=== Cross-character analysis ===");
    let kliff_key = player_keys.iter().find(|(_, n)| n == "Kliff").map(|(k, _)| *k);
    let damian_key = player_keys.iter().find(|(_, n)| n == "Damian").map(|(k, _)| *k);
    let yahn_key = player_keys.iter().find(|(_, n)| n == "Yahn").map(|(k, _)| *k);
    let oongka_key = player_keys.iter().find(|(_, n)| n == "Oongka").map(|(k, _)| *k);

    if let (Some(k), Some(d)) = (kliff_key, damian_key) {
        let kliff_skills: BTreeSet<u32> = skills_per_char.get(&k)
            .map(|v| v.iter().map(|(id, _)| *id).collect()).unwrap_or_default();
        let damian_skills: BTreeSet<u32> = skills_per_char.get(&d)
            .map(|v| v.iter().map(|(id, _)| *id).collect()).unwrap_or_default();

        let kliff_only: Vec<&u32> = kliff_skills.difference(&damian_skills).collect();
        let damian_only: Vec<&u32> = damian_skills.difference(&kliff_skills).collect();
        let shared: Vec<&u32> = kliff_skills.intersection(&damian_skills).collect();

        println!("\nKliff: {} total skills", kliff_skills.len());
        println!("Damian: {} total skills", damian_skills.len());
        println!("Shared (both): {} skills", shared.len());
        println!("Kliff-only:    {} skills", kliff_only.len());
        println!("Damian-only:   {} skills", damian_only.len());

        // Sample Kliff-only skills (these are why Kliff feels different)
        if let Some(kliff_skill_list) = skills_per_char.get(&k) {
            let kliff_only_with_names: Vec<&(u32, String)> = kliff_skill_list.iter()
                .filter(|(id, _)| kliff_only.contains(&id))
                .collect();
            println!("\nFirst 15 Kliff-only skills:");
            for (id, name) in kliff_only_with_names.iter().take(15) {
                println!("  key={:>6}  {}", id, name);
            }
        }

        if let Some(damian_skill_list) = skills_per_char.get(&d) {
            let damian_only_with_names: Vec<&(u32, String)> = damian_skill_list.iter()
                .filter(|(id, _)| damian_only.contains(&id))
                .collect();
            println!("\nFirst 15 Damian-only skills:");
            for (id, name) in damian_only_with_names.iter().take(15) {
                println!("  key={:>6}  {}", id, name);
            }
        }
    }

    if let (Some(y), Some(o)) = (yahn_key, oongka_key) {
        let yahn_skills: BTreeSet<u32> = skills_per_char.get(&y)
            .map(|v| v.iter().map(|(id, _)| *id).collect()).unwrap_or_default();
        let oongka_skills: BTreeSet<u32> = skills_per_char.get(&o)
            .map(|v| v.iter().map(|(id, _)| *id).collect()).unwrap_or_default();
        println!("\nYahn:   {} skills", yahn_skills.len());
        println!("Oongka: {} skills", oongka_skills.len());
    }
}
