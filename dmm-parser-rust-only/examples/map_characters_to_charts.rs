// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Cross-reference CharacterInfo entries with chart group names from
//! CharacterActionPackageDescription.xml.
//!
//! For each character, prints:
//!   - string_key (the character's identifier)
//!   - upper_chart.group_lookup (u32 hash from pabgb)
//!   - lower_chart.group_lookup
//!   - matched chart group name (if any chart group from the XML hashes to
//!     the same value with our Jenkins hashlittle2)
//!
//! Confirms the hash function and produces the character → chart group map.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::crypto::checksum::calculate_checksum;
use dmm_parser::tables::character_info::info::CharacterInfo;
use std::collections::HashMap;

const PABGB: &str =
    r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgb";
const PABGH: &str =
    r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgh";
const CHART_JSON: &str =
    r"C:\Users\corin\Desktop\CD DUMPING TOOLS\Chart-System\chart_groups.json";

fn main() {
    // Load chart groups from the parsed JSON
    let chart_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(CHART_JSON).expect("read chart_groups.json"),
    )
    .expect("parse JSON");
    let groups = chart_json.as_array().expect("JSON should be array");

    // Hash every chart group name with multiple variants to find which matches
    let mut hash_map: HashMap<u32, String> = HashMap::new();
    for g in groups {
        let name = g["name"].as_str().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        // Try several encodings the game might use
        let h_raw = calculate_checksum(name.as_bytes());
        hash_map.insert(h_raw, name.to_string());
        // Also try with null terminator
        let mut with_null = name.as_bytes().to_vec();
        with_null.push(0);
        let h_null = calculate_checksum(&with_null);
        hash_map.entry(h_null).or_insert_with(|| format!("{}\\0", name));
        // Try lowercase
        let lower = name.to_ascii_lowercase();
        let h_lower = calculate_checksum(lower.as_bytes());
        hash_map.entry(h_lower).or_insert_with(|| format!("{}(lower)", name));
    }
    println!("Hashed {} unique values from {} chart group names",
        hash_map.len(), groups.len());

    // Load CharacterInfo
    let pabgb = std::fs::read(PABGB).expect("read pabgb");
    let entries = load_pabgh_offsets(PABGH).expect("parse pabgh");
    let ranges = entry_ranges(&entries, pabgb.len());

    println!("CharacterInfo: {} entries", ranges.len());
    println!("\n{:6} {:32} {:>10} {:>10} {:30} {:30}",
        "key", "string_key", "upper_h", "lower_h", "upper_match", "lower_match");
    println!("{}", "-".repeat(120));

    let mut player_records = vec![];
    let mut hash_hits = 0usize;

    for (key, start, end) in ranges.iter() {
        let mut cursor = *start;
        let item = match CharacterInfo::read_with_size(&pabgb, &mut cursor, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };

        let upper_h = item.upper_chart.group_lookup;
        let lower_h = item.lower_chart.group_lookup;
        let upper_match = hash_map.get(&upper_h).cloned().unwrap_or_else(|| "".to_string());
        let lower_match = hash_map.get(&lower_h).cloned().unwrap_or_else(|| "".to_string());

        if !upper_match.is_empty() || !lower_match.is_empty() {
            hash_hits += 1;
        }

        let sk: &str = item.string_key.data;
        let is_player = sk.starts_with("Kliff")
            || sk.starts_with("Damian")
            || sk.starts_with("Yann")
            || sk.starts_with("Yahn")
            || sk.starts_with("Oongka")
            || sk.starts_with("Player");

        if is_player || !upper_match.is_empty() || (upper_h != 0 && player_records.len() < 30) {
            println!("{:6} {:32} {:>10x} {:>10x} {:30} {:30}",
                key, sk.chars().take(32).collect::<String>(), upper_h, lower_h, upper_match, lower_match);
            player_records.push((sk.to_string(), upper_h, lower_h, upper_match.clone(), lower_match.clone()));
        }
    }
    // Stats on upper_h distribution
    let mut hash_counts: HashMap<u32, usize> = HashMap::new();
    for (key, start, end) in ranges.iter() {
        let mut cursor = *start;
        if let Ok(item) = CharacterInfo::read_with_size(&pabgb, &mut cursor, end - start) {
            *hash_counts.entry(item.upper_chart.group_lookup).or_insert(0) += 1;
        }
        let _ = key;
    }
    println!("\n=== upper_chart.group_lookup distribution (top 20) ===");
    let mut sorted: Vec<_> = hash_counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (h, c) in sorted.iter().take(20) {
        let m = hash_map.get(h).cloned().unwrap_or_default();
        println!("  hash=0x{:08x}  count={:>5}  match={}", h, c, m);
    }

    println!("\n{} CharacterInfo entries had a chart-group hash match", hash_hits);

    // Sample first 5 unique upper_h values
    let mut unique_upper: HashMap<u32, (String, String)> = HashMap::new();
    for (sk, uh, _lh, um, _lm) in &player_records {
        unique_upper.entry(*uh).or_insert_with(|| (sk.clone(), um.clone()));
    }
    println!("\nUnique upper_chart hashes among player records: {}", unique_upper.len());
}
