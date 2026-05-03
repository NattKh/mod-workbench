// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find all files in the game install that reference Damian, Kliff, longsword,
//! or any character/weapon-specific chart pattern. Helps locate where
//! character-specific moveset data actually lives.

use dmm_parser::binary::papgt::PackGroupTreeMeta;
use dmm_parser::binary::pamt::PackMeta;
use std::collections::BTreeMap;
use std::path::Path;

const GAME_DIR: &str = r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert";
const PAPGT_PATH: &str =
    r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.papgt";

fn matches(file_name: &str, dir_path: &str) -> Option<&'static str> {
    let lf = file_name.to_ascii_lowercase();
    let ld = dir_path.to_ascii_lowercase();
    let blob = format!("{}/{}", ld, lf);

    if blob.contains("damian") {
        return Some("damian");
    }
    if blob.contains("longsword") || blob.contains("long_sword") {
        return Some("longsword");
    }
    if blob.contains("kliff") || blob.contains("macduff") {
        return Some("kliff/macduff");
    }
    if blob.contains("phw") && (blob.contains("upper") || blob.contains("lower")) {
        return Some("phw_action");
    }
    if blob.contains("phm") && (blob.contains("upper") || blob.contains("lower")) {
        return Some("phm_action");
    }
    if blob.contains("upperaction") || blob.contains("loweraction") {
        return Some("upper/lower_action");
    }
    if blob.contains("warhammer") || blob.contains("war_hammer") {
        return Some("warhammer");
    }
    None
}

fn main() {
    let game_dir = Path::new(GAME_DIR);
    let papgt_data = std::fs::read(PAPGT_PATH).expect("read PAPGT");
    let papgt = PackGroupTreeMeta::parse(&papgt_data).expect("parse PAPGT");

    let mut by_category: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for entry in &papgt.entries {
        let group_name = &entry.group_name;
        let pamt_path = game_dir.join(group_name).join("0.pamt");
        let pamt_data = match std::fs::read(&pamt_path) { Ok(d) => d, Err(_) => continue };
        let pamt = match PackMeta::parse(&pamt_data, None) { Ok(p) => p, Err(_) => continue };

        for dir in &pamt.directories {
            for f in &dir.files {
                if let Some(cat) = matches(&f.name, &dir.path) {
                    by_category
                        .entry(cat)
                        .or_default()
                        .push(format!("{}/{}/{}", group_name, dir.path, f.name));
                }
            }
        }
    }

    for (cat, files) in &by_category {
        println!("=== {} ({} files) ===", cat, files.len());
        for f in files.iter().take(50) {
            println!("  {}", f);
        }
        if files.len() > 50 {
            println!("  ... and {} more", files.len() - 50);
        }
        println!();
    }
}
