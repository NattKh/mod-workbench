// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find all chart resource files (paatt, paac, etc.) in the 1_pc/ tree
//! to locate per-character action data.

use dmm_parser::binary::papgt::PackGroupTreeMeta;
use dmm_parser::binary::pamt::PackMeta;
use std::collections::BTreeMap;
use std::path::Path;

const GAME_DIR: &str = r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert";
const PAPGT_PATH: &str =
    r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.papgt";

fn main() {
    let game_dir = Path::new(GAME_DIR);
    let papgt_data = std::fs::read(PAPGT_PATH).expect("read PAPGT");
    let papgt = PackGroupTreeMeta::parse(&papgt_data).expect("parse PAPGT");

    // Track files by interesting category
    let mut paatt_pc: Vec<String> = vec![];
    let mut paatt_other: BTreeMap<String, usize> = BTreeMap::new();
    let mut paac_files: Vec<String> = vec![];
    let mut chart_resource_dirs: BTreeMap<String, usize> = BTreeMap::new();
    let mut all_extensions: BTreeMap<String, usize> = BTreeMap::new();

    for entry in &papgt.entries {
        let group_name = &entry.group_name;
        let pamt_path = game_dir.join(group_name).join("0.pamt");
        let pamt_data = match std::fs::read(&pamt_path) { Ok(d) => d, Err(_) => continue };
        let pamt = match PackMeta::parse(&pamt_data, None) { Ok(p) => p, Err(_) => continue };

        for dir in &pamt.directories {
            let dlower = dir.path.to_ascii_lowercase();
            for f in &dir.files {
                let lower = f.name.to_ascii_lowercase();

                // Track all unique extensions in actionchart paths
                if dlower.contains("actionchart") {
                    if let Some(dot) = lower.rfind('.') {
                        *all_extensions.entry(lower[dot..].to_string()).or_insert(0) += 1;
                    }
                }

                // .paatt files
                if lower.ends_with(".paatt") {
                    let full = format!("{}/{}/{}", group_name, dir.path, f.name);
                    if dlower.contains("1_pc") || dlower.contains("/pc/") {
                        paatt_pc.push(full);
                    } else {
                        // Just count by class subpath
                        let key = if let Some(class_idx) = dlower.rfind('/') {
                            dir.path[..class_idx].to_string()
                        } else {
                            dir.path.clone()
                        };
                        *paatt_other.entry(key).or_insert(0) += 1;
                    }
                }

                // .paac files (chart files themselves?)
                if lower.ends_with(".paac") || lower.ends_with(".paacb") || lower.ends_with(".paacd") {
                    paac_files.push(format!("{}/{}/{}", group_name, dir.path, f.name));
                }

                // Track all chart-resource directories
                if dlower.contains("actionchart") || dlower.contains("upperaction") || dlower.contains("loweraction") {
                    *chart_resource_dirs.entry(dir.path.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    println!("=== File extensions inside actionchart paths ===");
    for (ext, count) in &all_extensions {
        println!("  [{:6}] {}", count, ext);
    }

    println!("\n=== .paatt files in 1_pc/ ({} total) ===", paatt_pc.len());
    for f in paatt_pc.iter().take(50) {
        println!("  {}", f);
    }
    if paatt_pc.len() > 50 {
        println!("  ... and {} more", paatt_pc.len() - 50);
    }

    println!("\n=== .paatt files NOT in 1_pc, by parent dir ===");
    for (k, v) in paatt_other.iter().take(20) {
        println!("  [{:5}] {}", v, k);
    }

    println!("\n=== .paac/paacb/paacd files ({}) ===", paac_files.len());
    for f in paac_files.iter().take(20) {
        println!("  {}", f);
    }

    println!("\n=== Chart-resource directories ===");
    for (path, count) in &chart_resource_dirs {
        println!("  [{:5}] {}", count, path);
    }
}
