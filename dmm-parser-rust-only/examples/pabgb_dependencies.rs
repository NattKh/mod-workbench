// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Walk vanilla PAMTs and report:
//! 1. All extensions that appear in `gamedata/binary__/client/bin/` (where pabgb lives)
//! 2. For every .pabgb stem, what other extensions share the same stem (sister files)
//! 3. Total counts of each pabgb-related extension across all groups

use dmm_parser::binary::pamt::PackMeta;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

fn main() {
    let game = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert");
    let mut groups: Vec<String> = std::fs::read_dir(game).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    groups.sort();

    // (1) Extensions in the pabgb directory
    let mut bin_dir_exts: BTreeMap<String, usize> = BTreeMap::new();
    // (2) Sister extensions per pabgb stem
    let _pabgb_stems: HashMap<String, HashSet<String>> = HashMap::new();
    // Collect every <stem, extension, group, dir> tuple, then group by stem
    let mut stems_to_files: HashMap<String, Vec<(String, String, String)>> = HashMap::new();

    for g in &groups {
        let p = game.join(g).join("0.pamt");
        if !p.exists() { continue; }
        let Ok(data) = std::fs::read(&p) else { continue };
        let Ok(meta) = PackMeta::parse(&data, None) else { continue };
        for d in &meta.directories {
            for f in &d.files {
                if d.path.starts_with("gamedata/binary__/client/bin") {
                    let ext = f.name.rsplit('.').next().unwrap_or("").to_string();
                    *bin_dir_exts.entry(ext).or_insert(0) += 1;
                }
                // Track stems that have a .pabgb companion
                let last_dot = f.name.rfind('.');
                if let Some(idx) = last_dot {
                    let stem = &f.name[..idx];
                    let ext = &f.name[idx + 1..];
                    stems_to_files.entry(stem.to_string()).or_default()
                        .push((ext.to_string(), g.clone(), d.path.clone()));
                }
            }
        }
    }

    println!("=== Extensions in gamedata/binary__/client/bin/ (pabgb home) ===");
    for (ext, count) in &bin_dir_exts {
        println!("  .{}: {} files", ext, count);
    }

    // For every stem with a .pabgb companion, list ALL extensions with that stem
    println!("\n=== Sister-extension count for .pabgb stems ===");
    let mut sister_ext_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut stems_with_pabgb = 0usize;
    for (_stem, files) in &stems_to_files {
        let has_pabgb = files.iter().any(|(e, _, _)| e == "pabgb");
        if !has_pabgb { continue; }
        stems_with_pabgb += 1;
        for (ext, _, _) in files {
            *sister_ext_counts.entry(ext.clone()).or_insert(0) += 1;
        }
    }
    println!("Total stems that have a .pabgb file: {}", stems_with_pabgb);
    println!("Of those, how many also have a sibling with extension X (same stem):");
    for (ext, count) in &sister_ext_counts {
        if ext == "pabgb" { continue; }
        let pct = (*count as f64 / stems_with_pabgb as f64) * 100.0;
        println!("  .{:12} {}/{} ({:>5.1}%)", ext, count, stems_with_pabgb, pct);
    }

    // Sample of pabgb-stem sister sets
    println!("\n=== Sample stems and their full sister sets ===");
    let mut samples: Vec<(&String, &Vec<(String, String, String)>)> = stems_to_files.iter()
        .filter(|(_, files)| files.iter().any(|(e, _, _)| e == "pabgb"))
        .collect();
    samples.sort_by_key(|(s, _)| s.to_string());
    for (stem, files) in samples.iter().take(20) {
        let mut exts: Vec<String> = files.iter().map(|(e, _, _)| e.clone()).collect();
        exts.sort();
        exts.dedup();
        println!("  {} → {:?}", stem, exts);
    }
}
