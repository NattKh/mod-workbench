// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! List all unique directory paths across all PAMT files that contain
//! action / chart / character related keywords. Helps locate where the
//! actual chart resource files (referenced by FileName= in the XML) live.

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

    // group_name -> dir_path -> file_count
    let mut chart_dirs: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut total_dirs = 0usize;

    for entry in &papgt.entries {
        let group_name = &entry.group_name;
        let pamt_path = game_dir.join(group_name).join("0.pamt");
        let pamt_data = match std::fs::read(&pamt_path) { Ok(d) => d, Err(_) => continue };
        let pamt = match PackMeta::parse(&pamt_data, None) { Ok(p) => p, Err(_) => continue };

        for dir in &pamt.directories {
            total_dirs += 1;
            let dlower = dir.path.to_ascii_lowercase();
            let interesting = dlower.contains("action")
                || dlower.contains("chart")
                || dlower.contains("character")
                || dlower.contains("upper")
                || dlower.contains("lower")
                || dlower.contains("damian")
                || dlower.contains("kliff")
                || dlower.contains("longsword")
                || dlower.contains("hammer")
                || dlower.contains("weapon");
            if interesting {
                chart_dirs
                    .entry(group_name.clone())
                    .or_default()
                    .insert(dir.path.clone(), dir.files.len());
            }
        }
    }

    println!("Scanned {} total directories across {} groups", total_dirs, papgt.entries.len());
    println!("Chart/action-related directories:\n");

    for (group, dirs) in &chart_dirs {
        println!("=== Group: {} ({} dirs) ===", group, dirs.len());
        for (path, count) in dirs {
            println!("  [{:5} files] {}", count, path);
        }
        println!();
    }
}
