// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Search every PAMT in the game install for chart-system XML files
//! (CharacterActionPackageDescription.xml, ActionChart-related .xml files,
//! anything with "Chart" or "ActionPackage" in the name) and extract them
//! to a target directory.
//!
//! Usage:
//!   cargo run --release --example extract_chart_xmls
//!
//! Reads from: C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert
//! Writes to:  C:\Users\corin\Desktop\CD DUMPING TOOLS\Chart-System\xml_dumps\

use dmm_parser::binary::papgt::PackGroupTreeMeta;
use dmm_parser::binary::pamt::PackMeta;
use dmm_parser::binary::paz;
use std::path::{Path, PathBuf};

const GAME_DIR: &str = r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert";
const PAPGT_PATH: &str =
    r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.papgt";
const OUTPUT_DIR: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\Chart-System\xml_dumps";

fn matches_target(file_name: &str, dir_path: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let dlower = dir_path.to_ascii_lowercase();

    // ALL .paatt files in 1_pc (player attack info — small set, extract all)
    if lower.ends_with(".paatt") && (dlower.contains("1_pc") || dlower.contains("/pc/")) {
        return true;
    }
    // ALL .paac files in 1_pc (chart files — larger set)
    if lower.ends_with(".paac") && (dlower.contains("1_pc") || dlower.contains("/pc/")) {
        return true;
    }
    // Pull EVERYTHING under any actionchart-like dir path (XML/json/txt/paacdesc)
    if dlower.contains("actionchart")
        || dlower.contains("actionpackage")
        || dlower.contains("upperaction")
        || dlower.contains("loweraction")
    {
        return lower.ends_with(".xml")
            || lower.ends_with(".json")
            || lower.ends_with(".txt")
            || lower.ends_with(".paacdesc");
    }
    // Match by filename patterns anywhere
    if lower.contains("characteractionpackage")
        || lower.contains("commonaction")
        || lower.contains("hitmaterial")
        || (lower.ends_with(".xml") && (lower.contains("chart") || lower.contains("actionpackage")))
    {
        return true;
    }
    false
}

fn main() {
    let game_dir = Path::new(GAME_DIR);
    let papgt_data = std::fs::read(PAPGT_PATH).expect("read PAPGT");
    let papgt = PackGroupTreeMeta::parse(&papgt_data).expect("parse PAPGT");
    println!("PAPGT: {} groups", papgt.entries.len());

    let output_root = PathBuf::from(OUTPUT_DIR);
    std::fs::create_dir_all(&output_root).expect("create output dir");

    let mut total_files = 0usize;
    let mut total_matches = 0usize;
    let mut total_extracted = 0usize;
    let mut total_failed = 0usize;

    for (gi, entry) in papgt.entries.iter().enumerate() {
        let group_name = &entry.group_name;
        let group_dir = game_dir.join(group_name);
        let pamt_path = group_dir.join("0.pamt");

        let pamt_data = match std::fs::read(&pamt_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[{:2}/{}] {}: skip (no PAMT: {})",
                    gi + 1, papgt.entries.len(), group_name, e);
                continue;
            }
        };
        let pamt = match PackMeta::parse(&pamt_data, None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{:2}/{}] {}: PAMT parse error: {}",
                    gi + 1, papgt.entries.len(), group_name, e);
                continue;
            }
        };

        let encrypt_info = pamt.header.encrypt_info.encrypt_info;
        let mut group_matches = 0usize;
        for dir in &pamt.directories {
            for f in &dir.files {
                total_files += 1;
                if !matches_target(&f.name, &dir.path) {
                    continue;
                }
                total_matches += 1;
                group_matches += 1;
                println!("  match: {}/{}/{}", group_name, dir.path, f.name);

                // Build output path: <output>/<group_name>/<dir_path>/<file_name>
                let safe_dir = dir.path.replace(":", "_").replace("\\", "/");
                let out_path = output_root.join(group_name).join(&safe_dir).join(&f.name);
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }

                match paz::extract_file(&group_dir, f, &dir.path, &encrypt_info) {
                    Ok(bytes) => {
                        match std::fs::write(&out_path, &bytes) {
                            Ok(_) => {
                                total_extracted += 1;
                                println!("    -> {} ({} bytes)", out_path.display(), bytes.len());
                            }
                            Err(e) => {
                                total_failed += 1;
                                eprintln!("    -> WRITE FAILED: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        total_failed += 1;
                        eprintln!("    -> EXTRACT FAILED: {}", e);
                    }
                }
            }
        }
        if group_matches > 0 {
            println!("[{:2}/{}] {}: {} matches",
                gi + 1, papgt.entries.len(), group_name, group_matches);
        }
    }

    println!("\n=== Summary ===");
    println!("Files scanned: {}", total_files);
    println!("Matches:       {}", total_matches);
    println!("Extracted:     {}", total_extracted);
    println!("Failed:        {}", total_failed);
    println!("Output:        {}", OUTPUT_DIR);
}
