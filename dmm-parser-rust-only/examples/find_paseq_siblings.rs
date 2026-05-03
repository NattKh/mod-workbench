// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Look for any sibling file of cd_seq_funcnpc_airship.paseq inside vanilla.
//! .paseqh / .paseqc / .seqc / anything sharing the stem. Across all vanilla
//! groups. If one exists per-paseq, the game might require it shipped in the
//! same overlay group as the .paseq we patched.

use dmm_parser::binary::pamt::PackMeta;
use std::path::Path;

const STEM: &str = "cd_seq_funcnpc_airship";

fn main() {
    let game = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert");
    let mut groups: Vec<String> = std::fs::read_dir(game).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    groups.sort();

    let mut hits = 0usize;
    for g in &groups {
        let p = game.join(g).join("0.pamt");
        if !p.exists() { continue; }
        let Ok(data) = std::fs::read(&p) else { continue };
        let Ok(meta) = PackMeta::parse(&data, None) else { continue };
        for d in &meta.directories {
            for f in &d.files {
                if f.name.contains(STEM) {
                    println!(
                        "GROUP {} | {}/{} | flags=0x{:02x} | {} bytes ({} compressed)",
                        g, d.path, f.name, f.file.flags,
                        f.file.uncompressed_size, f.file.compressed_size
                    );
                    hits += 1;
                }
            }
        }
    }
    println!("\n{} files match stem '{}' across all vanilla groups", hits, STEM);

    // Also dump anything in sequencer/binary__/ root to see what file types
    // live there (paseqh/paseqc may be flat-listed alongside paseq).
    println!("\n=== Top-level files in sequencer/binary__/ across all vanilla groups ===");
    let mut top_level_kinds = std::collections::BTreeMap::<String, usize>::new();
    for g in &groups {
        let p = game.join(g).join("0.pamt");
        if !p.exists() { continue; }
        let Ok(data) = std::fs::read(&p) else { continue };
        let Ok(meta) = PackMeta::parse(&data, None) else { continue };
        for d in &meta.directories {
            if d.path.starts_with("sequencer/binary__") {
                for f in &d.files {
                    let ext = f.name.rsplit('.').next().unwrap_or("?").to_string();
                    *top_level_kinds.entry(ext).or_insert(0) += 1;
                }
            }
        }
    }
    for (ext, count) in &top_level_kinds {
        println!("  .{}: {} files", ext, count);
    }
}
