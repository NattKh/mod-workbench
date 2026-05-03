// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find vanilla sublevelinfo.pabgb across all numbered groups, report its
//! flags and uncompressed size — if vanilla decomp != dmmsa decomp, the
//! overlay is shorter/longer than the engine expects and reads will land
//! in undefined memory or the engine refuses to load it.

use dmm_parser::binary::pamt::PackMeta;
use std::path::Path;

fn main() {
    let game = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert");
    let mut groups: Vec<String> = std::fs::read_dir(game).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    groups.sort();

    for g in &groups {
        let p = game.join(g).join("0.pamt");
        if !p.exists() { continue; }
        let Ok(data) = std::fs::read(&p) else { continue };
        let Ok(meta) = PackMeta::parse(&data, None) else { continue };
        for d in &meta.directories {
            for f in &d.files {
                if f.name == "sublevelinfo.pabgb" {
                    println!(
                        "GROUP {} | {}/{} | flags=0x{:02x} comp={:?} crypto={:?} | {} bytes ({} compressed)",
                        g, d.path, f.name, f.file.flags, f.file.compression, f.file.crypto,
                        f.file.uncompressed_size, f.file.compressed_size
                    );
                }
            }
        }
    }
}
