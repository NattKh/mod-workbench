// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Scan vanilla PAMTs for the cd_phm_02_sword_0036 family. Reports
//! which group, virtual path, file size, and encoding flags.

use dmm_parser::binary::pamt::PackMeta;
use std::path::Path;

const PACKAGES: &str =
    r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert";

const NEEDLES: &[&str] = &[
    "cd_phm_02_sword_0036",
    "cd_phm_01_sword_0107",
];

fn main() {
    let packages_dir = Path::new(PACKAGES);
    let Ok(rd) = std::fs::read_dir(packages_dir) else {
        eprintln!("Can't read packages dir");
        return;
    };
    let mut groups: Vec<String> = rd.filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    groups.sort();

    for g in &groups {
        let pamt_path = packages_dir.join(g).join("0.pamt");
        if !pamt_path.exists() { continue; }
        let Ok(data) = std::fs::read(&pamt_path) else { continue };
        let meta = match PackMeta::parse(&data, None) {
            Ok(m) => m,
            Err(e) => { eprintln!("group {}: parse error: {}", g, e); continue }
        };

        for dir in &meta.directories {
            for f in &dir.files {
                let full = format!("{}/{}", dir.path, f.name);
                for needle in NEEDLES {
                    if full.contains(needle) {
                        println!(
                            "GROUP {} | {} | flags=0x{:02x} comp={:?} crypto={:?} partial={} | {} bytes ({} compressed)",
                            g, full, f.file.flags, f.file.compression, f.file.crypto, f.file.is_partial,
                            f.file.uncompressed_size, f.file.compressed_size
                        );
                    }
                }
            }
        }
    }
}
