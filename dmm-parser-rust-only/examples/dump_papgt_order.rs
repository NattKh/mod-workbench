// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Dump the live PAPGT entry order so we can see where dmmsa lands relative
//! to vanilla groups. PAPGT layout (from dmm-parser's papgt.rs): header,
//! then list of (name_offset, lang, optional, crc) entries; names are stored
//! in a trailing string table. The game resolves a virtual path by walking
//! entries front-to-back and returning the first PAMT that contains it,
//! so position 0 = highest priority.

use dmm_parser::binary::papgt::PackGroupTreeMeta;
use std::path::Path;

fn main() {
    let papgt_path = Path::new(
        r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.papgt",
    );
    let data = std::fs::read(papgt_path).unwrap();
    println!("PAPGT size: {} bytes", data.len());

    let papgt = PackGroupTreeMeta::parse(&data).expect("PAPGT parse");
    println!("Entry count: {}", papgt.entries.len());
    println!("\nPAPGT entry order (position 0 = highest priority — game's first-match-wins):");
    for (i, e) in papgt.entries.iter().enumerate() {
        let marker = if e.group_name == "dmmsa" {
            " ← DMM STANDALONE (sublevelinfo + paseq overlay lives here)"
        } else if e.group_name.starts_with("dmm") {
            " ← DMM"
        } else {
            ""
        };
        println!("  [{:2}] name={:10} lang=0x{:04X} optional={} crc=0x{:08X}{}",
                 i, e.group_name, e.entry.language.0, e.entry.is_optional, e.entry.pack_meta_checksum, marker);
    }
}
