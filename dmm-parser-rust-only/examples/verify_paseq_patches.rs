// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Pull cd_seq_funcnpc_airship.paseq from dmmsa overlay, decompress, and
//! check if NPC_Instant's 5 patches actually landed at the declared offsets.
//! Prints PATCHED / VANILLA / UNEXPECTED for each site.

use dmm_parser::binary::pamt::{Compression, PackMeta};
use lz4_flex::block::decompress;
use std::path::Path;

const PATCHES: &[(usize, &str, u32, u32)] = &[
    (26861, "starting -> 1",        0x00000707, 0x00000001),
    (27103, "mid00 -> 1801",        0x00001517, 0x00000709),
    (27353, "mid01 -> 5401",        0x0000D097, 0x00001519),
    (27583, "mid02 -> 53401",       0x000124F7, 0x0000D099),
    (27821, "mid03 -> 74999",       0x00016B47, 0x000124F9),
];

fn main() {
    let dmmsa = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\dmmsa");
    let pamt = std::fs::read(dmmsa.join("0.pamt")).unwrap();
    let paz = std::fs::read(dmmsa.join("0.paz")).unwrap();
    let meta = PackMeta::parse(&pamt, None).unwrap();

    let mut info: Option<(u32, u32, u32, Compression)> = None;
    for d in &meta.directories {
        for f in &d.files {
            if f.name == "cd_seq_funcnpc_airship.paseq" {
                println!("dmmsa overlay: {}/{}", d.path, f.name);
                println!(
                    "  chunk_offset={}, comp={}, decomp={}, compression={:?}, flags=0x{:02x}",
                    f.file.chunk_offset, f.file.compressed_size,
                    f.file.uncompressed_size, f.file.compression, f.file.flags
                );
                info = Some((
                    f.file.chunk_offset, f.file.compressed_size,
                    f.file.uncompressed_size, f.file.compression,
                ));
            }
        }
    }
    let (off, comp, decomp, compression) = info.expect("paseq not in dmmsa");
    let comp_bytes = &paz[off as usize .. off as usize + comp as usize];
    let body = match compression {
        Compression::Lz4 => decompress(comp_bytes, decomp as usize).expect("lz4"),
        Compression::None => comp_bytes.to_vec(),
        other => panic!("unexpected compression {:?}", other),
    };
    println!("Decompressed body: {} bytes\n", body.len());

    let mut applied = 0;
    let mut vanilla_unchanged = 0;
    let mut unexpected = 0;
    for (off, label, orig, patched) in PATCHES {
        let actual = u32::from_le_bytes(body[*off..off + 4].try_into().unwrap());
        let status = if actual == *patched {
            applied += 1;
            "PATCHED"
        } else if actual == *orig {
            vanilla_unchanged += 1;
            "VANILLA (patch didn't apply!)"
        } else {
            unexpected += 1;
            "UNEXPECTED"
        };
        println!("  0x{:04X} ({:>5}) {:32}: actual=0x{:08X} expected_patched=0x{:08X} [{}]",
            off, off, label, actual, patched, status);
    }

    println!("\n=== Summary ===");
    println!("Applied:           {} / {}", applied, PATCHES.len());
    println!("Vanilla unchanged: {} / {}", vanilla_unchanged, PATCHES.len());
    println!("Unexpected:        {} / {}", unexpected, PATCHES.len());
}
