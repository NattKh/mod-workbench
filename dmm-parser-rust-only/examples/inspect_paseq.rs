// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Pull cd_seq_funcnpc_airship.paseq from vanilla group 0014, decompress,
//! and dump the bytes around NPC_Instant's patch offsets so we can see what
//! structure the mod is targeting. Each patched site's label tells us what
//! the bytes represent (animation frame counts), so the dump + label =
//! enough to start naming a paseq schema.

use dmm_parser::binary::pamt::{Compression, PackMeta};
use lz4_flex::block::decompress;
use std::path::Path;

// Patch offsets from NPC_Instant.json for cd_seq_funcnpc_airship.paseq.
// (offset, label, original_le, patched_le).
const PATCHES: &[(usize, &str, u32, u32)] = &[
    (26861, "starting animations 1799 -> 1",   0x00000707, 0x00000001),
    (27103, "mid00 animations 3599 -> 1",      0x00001517, 0x00000709),
    (27353, "mid01 animations 47999 -> 1",     0x0000D097, 0x00001519),
    (27583, "mid02 animations 21599 -> 1",     0x000124F7, 0x0000D099),
    (27821, "mid03 animations 17999 -> 1",     0x00016B47, 0x000124F9),
];

fn main() {
    let game = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert");
    let group_dir = game.join("0014");
    let pamt_data = std::fs::read(group_dir.join("0.pamt")).unwrap();
    let paz_data = std::fs::read(group_dir.join("0.paz")).unwrap();
    let meta = PackMeta::parse(&pamt_data, None).unwrap();

    let mut hit: Option<(&str, u32, u32, u32, Compression)> = None;
    for d in &meta.directories {
        for f in &d.files {
            if f.name == "cd_seq_funcnpc_airship.paseq" {
                hit = Some((
                    "found",
                    f.file.chunk_offset,
                    f.file.compressed_size,
                    f.file.uncompressed_size,
                    f.file.compression,
                ));
                println!("Vanilla {}/{}", d.path, f.name);
                println!("  chunk_offset={}, comp={}, decomp={}, compression={:?}",
                    f.file.chunk_offset, f.file.compressed_size, f.file.uncompressed_size, f.file.compression);
            }
        }
    }
    let (_, off, comp, decomp, compression) = hit.expect("paseq not found");

    let comp_bytes = &paz_data[off as usize .. off as usize + comp as usize];
    let body = match compression {
        Compression::Lz4 => decompress(comp_bytes, decomp as usize).expect("lz4"),
        Compression::None => comp_bytes.to_vec(),
        other => panic!("unexpected compression {:?}", other),
    };
    println!("Decompressed body: {} bytes\n", body.len());

    // Header dump: first 64 bytes
    println!("=== Header (first 64 bytes) ===");
    for chunk in body[..64].chunks(16) {
        for b in chunk { print!("{:02X} ", b); }
        print!(" ");
        for b in chunk {
            print!("{}", if b.is_ascii_graphic() { *b as char } else { '.' });
        }
        println!();
    }
    println!();

    // Walk patch sites. Show 32 bytes around each, mark the patch column.
    for (off, label, orig, _patched) in PATCHES {
        println!("=== Offset 0x{:04X} ({}) — {} ===", off, off, label);
        let win_start = off.saturating_sub(20);
        let win_end = (off + 24).min(body.len());
        // Confirm the original u32 at the offset
        let actual = u32::from_le_bytes(body[*off..off + 4].try_into().unwrap());
        let match_marker = if actual == *orig { "MATCHES" } else { "MISMATCH" };
        println!("  expected u32_le=0x{:08X} ({}), actual=0x{:08X} ({}) [{}]",
            orig, orig, actual, actual, match_marker);
        // Hex dump
        for (i, b) in body[win_start..win_end].iter().enumerate() {
            let abs = win_start + i;
            if abs == *off { print!("["); }
            print!("{:02X}", b);
            if abs == off + 3 { print!("]"); }
            print!(" ");
        }
        println!();
        // Try to read string-typed fields nearby — look back for a u32 length prefix
        // that matches a plausible cstring length (1..64) followed by ASCII bytes.
        for back in 4..=128 {
            if *off < back { break; }
            let len_off = off - back;
            if len_off + 4 > body.len() { continue; }
            let plen = u32::from_le_bytes(body[len_off..len_off + 4].try_into().unwrap());
            if plen >= 1 && plen <= 64 && len_off + 4 + plen as usize <= body.len() {
                let slice = &body[len_off + 4..len_off + 4 + plen as usize];
                if slice.iter().all(|&b| (b == 0) || b.is_ascii_graphic() || b == b'_' || b == b'.') {
                    let s = String::from_utf8_lossy(slice);
                    println!("  cstring at 0x{:04X} (back {}): len={} \"{}\"", len_off, back, plen, s.trim_end_matches('\0'));
                    break;
                }
            }
        }
        println!();
    }

    // Magic / format guess
    let magic_bytes = &body[..4];
    let magic_str = String::from_utf8_lossy(magic_bytes);
    println!("=== Format guess ===");
    println!("First 4 bytes: {:?} ({})", magic_bytes, magic_str);
    println!("First 4 bytes as u32 LE: 0x{:08X} = {}",
        u32::from_le_bytes(magic_bytes.try_into().unwrap()),
        u32::from_le_bytes(magic_bytes.try_into().unwrap()));
    let _ = compression;
    let _ = comp;
    let _ = decomp;
}
