// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Read dmmsa/0.paz, find sublevelinfo.pabgb (the first LZ4-compressed file
//! per the mount log), decompress, and check if Religion_Hernand's max_level
//! field actually got patched from 100 (0x64000000) to 500 (0xf4010000).
//!
//! The mount log says:
//!   sublevelinfo.pabgb: offset=0, comp=2840, decomp=8693, flags=0x0002
//!   Religion_Hernand + rel_offset 5 -> absolute 0x2068
//!
//! So the LZ4 body lives at PAZ bytes 0..2840 and decompresses to 8693 bytes.
//! At decompressed offset 0x2068 we expect f4 01 00 00 if the patch landed.

use lz4_flex::block::decompress;
use std::path::Path;

fn main() {
    let paz_path = Path::new(
        r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\dmmsa\0.paz",
    );
    let raw = std::fs::read(paz_path).unwrap();
    println!("PAZ total: {} bytes", raw.len());

    let comp_bytes = &raw[0..2840];
    let body = decompress(comp_bytes, 8693).expect("LZ4 decompress");
    println!("Decompressed body: {} bytes (expected 8693)", body.len());

    // Mount log resolved Religion_Hernand + rel_offset 5 -> 0x2068
    let target = 0x2068usize;
    let win_start = target.saturating_sub(40);
    let win_end = (target + 16).min(body.len());
    let window = &body[win_start..win_end];
    print!("body[0x{:04X}..0x{:04X}]: ", win_start, win_end);
    for (i, b) in window.iter().enumerate() {
        if win_start + i == target {
            print!("[");
        }
        print!("{:02X} ", b);
        if win_start + i == target + 3 {
            print!("] ");
        }
    }
    println!();

    let patched = &body[target..target + 4];
    let patched_hex: String = patched.iter().map(|b| format!("{:02X}", b)).collect();
    println!("body[0x{:04X}..+4] = {}", target, patched_hex);

    let value_le = u32::from_le_bytes([patched[0], patched[1], patched[2], patched[3]]);
    println!("As u32 LE: {} (0x{:08X})", value_le, value_le);

    if patched == [0xF4, 0x01, 0x00, 0x00] {
        println!("RESULT: PATCH APPLIED — value is 500 (0x000001F4 LE)");
    } else if patched == [0x64, 0x00, 0x00, 0x00] {
        println!("RESULT: VANILLA — value is 100 (0x00000064 LE), patch NOT applied");
    } else {
        println!("RESULT: UNEXPECTED bytes — neither vanilla nor patched");
    }

    // Walk back from 0x2068 to find Religion_Hernand cstring as a sanity check.
    let needle = b"Religion_Hernand";
    let mut found_at: Option<usize> = None;
    for s in 0..body.len().saturating_sub(needle.len()) {
        if &body[s..s + needle.len()] == needle {
            found_at = Some(s);
            break;
        }
    }
    match found_at {
        Some(s) => {
            println!("\n'Religion_Hernand' found at body offset 0x{:04X}", s);
            // Record layout: u32 key | u32 cstring_len | cstring bytes | u8 is_blocked | u32 min | u32 max | [u8;28] exp
            // cstring starts at s. cstring_len lives at s-4. record key at s-8.
            let rec_start = s - 8;
            let key = u32::from_le_bytes(body[rec_start..rec_start + 4].try_into().unwrap());
            let len = u32::from_le_bytes(body[rec_start + 4..rec_start + 8].try_into().unwrap());
            let data_start = rec_start + 8 + len as usize;
            let is_blocked = body[data_start];
            let min_lvl = u32::from_le_bytes(body[data_start + 1..data_start + 5].try_into().unwrap());
            let max_lvl = u32::from_le_bytes(body[data_start + 5..data_start + 9].try_into().unwrap());
            println!("  record_start=0x{:04X}, key={}, cstring_len={}, data_start=0x{:04X}",
                     rec_start, key, len, data_start);
            println!("  is_blocked={}, min_level={}, max_level={}", is_blocked, min_lvl, max_lvl);
            println!("  data_start + rel_offset 5 = 0x{:04X} (mount log said 0x2068, match={})",
                     data_start + 5,
                     data_start + 5 == 0x2068);
        }
        None => println!("\n'Religion_Hernand' NOT FOUND in decompressed body"),
    }
}
