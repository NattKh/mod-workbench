// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Probe the trigger entry size in the gimmick_info post_blob.
//! Each entry is `01 + CString name + ???`. Find the bytes-per-entry.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    // Find specific known long entry
    let target_keys: Vec<u32> = vec![0xf4254, 0xf4f33];
    for (key, start, end) in &ranges {
        if !target_keys.contains(key) { continue; }
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        let post_blob = match &item.tail {
            GimmickTail::Decoded { post_blob, .. } => post_blob,
            _ => continue,
        };
        if post_blob.is_empty() { continue; }
        let blob = post_blob;
        println!("\n=== Entry k=0x{:x} blob_len={} ===", key, blob.len());

        // Parse: u32 count
        if blob.len() < 4 { continue; }
        let count = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
        println!("count = {}", count);

        // For each count: u8 flag + CString
        let mut probe = 4usize;
        for i in 0..count.min(3) {
            if probe + 1 > blob.len() { println!("  Item {}: out of bytes", i); break; }
            let flag = blob[probe];
            probe += 1;
            if probe + 4 > blob.len() { println!("  Item {}: out of bytes for length", i); break; }
            let name_len = u32::from_le_bytes(blob[probe..probe+4].try_into().unwrap()) as usize;
            probe += 4;
            if probe + name_len > blob.len() { println!("  Item {}: out of bytes for name", i); break; }
            let name = &blob[probe..probe+name_len];
            let name_str = std::str::from_utf8(name).unwrap_or("<bad utf8>");
            probe += name_len;
            println!("  Item {}: flag=0x{:02x} name=\"{}\" (len={}) — at offset {}", i, flag, name_str, name_len, probe - 1 - 4 - name_len);
            // Show next 64 bytes
            let preview_end = (probe + 64).min(blob.len());
            print!("    next bytes: ");
            for j in probe..preview_end {
                print!("{:02x} ", blob[j]);
            }
            println!();
        }
    }
}
