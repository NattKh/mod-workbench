// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect the 6 entries that fall back to GimmickTail::Raw (top-level prefix fail).

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Raw(blob) = &item.tail {
            shown += 1;
            let entry_size = end - start;
            let blob_offset = entry_size - blob.len();
            println!("\n[{}] k=0x{:x} start=0x{:x} end=0x{:x} entry_size={} blob_offset={} blob_len={}",
                shown, key, start, end, entry_size, blob_offset, blob.len());

            let preview = 80.min(blob.len());
            println!("  First {} bytes of Raw blob:", preview);
            for i in 0..preview {
                if i % 16 == 0 { print!("    {:04x}: ", i); }
                print!("{:02x} ", blob[i]);
                if i % 16 == 15 { println!(); }
            }
            println!();
            // Last 32 bytes
            let lstart = if blob.len() > 32 { blob.len() - 32 } else { 0 };
            println!("  Last {} bytes:", blob.len() - lstart);
            for i in lstart..blob.len() {
                if (i - lstart) % 16 == 0 { print!("    {:04x}: ", i); }
                print!("{:02x} ", blob[i]);
                if (i - lstart) % 16 == 15 { println!(); }
            }
            println!();
        }
    }
    println!("\nTotal Raw entries: {}", shown);
}
