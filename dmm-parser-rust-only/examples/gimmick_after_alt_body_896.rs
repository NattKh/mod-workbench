// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect bytes for entries that fully chained alt_body to 896.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    let mut sizes: Vec<usize> = Vec::new();
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            alt_body_896, post_blob, ..
        } = &item.tail {
            if alt_body_896.is_some() && !post_blob.is_empty() {
                sizes.push(post_blob.len());
                if shown < 5 {
                    println!("\nk=0x{:x} blob_len={}", key, post_blob.len());
                    let preview = 80.min(post_blob.len());
                    for i in 0..preview {
                        if i % 16 == 0 { print!("  {:04x}: ", i); }
                        print!("{:02x} ", post_blob[i]);
                        if i % 16 == 15 { println!(); }
                    }
                    println!();
                    // Print as ASCII first 80 bytes
                    print!("  ASCII: ");
                    for i in 0..preview {
                        let c = post_blob[i];
                        if c >= 0x20 && c < 0x7f { print!("{}", c as char); }
                        else { print!("."); }
                    }
                    println!();
                    shown += 1;
                }
            }
        }
    }
    sizes.sort();
    if !sizes.is_empty() {
        println!("\n67 entries with alt_body_896 typed and non-empty post_blob:");
        println!("  min: {}", sizes[0]);
        println!("  median: {}", sizes[sizes.len()/2]);
        println!("  max: {}", sizes[sizes.len()-1]);
        println!("  avg: {}", sizes.iter().sum::<usize>() / sizes.len());
    }
}
