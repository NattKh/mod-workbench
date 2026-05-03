// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect the 61 entries with post_blob >= 4096 bytes.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    let mut first_u32_counts: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { post_blob, .. } = &item.tail {
            if post_blob.len() >= 4096 && post_blob.len() >= 4 {
                let count = u32::from_le_bytes(post_blob[..4].try_into().unwrap());
                *first_u32_counts.entry(count).or_insert(0) += 1;
                if shown < 10 {
                    println!("\nk=0x{:x} blob_len={}", key, post_blob.len());
                    println!("  First u32: 0x{:08x}", count);
                    let preview = 80.min(post_blob.len());
                    for i in 0..preview {
                        if i % 16 == 0 { print!("  {:04x}: ", i); }
                        print!("{:02x} ", post_blob[i]);
                        if i % 16 == 15 { println!(); }
                    }
                    println!();
                    // Print as ASCII, last 80 bytes
                    let lstart = if post_blob.len() > 80 { post_blob.len() - 80 } else { 0 };
                    println!("  Tail bytes (last 80, ASCII):");
                    for i in lstart..post_blob.len() {
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
    println!("\nFirst-u32 distribution for 4096+ entries:");
    let mut sorted: Vec<_> = first_u32_counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (val, c) in sorted.iter().take(20) {
        println!("  0x{:08x} ({:>10}): {} entries", val, val, c);
    }
}
