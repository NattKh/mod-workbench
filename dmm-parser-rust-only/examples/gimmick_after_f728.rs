// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect bytes after field_728 for entries that fully populated through 728.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    let mut counts: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            field_728_u32, post_blob, ..
        } = &item.tail {
            if field_728_u32.is_some() && !post_blob.is_empty() {
                if post_blob.len() >= 4 {
                    let count = u32::from_le_bytes(post_blob[..4].try_into().unwrap());
                    *counts.entry(count).or_insert(0) += 1;
                    if shown < 10 {
                        println!("\nk=0x{:x} blob_len={}", key, post_blob.len());
                        println!("  First u32: 0x{:08x} = {}", count, count);
                        let preview = 64.min(post_blob.len());
                        for i in 0..preview {
                            if i % 16 == 0 { print!("  {:04x}: ", i); }
                            print!("{:02x} ", post_blob[i]);
                            if i % 16 == 15 { println!(); }
                        }
                        println!();
                        shown += 1;
                    }
                }
            }
        }
    }
    println!("\nFirst-u32 distribution at field_728+ failure point:");
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (val, c) in sorted.iter().take(20) {
        println!("  0x{:08x} ({:>10}): {} entries", val, val, c);
    }
}
