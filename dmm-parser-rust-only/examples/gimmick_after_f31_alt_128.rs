// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect bytes after f31_alt_128 for entries that fully saturated.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    let mut blob_lens: Vec<usize> = Vec::new();
    let mut total_bytes = 0usize;
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            f31_alt_128, post_blob, ..
        } = &item.tail {
            if f31_alt_128.is_some() && !post_blob.is_empty() {
                blob_lens.push(post_blob.len());
                total_bytes += post_blob.len();
                if shown < 5 {
                    println!("\nk=0x{:x} blob_len={}", key, post_blob.len());
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
    blob_lens.sort();
    if !blob_lens.is_empty() {
        println!("\nf31_alt_128 saturated entries with post_blob>0:");
        println!("  count: {}", blob_lens.len());
        println!("  total bytes: {}", total_bytes);
        println!("  avg: {}", total_bytes / blob_lens.len());
        println!("  min: {}", blob_lens[0]);
        println!("  median: {}", blob_lens[blob_lens.len()/2]);
        println!("  max: {}", blob_lens[blob_lens.len()-1]);
    }
}
