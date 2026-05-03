// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many entries still type past alt_body_576.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut alt576 = 0usize;
    let mut max_blob = 0usize;
    let mut total_blob = 0usize;
    let mut entries_with_data: Vec<usize> = vec![];
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { alt_body_576, post_blob, .. } = &item.tail {
            if alt_body_576.is_some() { alt576 += 1; }
            if !post_blob.is_empty() {
                total_blob += post_blob.len();
                if post_blob.len() > max_blob { max_blob = post_blob.len(); }
                entries_with_data.push(post_blob.len());
            }
        }
    }
    println!("Entries typed past alt_body_576: {}", alt576);
    println!("Total post_blob bytes:           {}", total_blob);
    println!("Max remaining:                   {}", max_blob);
    println!("Entries with data:               {}", entries_with_data.len());
    if alt576 > 0 {
        println!("Per-batch savings projection:    {} entries × 256 bytes = {} bytes",
                 alt576, alt576 * 256);
    }
}
