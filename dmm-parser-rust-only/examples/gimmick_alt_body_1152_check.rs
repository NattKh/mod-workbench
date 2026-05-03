// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check alt_body saturation at 1152.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut alt_body_896 = 0;
    let mut alt_body_1152 = 0;
    let mut alt_body_1152_with_residual = 0;
    let mut alt_body_1152_residual_bytes = 0usize;
    let mut residual_sizes: Vec<usize> = Vec::new();
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            alt_body_896: a896, alt_body_1152: a1152, post_blob, ..
        } = &item.tail {
            if a896.is_some() { alt_body_896 += 1; }
            if a1152.is_some() {
                alt_body_1152 += 1;
                if !post_blob.is_empty() {
                    alt_body_1152_with_residual += 1;
                    alt_body_1152_residual_bytes += post_blob.len();
                    residual_sizes.push(post_blob.len());
                }
            }
        }
    }
    residual_sizes.sort();
    println!("alt_body chain after extension to 1152:");
    println!("  alt_body_896 typed: {}", alt_body_896);
    println!("  alt_body_1152 typed (full): {}", alt_body_1152);
    println!("  alt_body_1152 with non-empty post_blob: {} ({} bytes)", alt_body_1152_with_residual, alt_body_1152_residual_bytes);
    if !residual_sizes.is_empty() {
        println!("  min: {}", residual_sizes[0]);
        println!("  median: {}", residual_sizes[residual_sizes.len()/2]);
        println!("  max: {}", residual_sizes[residual_sizes.len()-1]);
        println!("  avg: {}", alt_body_1152_residual_bytes / residual_sizes.len());
    }
}
