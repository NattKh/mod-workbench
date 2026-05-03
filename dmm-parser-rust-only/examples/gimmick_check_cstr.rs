// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many entries successfully captured alt_post_cstr_a.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut typed_a = 0usize;
    let mut typed_b = 0usize;
    let mut total_saved = 0usize;
    let mut samples: Vec<String> = vec![];
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { alt_post_cstr_a, alt_post_cstr_b, .. } = &item.tail {
            if let Some(s) = alt_post_cstr_a {
                typed_a += 1;
                total_saved += 4 + s.data.as_bytes().len();
                if samples.len() < 5 {
                    samples.push(s.data.to_string());
                }
            }
            if alt_post_cstr_b.is_some() { typed_b += 1; }
        }
    }
    println!("Entries with alt_post_cstr_a: {}", typed_a);
    println!("Entries with alt_post_cstr_b: {}", typed_b);
    println!("Total bytes saved by cstr_a:  {}", total_saved);
    println!("Samples:");
    for s in &samples {
        let preview = if s.len() > 80 { &s[..80] } else { s };
        println!("  \"{}\"", preview);
    }
}
