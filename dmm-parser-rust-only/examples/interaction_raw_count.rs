// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many interaction_info entries fall back to Raw vs Decoded.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::interaction_info::info::{InteractionInfo, InteractionTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\interactioninfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\interactioninfo.pabgh";

fn main() {
    let data = match std::fs::read(PABGB) {
        Ok(d) => d,
        Err(e) => { println!("Cannot open PABGB: {}", e); return; }
    };
    let entries = match load_pabgh_offsets(PABGH) {
        Some(e) => e,
        None => { println!("Cannot open PABGH"); return; }
    };
    let ranges = entry_ranges(&entries, data.len());
    let mut decoded = 0usize;
    let mut raw = 0usize;
    let mut raw_sizes: Vec<usize> = vec![];
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match InteractionInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        match &item.tail {
            InteractionTail::Decoded(_) => decoded += 1,
            InteractionTail::Raw(b) => { raw += 1; raw_sizes.push(b.len()); }
        }
    }
    println!("Total entries: {}", ranges.len());
    println!("Decoded:       {}", decoded);
    println!("Raw:           {}", raw);
    if !raw_sizes.is_empty() {
        raw_sizes.sort();
        println!("Raw sizes: min={}, p50={}, max={}",
            raw_sizes[0], raw_sizes[raw_sizes.len()/2], raw_sizes[raw_sizes.len()-1]);
    }
}
