// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Quick count of condition_info Raw vs Decoded.
//! Looks for ConditionData::Raw fallback in the inner condition_data field.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::condition_info::info::ConditionInfo;

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\conditioninfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\conditioninfo.pabgh";

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
    let mut top_parse_fail = 0usize;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        match ConditionInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(_) => decoded += 1,
            Err(_) => { top_parse_fail += 1; raw += 1; }
        }
    }
    println!("Total entries:     {}", ranges.len());
    println!("Top-level parsed:  {}", decoded);
    println!("Top-level failed:  {}", top_parse_fail);
}
