// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many quest_info entries fall back to Raw on the
//! _questDialogFilterDataList field.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::quest_info::info::{QuestInfo, QuestDialogFilterDataList};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgh";

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
    let mut total_decoded = 0usize;
    let mut total_failed_to_parse = 0usize;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match QuestInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => { total_failed_to_parse += 1; continue; }
        };
        total_decoded += 1;
        match &item.quest_dialog_filter_data_list {
            QuestDialogFilterDataList::Decoded(_) => decoded += 1,
            QuestDialogFilterDataList::Raw(b) => { raw += 1; raw_sizes.push(b.len()); }
        }
    }
    println!("Total entries:      {}", ranges.len());
    println!("Failed top parse:   {}", total_failed_to_parse);
    println!("Quest parsed:       {}", total_decoded);
    println!("  Filter Decoded:   {}", decoded);
    println!("  Filter Raw:       {}", raw);
    if !raw_sizes.is_empty() {
        raw_sizes.sort();
        let total: usize = raw_sizes.iter().sum();
        println!("  Raw size: min={}, p50={}, max={}, total={}",
            raw_sizes[0], raw_sizes[raw_sizes.len()/2], raw_sizes[raw_sizes.len()-1], total);
    }
}
