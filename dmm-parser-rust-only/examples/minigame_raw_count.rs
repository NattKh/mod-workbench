// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count Decoded vs Raw for mini_game_data_info spawn_data_list.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::mini_game_data_info::info::{MiniGameDataInfo, SpawnDataList};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\minigamedatainfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\minigamedatainfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut decoded = 0usize;
    let mut raw = 0usize;
    let mut raw_total = 0usize;
    let mut raw_sizes: Vec<usize> = vec![];
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match MiniGameDataInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        match &item.spawn_data_list {
            SpawnDataList::Decoded(_) => decoded += 1,
            SpawnDataList::Raw(b) => { raw += 1; raw_total += b.len(); raw_sizes.push(b.len()); }
        }
    }
    println!("Total entries: {}", ranges.len());
    println!("Decoded:       {}", decoded);
    println!("Raw:           {}", raw);
    println!("Raw bytes:     {}", raw_total);
    if !raw_sizes.is_empty() {
        raw_sizes.sort();
        println!("  min={}, p50={}, max={}", raw_sizes[0], raw_sizes[raw_sizes.len()/2], raw_sizes[raw_sizes.len()-1]);
    }
}
