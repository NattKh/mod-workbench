// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count entries that don't even type field 17 (TGPEHD list).

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut no_f17_total = 0usize;
    let mut no_f17_bytes = 0usize;
    let mut no_f17_max = 0usize;
    let mut no_f17_keys: Vec<(u32, usize)> = vec![];
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { trigger_event_handler_list, post_blob, .. } = &item.tail {
            if trigger_event_handler_list.is_none() && !post_blob.is_empty() {
                no_f17_total += 1;
                no_f17_bytes += post_blob.len();
                if post_blob.len() > no_f17_max { no_f17_max = post_blob.len(); }
                no_f17_keys.push((*key, post_blob.len()));
            }
        }
    }
    no_f17_keys.sort_by_key(|(_, l)| std::cmp::Reverse(*l));
    println!("Entries with no field 17 (TGPEHD): {}", no_f17_total);
    println!("Total bytes locked in those:        {}", no_f17_bytes);
    println!("Max size:                           {}", no_f17_max);
    println!("Top 20 by size:");
    for (k, l) in no_f17_keys.iter().take(20) {
        println!("  k=0x{:x} blob_len={}", k, l);
    }
}
