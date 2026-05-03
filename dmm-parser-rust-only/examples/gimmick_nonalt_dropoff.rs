// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find where NON-alt-format (TGPEHD-typed) entries fall off in the field chain.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    // For non-alt-format entries (those with trigger_event_handler_list typed)
    // bucketize where they fall off in the field 18..728 chain
    let mut counts: std::collections::BTreeMap<u32, (usize, usize)> = std::collections::BTreeMap::new();
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            trigger_event_handler_list, gimmick_chart_parameter_list,
            field_19_u32_list, field_29_u32_list, field_39_u32_list, field_50_u32_list,
            field_75_u32, field_100_u32, field_150_u32, field_200_u32,
            field_300_u32, field_400_u32, field_500_u32, field_600_u32,
            field_700_u32, field_728_u32, post_blob, ..
        } = &item.tail {
            if trigger_event_handler_list.is_none() { continue; } // skip alt
            let bucket: u32 = if gimmick_chart_parameter_list.is_none() { 17 }
                else if field_19_u32_list.is_none() { 18 }
                else if field_29_u32_list.is_none() { 19 }
                else if field_39_u32_list.is_none() { 29 }
                else if field_50_u32_list.is_none() { 39 }
                else if field_75_u32.is_none() { 50 }
                else if field_100_u32.is_none() { 75 }
                else if field_150_u32.is_none() { 100 }
                else if field_200_u32.is_none() { 150 }
                else if field_300_u32.is_none() { 200 }
                else if field_400_u32.is_none() { 300 }
                else if field_500_u32.is_none() { 400 }
                else if field_600_u32.is_none() { 500 }
                else if field_700_u32.is_none() { 600 }
                else if field_728_u32.is_none() { 700 }
                else { 728 };
            let entry = counts.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += post_blob.len();
        }
    }
    println!("Non-alt-format entry drop-off histogram (last typed field):");
    let mut total_entries = 0usize;
    let mut total_bytes = 0usize;
    for (b, (c, by)) in &counts {
        println!("  field_{}: {} entries, {} post_blob bytes", b, c, by);
        total_entries += c;
        total_bytes += by;
    }
    println!("  TOTAL: {} entries, {} bytes", total_entries, total_bytes);
}
