// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Narrow down which field 20-28 fails for the 1039 entries.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut counts: std::collections::BTreeMap<u32, (usize, usize)> = std::collections::BTreeMap::new();
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            field_19_u32_list, field_20_u32_list, field_21_u32_list,
            field_22_u32_list, field_23_u32_list, field_24_u32_list,
            field_25_u32_list, field_26_u32, field_27_u32_list,
            field_28_u32, field_29_u32_list,
            post_blob, ..
        } = &item.tail {
            // Only consider entries that typed field_19 but failed before field_29
            if field_19_u32_list.is_none() { continue; }
            if field_29_u32_list.is_some() { continue; }
            let bucket: u32 = if field_20_u32_list.is_none() { 19 }
                else if field_21_u32_list.is_none() { 20 }
                else if field_22_u32_list.is_none() { 21 }
                else if field_23_u32_list.is_none() { 22 }
                else if field_24_u32_list.is_none() { 23 }
                else if field_25_u32_list.is_none() { 24 }
                else if field_26_u32.is_none() { 25 }
                else if field_27_u32_list.is_none() { 26 }
                else if field_28_u32.is_none() { 27 }
                else { 28 };
            let entry = counts.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += post_blob.len();
        }
    }
    println!("Field 19→29 failure narrow-down (1039 entries, 887K bytes total):");
    for (b, (c, by)) in &counts {
        println!("  Last typed field_{}: {} entries, {} post_blob bytes", b, c, by);
    }
}
