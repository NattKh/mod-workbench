// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find exact failure point in field 30-39 for the 1039 entries.

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
            field_29_u32_list, field_30_u32_list, field_31_u32_list,
            field_32_u32_list, field_33_u32, field_34_u32,
            field_35_u32_list, field_36_u32, field_37_u32, field_38_u32,
            field_39_u32_list, post_blob, ..
        } = &item.tail {
            if field_29_u32_list.is_none() { continue; }
            if field_39_u32_list.is_some() { continue; }
            let bucket: u32 = if field_30_u32_list.is_none() { 29 }
                else if field_31_u32_list.is_none() { 30 }
                else if field_32_u32_list.is_none() { 31 }
                else if field_33_u32.is_none() { 32 }
                else if field_34_u32.is_none() { 33 }
                else if field_35_u32_list.is_none() { 34 }
                else if field_36_u32.is_none() { 35 }
                else if field_37_u32.is_none() { 36 }
                else if field_38_u32.is_none() { 37 }
                else { 38 };
            let entry = counts.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += post_blob.len();
        }
    }
    println!("Field 29→39 failure narrow-down:");
    for (b, (c, by)) in &counts {
        println!("  Last typed field_{}: {} entries, {} post_blob bytes", b, c, by);
    }
}
