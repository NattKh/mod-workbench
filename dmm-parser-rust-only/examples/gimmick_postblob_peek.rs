// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Peek at the first 32 bytes of post_blob across decoded gimmick_info
//! entries to identify the next typed field's pattern.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).expect("read");
    let entries = load_pabgh_offsets(PABGH).expect("pabgh");
    let ranges = entry_ranges(&entries, data.len());

    let mut shown = 0usize;
    let mut first_u32_hist: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();

    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            gimmick_chart_parameter_list: Some(_),
            post_blob, ..
        } = &item.tail {
            if post_blob.len() >= 4 {
                let u = u32::from_le_bytes(post_blob[..4].try_into().unwrap());
                *first_u32_hist.entry(u).or_insert(0) += 1;
            }
            if shown < 8 && post_blob.len() >= 32 {
                let bytes: Vec<String> = post_blob[..32].iter()
                    .map(|b| format!("{:02x}", b)).collect();
                println!("k=0x{:x} blob_len={} first32: {}",
                    key, post_blob.len(),
                    bytes.chunks(4).map(|c| c.join("")).collect::<Vec<_>>().join(" "));
                shown += 1;
            }
        }
    }

    println!("\n=== First u32 of post_blob — top 12 most common ===");
    let mut sorted: Vec<_> = first_u32_hist.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (val, count) in sorted.iter().take(12) {
        let f32_val = f32::from_bits(**val);
        println!("  0x{:08x} ({:>10}): {} entries  [as f32: {}]",
            val, val, count, f32_val);
    }
}
