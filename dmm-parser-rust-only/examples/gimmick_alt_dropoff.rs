// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Find where entries fall off in alt_body sequence.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    // Bucket where each alt-format entry falls off
    let buckets = [
        (0, "alt_inner_count fail"),
        (1, "0-64"), (64, "65-128"), (128, "129-192"), (192, "193-256"),
        (256, "257-320"), (320, "321-384"), (384, "385-448"), (448, "449-512"),
        (512, "513-576"), (576, "577+"),
    ];
    let mut counts: std::collections::BTreeMap<usize, (usize, usize)> = std::collections::BTreeMap::new();
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            alt_trigger_name, alt_inner_count,
            alt_body_064, alt_body_128, alt_body_192, alt_body_256,
            alt_body_320, alt_body_384, alt_body_448, alt_body_512,
            alt_body_576, alt_body_640,
            post_blob, ..
        } = &item.tail {
            if alt_trigger_name.is_none() { continue; } // not alt-format
            // Find drop position
            let bucket = if alt_inner_count.is_none() { 0 }
                else if alt_body_064.is_none() { 1 }
                else if alt_body_128.is_none() { 64 }
                else if alt_body_192.is_none() { 128 }
                else if alt_body_256.is_none() { 192 }
                else if alt_body_320.is_none() { 256 }
                else if alt_body_384.is_none() { 320 }
                else if alt_body_448.is_none() { 384 }
                else if alt_body_512.is_none() { 448 }
                else if alt_body_576.is_none() { 512 }
                else if alt_body_640.is_none() { 576 }
                else { 640 };
            let entry = counts.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += post_blob.len();
        }
    }
    println!("Alt-format entry drop-off histogram:");
    for (bucket, label) in &buckets {
        let (c, b) = counts.get(bucket).copied().unwrap_or((0, 0));
        println!("  {} ({}): {} entries, {} post_blob bytes", label, bucket, c, b);
    }
    if let Some(&(c, b)) = counts.get(&640) {
        println!("  640+ (typed all): {} entries, {} post_blob bytes", c, b);
    }
}
