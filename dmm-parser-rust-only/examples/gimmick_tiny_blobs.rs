// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect entries with 1-3 trailing bytes to find the pattern.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut by_len: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    let mut byte_pattern_count_2: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    let mut byte_pattern_count_1: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();
    let mut byte_pattern_count_3: std::collections::BTreeMap<(u8,u8,u8), usize> = std::collections::BTreeMap::new();
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { post_blob, .. } = &item.tail {
            if !post_blob.is_empty() && post_blob.len() <= 3 {
                *by_len.entry(post_blob.len()).or_insert(0) += 1;
                if post_blob.len() == 1 {
                    *byte_pattern_count_1.entry(post_blob[0]).or_insert(0) += 1;
                } else if post_blob.len() == 2 {
                    let v = u16::from_le_bytes(post_blob[..2].try_into().unwrap());
                    *byte_pattern_count_2.entry(v).or_insert(0) += 1;
                } else if post_blob.len() == 3 {
                    *byte_pattern_count_3.entry((post_blob[0], post_blob[1], post_blob[2])).or_insert(0) += 1;
                }
            }
        }
    }
    println!("Entries with 1-3 trailing bytes (sizes):");
    for (len, count) in &by_len {
        println!("  {} byte: {} entries", len, count);
    }
    println!("\n1-byte patterns:");
    let mut sorted: Vec<_> = byte_pattern_count_1.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (b, c) in sorted.iter().take(10) {
        println!("  0x{:02x}: {} entries", b, c);
    }
    println!("\n2-byte patterns (u16 LE):");
    let mut sorted: Vec<_> = byte_pattern_count_2.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (v, c) in sorted.iter().take(10) {
        println!("  0x{:04x}: {} entries", v, c);
    }
    println!("\n3-byte patterns:");
    let mut sorted: Vec<_> = byte_pattern_count_3.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for ((a,b,d), c) in sorted.iter().take(10) {
        println!("  {:02x} {:02x} {:02x}: {} entries", a, b, d, c);
    }
}
