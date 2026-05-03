// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect the longest gimmick_info entries' remaining post_blob.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut entries_with_tail: Vec<(u32, Vec<u8>)> = vec![];
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { post_blob, .. } = &item.tail {
            if !post_blob.is_empty() {
                entries_with_tail.push((*key, post_blob.clone()));
            }
        }
    }
    entries_with_tail.sort_by_key(|(_, b)| std::cmp::Reverse(b.len()));
    println!("Total entries with non-empty post_blob: {}", entries_with_tail.len());
    println!("Top-5 longest:\n");
    for (key, blob) in entries_with_tail.iter().take(5) {
        println!("k=0x{:x} blob_len={}", key, blob.len());
        // Show first 64 bytes
        let preview = 64.min(blob.len());
        for i in 0..preview {
            if i % 16 == 0 { print!("  {:04x}: ", i); }
            print!("{:02x} ", blob[i]);
            if i % 16 == 15 { println!(); }
        }
        println!();
        // Try ASCII
        let visible: String = blob[..preview].iter()
            .map(|&b| if (b >= 0x20 && b < 0x7f) { b as char } else { '.' })
            .collect();
        println!("  ASCII: {}", visible);
        println!();
    }

    // Distribution
    let total: usize = entries_with_tail.iter().map(|(_, b)| b.len()).sum();
    println!("Total tail bytes:  {}", total);
    println!("Entries with tail: {}", entries_with_tail.len());
    let buckets = [(0, 100), (100, 500), (500, 1000), (1000, 5000), (5000, 60000)];
    for (lo, hi) in buckets {
        let count = entries_with_tail.iter()
            .filter(|(_, b)| b.len() >= lo && b.len() < hi).count();
        let bytes: usize = entries_with_tail.iter()
            .filter(|(_, b)| b.len() >= lo && b.len() < hi)
            .map(|(_, b)| b.len()).sum();
        println!("  {}-{} bytes: {} entries, {} bytes", lo, hi, count, bytes);
    }
}
