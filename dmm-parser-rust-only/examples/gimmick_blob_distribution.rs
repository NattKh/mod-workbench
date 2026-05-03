// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Distribution of post_blob sizes — count entries by blob_len bucket.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    // Buckets: 0, 1-3, 4-15, 16-63, 64-255, 256-1023, 1024-4095, 4096+
    let mut bucket_counts = [0usize; 8];
    let mut bucket_bytes = [0usize; 8];
    let mut total_with_blob = 0usize;
    let mut total_bytes = 0usize;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { post_blob, .. } = &item.tail {
            let bl = post_blob.len();
            if bl > 0 { total_with_blob += 1; total_bytes += bl; }
            let bucket = if bl == 0 { 0 }
                else if bl <= 3 { 1 }
                else if bl <= 15 { 2 }
                else if bl <= 63 { 3 }
                else if bl <= 255 { 4 }
                else if bl <= 1023 { 5 }
                else if bl <= 4095 { 6 }
                else { 7 };
            bucket_counts[bucket] += 1;
            bucket_bytes[bucket] += bl;
        }
    }
    println!("post_blob size distribution:");
    let names = ["0", "1-3", "4-15", "16-63", "64-255", "256-1023", "1024-4095", "4096+"];
    for i in 0..8 {
        println!("  {:<10}: {:>6} entries, {:>10} bytes",
            names[i], bucket_counts[i], bucket_bytes[i]);
    }
    println!("\nTotal entries with post_blob > 0: {}", total_with_blob);
    println!("Total post_blob bytes: {}", total_bytes);
}
