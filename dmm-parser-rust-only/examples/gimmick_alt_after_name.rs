// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect bytes AFTER alt_trigger_name for the 4975 alt-format entries.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut alt_count_typed = 0usize;
    let mut sample_blobs: Vec<(u32, String, Vec<u8>)> = vec![];
    let mut blob_size_total = 0usize;
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { alt_trigger_name, post_blob, .. } = &item.tail {
            if let Some(name) = alt_trigger_name {
                alt_count_typed += 1;
                blob_size_total += post_blob.len();
                if sample_blobs.len() < 5 {
                    sample_blobs.push((*key, name.data.to_string(), post_blob.clone()));
                }
            }
        }
    }
    println!("Total alt-format typed entries: {}", alt_count_typed);
    println!("Total post_blob bytes for alt entries: {}", blob_size_total);
    if alt_count_typed > 0 {
        println!("Avg post_blob per alt entry: {}", blob_size_total / alt_count_typed);
    }
    println!("\nFirst 5 entries with alt name + 64 bytes of post_blob:");
    for (k, name, blob) in &sample_blobs {
        println!("\n  k=0x{:x} name=\"{}\" blob_len={}", k, name, blob.len());
        let preview_len = 64.min(blob.len());
        for i in 0..preview_len {
            if i % 16 == 0 { print!("    {:04x}: ", i); }
            print!("{:02x} ", blob[i]);
            if i % 16 == 15 { println!(); }
        }
        println!();
        let visible: String = blob[..preview_len].iter()
            .map(|&b| if (b >= 0x20 && b < 0x7f) { b as char } else { '.' })
            .collect();
        println!("    ASCII: {}", visible);
    }
}
