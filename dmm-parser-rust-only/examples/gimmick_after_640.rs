// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect first 64 bytes of post_blob for entries that typed alt_body_640.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut shown = 0usize;
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { alt_body_640, post_blob, .. } = &item.tail {
            if alt_body_640.is_some() && !post_blob.is_empty() && shown < 5 {
                println!("\nk=0x{:x} blob_len={}", key, post_blob.len());
                let preview = 64.min(post_blob.len());
                for i in 0..preview {
                    if i % 16 == 0 { print!("  {:04x}: ", i); }
                    print!("{:02x} ", post_blob[i]);
                    if i % 16 == 15 { println!(); }
                }
                println!();
                let visible: String = post_blob[..preview].iter()
                    .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                    .collect();
                println!("  ASCII: {}", visible);
                // Try to interpret first 4 bytes as u32 length, see if next bytes are valid UTF-8
                if post_blob.len() >= 8 {
                    let len = u32::from_le_bytes(post_blob[..4].try_into().unwrap()) as usize;
                    if len > 0 && len < 200 && post_blob.len() >= 4 + len {
                        if let Ok(s) = std::str::from_utf8(&post_blob[4..4+len]) {
                            if s.chars().all(|c| c.is_ascii_graphic() || c == '_' || c == ' ') {
                                println!("  POSSIBLE CSTRING (len={}): \"{}\"", len, s);
                            }
                        }
                    }
                }
                shown += 1;
            }
        }
    }
}
