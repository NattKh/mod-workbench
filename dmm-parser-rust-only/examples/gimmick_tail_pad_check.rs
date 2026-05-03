// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check tail_pad activation rate.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut field_728_some = 0;
    let mut tail_pad_001 = 0; let mut tail_pad_002 = 0; let mut tail_pad_003 = 0; let mut tail_pad_004 = 0;
    let mut field_728_some_with_blob = 0;
    let mut tiny_blob_with_field_728 = 0;
    let mut tiny_blob_without_field_728 = 0;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded { field_728_u32, tail_pad_001: t1, tail_pad_002: t2, tail_pad_003: t3, tail_pad_004: t4, post_blob, .. } = &item.tail {
            if field_728_u32.is_some() { field_728_some += 1; if !post_blob.is_empty() { field_728_some_with_blob += 1; } }
            if t1.is_some() { tail_pad_001 += 1; }
            if t2.is_some() { tail_pad_002 += 1; }
            if t3.is_some() { tail_pad_003 += 1; }
            if t4.is_some() { tail_pad_004 += 1; }
            if post_blob.len() > 0 && post_blob.len() <= 3 {
                if field_728_u32.is_some() { tiny_blob_with_field_728 += 1; }
                else { tiny_blob_without_field_728 += 1; }
            }
        }
    }
    println!("field_728_u32 typed: {} (with non-empty post_blob: {})", field_728_some, field_728_some_with_blob);
    println!("tail_pad_001 typed: {}", tail_pad_001);
    println!("tail_pad_002 typed: {}", tail_pad_002);
    println!("tail_pad_003 typed: {}", tail_pad_003);
    println!("tail_pad_004 typed: {}", tail_pad_004);
    println!("\nTiny blob (1-3 bytes) entries:");
    println!("  with field_728: {} (these we should have drained)", tiny_blob_with_field_728);
    println!("  without field_728: {} (alt-format, can't drain via this path)", tiny_blob_without_field_728);
}
