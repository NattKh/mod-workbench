// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check alt_body saturation at 1536 + alt_post_cstr_a typed counts.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut alt_body_1408 = 0;
    let mut alt_body_1536 = 0;
    let mut alt_body_1536_with_residual = 0;
    let mut alt_body_1536_residual_bytes = 0usize;
    let mut alt_post_cstr_a_typed = 0;
    let mut alt_post_cstr_b_typed = 0;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            alt_body_1408: a1408, alt_body_1536: a1536,
            alt_post_cstr_a, alt_post_cstr_b, post_blob, ..
        } = &item.tail {
            if a1408.is_some() { alt_body_1408 += 1; }
            if a1536.is_some() {
                alt_body_1536 += 1;
                if !post_blob.is_empty() {
                    alt_body_1536_with_residual += 1;
                    alt_body_1536_residual_bytes += post_blob.len();
                }
            }
            if alt_post_cstr_a.is_some() { alt_post_cstr_a_typed += 1; }
            if alt_post_cstr_b.is_some() { alt_post_cstr_b_typed += 1; }
        }
    }
    println!("alt_body 1536 saturation:");
    println!("  alt_body_1408 typed: {}", alt_body_1408);
    println!("  alt_body_1536 typed (full): {}", alt_body_1536);
    println!("  alt_body_1536 with non-empty post_blob: {} ({} bytes)", alt_body_1536_with_residual, alt_body_1536_residual_bytes);
    println!("  alt_post_cstr_a typed (CString detected): {}", alt_post_cstr_a_typed);
    println!("  alt_post_cstr_b typed: {}", alt_post_cstr_b_typed);
}
