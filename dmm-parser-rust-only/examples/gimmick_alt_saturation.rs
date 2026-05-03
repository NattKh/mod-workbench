// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check saturation of alt chains at multiple breakpoints.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    // Track sat at various points
    let mut f31_64 = 0; let mut f31_128 = 0; let mut f31_192 = 0; let mut f31_256 = 0;
    let mut f32_64 = 0; let mut f32_128 = 0;
    let mut f39_64 = 0; let mut f39_128 = 0;
    let mut f31_post_blob_total = 0usize;
    let mut f32_post_blob_total = 0usize;
    let mut f39_post_blob_total = 0usize;
    let mut f31_with_residual = 0usize;
    let mut f32_with_residual = 0usize;
    let mut f39_with_residual = 0usize;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            f31_alt_064, f31_alt_128, f31_alt_192, f31_alt_256,
            f32_alt_064, f32_alt_128,
            f39_alt_064, f39_alt_128,
            post_blob, ..
        } = &item.tail {
            if f31_alt_064.is_some() { f31_64 += 1; }
            if f31_alt_128.is_some() { f31_128 += 1; }
            if f31_alt_192.is_some() { f31_192 += 1; }
            if f31_alt_256.is_some() { f31_256 += 1; if !post_blob.is_empty() { f31_post_blob_total += post_blob.len(); f31_with_residual += 1; } }
            if f32_alt_064.is_some() { f32_64 += 1; }
            if f32_alt_128.is_some() { f32_128 += 1; if !post_blob.is_empty() { f32_post_blob_total += post_blob.len(); f32_with_residual += 1; } }
            if f39_alt_064.is_some() { f39_64 += 1; }
            if f39_alt_128.is_some() { f39_128 += 1; if !post_blob.is_empty() { f39_post_blob_total += post_blob.len(); f39_with_residual += 1; } }
        }
    }
    println!("f31_alt: full64={} full128={} full192={} full256={}", f31_64, f31_128, f31_192, f31_256);
    println!("  f31_alt_256 residual: {} entries with post_blob, {} bytes total", f31_with_residual, f31_post_blob_total);
    println!("f32_alt: full64={} full128={}", f32_64, f32_128);
    println!("  f32_alt_128 residual: {} entries with post_blob, {} bytes total", f32_with_residual, f32_post_blob_total);
    println!("f39_alt: full64={} full128={}", f39_64, f39_128);
    println!("  f39_alt_128 residual: {} entries with post_blob, {} bytes total", f39_with_residual, f39_post_blob_total);
}
