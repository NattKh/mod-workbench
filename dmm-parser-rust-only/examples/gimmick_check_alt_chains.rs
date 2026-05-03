// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many entries successfully use each alt chain at saturation.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut f31_active = 0usize; let mut f31_full = 0usize; let mut f31_full128 = 0usize;
    let mut f32_active = 0usize; let mut f32_full = 0usize;
    let mut f39_active = 0usize; let mut f39_full = 0usize; let mut f39_full128 = 0usize;
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            f31_alt_001, f31_alt_064, f31_alt_128,
            f32_alt_001, f32_alt_064,
            f39_alt_001, f39_alt_064, f39_alt_128, ..
        } = &item.tail {
            if f31_alt_001.is_some() { f31_active += 1; }
            if f31_alt_064.is_some() { f31_full += 1; }
            if f31_alt_128.is_some() { f31_full128 += 1; }
            if f32_alt_001.is_some() { f32_active += 1; }
            if f32_alt_064.is_some() { f32_full += 1; }
            if f39_alt_001.is_some() { f39_active += 1; }
            if f39_alt_064.is_some() { f39_full += 1; }
            if f39_alt_128.is_some() { f39_full128 += 1; }
        }
    }
    println!("f31_alt: active {} / full64 {} / full128 {}", f31_active, f31_full, f31_full128);
    println!("f32_alt: active {} / full64 {}", f32_active, f32_full);
    println!("f39_alt: active {} / full64 {} / full128 {}", f39_active, f39_full, f39_full128);
}
