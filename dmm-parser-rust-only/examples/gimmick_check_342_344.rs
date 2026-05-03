// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check how many entries successfully type fields 342-344.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    let mut f342 = 0usize;
    let mut f343 = 0usize;
    let mut f344 = 0usize;
    let mut f344_real_str = 0usize;
    let mut sample_names: Vec<String> = vec![];
    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let GimmickTail::Decoded {
            field_342_u32_count,
            field_343_u8_flag,
            field_344_cstr_name,
            ..
        } = &item.tail {
            if field_342_u32_count.is_some() { f342 += 1; }
            if field_343_u8_flag.is_some() { f343 += 1; }
            if let Some(s) = field_344_cstr_name {
                f344 += 1;
                let bytes = s.data.as_bytes();
                let printable = bytes.iter().all(|&b| (b >= 0x20 && b < 0x7f) || b == 0);
                if printable && !bytes.is_empty() {
                    f344_real_str += 1;
                    if sample_names.len() < 10 {
                        sample_names.push(s.data.to_string());
                    }
                }
            }
        }
    }
    println!("Field 342 (u32 count) typed: {}", f342);
    println!("Field 343 (u8 flag)   typed: {}", f343);
    println!("Field 344 (CString)   typed: {}", f344);
    println!("  of which printable + non-empty: {}", f344_real_str);
    println!("Sample names:");
    for s in &sample_names {
        println!("  \"{}\"", s);
    }
}
