// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Inspect the 3 quest_info entries that fall back to Raw on filter list.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::quest_info::info::{QuestInfo, QuestDialogFilterDataList};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    for (key, start, end) in &ranges {
        let mut cur = *start;
        let item = match QuestInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        if let QuestDialogFilterDataList::Raw(b) = &item.quest_dialog_filter_data_list {
            println!("\nQuest key=0x{:x} size={}", key, b.len());
            // Show first 64 bytes
            let preview_len = 64.min(b.len());
            for i in 0..preview_len {
                if i % 16 == 0 { print!("  {:04x}: ", i); }
                print!("{:02x} ", b[i]);
                if i % 16 == 15 { println!(); }
            }
            println!();
            // Try to parse as CArray<u32> count
            if b.len() >= 4 {
                let count = u32::from_le_bytes(b[..4].try_into().unwrap());
                println!("  As CArray<>.count: {}", count);
            }
        }
    }
}
