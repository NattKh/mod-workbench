// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Try to parse QuestDialogFilterData entries one-by-one until one fails.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::quest_info::info::{QuestInfo, QuestDialogFilterDataList};
use dmm_parser::binary::variants::filter_condition::QuestDialogFilterData;
use dmm_parser::binary::BinaryRead;

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
            // Try parsing items one by one
            let mut probe = 0usize;
            if probe + 4 > b.len() { continue; }
            let count = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
            probe = 4;
            println!("\nQuest key=0x{:x} size={} count={}", key, b.len(), count);
            for i in 0..count {
                let pre = probe;
                match <QuestDialogFilterData>::read_from(b, &mut probe) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("  Item {} FAILED at offset {}: {}", i, pre, e);
                        // Show 32 bytes around failure
                        let start = pre;
                        let stop = (pre + 32).min(b.len());
                        for j in start..stop {
                            if (j - start) % 16 == 0 { print!("    {:04x}: ", j); }
                            print!("{:02x} ", b[j]);
                            if (j - start) % 16 == 15 { println!(); }
                        }
                        println!();
                        break;
                    }
                }
                if i < 3 || i == count - 1 {
                    println!("  Item {} ok at offset {}", i, pre);
                }
            }
        }
    }
}
