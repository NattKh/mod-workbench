// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Check why the longest entry (k=0xf4254) doesn't type through.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    for (key, start, end) in &ranges {
        if *key != 0xf4254 { continue; }
        let mut cur = *start;
        let item = GimmickInfo::read_with_size(&data, &mut cur, end - start).unwrap();
        if let GimmickTail::Decoded {
            trigger_event_handler_list,
            gimmick_chart_parameter_list,
            field_19_u32_list,
            field_20_u32_list,
            field_50_u32_list,
            field_100_u32, field_200_u32: _,
            field_341_u32,
            field_342_u32_count,
            field_343_u8_flag,
            field_400_u32,
            field_500_u32,
            field_600_u32,
            field_700_u32,
            field_728_u32,
            post_blob, ..
        } = &item.tail {
            println!("Entry k=0x{:x}", key);
            println!("  trigger_event_handler_list: {}", trigger_event_handler_list.is_some());
            println!("  gimmick_chart_parameter_list: {}", gimmick_chart_parameter_list.is_some());
            println!("  field_19_u32_list: {}", field_19_u32_list.is_some());
            println!("  field_20_u32_list: {}", field_20_u32_list.is_some());
            println!("  field_50_u32_list: {}", field_50_u32_list.is_some());
            println!("  field_100_u32: {:?}", field_100_u32);
            println!("  field_341_u32: {:?}", field_341_u32);
            println!("  field_342_u32_count: {:?}", field_342_u32_count);
            println!("  field_343_u8_flag: {:?}", field_343_u8_flag);
            println!("  field_400_u32: {:?}", field_400_u32);
            println!("  field_500_u32: {:?}", field_500_u32);
            println!("  field_600_u32: {:?}", field_600_u32);
            println!("  field_700_u32: {:?}", field_700_u32);
            println!("  field_728_u32: {:?}", field_728_u32);
            println!("  post_blob len: {}", post_blob.len());
        }
        break;
    }
}
