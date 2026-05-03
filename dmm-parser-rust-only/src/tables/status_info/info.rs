// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `StatusInfo.pabgb`.
//!
//! Per IDA sub_1410FC1A0: 34 fields matching mac binary __cstring order.
//! Two CArrays: _reserveSlotInfoList (CArray<{u32+u32}>) and _statLevelData
//! (CArray<u64>). All "lookup" subs (sub_1411006D0/sub_141101A40/etc.) read
//! 4 bytes from disk; preserved as u32 for round-trip.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct ReserveSlotEntry {
        pub slot_a: u32,
        pub slot_b: u32,
    }
}

py_binary_struct! {
    pub struct StatusInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub regenerate_type: u8,
        pub status_index_xxxxx: u32,
        pub is_hard_coded: u8,
        pub use_init_value_zero: u8,
        pub min_resistance_status_info: u32,
        pub max_resistance_status_info: u32,
        pub is_resistance_stat: u8,
        pub is_elemental_stat: u8,
        // [u8;8] → u64 for field-level scalar access. Wire preserved;
        // semantic is a tick-timing value (fixed-point or u64 ID).
        pub block_regen_on_min_stat_tick: u64,
        pub decrease_on_item_broken: u8,
        pub buff_info: u32,
        pub actual_status_key_to_refer: u32,
        pub stat_type: u8,
        pub static_stat_type: u8,
        pub elemental_stat_type: u8,
        pub active_knowledge_info: u32,
        pub send_gimmick_event_key_for_stat_changed: u32,
        pub reserve_slot_info_list: CArray<ReserveSlotEntry>,
        pub use_limit_hit_min_stat: u8,
        pub use_limit_hit_max_stat: u8,
        pub status_key_hash_code32: u32,
        pub min_hash_code32: u32,
        pub max_hash_code32: u32,
        pub is_full_recover_when_revived: u8,
        pub use_percent: u8,
        pub is_repeat_update_from_server: u8,
        pub stat_level_data: CArray<u64>,
        pub is_reset_on_revive: u8,
        pub not_enough_resource_message: u32,
        pub ui_template_name: u32,
        pub ui_component_name: u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\statusinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(StatusInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "statusinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(StatusInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            StatusInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
