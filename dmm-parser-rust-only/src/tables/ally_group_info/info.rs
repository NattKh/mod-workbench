// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `AllyGroupInfo.pabgb`.
//!
//! Per IDA sub_1410D5BE0:
//!   - u32 key (sub_141BF6720 is internal storage helper, not a stream read)
//!   - CString string_key
//!   - u8 is_blocked
//!   - relation_type_list: 7-element fixed array of CArray<u32>
//!   - 5 u8 flags
//!   - u32 interesting_condition (sub_1410FF430 = u32 hash)
//!   - add_on_ally_group_list: CArray<u32> (sub_1410FF4A0 thunk)
//!   - interesting_order_list: CArray<u32> (sub_1410FF4A0 thunk)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct AllyGroupInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub relation_type_list_0: CArray<u32>,
        pub relation_type_list_1: CArray<u32>,
        pub relation_type_list_2: CArray<u32>,
        pub relation_type_list_3: CArray<u32>,
        pub relation_type_list_4: CArray<u32>,
        pub relation_type_list_5: CArray<u32>,
        pub relation_type_list_6: CArray<u32>,
        pub killer_detection_time: u8,
        pub apply_reporting: u8,
        pub is_wild: u8,
        pub is_main_ally_group: u8,
        pub is_intruder: u8,
        pub interesting_condition: u32,
        pub add_on_ally_group_list: CArray<u32>,
        pub interesting_order_list: CArray<u32>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\allygroupinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(AllyGroupInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "allygroupinfo roundtrip bytes mismatch");
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
            items.push(AllyGroupInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            AllyGroupInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
