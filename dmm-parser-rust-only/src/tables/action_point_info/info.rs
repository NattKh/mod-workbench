// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `ActionPointInfo.pabgb`.
//!
//! Per IDA sub_1410D5120 (outer): u32 key, CString string_key, u8 is_blocked,
//! ActionPoint action_point (sub_1410D4FE0), u32 level_action_point_info
//! (sub_1410FED30 lookup).
//!
//! Per IDA sub_1410D4FE0 + sub_1410D4DF0 (ActionPoint inner reader):
//!   sub_1410D4DF0 reads (in disk order): u32, [u8;24], u32, [u8;16], u32, u32 = 56 bytes
//!   sub_1410D4FE0 then reads: u32 (lookup), u32, u32, u32 (lookup),
//!   [u8;12], u32 = 32 bytes
//! Total ActionPoint disk size = 88 bytes.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct ActionPoint {
        pub field_a: u32,
        pub block_a_floats: [f32; 4],
        pub block_a_nan_tail_lo: u32,
        pub block_a_nan_tail_hi: u32,
        pub field_b: u32,
        pub block_b: [f32; 4],
        pub field_c: u32,
        pub field_d: u32,
        pub level_action_lookup: u32,
        pub field_e: u32,
        pub field_f: u32,
        pub field_g: u32,
        pub block_c: [f32; 3],
        pub field_h: u32,
        pub ext_float_a: f32,
        pub ext_field_a: u32,
        pub ext_float_b: f32,
        pub ext_scale: [f32; 3],
        pub ext_nan_lo: u32,
        pub ext_nan_hi: u32,
        pub ext_block_a1: [u32; 4],
        pub ext_block_a2: [u32; 2],
        pub ext_block_b: [f32; 4],
        pub ext_tail: [u32; 4],
    }
}

py_binary_struct! {
    pub struct ActionPointInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub action_point: ActionPoint,
        pub level_action_point_info: u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\actionpointinfo.pabgb";




    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(ActionPointInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "actionpointinfo roundtrip bytes mismatch");
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
            items.push(ActionPointInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            ActionPointInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
