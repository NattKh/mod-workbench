// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `AIMoveSpeedInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

// Hand-corrected: ai_move_speed_data_list is a fixed-size 6-slot
// `[COptional<AIMoveSpeedData>; 6]` per IDA sub_1410D58A0
// (loop runs exactly 6 iterations, each preceded by u8 presence flag).
// Element struct AIMoveSpeedData has 127 bytes per IDA sub_1410EDD90.
py_binary_struct! {
    pub struct AIMoveSpeedData {
        pub target_move_speed: f32,
        pub min_move_speed: f32,
        // 8-slot acceleration ramp (f32 each). Empirical sweep across 10
        // present vanilla slots × 16 f32 values found 0 NaN — safe to
        // expose as f32. acc_count above tells how many slots are valid.
        pub move_acc_0: f32, pub move_acc_1: f32, pub move_acc_2: f32, pub move_acc_3: f32,
        pub move_acc_4: f32, pub move_acc_5: f32, pub move_acc_6: f32, pub move_acc_7: f32,
        // 8-slot deceleration ramp.
        pub move_dcc_0: f32, pub move_dcc_1: f32, pub move_dcc_2: f32, pub move_dcc_3: f32,
        pub move_dcc_4: f32, pub move_dcc_5: f32, pub move_dcc_6: f32, pub move_dcc_7: f32,
        pub look_forward_sec: f32,
        pub look_forward_turn_sec: f32,
        pub min_degree_diff: f32,
        pub max_degree_diff: f32,
        pub rotation_damping: f32,
        pub max_rotation_speed: f32,
        pub acc_prevent_distance_after_curve: f32,
        pub min_degree_diff_stride: f32,
        pub max_degree_diff_stride: f32,
        pub min_move_speed_stride: f32,
        pub min_distance_rotate_to_target: f32,
        pub max_distance_rotate_to_target: f32,
        pub speed_down_distance_before_curve_limit: f32,
        pub acc_count: u8,
        pub dcc_count: u8,
        pub rotate_to_target_sync_with_ik: u8,
    }
}

py_binary_struct! {
    pub struct AIMoveSpeedInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub slot_0: COptional<AIMoveSpeedData>,
        pub slot_1: COptional<AIMoveSpeedData>,
        pub slot_2: COptional<AIMoveSpeedData>,
        pub slot_3: COptional<AIMoveSpeedData>,
        pub slot_4: COptional<AIMoveSpeedData>,
        pub slot_5: COptional<AIMoveSpeedData>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\aimovespeedinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(AIMoveSpeedInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "aimovespeedinfo roundtrip bytes mismatch");
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
            items.push(AIMoveSpeedInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            AIMoveSpeedInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
