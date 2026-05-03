// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed (no _tail_b64).
//!
//! Reader: `sub_1410F60E0` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                              (_key)
//!   2. CString string_key                   (_stringKey)
//!   3. u8 is_blocked                        (_isBlocked)
//!   4. u8 type_                             (_type, Rust keyword suffix)
//!   5. u32 active_condition_info            (_activeConditionInfo,
//!      sub_1410FF430 wire u32)
//!   6. CString post_process_sequencer_name  (_postProcessSequencerName)
//!   7. u32 time_scale                       (_timeScale, f32-as-u32)
//!   8. u32 player_time_scale                (_playerTimeScale)
//!   9. u32 mode_radius                      (_modeRadius, f32)
//!  10. u32 passive_skill                    (_passiveSkill, sub_1410FEBE0
//!      wire u32 → qword_145F0DA68)
//!  11. u32 skill_level                      (_skillLevel)
//!  12. u32 input_key_hash                   (_inputKeyHash)
//!  13. u32 cancel_input_key_hash            (_cancelInputKeyHash)
//!  14. u8 has_near_by_target_option         (_hasNearByTargetOption)
//!  15. u8 is_high_priority                  (_isHighPriority)
//!  16. u8 exclusive_with_detect             (_exclusiveWithDetect)
//!  17. u8 disable_occlusion_culling         (_disableOcclusionCulling)
//!  18. u8 disable_player_targetable         (_disablePlayerTargetable)
//!  19. u8 change_minimap_scale              (_changeMinimapScale)
//!  20. u8 is_minimap_zoom_out               (_isMinimapZoomOut)
//!  21. u8 is_allow_dialog                   (_isAllowDialog)
//!  22. SpecialModeOptionSlots option_slots  (24 fixed CArray slots, each
//!      a CArray<SpecialModeOption> via sub_141128AF0 → sub_1410F5A30)
//!  23. DetectModeAreaData detect_mode_area_data
//!      (sub_1410F5F80, 64 mem bytes / 8 wire fields at a2+456)
//!  24. PlayerActionLimitDesc player_action_limit_desc
//!      (sub_14B92C740 via thunk sub_1410D4540, ~40 mem bytes / 8 wire
//!      fields at a2+520)
//!
//! SpecialModeOption (sub_1410F5A30 inner, 176 mem bytes / 32 wire fields).

use crate::binary::*;
use crate::py_binary_struct;

// sub_14110A460 inner element — 24 mem bytes / 3 wire fields (variable).
py_binary_struct! {
    pub struct SpecialModeOptionMacroEntry<'a> {
        pub key_str: CString<'a>,    // sub_1410A9D40 (wire = CString)
        pub name: CString<'a>,       // direct read_CString
        pub flag: u8,
    }
}

// sub_1410F5A30 inner — 176 mem bytes / 32 wire fields.
py_binary_struct! {
    pub struct SpecialModeOption<'a> {
        pub flag_a: u8,
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub key_a: CString<'a>,
        pub raw_a: u32,
        pub key_b: CString<'a>,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u32,
        pub raw_e: u32,
        pub raw_f: u64,
        pub raw_g: u64,
        pub lookup_c: u32,
        pub flag_b: u8,
        pub list_u32: CArray<u32>,
        pub list_macro: CArray<SpecialModeOptionMacroEntry<'a>>,
        pub lookup_d: u32,
        pub name: CString<'a>,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub raw_h: u32,
        pub raw_i: u32,
        pub raw_j: u32,
        pub flag_f: u8,
        pub raw_k: u32,
        pub raw_l: u32,
        pub raw_m: u32,
        pub raw_n: u32,
        pub raw_o: u32,
        pub raw_p: u32,
        // Per IDA sub_1410F5A30: 16 individual 1-byte reads in a loop
        // (read 1 byte, increment, until 16 collected) — split into named u8 fields.
        pub trailing_00: u8, pub trailing_01: u8, pub trailing_02: u8, pub trailing_03: u8,
        pub trailing_04: u8, pub trailing_05: u8, pub trailing_06: u8, pub trailing_07: u8,
        pub trailing_08: u8, pub trailing_09: u8, pub trailing_10: u8, pub trailing_11: u8,
        pub trailing_12: u8, pub trailing_13: u8, pub trailing_14: u8, pub trailing_15: u8,
    }
}

// 24 fixed CArray<SpecialModeOption> slots — _optionList iterates 0..24.
// Each slot is a separate CArray header (16 mem bytes).
py_binary_struct! {
    pub struct SpecialModeOptionSlots<'a> {
        pub slot_00: CArray<SpecialModeOption<'a>>,
        pub slot_01: CArray<SpecialModeOption<'a>>,
        pub slot_02: CArray<SpecialModeOption<'a>>,
        pub slot_03: CArray<SpecialModeOption<'a>>,
        pub slot_04: CArray<SpecialModeOption<'a>>,
        pub slot_05: CArray<SpecialModeOption<'a>>,
        pub slot_06: CArray<SpecialModeOption<'a>>,
        pub slot_07: CArray<SpecialModeOption<'a>>,
        pub slot_08: CArray<SpecialModeOption<'a>>,
        pub slot_09: CArray<SpecialModeOption<'a>>,
        pub slot_10: CArray<SpecialModeOption<'a>>,
        pub slot_11: CArray<SpecialModeOption<'a>>,
        pub slot_12: CArray<SpecialModeOption<'a>>,
        pub slot_13: CArray<SpecialModeOption<'a>>,
        pub slot_14: CArray<SpecialModeOption<'a>>,
        pub slot_15: CArray<SpecialModeOption<'a>>,
        pub slot_16: CArray<SpecialModeOption<'a>>,
        pub slot_17: CArray<SpecialModeOption<'a>>,
        pub slot_18: CArray<SpecialModeOption<'a>>,
        pub slot_19: CArray<SpecialModeOption<'a>>,
        pub slot_20: CArray<SpecialModeOption<'a>>,
        pub slot_21: CArray<SpecialModeOption<'a>>,
        pub slot_22: CArray<SpecialModeOption<'a>>,
        pub slot_23: CArray<SpecialModeOption<'a>>,
    }
}

// sub_1410F5F80 — DetectModeAreaData, 64 mem bytes / 8 wire fields.
py_binary_struct! {
    pub struct DetectModeAreaData<'a> {
        pub flag_a: u8,
        pub name_a: CString<'a>,
        pub name_b: CString<'a>,
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag_b: u8,
    }
}

// sub_14B92C740 (thunked via sub_1410D4540) — PlayerActionLimitDesc.
py_binary_struct! {
    pub struct PlayerActionLimitDesc {
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub flag_f: u8,
        pub list_a: CArray<u16>,
        pub list_b: CArray<u16>,
    }
}

py_binary_struct! {
    pub struct SpecialModeInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub type_: u8,
        pub active_condition_info: u32,
        pub post_process_sequencer_name: CString<'a>,
        pub time_scale: u32,
        pub player_time_scale: u32,
        pub mode_radius: u32,
        pub passive_skill: u32,
        pub skill_level: u32,
        pub input_key_hash: u32,
        pub cancel_input_key_hash: u32,
        pub has_near_by_target_option: u8,
        pub is_high_priority: u8,
        pub exclusive_with_detect: u8,
        pub disable_occlusion_culling: u8,
        pub disable_player_targetable: u8,
        pub change_minimap_scale: u8,
        pub is_minimap_zoom_out: u8,
        pub is_allow_dialog: u8,
        pub option_slots: SpecialModeOptionSlots<'a>,
        pub detect_mode_area_data: DetectModeAreaData<'a>,
        pub player_action_limit_desc: PlayerActionLimitDesc,
    }
}

impl<'a> SpecialModeInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SpecialModeInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\specialmode.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\specialmode.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                SpecialModeInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "specialmode roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP: missing fixture {}", PABGB);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP: missing pabgh fixture {}", PABGH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = SpecialModeInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            SpecialModeInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
