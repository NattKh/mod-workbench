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
//! Reader: `sub_1410ED0E0` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                          (_key)
//!   2. CString string_key               (_stringKey)
//!   3. u8 is_blocked                    (_isBlocked)
//!   4. u32 parent_quest                 (_parentQuest, sub_141102CB0
//!      → qword_145F0EF20 lookup)
//!   5. CArray<u32> sub_mission_list     (_subMissionList, sub_1411049D0
//!      → qword_145F0EF00)
//!   6. CArray<MissionBranchData> branch_mission_list
//!      (sub_1411068C0 → sub_1410F3380; per element: u32 lookup +
//!      u32 lookup + 2× u32 raw + 3× u8 — 19 wire bytes / 20 mem)
//!   7. CArray<MissionExecuteStage> execute_stage_list
//!      (inline CArray of 16-byte items via sub_1410ED7D0; per element:
//!      u32 lookup + u32 lookup + 2× u32 raw + 2× u8 — 18 wire bytes)
//!   8. CArray<u32> start_player_list  (sub_1410FF890 → qword_145F0DA08)
//!   9. CArray<u32> field_revive_list  (sub_1411069E0 → qword_145F1A890)
//!  10. CArray<u32> give_up_field_revive_list (sub_1411069E0)
//!      ← TAIL STARTS HERE
//!  11. _triggerVolumeData (sub_141106AE0 — polymorphic Optional<88-byte
//!      via sub_141D7FE40>; hard blocker without decoding sub_141D7FE40)
//!  12. (body) _rewardList, _resultDataList, _rewardInventoryKey, _uiDesc,
//!      … 25+ more wire reads.
//!
//! Steps 1-7 are typed. Body has many helpers; reopens cleanly when each
//! is decoded.

use crate::binary::*;
use crate::py_binary_struct;

// sub_1410AA0D0 inner — Quaternion ([f32; 4], 16 wire bytes).
py_binary_struct! {
    pub struct Quaternion {
        pub x: f32,
        pub y: f32,
        pub z: f32,
        pub w: f32,
    }
}

// sub_1410AA1B0 — Transform: Vec3 (wire first) + Quaternion + Vec3.
// Total 40 wire bytes. Mem offsets are out-of-order but wire shape
// is just sequential reads.
py_binary_struct! {
    pub struct TriggerVolumeTransform {
        pub vec3_a: [f32; 3],
        pub rotation: Quaternion,
        pub vec3_b: [f32; 3],
    }
}

// sub_141D7FE40 — TriggerVolumeData (88 mem bytes / 9 wire fields).
py_binary_struct! {
    pub struct TriggerVolumeData<'a> {
        pub flag_a: u8,
        pub transform: TriggerVolumeTransform,
        pub tag: CString<'a>,             // sub_1410A9D40 (wire = CString)
        pub name: CString<'a>,
        pub flag_b: u8,
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
        pub flag_c: u8,
        pub flag_d: u8,
    }
}

// sub_1410ECC50 — sub_14110DCE0 inner, 104 mem bytes / 12 wire fields.
py_binary_struct! {
    pub struct MissionResultData2<'a> {
        pub flag_a: u8,
        pub name_a: CString<'a>,
        pub name_b: CString<'a>,
        pub region_lookup: u16,             // sub_1410FF220 (wire u16)
        pub lookup_a: u16,                  // sub_141106810 (wire u16)
        pub flag_b: u8,
        pub name_c: CString<'a>,
        pub list_a: CArray<u32>,            // sub_1410FFC20
        pub list_b: CArray<u32>,            // sub_141102FF0
        pub list_c: CArray<u32>,            // sub_141102EF0
        pub raw: u64,
        pub flag_c: u8,
    }
}

// sub_1410ECFD0 — sub_14110DB10 inner, 32 mem bytes / 9 wire fields.
// First 4 fields are sub_1410E2030 (u8 flag + 3× u32 lookup).
py_binary_struct! {
    pub struct MissionStageData {
        pub flag_a: u8,
        pub lookup_a: u32,                  // sub_1410FF430
        pub lookup_b: u32,                  // sub_1410FF430
        pub lookup_c: u32,                  // sub_1410FF430
        pub list: CArray<u32>,              // sub_141101610
        pub lookup_d: u32,                  // sub_1410FF5C0
        pub lookup_e: u16,                  // sub_141100620 (wire u16)
        pub flag_b: u8,
        pub flag_c: u8,
    }
}

// sub_1410EC8B0 — MissionUIDesc, 80 mem bytes / 18 wire fields.
py_binary_struct! {
    pub struct MissionUIDesc {
        pub icon_a: u32,           // read_u32_lookup_DA30
        pub icon_b: u32,           // read_u32_lookup_DA30
        pub icon_c: u32,           // read_u32_lookup_DA30
        pub lookup_a: u32,         // sub_1410FF050
        pub lookup_b: u32,         // sub_1410FF430
        pub lookup_c: u32,         // sub_141102D90
        pub list_a: CArray<u32>,   // sub_141101610 → qword_145F0EF38
        pub list_b: CArray<u32>,   // inline CArray<u32 raw>
        pub lookup_d: u32,         // sub_141101D50
        pub vec3: [f32; 3],
        pub raw_a: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub flag_f: u8,
        pub trailing: u16,         // sub_141106760 (wire u16)
    }
}

// sub_1410ECE20 inner — 48 mem bytes / 11 wire fields.
py_binary_struct! {
    pub struct MissionResultData {
        pub flag_a: u8,
        pub list: CArray<u32>,           // sub_1410FEF40
        pub lookup_a: u32,                // sub_141100370
        pub lookup_b: u32,                // sub_1410FF5C0
        pub raw_a: u32,
        pub lookup_c: u32,                // read_u32_lookup_DA30
        pub lookup_d: u32,                // read_u32_lookup_DA30
        pub raw_b: u32,
        pub lookup_e: u32,                // sub_141102D90
        pub flag_b: u8,
        pub flag_c: u8,
    }
}

// sub_1410F3380 inner — 20 mem bytes / 7 wire fields.
py_binary_struct! {
    pub struct MissionBranchData {
        pub lookup_a: u32,    // sub_141102D20
        pub lookup_b: u32,    // sub_1410FF430
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
    }
}

// sub_1410ED7D0 inner — 16 mem bytes / 6 wire fields.
py_binary_struct! {
    pub struct MissionExecuteStage {
        pub lookup_a: u32,    // sub_141102D90
        pub lookup_b: u32,    // sub_1410FF430
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
    }
}

py_binary_struct! {
    pub struct MissionInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub parent_quest: u32,
        pub sub_mission_list: CArray<u32>,
        pub branch_mission_list: CArray<MissionBranchData>,
        pub execute_stage_list: CArray<MissionExecuteStage>,
        pub start_player_list: CArray<u32>,
        pub field_revive_list: CArray<u32>,
        pub give_up_field_revive_list: CArray<u32>,
        pub trigger_volume_data: COptional<TriggerVolumeData<'a>>,
        pub reward_list: CArray<u32>,
        pub result_data_list: CArray<MissionResultData>,
        pub reward_inventory_key: u16,
        pub ui_desc: MissionUIDesc,
        pub label_a: LocalizableString<'a>,
        pub label_b: LocalizableString<'a>,
        pub label_c: LocalizableString<'a>,
        pub label_d: LocalizableString<'a>,
        pub result_data_2_lookup: u32,       // sub_141102D90 (KNOWN)
        pub result_data_list_2: CArray<MissionResultData2<'a>>,
        pub mission_stage_list: CArray<MissionStageData>,
        pub category_info: u32,             // sub_1410FF430
        pub raw_418: u16,
        pub raw_420: u16,
        pub raw_424: u32,
        pub flag_428: u8,
        pub flag_429: u8,
        pub flag_430: u8,
        pub flag_431: u8,
        pub flag_432: u8,
        pub flag_433: u8,
        pub flag_434: u8,
        pub flag_435: u8,
        pub flag_436: u8,
        pub flag_437: u8,
        pub flag_438: u8,
        pub flag_439: u8,
        pub flag_440: u8,
        pub trailing_u32: u32,              // sub_141BD4120 (raw u32)
    }
}

impl<'a> MissionInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MissionInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\missioninfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\missioninfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                MissionInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "missioninfo roundtrip mismatch");
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
            let item = MissionInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            MissionInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
