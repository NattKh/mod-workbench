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
//! Reader: `sub_1410E4450` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                                  (_key)
//!   2. CString string_key                       (_stringKey)
//!   3. u8 is_blocked                            (_isBlocked)
//!   4. u32 main_gimmick_group_info_of_combination
//!      (_mainGimmickGroupInfoOfCombination, sub_141104AE0 →
//!      qword_145F11D70 lookup)
//!   5. u64 battery_init_capacity            (_batteryInitCapacity)
//!   6. u64 battery_total_capacity           (_batteryTotalCapacity)
//!   7. CArray<GimmickProperty> link_signal_group_list
//!      (_linkSignalGroupList, sub_141113BF0 wraps sub_1410E3D20;
//!      per element: CString name + u8 + u32 + u8 + u32 + u32 +
//!      u64 + u64 — 30 + variable wire bytes)
//!   8. CArray<u32> property_list                (_propertyList,
//!      sub_141101AB0 — wire u32 per element, mem u32)
//!   9. CArray<CString> gimmick_tag_list         (_gimmickTagList,
//!      sub_141102990 — runtime hashes each tag to u32 via
//!      sub_1410A9D40, wire is CString)
//!  10. CString gimmick_chart_path               (_gimmickChartPath)
//!  11. u8 gimmick_type                          (_gimmickType)
//!  12. u8 gimmick_placement_style               (_gimmickPlacementStyle)
//!  13. u8 gimmick_interface_type                (_gimmickInterfaceType)
//!  14. [f32; 3] gimmick_remote_catchable_data
//!      (_gimmickRemoteCatchableData, Vec3 — 12 raw wire bytes)
//!  15. u8 use_attack_target_owner_constraint
//!  16. u8 use_self_constraint
//!      ← TAIL STARTS HERE
//!  17. _autoTargetingConstraintDataList (sub_141113A50 → CArray<64-byte
//!      composite via sub_1410E3E90>; 11-field GimmickConstraintData
//!      with 2 CString-hash + 5 u8 + u32 + 2 Vec3 + CArray<CString>)
//!  18. _gimmickConstraintDataList (sub_141113A50 — same composite)
//!  19. _gimmickInfoList, _gameEventHandlerList,
//!      _unlockableIDataList, _defaultSpawnReasonHash,
//!      _initialBodyMotionType,
//!      _sequencerLevelAllowGimmickEventKeyList,
//!      _sequencerLevelConnectAliasNameList, _gimmickAliasDataList,
//!      _logoutTimeAfterBreak, _attackByCollisionInfoListKey,
//!      _useSlidingMotionProperty, _isEditorUseable,
//!      _isGetKnowledgeWhenGetItem, _isUseConstrainSound, …
//!
//! Steps 1-16 are typed (16 fields). Body has 80+ wire reads with
//! several deep composites; reopens cleanly when those are decoded.
//!
//! Helper: `sub_141104AE0` = u32 lookup at qword_145F11D70.
//! `sub_141113BF0` = CArray<GimmickProperty> (48 mem bytes/element
//! via sub_1410E3D20).
//! `sub_1410E3D20` = inner GimmickProperty reader (8 wire fields).
//! `sub_141101AB0` = CArray<u32> (4 wire bytes/element).
//! `sub_141102990` = CArray<CString> via sub_1410A9D40
//! (CString-hash; wire bytes are u32 length + N raw bytes).

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct GimmickProperty<'a> {
        pub name: CString<'a>,
        pub flag_a: u8,
        pub raw_a: u32,
        pub flag_b: u8,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u64,
        pub raw_e: u64,
    }
}

// GameEventHandler — sub_1411138C0 inner, 8 mem bytes.
// Wire: u8 + sub_1410FF430 (u32 wire) + u32 raw = 9 wire bytes.
py_binary_struct! {
    pub struct GameEventHandler {
        pub kind: u8,
        pub lookup: u32,
        pub raw: u32,
    }
}

// UnlockableData — sub_1411135E0 outer per element. The reader uses
// hash-table sizing (prime numbers) at runtime, but wire shape per
// element is just: u32 hash key + 2 nested CArrays + u8 trailing.
py_binary_struct! {
    pub struct UnlockableData {
        pub key: u32,
        pub item_info_list: CArray<u32>,    // sub_1410FFF10 → qword_145F0DA00
        pub mission_info_list: CArray<u32>, // sub_1411049D0 → qword_145F0EF00
        pub flag: u8,
    }
}

// GimmickAliasInner — sub_1410E2030 + trailing u8.
// Wire: u8 + 3× u32 lookup + u8 = 14 wire bytes per element.
py_binary_struct! {
    pub struct GimmickAliasInnerEntry {
        pub flag: u8,
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub lookup_c: u32,
        pub raw: u8,
    }
}

// GimmickCollisionTagData — sub_141113220 inner, 24 mem bytes.
// Wire: CString name + u8 + 2× CString-hash (sub_1410A9D40).
py_binary_struct! {
    pub struct GimmickCollisionTagData<'a> {
        pub name: CString<'a>,
        pub flag: u8,
        pub tag_a: CString<'a>,
        pub tag_b: CString<'a>,
    }
}

// GimmickInteractionData — sub_1411130A0 inner via sub_1410E4050,
// 56 mem bytes / 10 wire fields.
py_binary_struct! {
    pub struct GimmickInteractionData<'a> {
        pub lookup_a: u32,    // sub_141104AE0
        pub raw_a: u32,
        pub name_a: CString<'a>,
        pub flag_a: u8,
        pub lookup_b: u32,    // sub_141104AE0
        pub raw_b: u32,
        pub name_b: CString<'a>,
        pub flag_b: u8,
        pub name_c: CString<'a>,
        pub raw_c: u32,
    }
}

// GimmickFieldEntry — sub_141101B80 inner, 8 mem bytes / 2 wire fields.
// Wire: u32 raw + u32 (hashed via sub_141BF6840 → qword_145F11478 lookup).
py_binary_struct! {
    pub struct GimmickFieldEntry {
        pub raw: u32,
        pub lookup_hash: u32,
    }
}

// GimmickU32Pair — sub_141104B50 inner, 8 mem bytes / 2 u32 raw.
py_binary_struct! {
    pub struct GimmickU32Pair {
        pub a: u32,
        pub b: u32,
    }
}

// GimmickAttackByCollisionData — sub_141C79D00 flat struct.
// Wire: CString + CString + u32 + u32 + u32 = variable + 12 bytes.
py_binary_struct! {
    pub struct GimmickAttackByCollisionData<'a> {
        pub name: CString<'a>,
        pub material: CString<'a>,
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
    }
}

// GimmickAliasData — sub_1410E41E0 inner, 40 mem bytes.
// Wire: 2× u32 raw + 2× u32 lookup + u32 raw + u16 region lookup +
// CArray<GimmickAliasInnerEntry>.
py_binary_struct! {
    pub struct GimmickAliasData {
        pub raw_a: u32,
        pub raw_b: u32,
        pub knowledge_info: u32,        // sub_1411006D0
        pub condition_logic: u32,       // sub_1410FF430
        pub raw_c: u32,
        pub region_info: u16,           // sub_1410FF220 (wire u16)
        pub aliases: CArray<GimmickAliasInnerEntry>,
    }
}

// GimmickConstraintData — sub_1410E3E90 inner, 64 mem bytes.
// Wire: CString (sub_1410A9D40) + 5 u8 + u32 + 2× Vec3 +
// CString (sub_1410A9D40) + CArray<CString> (sub_141102990).
py_binary_struct! {
    pub struct GimmickConstraintData<'a> {
        pub name: CString<'a>,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub raw: u32,
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
        pub tag: CString<'a>,
        pub tag_list: CArray<CString<'a>>,
    }
}

py_binary_struct! {
    pub struct GimmickGroupInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub main_gimmick_group_info_of_combination: u32,
        pub battery_init_capacity: u64,
        pub battery_total_capacity: u64,
        pub link_signal_group_list: CArray<GimmickProperty<'a>>,
        pub property_list: CArray<u32>,
        pub gimmick_tag_list: CArray<CString<'a>>,
        pub gimmick_chart_path: CString<'a>,
        pub gimmick_type: u8,
        pub gimmick_placement_style: u8,
        pub gimmick_interface_type: u8,
        pub gimmick_remote_catchable_data: [f32; 3],
        pub use_attack_target_owner_constraint: u8,
        pub use_self_constraint: u8,
        pub auto_targeting_constraint_data_list: CArray<GimmickConstraintData<'a>>,
        pub gimmick_constraint_data_list: CArray<GimmickConstraintData<'a>>,
        pub gimmick_info_list: CArray<u32>,
        pub game_event_handler_list: CArray<GameEventHandler>,
        pub unlockable_data_list: CArray<UnlockableData>,
        pub default_spawn_reason_hash: u32,
        pub initial_body_motion_type: u8,
        pub sequencer_level_allow_gimmick_event_key_list: CArray<u32>,
        pub sequencer_level_connect_alias_name_list: CArray<CString<'a>>,
        pub gimmick_alias_data_list: CArray<GimmickAliasData>,
        pub logout_time_after_break: u64,
        pub attack_by_collision_info_list_key: u32,
        pub flag_28_4: u8,
        pub flag_28_5: u8,
        pub flag_28_6: u8,
        pub flag_28_7: u8,
        pub flag_29_0: u8,
        pub flag_29_1: u8,
        pub flag_29_2: u8,
        pub flag_29_3: u8,
        pub flag_29_4: u8,
        pub flag_29_5: u8,
        pub flag_29_6: u8,
        pub flag_29_7: u8,
        pub flag_30_0: u8,
        pub flag_30_1: u8,
        pub flag_30_2: u8,
        pub flag_30_3: u8,
        pub flag_30_4: u8,
        pub flag_30_5: u8,
        pub flag_30_6: u8,
        pub attack_by_collision: GimmickAttackByCollisionData<'a>,
        pub flag_336: u8,
        pub raw_340: u32,
        pub flag_344: u8,
        pub flag_345: u8,
        pub flag_346: u8,
        pub flag_347: u8,
        pub flag_348: u8,
        pub flag_349: u8,
        pub flag_350: u8,
        pub flag_351: u8,
        pub flag_352: u8,
        pub flag_353: u8,
        pub flag_354: u8,
        pub flag_355: u8,
        pub flag_356: u8,
        pub allow_event_keys: CArray<CString<'a>>,
        pub block_event_keys: CArray<CString<'a>>,
        pub collision_tag_data_list: CArray<GimmickCollisionTagData<'a>>,
        pub interaction_data_list: CArray<GimmickInteractionData<'a>>,
        pub flag_424: u8,
        pub flag_425: u8,
        pub flag_426: u8,
        pub field_list: CArray<GimmickFieldEntry>,
        pub u32_pair_list: CArray<GimmickU32Pair>,
    }
}

impl<'a> GimmickGroupInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GimmickGroupInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickgroupinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickgroupinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                GimmickGroupInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "gimmickgroupinfo roundtrip mismatch");
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
            let item = GimmickGroupInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            GimmickGroupInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
