//! Full Tier 1 — every wire read decoded.
//!
//! Reader: `sub_1410F6600` in CrimsonDesert.exe (Win build).
//!
//! All helpers are non-polymorphic single-shot or CArray hash-lookups
//! at qword_145F0DAxx / qword_145F0E9C0 / qword_145F0DA40 / qword_145F0DA20.
//! Raw wire u16/u32 round-trip directly.
//!
//! Wire reads, in order (canonical names from Mac Korean error strings —
//! 1.3.5 audit re-mapped placeholder field names like `raw_24`, `lookup_36`,
//! `u8_64`, `list_72` to canonical `_timeLimit`, `_autoUseItemInfo`,
//! `_reserveSlotType`, `_enableTribeList`, etc.):
//!   1. u32 key                                  (_key)
//!   2. CString string_key                       (_stringKey)
//!   3. u8 is_blocked                            (_isBlocked)
//!   4. u64 time_limit                           (_timeLimit)
//!   5. u32 cool_time                            (_coolTime)
//!   6. u32 auto_use_item_info                   (_autoUseItemInfo,
//!      sub_1410FF5C0 → qword_145F0DA00)
//!   7. u32 convert_item_info                    (_convertItemInfo,
//!      sub_1410FF5C0 → qword_145F0DA00)
//!   8. CArray<ReserveSlotPairA> fill_data_list  (_fillDataList,
//!      element: u32 lookup sub_1410FF430 + u64)
//!   9. CString memo                             (_memo)
//!  10. u8 reserve_slot_type                     (_reserveSlotType)
//!  11. u8 using_type                            (_usingType)
//!  12. CArray<u32> enable_tribe_list            (_enableTribeList,
//!      sub_1410FF9A0 → qword_145F0DA50)
//!  13. CArray<u16> enable_vehicle_list          (_enableVehicleList,
//!      sub_1411075A0 → qword_145F0DA40)
//!  14. CArray<ReserveSlotPairB> enable_special_name_hash_list
//!      (_enableSpecialNameHashList, element: u32 read_u32_lookup_DA30 +
//!      u32 sub_1410FF430)
//!  15. CArray<u16> target_item_group_list       (_targetItemGroupList,
//!      sub_1411022B0 → qword_145F0DA20)
//!  16. u32 send_gimmick_event_key_for_slot_data_changed
//!      (_sendGimmickEventKeyForSlotDataChanged)
//!  17. u8 is_self_player_only                   (_isSelfPlayerOnly)


// ─────────────────────────────────────────────────────────────────────────
// CANONICAL FIELD CATALOG — pa::ReserveSlotInfo
// ─────────────────────────────────────────────────────────────────────────
//
// Schema source: NattKh/CrimsonDesertModdingTools `pabgb_complete_schema.json`
// (canonical PA names extracted from Korean error strings in CrimsonDesert.exe).
//
// Total canonical fields:  17
// Decoded by dmm-parser:   17
// Missing in this struct:  0
//
// ✅ = present in this struct (round-trips via shape='v3.1')
// ⏳ = in canonical schema but not yet decoded by dmm-parser
//
// ✅ _sendGimmickEventKeyForSlotDataChanged (direct_u32, stream=4)
// ✅ _targetItemGroupList (reader_2B, stream=2)
// ✅ _isSelfPlayerOnly
// ✅ _fillDataList
// ✅ _convertItemInfo (reader_4B, stream=4)
// ✅ _reserveSlotType (direct_13B, stream=13)
// ✅ _memo
// ✅ _enableTribeList
// ✅ _usingType (direct_13B, stream=13)
// ✅ _enableSpecialNameHashList
// ✅ _enableVehicleList (reader_2B, stream=2)
// ✅ _stringKey
// ✅ _key
// ✅ _timeLimit (direct_u64, stream=8)
// ✅ _isBlocked (direct_13B, stream=13)
// ✅ _autoUseItemInfo (reader_4B, stream=4)
// ✅ _coolTime (direct_u32, stream=4)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct ReserveSlotPairA {
        pub lookup: u32,
        pub raw_bytes: u64,
    }
}

py_binary_struct! {
    pub struct ReserveSlotPairB {
        pub lookup_a: u32,
        pub lookup_b: u32,
    }
}

py_binary_struct! {
    pub struct ReserveSlotInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub time_limit: u64,
        pub cool_time: u32,
        pub auto_use_item_info: u32,
        pub convert_item_info: u32,
        pub fill_data_list: CArray<ReserveSlotPairA>,
        pub memo: CString<'a>,
        pub reserve_slot_type: u8,
        pub using_type: u8,
        pub enable_tribe_list: CArray<u32>,
        pub enable_vehicle_list: CArray<u16>,
        pub enable_special_name_hash_list: CArray<ReserveSlotPairB>,
        pub target_item_group_list: CArray<u16>,
        pub send_gimmick_event_key_for_slot_data_changed: u32,
        pub is_self_player_only: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"/mnt/c/temp/GIT/CrimsonDesertUpdates/pabgb/2026-5-1/reserveslot.pabgb";
    const PABGH: &str = r"/mnt/c/temp/GIT/CrimsonDesertUpdates/pabgb/2026-5-1/reserveslot.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                ReserveSlotInfo::read_from(&data, &mut c)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e, "entry {} key=0x{:x}: cursor at {} expected {}", i, k, c, e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "reserveslot roundtrip mismatch");
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
            let mut c = *start;
            let item = ReserveSlotInfo::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            ReserveSlotInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
