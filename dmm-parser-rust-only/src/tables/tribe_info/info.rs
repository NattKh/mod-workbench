//! Full Tier 1 — every wire read decoded.
//!
//! Reader: `sub_1410FBC30` in CrimsonDesert.exe (Win build).
//!
//! ─── v3.1 closure plan (iter 109) ───────────────────────────────────────
//! Cross-checked via the iter-42-registry per-record reader
//! `sub_1410C8A20`. Wire-read sequence (mem offsets):
//!
//!   wire 0   4 bytes        key (u32)              SHIPPED → _key
//!   wire 4   CString        string_key             SHIPPED → _stringKey
//!   wire 8   1 byte         is_blocked             SHIPPED → _isBlocked
//!   wire 9   sub_1410CD790  lookup_a (4B → u16 mem 18)  ⏳ reader_4B
//!   wire 13  sub_1410CBB90  lookup_b (4B → u16 mem 20)  ⏳ reader_4B
//!   wire 17  1 byte         unk_22                       ⏳ direct_u8
//!   wire 18  4 bytes        unk_24                       ⏳ direct_u32
//!   wire 22  9× 1 byte      unk_28..36                   ⏳ 9 direct_u8 booleans
//!   wire 31  3× 4 bytes     unk_40, unk_44, unk_48       ⏳ 3 direct_u32
//!   wire 43  CString        unk_56                  iter 108 → _tribeNameForEditor
//!   wire ?   4× 4 bytes     unk_64..76                   ⏳ 4 direct_u32
//!   wire ?   2× 1 byte      unk_80, unk_81               ⏳ 2 direct_u8
//!   wire ?   4 bytes        unk_84                       ⏳ direct_u32
//!   wire ?   8 bytes raw    unk_88 (u64)                 ⏳ NO direct_u64 in
//!                            schema — possibly 2× direct_u32 packed,
//!                            or a [f32;2]?
//!   wire ?   sub_1410CCE80  ref_list (CArray<u32>)       ⏳ reader_4B
//!
//! Schema has 4 reader_4B canonicals (excluding _key): _footStepTypeEffectName,
//! _tamedSkillList, _ignoredReactionInSafeZoneFlag, _parentTribeInfo. The 3
//! reader_4B wire reads at mem 18 / mem 20 / ref_list need 1 more candidate
//! mapping — possibly _parentTribeInfo lives in one of the unk_64..76 slots
//! (since "parent tribe info" semantically = "u32 reference to another
//! tribe's _key" which is just a raw u32, not a CArray).
//!
//! Strong candidate ships (next iter, with semantic disambiguation):
//!   ref_list       → _tamedSkillList       (only CArray = list-of-skills)
//!   lookup_a / b   → _footStepTypeEffectName + _ignoredReactionInSafeZoneFlag
//!                    (need IDA function-string-associate to confirm order)
//!
//! schema verifier: 4 of 29 verified after iter 108. 25 still pending.
//!
//! Every helper in the read chain is non-polymorphic (u32 lookups via
//! `sub_1411008D0`, `read_u32_lookup_DA30`, plus a CArray<u32> via
//! `sub_141100090`). No COptional, no `sub_141D8C6D0` dispatcher. Wire
//! reads in order:
//!
//!   1. u32 key (via `sub_141BF6400` writer wrapper, wire 4)
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. u32 lookup_a (sub_1411008D0 → qword_145F0DA50, wire 4 / store u32 raw)
//!   5. u32 lookup_b (read_u32_lookup_DA30 → qword_145F0DA30, wire 4)
//!   6. u8 unk_22
//!   7. u32 unk_24
//!   8. 9× u8 (unk_28..unk_36)
//!   9. u32 unk_40, unk_44, unk_48
//!  10. CString unk_56
//!  11. u32 unk_64, unk_68, unk_72, unk_76
//!  12. u8 unk_80, unk_81
//!  13. u32 unk_84
//!  14. u64 unk_88 (read as 8 raw bytes)
//!  15. CArray<u32> ref_list (sub_141100090: count + N×u32 lookup hashes)
//!
//! All field NAMES are placeholder (`unk_<offset>`); semantics aren't
//! confirmed yet. Mods can edit any field by raw value; renaming when
//! Mac symbol-cross-reference confirms meaning is mechanical.


// ─────────────────────────────────────────────────────────────────────────
// CANONICAL FIELD CATALOG — pa::TribeInfo
// ─────────────────────────────────────────────────────────────────────────
//
// Schema source: NattKh/CrimsonDesertModdingTools `pabgb_complete_schema.json`
// (canonical PA names extracted from Korean error strings in CrimsonDesert.exe).
//
// Total canonical fields:  29
// Decoded by dmm-parser:   3
// Missing in this struct:  26
//
// ✅ = present in this struct (round-trips via shape='v3.1')
// ⏳ = in canonical schema but not yet decoded by dmm-parser
//
// ✅ _key (reader_4B, stream=4)
// ✅ _isBlocked (direct_u8, stream=1)
// ✅ _stringKey
// ⏳ _footStepTypeEffectName (reader_4B, stream=4)
// ⏳ _parentTribeInfo
// ⏳ _bumpTypeHash (direct_u32, stream=4)
// ⏳ _tribeMassLevel (direct_u8, stream=1)
// ⏳ _wantedCrimeType (direct_u8, stream=1)
// ⏳ _footMaterialKey (direct_u32, stream=4)
// ⏳ _characterPauseType (direct_u32, stream=4)
// ⏳ _interactionUIDistanceLv (direct_u8, stream=1)
// ⏳ _tamedSkillList (reader_4B, stream=4)
// ⏳ _ignoredReactionInSafeZoneFlag (reader_4B, stream=4)
// ⏳ _detourMaxDegree (direct_u32, stream=4)
// ⏳ _ignoreWaterFall (direct_u8, stream=1)
// ⏳ _velocityDampSpeed (direct_u32, stream=4)
// ⏳ _activityWaterDepth (direct_u32, stream=4)
// ⏳ _weaponMaterialKey (direct_u32, stream=4)
// ⏳ _tribeNameForEditor
// ⏳ _armorMaterialKey (direct_u32, stream=4)
// ⏳ _baseMaterialKey (direct_u32, stream=4)
// ⏳ _isBird (direct_u8, stream=1)
// ⏳ _isHumanoid (direct_u8, stream=1)
// ⏳ _hasChild (direct_u8, stream=1)
// ⏳ _isDeathByDrowning (direct_u8, stream=1)
// ⏳ _detourOnRoad (direct_u8, stream=1)
// ⏳ _detectModeShowEnemy (direct_u8, stream=1)
// ⏳ _escapePlatform (direct_u8, stream=1)
// ⏳ _ignoreOverlapPush (direct_u8, stream=1)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct TribeInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub unk_22: u8,
        pub unk_24: u32,
        pub unk_28: u8,
        pub unk_29: u8,
        pub unk_30: u8,
        pub unk_31: u8,
        pub unk_32: u8,
        pub unk_33: u8,
        pub unk_34: u8,
        pub unk_35: u8,
        pub unk_36: u8,
        pub unk_40: u32,
        pub unk_44: u32,
        pub unk_48: u32,
        pub unk_56: CString<'a>,
        pub unk_64: u32,
        pub unk_68: u32,
        pub unk_72: u32,
        pub unk_76: u32,
        pub unk_80: u8,
        pub unk_81: u8,
        pub unk_84: u32,
        pub unk_88: u64,
        pub ref_list: CArray<u32>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"/mnt/c/temp/GIT/CrimsonDesertUpdates/pabgb/2026-5-1/tribeinfo.pabgb";
    const PABGH: &str = r"/mnt/c/temp/GIT/CrimsonDesertUpdates/pabgb/2026-5-1/tribeinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                TribeInfo::read_from(&data, &mut c)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e, "entry {} key=0x{:x}: cursor at {} expected {}", i, k, c, e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "tribeinfo roundtrip mismatch");
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
            let item = TribeInfo::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            TribeInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
