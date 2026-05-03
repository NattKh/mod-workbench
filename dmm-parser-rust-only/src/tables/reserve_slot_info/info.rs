// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Full Tier 1 — every wire read decoded.
//!
//! Reader: `sub_1410F6600` in CrimsonDesert.exe (Win build).
//!
//! All helpers are non-polymorphic single-shot or CArray hash-lookups
//! at qword_145F0DAxx / qword_145F0E9C0 / qword_145F0DA40 / qword_145F0DA20.
//! Raw wire u16/u32 round-trip directly.
//!
//! Wire reads, in order:
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. u64 raw_24
//!   5. u32 u32_32
//!   6. u32 lookup_36 (sub_1410FF5C0 → qword_145F0DA00)
//!   7. u32 lookup_38 (sub_1410FF5C0 → qword_145F0DA00)
//!   8. CArray<ReserveSlotPairA> pair_list_a (inline: u32 lookup
//!      sub_1410FF430 + u64)
//!   9. CString second_string
//!  10. u8 u8_64
//!  11. u8 u8_65
//!  12. CArray<u32> list_72 (sub_1410FF9A0 → qword_145F0DA50)
//!  13. CArray<u16> list_88 (sub_1411075A0 → qword_145F0DA40)
//!  14. CArray<ReserveSlotPairB> pair_list_b (inline: u32
//!      read_u32_lookup_DA30 + u32 sub_1410FF430)
//!  15. CArray<u16> list_120 (sub_1411022B0 → qword_145F0DA20)
//!  16. u32 u32_136
//!  17. u8 u8_140

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
        pub raw_24: u64,
        pub u32_32: u32,
        pub lookup_36: u32,
        pub lookup_38: u32,
        pub pair_list_a: CArray<ReserveSlotPairA>,
        pub second_string: CString<'a>,
        pub u8_64: u8,
        pub u8_65: u8,
        pub list_72: CArray<u32>,
        pub list_88: CArray<u16>,
        pub pair_list_b: CArray<ReserveSlotPairB>,
        pub list_120: CArray<u16>,
        pub u32_136: u32,
        pub u8_140: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\reserveslot.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\reserveslot.pabgh";

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
