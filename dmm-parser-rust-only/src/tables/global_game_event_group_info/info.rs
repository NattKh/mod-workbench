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
//! Reader: `sub_1410E3C20` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order:
//!   1. u16 key (pabgh format 2)
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. CArray<u16> events (via sub_141104870: u32 count + N×u16
//!      hash-keyed at qword_145F0E9D0; raw u16 round-trips)
//!   5. u64 tail_qword (8 raw bytes; promoted from [u8;8] for field-level
//!      JSON access — semantic could be u64 or packed 2× u32)
//!
//! No polymorphic helpers, no COptional, no nested CArrays.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct GlobalGameEventGroupEventData {
        pub field_a: u32,
        pub field_b: u64,
        pub field_c: u64,
        pub field_d: u32,
    }
}

py_binary_struct! {
    pub struct GlobalGameEventGroupInfo<'a> {
        pub key: u16,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub priority: u32,
        pub cooltime: u64,
        pub duration: u64,
        pub flags: u32,
        pub event_data_list: CArray<GlobalGameEventGroupEventData>,
        pub event_key_list: CArray<u16>,
        pub field_info_key: u32,
        pub is_enabled: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalgameeventgroup.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalgameeventgroup.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                GlobalGameEventGroupInfo::read_from(&data, &mut c)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e, "entry {} key=0x{:x}: cursor at {} expected {}", i, k, c, e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "globalgameeventgroup roundtrip mismatch");
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
            let item = GlobalGameEventGroupInfo::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            GlobalGameEventGroupInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
