// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser.
//!
//! Reader (Mac CrimsonDesert_Steam):
//!   - Entry-level: `sub_10185B044` at 0x10185B044.
//!   - `_boardDataGroupList` element reader: `sub_10185ADC4` at 0x10185ADC4
//!     (Korean error strings inside name every BoardDataGroup field).
//!
//! Wire layout (in order; canonical names from Mac Korean error strings):
//!   BoardInfo (sub_10185B044):
//!     1. u32 key
//!     2. CString string_key
//!     3. u8  is_blocked
//!     4. CArray<BoardSubItem> board_data_list
//!     5. CArray<BoardDataGroup> board_data_group_list
//!
//!   BoardSubItem (sub_141118F10 / Mac equiv) — element of board_data_list:
//!     - u32 u32_a (raw)
//!     - u32 lookup_b (sub_1410FF5C0 lookup hash)
//!     - u32 lookup_c (sub_1410FF430 lookup hash)
//!     Total 12 wire bytes.
//!
//!   BoardDataGroup (sub_10185ADC4) — element of board_data_group_list:
//!     1. [u8;8] spawn_percent      (sub_1006B3DA0 = vtable[2] width 8;
//!        kept opaque so f64/u64 NaN canonicalization can't break the
//!        byte-perfect round-trip)
//!     2. u32 total_rate            (sub_1006B3D80 = u32 reader)
//!     3. u8  category              (vtable[2] width 1)
//!     4. LocalizableString name    (sub_1006D8484, struct stride 32)
//!     5. u32 condition             (ConditionKey hash; runtime looks up
//!        to u16 at struct +48 via StaticInfoWrapper<ConditionKey,
//!        ConditionInfo, ConditionInfoManager, unsigned short>)
//!     6. u32 player_condition      (same ConditionKey lookup pattern at
//!        struct +50)
//!     7. CArray<BoardSubItem> board_data_list (same shape as outer)
//!     C++ struct slot stride is 72 bytes (with 3+4 bytes of memory
//!     padding around `_category` and the `_condition`/`_playerCondition`
//!     u16 lookup results) — wire is tightly packed.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct BoardSubItem {
        pub u32_a: u32,
        pub lookup_b: u32,
        pub lookup_c: u32,
    }
}

py_binary_struct! {
    pub struct BoardDataGroup<'a> {
        // Promoted [u8;8] → u64 — preserves any NaN bit patterns
        // losslessly through JSON (u-types don't normalize NaN).
        pub spawn_percent: u64,
        pub total_rate: u32,
        pub category: u8,
        pub name: LocalizableString<'a>,
        pub condition: u32,
        pub player_condition: u32,
        pub board_data_list: CArray<BoardSubItem>,
    }
}

py_binary_struct! {
    pub struct BoardInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub board_data_list: CArray<BoardSubItem>,
        pub board_data_group_list: CArray<BoardDataGroup<'a>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\board.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\board.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = BoardInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "entry {} k=0x{:x} consumed {} of {} bytes", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "board roundtrip mismatch");
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
            let item = BoardInfo::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            BoardInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
