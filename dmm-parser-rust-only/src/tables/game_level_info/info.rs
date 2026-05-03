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
//! Reader: `sub_1410E4F30` in CrimsonDesert.exe (Win build), discovered
//! via xref to "GameLevelInfo" string at 0x144afad10.
//!
//! Wire reads, in order (canonical names from
//! `docs/449_TABLE_CATALOG.md` GameLevelInfo section, 6 fields):
//!   1. u32 key                               (_key)
//!   2. CString string_key                    (_stringKey)
//!   3. u8 is_blocked                         (_isBlocked)
//!   4. u32 default_level_data_name           (_defaultLevelDataName,
//!      read_u32_lookup_DA30 — wire u32, mem u16)
//!   5. u16 update_region_info                (_updateRegionInfo,
//!      sub_1410FF220 — wire u16, mem u16)
//!   6. CArray<GameLevelData> level_data_list (_levelDataList,
//!      sub_141112EA0; per element: 3× u32 lookup + CArray<u32> + u8 —
//!      32 mem bytes / 5 wire fields)
//!
//! GameLevelData (sub_141112EA0 inner):
//!   - lookup_a: u32 (read_u32_lookup_DA30)
//!   - lookup_b: u32 (sub_1410FF430)
//!   - lookup_c: u32 (sub_141104340)
//!   - list: CArray<u32> (sub_1410FEF40 → qword_145F0DA30)
//!   - flag: u8

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct GameLevelData {
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub lookup_c: u32,
        pub list: CArray<u32>,
        pub flag: u8,
    }
}

py_binary_struct! {
    pub struct GameLevelInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub default_level_data_name: u32,
        pub update_region_info: u16,
        pub level_data_list: CArray<GameLevelData>,
    }
}

impl<'a> GameLevelInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GameLevelInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\levelinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\levelinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = GameLevelInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "gamelevelinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = GameLevelInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            GameLevelInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
