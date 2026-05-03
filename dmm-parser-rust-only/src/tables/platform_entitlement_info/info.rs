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
//! Reader (Win): `sub_1410F3830` in CrimsonDesert.exe, discovered via
//! xref to "PlatformEntitlementInfo" string at 0x144b13490. Mac equivalent
//! `sub_10184B44C` at 0x10184B44C (size 0x220).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u16 key                            (_key, pabgh format 2)
//!   2. CString string_key                 (_stringKey)
//!   3. u8 is_blocked                      (_isBlocked)
//!   4. LocalizableString entitlement_name (_entitlementName)
//!   5. LocalizableString entitlement_desc (_entitlementDesc)
//!   6. u32 icon_path                      (_iconPath, read_u32_lookup_DA30
//!      — wire u32, mem u16)
//!   7. u8 type_                           (_type)
//!   8. CArray<u32> result_drop_info_list  (_resultDropInfoList,
//!      sub_141100510 → qword_145F113C8 — wire u32, mem u16)
//!   9. CArray<PlatformIdEntry> platform_id_list (_platformIdList; inline
//!      CArray, per element CString platform (sub_1410A9D40 — reads
//!      CString, hashes to u32 in mem) + CString sku/code)
//!
//! sub_1410A9D40 reads a CString (u32 len + bytes) and hashes to u32 for
//! the in-memory key. Roundtrip stores both source CString + sku CString.
//!
//! All fields typed. JSON-addressable for full mod-editing.

use crate::binary::*;
use crate::py_binary_struct;

// _platformIdList inner element — sub_1410F3830 inline loop.
// Wire: CString platform ("PS5"/"XBOX"/"EPIC"/...) + CString sku.
py_binary_struct! {
    pub struct PlatformIdEntry<'a> {
        pub platform: CString<'a>,
        pub sku: CString<'a>,
    }
}

py_binary_struct! {
    pub struct PlatformEntitlementInfo<'a> {
        pub key: u16,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub entitlement_name: LocalizableString<'a>,
        pub entitlement_desc: LocalizableString<'a>,
        pub icon_path: u32,
        pub type_: u8,
        pub result_drop_info_list: CArray<u32>,
        pub platform_id_list: CArray<PlatformIdEntry<'a>>,
    }
}

impl<'a> PlatformEntitlementInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> std::io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("PlatformEntitlementInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\entitlementinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\entitlementinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                PlatformEntitlementInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "platformentitlementinfo roundtrip mismatch");
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
            let item = PlatformEntitlementInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            PlatformEntitlementInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
