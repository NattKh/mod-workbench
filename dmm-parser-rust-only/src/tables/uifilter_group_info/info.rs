// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `UIFilterGroupInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

// Hand-corrected: per IDA sub_1410FE310 + sub_141108060 + sub_1411082E0,
// the schema is fully nested. UIFilterIconData = {u32 + u32 + u8} (sub_1411082E0
// inner element). UIFilterData = {CArray<UIFilterIconData> + u32 + u32 +
// LocalizableString + u8}. ui_icon_path on outer is u32 (file format - the
// hash-lookup result is u16 in memory but the file holds the u32 lookup key).
py_binary_struct! {
    pub struct UIFilterIconData {
        pub icon_lookup_a: u32,
        pub icon_lookup_b: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    pub struct UIFilterData<'a> {
        pub ui_filter_icon_data_list: CArray<UIFilterIconData>,
        pub ui_filter_key: u32,
        pub ui_icon_path: u32,
        pub ui_icon_name: LocalizableString<'a>,
        pub is_icon_visible: u8,
    }
}

py_binary_struct! {
    pub struct UIFilterGroupInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub ui_filter_data_list: CArray<UIFilterData<'a>>,
        pub ui_group_name: LocalizableString<'a>,
        pub ui_icon_path: u32,
        pub filter_type: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\uifiltergroupinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(UIFilterGroupInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "uifiltergroupinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(UIFilterGroupInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            UIFilterGroupInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
