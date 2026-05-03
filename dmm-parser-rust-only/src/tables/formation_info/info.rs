// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `FormationInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

// Hand-corrected: empirical sweep across all 1233 vanilla member entries
// shows 21-byte elements split as 5×f32 + u8 (no NaN values present).
// First f32 looks like a position offset (varies signed); rest are
// formation parameters (most are 0.0 or constant 0.2).
py_binary_struct! {
    pub struct FormationMemberData {
        pub offset_a: f32,
        pub offset_b: f32,
        pub offset_c: f32,
        pub param_a: f32,
        pub param_b: f32,
        pub flag: u8,
    }
}

py_binary_struct! {
    pub struct FormationInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub member_data_list: CArray<FormationMemberData>,
        pub absolute_offset: u8,
        pub is_super_strict: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\formationinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(FormationInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "formationinfo roundtrip bytes mismatch");
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
            items.push(FormationInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FormationInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
