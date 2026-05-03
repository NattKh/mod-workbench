// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `DetectReactionInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

// Hand-corrected: parser reads a 5x12=60 byte fixed block for _reactionTable
// (nested for-loop in the IDA decompile — 60 individual u8 reads).
// Promoted to typed 5-row struct with 12 named cells per row.
// Each cell is a small enum value (0x01, 0x15, 0x17, 0x2a, 0x2d, 0x3b
// observed in vanilla); JSON consumers can edit any individual cell.
py_binary_struct! {
    pub struct DetectReactionRow {
        pub c0: u8, pub c1: u8, pub c2: u8, pub c3: u8,
        pub c4: u8, pub c5: u8, pub c6: u8, pub c7: u8,
        pub c8: u8, pub c9: u8, pub c10: u8, pub c11: u8,
    }
}

py_binary_struct! {
    pub struct DetectReactionInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub reaction_row_0: DetectReactionRow,
        pub reaction_row_1: DetectReactionRow,
        pub reaction_row_2: DetectReactionRow,
        pub reaction_row_3: DetectReactionRow,
        pub reaction_row_4: DetectReactionRow,
        pub buff_reaction_type: u8,
        pub strong_buff_reaction_type: u8,
        pub player_sensible_reaction_type: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\detectreactioninfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(DetectReactionInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "detectreactioninfo roundtrip bytes mismatch");
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
            items.push(DetectReactionInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            DetectReactionInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
