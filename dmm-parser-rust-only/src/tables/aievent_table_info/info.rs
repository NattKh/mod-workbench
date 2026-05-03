// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `AIEventTableInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.

use crate::binary::*;
use crate::py_binary_struct;

// Hand-corrected: the auto-extractor saw `key` as [u8;12] but empirical
// sweep across 937 entries shows a structured 12-byte composite:
//   - u16 head sentinel (always 0xFFFF — hash-result default)
//   - u16 padding (always 0)
//   - u32 random hash
//   - u32 trailing value (0xFFFFFFFF in 928/937, varies in 9)
py_binary_struct! {
    pub struct AIEventTableInfo<'a> {
        pub key_head: u16,
        pub key_pad: u16,
        pub key_hash: u32,
        pub key_tail: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub show_name: CString<'a>,
        pub delegate_event_handler: u32,
        pub reaction_level: u32,
        pub allow_type_flag: u32,
        pub event_type: u32,
        pub event_delay_type: u64,
        pub is_sequencer_interrupt_event: u8,
        pub is_target_must_exist: u8,
        pub is_must_handled: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\aieventtableinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(AIEventTableInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "aieventtableinfo roundtrip bytes mismatch");
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
            items.push(AIEventTableInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            AIEventTableInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {}: write_from_json_dict: {}", i, e));
            assert_eq!(
                from_json, from_typed,
                "entry {}: JSON round-trip diverges from typed write", i
            );
        }
    }
}
