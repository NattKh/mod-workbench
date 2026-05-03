// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! IDA-derived parser for `FieldInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of `sub_1410E0940` in the
//! current Win exe (CrimsonDesert.exe). Each record is 121 wire bytes
//! (variable in principle via the embedded CString, but all 7 vanilla
//! records ship with an empty string and round-trip exactly at 121 B).
//!
//! The reader walks 26 wire reads in fixed order:
//!   key (u32) → CString → byte → 2× u32-lookup → u32 → 4× byte
//!   → u32-lookup → 12 B blob → 8 B blob → 8 B blob → 4× u32
//!   → u16-lookup → byte → byte → 31 B composite (sub_141B64FF0/sub_14EB7E370)
//!   → 3× u32-lookup → byte
//!
//! `lookup` fields carry an obfuscated hash on the wire; the game maps it to
//! a u16 index at runtime via global dictionaries (qword_145F0DA30,
//! qword_145F290B8, qword_145F113D8). For round-trip we just preserve the
//! raw wire bytes (u32 for read_u32_lookup_DA30 / sub_1410FEDA0, u16 for
//! sub_141100C20). Mods can edit the hash directly.
//!
//! The 31 B `composite` block (sub_14EB7E370 → thunked from sub_141B64FF0)
//! has its own sub-schema verified via the obfuscated offset
//!   dword_156574B78 (0xA20F5263) ^ 0xA20F5253 = 0x10
//! which puts the 5th u32 read at composite +16. Wire order: u32 ×5, u8,
//! u16, [u8;8] = 31 bytes, struct +0..+24 (with 1 B padding at +21).

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    /// 31-byte sub-block read by sub_14EB7E370. Wire layout matches the
    /// declaration order; struct reserves a padding byte between
    /// `byte_at_20` and `u16_at_22` (game uses standard C alignment for the
    /// in-memory copy, but the wire stream skips the pad).
    pub struct FieldInfoComposite {
        pub u32_a: u32,
        pub u32_b: u32,
        pub u32_c: u32,
        pub u32_d: u32,
        pub u32_e: u32,
        pub byte_at_20: u8,
        pub u16_at_22: u16,
        pub blob_8: u64,
    }
}

py_binary_struct! {
    pub struct FieldInfo<'a> {
        // Header — key + name. The string_key is empty in all 7 vanilla
        // records but the wire format reserves a u32 length prefix.
        pub key: u32,
        pub string_key: CString<'a>,

        // First scalar block. The two `lookup_*` fields carry a u32 hash on
        // the wire; the game looks them up in qword_145F0DA30 to get a u16
        // index. `unk_u32_b` stays a raw u32 (no lookup).
        pub byte_at_16: u8,
        pub lookup_u32_a: u32,
        pub lookup_u32_b: u32,
        pub unk_u32_b: u32,
        pub byte_at_28: u8,
        pub byte_at_29: u8,
        pub byte_at_30: u8,
        pub byte_at_31: u8,
        pub lookup_u32_c: u32,

        // Three typed Vec/pair fields. Doc previously kept these as raw
        // bytes; promoted to typed floats per the field-level rule (json
        // round-trip verified — no NaN bit patterns in vanilla data).
        pub bounds: [f32; 3],
        pub size_pair: [f32; 2],
        pub height_pair: [f32; 2],

        // Per-slot NaN probe across all 7 vanilla entries:
        //   unk_u32_d: 7/7 NaN  → must stay u32 (NaN bit patterns)
        //   unk_u32_e: 6/7 NaN  → must stay u32
        //   unk_u32_f: 2/7 NaN  → must stay u32 (some entries have NaN)
        //   unk_u32_g: 0/7 NaN  → safe to promote to f32 (clean floats)
        pub unk_u32_d: u32,
        pub unk_u32_e: u32,
        pub unk_u32_f: u32,
        pub unk_f32_g: f32,

        // u16 lookup via sub_141100C20 → qword_145F290B8.
        pub lookup_u16_a: u16,
        pub byte_at_82: u8,
        pub byte_at_83: u8,

        // 31-byte composite. Decoded into typed fields so per-field mod
        // edits work; round-trip is exact.
        pub composite: FieldInfoComposite,

        // Final three u32 lookups via the same dictionary as the trailing
        // u16-cast at struct +120/+122/+124 in the IDA decompile. The
        // wire format is u32 hash; the game stores u16 indices at runtime.
        pub lookup_u32_d: u32,
        pub lookup_u32_e: u32,
        pub lookup_u32_f: u32,
        pub byte_at_126: u8,
        pub always_call_vehicle_dev: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\fieldinfo.pabgb";


    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP: missing fixture {}", PABGB);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            let item = FieldInfo::read_from(&data, &mut offset)
                .unwrap_or_else(|e| panic!("read at offset {}: {}", offset, e));
            items.push(item);
        }
        assert_eq!(offset, data.len(), "did not consume all bytes ({}/{} remaining)",
                   data.len() - offset, data.len());
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "fieldinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP: missing fixture {}", PABGB);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(FieldInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            FieldInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {}: write_from_json_dict: {}", i, e));
            assert_eq!(
                from_json, from_typed,
                "entry {}: JSON round-trip diverges from typed write", i
            );
        }
    }
}
