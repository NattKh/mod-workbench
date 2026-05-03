// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser. All 174 wire fields editable; tail blob
//! is empty for every vanilla entry (see `roundtrip` test which prints
//! `0 nonempty tails`). The `pabgh_typed_blob_table!` macro now omits
//! `_tail_b64` from JSON output when the tail Vec is empty, and the
//! `json_roundtrip` test asserts the field never leaks.
//!
//! Reader: `sub_1410D7480` in CrimsonDesert.exe (Win build). Massive
//! 8616-byte function — largest pabgb reader in the binary. Reader
//! string xref via " CharacterInfo" (with leading space) at 0x144ae12e0.
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. LocalizableString name
//!   5. LocalizableString desc
//!   6. u32 ui_icon_path                   (read_u32_lookup_DA30 wire u32)
//!   7. u32 category                       (read_u32_lookup_DA30 wire u32)
//!   8. CString character_edit_name
//!   9. u8 spawn_actor_type
//!  10. u8 none_player_sub_type
//!  11. u32 equip_info                     (inline → qword_145F0EF30)
//!  12. u32 npc_info                       (inline → qword_145F15060)
//!  13. u16 vehicle_info                   (sub_1411007B0 wire u16)
//!  14. u64 call_mercenary_cool_time       (8 raw bytes)
//!  15. u64 call_mercenary_spawn_duration  (8 raw bytes)
//!  16. u8 mercenary_cool_time_type
//!  17. CharacterActionChartEntry upper_chart  (u32 group + u16 package)
//!  18. CharacterActionChartEntry lower_chart  (u32 group + u16 package)
//!  19. u32 character_game_play_data_name  (sub_141100860 wire u32)
//!  20. u32 appearance_name                (read_u32_lookup_DA30 wire u32)
//!  21. u32 character_prefab_path
//!  22. u32 skeleton_name
//!  23. u32 lookup_22
//!  24. u32 lookup_23
//!  25. u32 lookup_24
//!  26. u32 lookup_25
//!  27. u32 raw_a                          (4 raw bytes at +156)
//!  28. u32 lookup_27                      (read_u32_lookup_DA30)
//!  29. u32 lookup_28                      (read_u32_lookup_DA30)
//!  30. u32 lookup_29                      (sub_1411008D0 wire u32)
//!  31. u32 raw_b                          (at +168)
//!  32. u32 lookup_31                      (read_u32_lookup_DA30)
//!  33. u32 raw_c                          (at +176)
//!  34. u32 raw_d                          (at +180)
//!  35. u8 flag_a                          (at +184)
//!  36. u8 flag_b
//!  37. u8 flag_c
//!  38. u8 flag_d                          (sub_141100950 wire u8)
//!  39. LocalizableString label_a          (at +192, 32 mem bytes)
//!  40. u32 lookup_36                      (sub_1410FF340 wire u32, at +224)
//!  41. u8 flag_e                          (at +226)
//!  42. u16 raw_e                          (at +228, 2 raw bytes)
//!  43. CharacterFourFlags four_flags      (sub_1410E0380, 4× u8 at +230)
//!  44-82. 39× u8 flags                    (at +234 through +272)
//!  83. u32 raw_f                          (at +276)
//!  84. u32 lookup_77                      (read_u32_lookup_DA30, at +280)
//!  85. u32 lookup_78                      (at +282)
//!  86. CArray<u64> list_a                 (sub_141100A00 — per element
//!      u32 lookup (sub_1410FEBE0) + u32 raw)
//!  87. CArray<u64> list_b                 (sub_141100A00)
//!  88. CArray<u64> list_c                 (sub_141100A00)
//!  89. CArray<u64> list_d                 (sub_141100A00)
//!  90. CArray<u32> list_e                 (sub_141100B10 → qword_145F0DA78)
//!  91. u32 raw_g                          (at +368)
//!  92. u32 lookup_84                      (sub_141BF63C0 wire u32)
//!  93. CArray<u32> list_f                 (sub_141F8F830 — per element 4
//!      wire bytes hashed via sub_141BF61C0)
//!  94. u32 raw_h                          (4 raw bytes at +392)
//!  95. u8 flag_85                         (at +396)
//!  96. u8 flag_86                         (at +397)
//!  97. u32 lookup_87                      (inline u32 → qword_145F113B0
//!      hash lookup → u16 at +398)
//!  98. u8 flag_88                         (at +400)
//!  99. u32 lookup_89                      (sub_1411006D0 wire u32, +402)
//! 100. u8 flag_90                         (at +404)
//! 101. CArray<CharacterMercenaryEntry> mercenary_list (sub_141118980 →
//!      sub_1410D9880; 96 mem bytes / 20 wire fields per entry incl.
//!      CString hash, LocalizableString, 4 lookups, 11 raw u8/u32)
//! 102. CArray<u16> list_g                 (sub_1410FF0C0 wire u16)
//! 103. u8 flag_91                         (at +440)
//!      ← TAIL STARTS HERE
//! 104. (tail, conditional) when flag_91 == 0: sub_141105AC0 reads u32
//!      wire / u16 mem at +442. When flag_91 != 0, this read is SKIPPED.
//!      Vanilla distribution: flag_91 == 0 (2035 entries), flag_91 == 2
//!      (4931 entries). Promotion past field 103 requires manual impl
//!      to dispatch on flag_91 — pabgh_typed_blob_table macro can't
//!      express conditional reads.
//! 105. (tail) sub_141100C20 — u16 wire / u16 mem at +444
//! 106. (tail) 2 raw bytes (u16) at +446
//! 107. (tail) u8 at +448
//! 108. (tail) u8 at +449
//! 109. (tail) sub_1410FFAC0 — CArray<u16> at +456
//! 110. (tail) u8 at +472
//! 111. (tail) CString at +480
//! 112. (tail) sub_1410FEE90 — u16 wire / u16 mem at +488
//! 113. (tail) inline u16 wire / u16 mem at +490 (qword_145F290C0 lookup)
//! 114. (tail) sub_141100C90 — u32 wire / u16 mem at +492
//! 115. (tail) sub_141100D00 — u32 wire / u16 mem at +494 (post-process
//!      via sub_141BF6720)
//! 116. (tail) 4 raw bytes (u32) at +496
//! 117. (tail) u8 at +500
//! 118. (tail) sub_141100510 — CArray<u32> at +504
//! 119. (tail) sub_1410FF890 — CArray<u32> at +520
//! 120. (tail) sub_1410FF890 — CArray<u32> at +536
//! 121. (tail) 4 raw bytes (u32) at +552
//! 122. (tail) sub_1411187E0 — CArray of 12-wire-byte items (u16 lookup
//!      sub_141100370 + u32 raw + u32 raw) at +560
//! 123. (tail) u8 at +576
//! 124. (tail) sub_141100510 — CArray<u32> at +584
//! 125. (tail) sub_141100D80 — CArray of 64-byte items via sub_1410D7170
//!      (per element: 2 u32 lookups + 7× u64 = 64 wire bytes) at +600
//! 126. (tail) sub_141100E90 — CArray<FactionAdjacencyMobItem> at +616
//! 127-128. (tail) 2× sub_141118620 — CArray of 24-byte items per element
//!      (u32 lookup + u64 raw + u32 raw + u32 lookup = 20 wire bytes)
//!      at +632 and +648
//!
//! Steps 1-172 typed via incremental walk through sub_1410D7480
//! (8616-byte function decompiled to a tool-results file then
//! grep-traversed). Reusable per-element substructs:
//!
//!   CharacterField136Entry  — 32-byte stride (CArray<u32> + 3 lookups
//!                             + u64), used by sub_1411181F0 at +760.
//!   CharacterField137Entry  — 8-byte stride (2× u32 lookup), used by
//!                             sub_141101380 at +784.
//!   CharacterField141Entry  — 24-byte stride (2× u32 lookup +
//!                             CArray<u32>), used by sub_141118000.
//!   CharacterField144Entry  — 12-byte stride (2× u32 + u8 + u32),
//!                             used by sub_1411014B0 at +864.
//!   CharacterInline147       — 14 wire bytes (3× u32 + 2× u8) inline
//!                             via sub_1410D7370 at +896 (NOT a CArray).
//!   CharacterField150Entry  — 32-byte stride (u32 + CString-hash +
//!                             2× Vec3), used by sub_141101710.
//!   CharacterField169Entry  — 16-byte stride (u32 lookup + u64), one
//!                             entry of the 5-iter loop at +1032.
//!   CharacterFiveU64        — 5× u64 (40 wire bytes), used by
//!                             sub_1411001A0 inner.
//!   CharacterField171Entry  — 128-byte stride for sub_141117EC0
//!                             (u32 + 2× u64 + [u32; 4] + u32 + 5
//!                             nested CArrays).
//!
//! Field 173 (sub_141101AB0 CArray<u32>) and field 174 (sub_141101B80
//! CArray<{u32, u32}>) close out the wire layout. The earlier "field_173
//! breaks the test" symptom was caused by a missing 3-iter raw u32 loop
//! at mem +1008-+1019 (the loop that runs between raw_165 and lookup_166
//! in sub_1410D7480). Adding raw_165a/b/c restored byte alignment and
//! cleared the cascade.

use crate::binary::*;
use crate::binary::variants::gimmick_interaction_override::GimmickInteractionOverrideCArray;
use crate::json_traits::{ToJsonValue, WriteJsonValue};
use crate::pabgh_typed_blob_table;
use crate::py_binary_struct;
use serde_json::Value;
use std::io::{self, Write};

/// Conditional u32 wire field that's only present when the IMMEDIATELY
/// PRECEDING byte (flag_91) is 0. Reverse-engineered from sub_1410D7480
/// where:
/// ```c
/// if ( !*(_BYTE *)(a2 + 440) && !sub_141105AC0(a1, a2 + 442) )
/// ```
/// Vanilla distribution (6966 entries): flag_91 == 0 (2035 entries, has
/// the conditional u32) vs flag_91 == 2 (4931 entries, no conditional).
///
/// Implemented as a wire-trait wrapper around `Option<u32>` so the
/// `pabgh_typed_blob_table!` macro can keep generating CharacterInfo's
/// 100+ fields straightline. read_from peeks at `data[offset - 1]` to
/// dispatch — relies on the macro reading flag_91 immediately before.
#[derive(Debug)]
pub struct Conditional92(pub Option<u32>);

impl<'a> BinaryRead<'a> for Conditional92 {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        // Peek at the byte just consumed by flag_91 (the previous field).
        if *offset == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "Conditional92: cannot read at offset 0 (no preceding flag_91 byte)"));
        }
        let flag_91 = data[*offset - 1];
        if flag_91 == 0 {
            Ok(Self(Some(u32::read_from(data, offset)?)))
        } else {
            Ok(Self(None))
        }
    }
}

impl BinaryWrite for Conditional92 {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        if let Some(v) = &self.0 {
            v.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryReadTracked<'a> for Conditional92 {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        if item.0.is_some() {
            ranges.push(FieldRange {
                path: path.clone(),
                start,
                end: *offset,
                ty: "Conditional92",
            });
        }
        Ok(item)
    }
}

impl ToJsonValue for Conditional92 {
    fn to_json_value(&self) -> Value {
        match &self.0 {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }
}

impl WriteJsonValue for Conditional92 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            // No bytes written — the wire skips the conditional read.
            return Ok(());
        }
        <u32 as WriteJsonValue>::write_from_json(w, v)
    }
}

// 2-iter loop body in sub_1410D7480: u32 lookup + u16 lookup per entry.
py_binary_struct! {
    pub struct CharacterActionChartEntry {
        pub group_lookup: u32,    // sub_1410FF340 wire u32
        pub package_lookup: u16,  // sub_1411003E0 wire u16
    }
}

// sub_1410E0380 inner: 4 u8s = 4 wire bytes.
py_binary_struct! {
    pub struct CharacterFourFlags {
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
    }
}

// sub_1411187E0 inner — 12-wire-byte items.
py_binary_struct! {
    pub struct CharacterPropEntry {
        pub lookup: u32,    // sub_141100370 wire u32 / u16 mem
        pub raw_a: u32,
        pub raw_b: u32,
    }
}

// sub_1410D7170 inner — 64-wire-byte items.
py_binary_struct! {
    pub struct CharacterMobEntry {
        pub lookup_a: u32,    // sub_1410FF5C0 wire u32
        pub lookup_b: u32,    // sub_141100370 wire u32
        pub raw_a: u64,
        pub raw_b: u64,
        pub raw_c: u64,
        pub raw_d: u64,
        pub raw_e: u64,
        pub raw_f: u64,
        pub raw_g: u64,
    }
}

// sub_141118620 inner — 20-wire-byte items.
py_binary_struct! {
    pub struct CharacterTagEntry {
        pub lookup_a: u32,    // sub_1410FF5C0 wire u32
        pub raw_a: u64,
        pub raw_b: u32,
        pub lookup_b: u32,    // sub_1410FF5C0 wire u32
    }
}

// sub_141101010 inner — 4-wire-byte items (u16 lookup + u16 raw).
py_binary_struct! {
    pub struct CharacterShortPair {
        pub lookup: u16,    // sub_141103F00 wire u16
        pub raw: u16,
    }
}

// sub_1411181F0 inner — 32 mem bytes per element.
// Wire: CArray<u32> + u32 lookup + u16 lookup + u32 lookup + u64 raw
// (per sub_1411181F0 IDA decompile).
py_binary_struct! {
    pub struct CharacterField136Entry {
        pub list: CArray<u32>,            // sub_141100510 (qword_145F113C8)
        pub lookup_a: u32,                // sub_1410FF5C0 (qword_145F0DA00)
        pub lookup_b: u16,                // sub_141100620 (qword_145F0DA20)
        pub lookup_c: u32,                // sub_1411006D0 (qword_145F0DA28)
        pub raw: u64,
    }
}

// sub_141101380 inner — 8 wire bytes per element.
// Wire: u32 lookup (sub_1410FF2D0 → qword_145F115E8) + u32 lookup
// (qword_145F1A550). Both are u32 on the wire even though mem stores
// u16 hashes after the lookup.
py_binary_struct! {
    pub struct CharacterField137Entry {
        pub lookup_a: u32,
        pub lookup_b: u32,
    }
}

// sub_141118000 inner — 24 mem bytes per element.
// Wire: u32 lookup (sub_1410FF430) + u32 lookup (read_u32_lookup_DA30)
// + CArray<u32> (sub_1410FEF40 → qword_145F0DA30).
py_binary_struct! {
    pub struct CharacterField141Entry {
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub list: CArray<u32>,
    }
}

// sub_1411014B0 inner — 13 wire bytes / 12 mem bytes per element.
// Wire: u32 lookup (sub_1410FF430) + u32 lookup (sub_1410FF430) + u8 + u32.
py_binary_struct! {
    pub struct CharacterField144Entry {
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub flag: u8,
        pub raw: u32,
    }
}

// sub_1410D7370 inline (NOT a CArray — single 14-wire-byte struct)
// at a2+896. Wire: 3× u32 + 2× u8.
py_binary_struct! {
    pub struct CharacterInline147 {
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub flag_a: u8,
        pub flag_b: u8,
    }
}

// sub_141101710 inner — 32 mem bytes per element.
// Wire: u32 raw + CString-hash (sub_1410A9D40) + Vec3 + Vec3.
py_binary_struct! {
    pub struct CharacterField150Entry<'a> {
        pub raw: u32,
        pub key_hash: CString<'a>,    // sub_1410A9D40 — wire CString
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
    }
}

// One entry of the 5-iteration loop at a2+1032..+1112. Each iteration:
// read_u32_lookup_DA10 (u32 wire / u16 mem) + 8 raw bytes (u64).
py_binary_struct! {
    pub struct CharacterField169Entry {
        pub lookup: u32,
        pub raw: u64,
    }
}

// sub_1410FC090 — 40-byte struct, 5× u64 raw.
py_binary_struct! {
    pub struct CharacterFiveU64 {
        pub a: u64,
        pub b: u64,
        pub c: u64,
        pub d: u64,
        pub e: u64,
    }
}

// sub_141101B80 inner — 8-byte items per element.
// Wire: u32 raw + u32 raw (post-processed via sub_141BF6840).
py_binary_struct! {
    pub struct CharacterField174Entry {
        pub raw_a: u32,
        pub raw_b: u32,
    }
}

// sub_1410D6F70 — 128-byte per-element of sub_141117EC0.
// Wire: u32 + u64 + u64 + 4× u32 (loop) + u32 + 5 nested CArrays.
py_binary_struct! {
    pub struct CharacterField171Entry {
        pub raw_a: u32,
        pub raw_b: u64,
        pub raw_c: u64,
        pub block: [u32; 4],
        pub raw_d: u32,
        pub list_a: CArray<u32>,                 // sub_141100090 (qword_145F0DA68 hash)
        pub list_b: CArray<u32>,                 // sub_141100090
        pub quint_list_a: CArray<CharacterFiveU64>, // sub_1411001A0 → sub_1410FC090
        pub quint_list_b: CArray<CharacterFiveU64>, // sub_1411001A0
        pub byte_list: CArray<u8>,                // sub_1411002A0
    }
}

// sub_141B536F0 inner — 76 mem bytes, ~78 wire bytes (with empty
// strings) / 24 wire fields. Wire ORDER (not mem order):
py_binary_struct! {
    pub struct CharacterChartEntry<'a> {
        pub lookup_a: u32,             // inline u32 → qword_145F0DA38
        pub lookup_b: u32,             // inline u32 → qword_145F0DA08
        pub lookup_c: u32,             // inline u32 → qword_145F0DA00
        pub key_a: CString<'a>,        // sub_1410A9D40 wire CString
        pub key_b: CString<'a>,        // sub_1410A9D40
        // raw_block_a was [u8;16] — sub_141107700 IDA-confirmed as
        // `for i in 0..4 { read_u32() }`, so split into 4 named u32s
        // per the field-level rule (lane-c, 2026-04-30).
        pub block_a_dword_0: u32,
        pub block_a_dword_1: u32,
        pub block_a_dword_2: u32,
        pub block_a_dword_3: u32,
        pub raw_a: u16,
        pub raw_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub flag_f: u8,
        pub lookup_d: u32,             // sub_1410FF430 wire u32 (inserted mid-sequence)
        pub flag_g: u8,
        pub flag_h: u8,
        pub flag_i: u8,
        pub flag_j: u8,
        pub flag_k: u8,
        pub flag_l: u8,
        pub key_c: CString<'a>,        // sub_1410A9D40
        pub flag_m: u8,
        // raw_block_b: same 4× u32 split (sub_141107700).
        pub block_b_dword_0: u32,
        pub block_b_dword_1: u32,
        pub block_b_dword_2: u32,
        pub block_b_dword_3: u32,
    }
}

// sub_141101210 inner — 20 mem bytes / 5 wire fields = 17 wire bytes.
// Wire reads in stack-stuffing order: u32 raw + u8 flag + u32 raw +
// u32 raw + u32 raw.
py_binary_struct! {
    pub struct CharacterFiveTuple {
        pub raw_a: u32,
        pub flag: u8,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u32,
    }
}

// sub_141100E90 inner — 32 mem bytes / 28 wire bytes (f32 + 3× 8 bytes).
// Same shape as faction_node_info::FactionAdjacencyMobItem.
py_binary_struct! {
    pub struct CharacterAdjacencyMobItem {
        pub raw_a: u32,
        pub raw_b: u64,
        pub raw_c: u64,
        pub raw_d: u64,
    }
}

// sub_1410D9880 inner — 96 mem bytes / 20 wire fields, CArray element of
// sub_141118980 (CharacterInfo's _hireableMercenaryList).
py_binary_struct! {
    pub struct CharacterMercenaryEntry<'a> {
        pub lookup_a: u32,                      // sub_1410FF5C0 wire u32
        pub lookup_b: u32,                      // sub_141100740 wire u32
        pub lookup_c: u32,                      // sub_1410FF340 wire u32
        pub raw_a: u32,
        pub key_str: CString<'a>,               // sub_1410A9D40 wire CString
        pub lookup_d: u32,                      // sub_1410FF340 wire u32
        pub raw_b: u32,
        pub flag_a: u8,
        pub lookup_e: u32,                      // sub_1411006D0 wire u32
        pub label: LocalizableString<'a>,
        pub raw_c: u32,
        pub flag_b: u8,
        pub raw_d: u32,
        pub raw_e: u32,
        pub flag_c: u8,
        pub lookup_f: u32,                      // sub_1411006D0 wire u32
        pub flag_d: u8,
        pub flag_e: u8,
        pub raw_f: u32,
        pub raw_g: u32,
    }
}

pabgh_typed_blob_table! {
    pub struct CharacterInfo<'a> {
        pub key: u32,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub name: LocalizableString<'a>,
        pub desc: LocalizableString<'a>,
        pub ui_icon_path: u32,
        pub category: u32,
        pub character_edit_name: CString<'a>,
        pub spawn_actor_type: u8,
        pub none_player_sub_type: u8,
        pub equip_info: u32,
        pub npc_info: u32,
        pub vehicle_info: u16,
        pub call_mercenary_cool_time: u64,
        pub call_mercenary_spawn_duration: u64,
        pub mercenary_cool_time_type: u8,
        pub upper_chart: CharacterActionChartEntry,
        pub lower_chart: CharacterActionChartEntry,
        pub character_game_play_data_name: u32,
        pub appearance_name: u32,
        pub character_prefab_path: u32,
        pub skeleton_name: u32,
        pub lookup_22: u32,
        pub lookup_23: u32,
        pub lookup_24: u32,
        pub lookup_25: u32,
        pub raw_a: u32,
        pub lookup_27: u32,
        pub lookup_28: u32,
        pub lookup_29: u32,
        pub raw_b: u32,
        pub lookup_31: u32,
        pub raw_c: u32,
        pub raw_d: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub label_a: LocalizableString<'a>,
        pub lookup_36: u32,
        pub flag_e: u8,
        pub raw_e: u16,
        pub four_flags: CharacterFourFlags,
        pub flag_38: u8,
        pub flag_39: u8,
        pub flag_40: u8,
        pub flag_41: u8,
        pub flag_42: u8,
        pub flag_43: u8,
        pub flag_44: u8,
        pub flag_45: u8,
        pub flag_46: u8,
        pub flag_47: u8,
        pub flag_48: u8,
        pub flag_49: u8,
        pub flag_50: u8,
        pub flag_51: u8,
        pub flag_52: u8,
        pub flag_53: u8,
        pub flag_54: u8,
        pub flag_55: u8,
        pub flag_56: u8,
        pub flag_57: u8,
        pub flag_58: u8,
        pub flag_59: u8,
        pub flag_60: u8,
        pub flag_61: u8,
        pub flag_62: u8,
        pub flag_63: u8,
        pub flag_64: u8,
        pub flag_65: u8,
        pub flag_66: u8,
        pub flag_67: u8,
        pub flag_68: u8,
        pub flag_69: u8,
        pub flag_70: u8,
        pub flag_71: u8,
        pub flag_72: u8,
        pub flag_73: u8,
        pub flag_74: u8,
        pub flag_75: u8,
        pub flag_76: u8,
        pub raw_f: u32,
        pub lookup_77: u32,
        pub lookup_78: u32,
        pub list_a: CArray<u64>,
        pub list_b: CArray<u64>,
        pub list_c: CArray<u64>,
        pub list_d: CArray<u64>,
        pub list_e: CArray<u32>,
        pub raw_g: u32,
        pub lookup_84: u32,
        pub list_f: CArray<u32>,
        pub raw_h: u32,
        pub flag_85: u8,
        pub flag_86: u8,
        pub lookup_87: u32,
        pub flag_88: u8,
        pub lookup_89: u32,
        pub flag_90: u8,
        pub mercenary_list: CArray<CharacterMercenaryEntry<'a>>,
        pub list_g: CArray<u16>,
        pub flag_91: u8,
        pub conditional_92: Conditional92,
        pub lookup_93: u16,
        pub raw_94: u16,
        pub flag_95: u8,
        pub flag_96: u8,
        pub list_h: CArray<u16>,
        pub flag_97: u8,
        pub name_path: CString<'a>,
        pub lookup_98: u16,
        pub lookup_99: u16,
        pub lookup_100: u32,
        pub lookup_101: u32,
        pub raw_102: u32,
        pub flag_103: u8,
        pub list_i: CArray<u32>,
        pub list_j: CArray<u32>,
        pub list_k: CArray<u32>,
        pub raw_104: u32,
        pub prop_list: CArray<CharacterPropEntry>,
        pub flag_105: u8,
        pub list_l: CArray<u32>,
        pub mob_list: CArray<CharacterMobEntry>,
        pub adj_list: CArray<CharacterAdjacencyMobItem>,
        pub tag_list_a: CArray<CharacterTagEntry>,
        pub tag_list_b: CArray<CharacterTagEntry>,
        pub lookup_125: u32,
        pub raw_126: u32,
        pub lookup_127: u32,
        pub flag_128: u8,
        pub short_pair_list: CArray<CharacterShortPair>,
        pub raw_130: u32,
        pub chart_entry_list: CArray<CharacterChartEntry<'a>>,
        pub five_tuple_list: CArray<CharacterFiveTuple>,
        pub gimmick_interaction_override_list: GimmickInteractionOverrideCArray<'a>,
        pub flag_after_gimmick: u8,                       // a2 + 752
        pub raw_after_gimmick: u32,                       // a2 + 756
        pub field_136_list: CArray<CharacterField136Entry>, // sub_1411181F0 a2+760
        pub raw_after_136: u32,                           // a2 + 776
        pub field_137_list: CArray<CharacterField137Entry>, // sub_141101380 a2+784
        pub field_138_list: CArray<u32>,                  // sub_1410FFF10 a2+800
        pub raw_140a: u64,                                // a2 + 816
        pub raw_140b: u64,                                // a2 + 824
        pub raw_140c: u32,                                // a2 + 832
        pub flag_140a: u8,                                // a2 + 836
        pub flag_140b: u8,                                // a2 + 837
        pub field_141_list: CArray<CharacterField141Entry>, // sub_141118000 a2+840
        pub raw_142: u32,                                 // a2 + 856
        pub flag_143: u8,                                 // a2 + 860
        pub field_144_list: CArray<CharacterField144Entry>, // sub_1411014B0 a2+864
        pub field_146_list: CArray<u32>,                  // sub_141101610 a2+880 (qword_145F0EF38)
        pub inline_147: CharacterInline147,               // sub_1410D7370 inline at a2+896
        pub raw_148: u32,                                 // a2 + 912
        pub lookup_149: u16,                              // inline u16 → qword_145F15960 hash, a2+916
        pub field_150_list: CArray<CharacterField150Entry<'a>>, // sub_141101710 a2+920
        pub raw_151: u32,                                 // a2 + 936
        pub raw_152: u32,                                 // a2 + 940
        pub raw_153: u32,                                 // a2 + 944
        pub raw_154: u32,                                 // a2 + 948
        pub lookup_155: u16,                              // sub_1411018B0 a2+952
        pub lookup_156: u32,                              // sub_141100740 a2+954 (u32 wire / u16 mem)
        pub flag_157: u8,                                 // a2 + 956
        pub raw_158: u32,                                 // a2 + 960
        pub flag_159: u8,                                 // a2 + 964
        pub raw_160: u32,                                 // a2 + 968
        pub lookup_161: u32,                              // sub_141100740 a2+972
        pub lookup_162: u32,                              // sub_141100370 a2+974
        pub field_163_list: CArray<u32>,                  // sub_141101960 a2+976 (raw u32 elements)
        pub raw_164: u32,                                 // a2 + 992
        pub raw_165: u64,                                 // a2 + 1000
        pub raw_165a: u32,                                // a2 + 1008 (3-iter raw u32 loop)
        pub raw_165b: u32,                                // a2 + 1012
        pub raw_165c: u32,                                // a2 + 1016
        pub lookup_166: u32,                              // sub_141101A40 a2+1020 (u32 wire / u16 mem)
        pub raw_167: u32,                                 // a2 + 1024
        pub flag_168: u8,                                 // a2 + 1028
        pub field_169a: CharacterField169Entry,           // 5-iter loop, a2+1032
        pub field_169b: CharacterField169Entry,
        pub field_169c: CharacterField169Entry,
        pub field_169d: CharacterField169Entry,
        pub field_169e: CharacterField169Entry,
        pub lookup_170: u32,                              // inline u32 → qword_145F14D90 hash, a2+1112
        pub field_171_list: CArray<CharacterField171Entry>, // sub_141117EC0 a2+1120
        pub field_172_list: CArray<u32>,                    // sub_141101AB0 a2+1136
        pub field_173_list: CArray<u32>,                    // sub_141101AB0 a2+1152
        pub field_174_list: CArray<CharacterField174Entry>, // sub_141101B80 a2+1168
    }
    tail: tail_blob;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgb";
    const PABGH_PATH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\characterinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        let mut max_tail = 0usize;
        let mut nonempty_tails = 0usize;
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = CharacterInfo::read_with_size(&data, &mut c, e - s).unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e);
            let t = item.tail_blob.len();
            if t > 0 { nonempty_tails += 1; max_tail = max_tail.max(t); }
            items.push(item);
        }
        eprintln!("characterinfo: {} entries, {} nonempty tails (max={} bytes)",
            ranges.len(), nonempty_tails, max_tail);
        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "characterinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = CharacterInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            // CharacterInfo's typed prefix consumes every byte of every
            // vanilla entry, so the macro-generated `_tail_b64` field
            // must never leak into the JSON dict (Tier 1 invariant).
            assert!(!dict.contains_key("_tail_b64"),
                "entry {} key=0x{:x}: _tail_b64 leaked — typed reader is missing fields", i, key);
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            CharacterInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
