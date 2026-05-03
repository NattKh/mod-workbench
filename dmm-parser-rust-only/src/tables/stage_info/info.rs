#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed.
//!
//! Reader: `sub_1410FA990` in CrimsonDesert.exe (Win build) — confirmed via
//! Win-IDA decompile this session. 25 MB pabgb / largest table in the set.
//!
//! Wire reads, in order:
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. LocalizableString name
//!   5. LocalizableString stage_desc
//!   6. LocalizableString complete_log
//!   7. SequencerStageChartDescPartial sequencer_desc (sub_141D8C6D0,
//!      INLINE single-instance — distinct from global_stage_sequencer_info
//!      which has a CArray of these)
//!   8. u32 spawn_faction_spawn_data_info (mem +352, qword_145F0EF08)
//!   9. u32 spawn_faction_node_info       (sub_141101D50, qword_145F0EEE8)
//!  10. CArray<u32> disable_faction_spawn_party_name_hash_list
//!                                        (sub_141101AB0, mem +360)
//!  11. u64 raw_a                         (mem +376)
//!  12. u64 raw_b                         (mem +384)
//!  13. u64 raw_c                         (mem +392)
//!  14. CArray<u32> list_a                (sub_1410FF890, qword_145F0DA08
//!                                         hash, mem +400)
//!  15. u8 flag_a                         (mem +416)
//!  16. u8 flag_b                         (mem +417)
//!  17. u32 lookup_c                      (sub_141102CB0, qword_145F0EF20)
//!  18. u32 lookup_d                      (sub_141102D20, qword_145F0EF38)
//!  19. u32 lookup_e                      (sub_141102D90)
//!  20. CArray<u32> close_filter_a        (sub_141101610, qword_145F0EF38)
//!  21. CArray<u32> close_filter_b        (sub_1411049D0, qword_145F0EF00)
//!  22. CArray<u32> close_filter_c        (sub_141101610, qword_145F0EF38)
//!  23. CArray<StageFilterEntry> filter_entry_list
//!                                        (sub_1411068C0 → sub_1410F3380)
//!  24. u32 lookup_f                      (sub_1410FF430, qword_145F0E9C0)
//!  25. u32 lookup_g                      (sub_1410FF430)
//!  26. u32 lookup_h                      (qword_145F11398 hash)
//!  27. CArray<u32> list_b                (sub_1410FF890, qword_145F0DA08)
//!  28. CArray<u32> list_c                (sub_1410FF890, qword_145F0DA08)
//!  29. u32 lookup_i                      (sub_1410FF340)
//!  30. u32 raw_d
//!  31. CString cstring_a                 (sub_1410A9D40 — wire CString)
//!  32. u8 flag_c
//!  33. u8 flag_d
//!  34. u32 raw_e
//!  35. u32 raw_f
//!  36. u32 pair_a, u32 pair_b            (sub_1410AA070 — 2 raw u32s)
//!  37. u64 raw_g
//!  38. u32 raw_h
//!  39. u16 raw_i
//!  40. CArray<StageMobMapEntry> mob_map_list (sub_141108F70 — per
//!      element u8 flag + 3× u32 lookup, 13 wire bytes)
//!  41. u32 lookup_j                      (sub_1410FF430)
//!  42. CArray<StageU32StringEntry> string_entry_list (sub_141108DE0)
//!  43-46. 4× CArray<FactionAdjacencyMobItem> adjacency_mob_lists
//!         (sub_141100E90, 28 wire bytes per element)
//!  47-50. 4× CArray<u32> close_filter_d_list (sub_141100510,
//!         qword_145F113C8 hash)
//!  51. CArray<u32> list_d                (sub_1410FEF40,
//!                                         qword_145F0DA30 hash)
//!  52. OptStageOpt52 platform_entry      (sub_141108C30 — presence-
//!      flagged { Optional<StagePlatformEntry> + u16 + u32 + u32 }.
//!      The inner StagePlatformEntry decodes through sub_141D7FE40 +
//!      sub_1410AA1B0 and exposes 9 named fields.)
//!  53. u32 lookup_k                      (read_u32_lookup_DA30)
//!  54. u32 lookup_l                      (qword_145F1A890)
//!  55-58. 4× u32 lookup_m..p             (read_u32_lookup_DA30)
//!  59-60. 2× u32 lookup_q, lookup_r      (sub_1410FF340)
//!  61. LocalizableString label_b
//!  62. u32 lookup_s                      (read_u32_lookup_DA30)
//!  63. u8 flag_e
//!  64. u8 flag_f
//!  65. u32 lookup_t                      (sub_1411006D0 — qword_145F0DA28)
//!  66. CArray<StageBehaviorEntry> behavior_entry_list
//!                                        (sub_141107B30 — per element
//!                                         u32 + PlayerBehaviorOptional)
//!  67. u32 raw_j
//!  68. u16 lookup_u                      (sub_141107C70 — qword_145F0E9D8)
//!  69. u32 lookup_v                      (sub_141103530 — qword_145F0EEF8)
//!  70. u32 lookup_w                      (read_u32_lookup_DA30)
//!  71-76. 6× u32 raw_k..p
//!  77-91. 15× u8 flag_g..u (trailing booleans)
//!
//! All 91 wire fields fully decoded. opaque_tail kept for graceful
//! future-format degradation; always empty on vanilla data.
//!
//! Promotion note: the previous Tier 1.5 cut stopped at field 6 because
//! field 7 was an opaque polymorphic SequencerStageChartDesc. Now that
//! the desc has a complete decoder, it joins the typed prefix.

use crate::binary::*;
use crate::binary::variants::sequencer_stage_chart_desc::SequencerStageChartDescPartial;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use crate::tables::faction_node_info::info::FactionAdjacencyMobItem;
use crate::tables::global_stage_sequencer_info::info::PlayerBehaviorOptional;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// `sub_1410F3380` per-element of stage_info field 23's outer
    /// CArray (sub_1411068C0). 19 wire bytes / 20 mem bytes.
    pub struct StageFilterEntry {
        pub lookup_a: u32,    // sub_141102D20 → qword_145F0EF38
        pub lookup_b: u32,    // sub_1410FF430 → qword_145F0E9C0
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
    }
}

py_binary_struct! {
    /// Inner of stage_info field 40 (sub_141108F70).
    /// 13 wire bytes / 8 mem bytes per element.
    pub struct StageMobMapEntry {
        pub flag: u8,
        pub lookup_a: u32,    // read_u32_lookup_DA30 → qword_145F0DA30
        pub lookup_b: u32,    // read_u32_lookup_DA30
        pub lookup_c: u32,    // read_u32_lookup_DA30
    }
}

py_binary_struct! {
    /// Inner of stage_info field 42 (sub_141108DE0).
    /// u32 + CString per element / 16 mem bytes.
    pub struct StageU32StringEntry<'a> {
        pub raw: u32,
        pub label: CString<'a>,
    }
}

/// Inner of stage_info field 66 (sub_141107B30).
/// Per element: u32 + Option<{u8 + 3× u32 lookup}>.
#[derive(Debug)]
pub struct StageBehaviorEntry {
    pub raw: u32,
    pub behavior: PlayerBehaviorOptional,
}

impl<'a> BinaryRead<'a> for StageBehaviorEntry {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            raw: u32::read_from(data, offset)?,
            behavior: PlayerBehaviorOptional::read_from(data, offset)?,
        })
    }
}

impl BinaryWrite for StageBehaviorEntry {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.raw.write_to(w)?;
        self.behavior.write_to(w)?;
        Ok(())
    }
}

impl ToJsonValue for StageBehaviorEntry {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("raw".to_string(), self.raw.to_json_value());
        m.insert("behavior".to_string(), self.behavior.to_json_value());
        Value::Object(m)
    }
}

impl WriteJsonValue for StageBehaviorEntry {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "StageBehaviorEntry: expected object",
        ))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw")?)?;
        PlayerBehaviorOptional::write_from_json(w, json_get_field(obj, "behavior")?)?;
        Ok(())
    }
}

py_binary_struct! {
    /// `sub_1410AA1B0` — 40 wire bytes.
    /// Wire order: Vec3 (12) + 4× u32 (16) + Vec3 (12).
    pub struct StagePosBlock {
        pub pos_a: [f32; 3],
        pub block: [u32; 4],
        pub pos_b: [f32; 3],
    }
}

py_binary_struct! {
    /// `sub_141D7FE40` inner — 86 mem bytes / 9 wire fields.
    /// Wire: u8 + StagePosBlock + CString-hash + CString + u8 + Vec3 +
    /// Vec3 + 2× u8.
    pub struct StagePlatformEntry<'a> {
        pub flag_a: u8,
        pub pos_block: StagePosBlock,
        pub key_hash: CString<'a>,    // sub_1410A9D40 — wire CString, mem u32
        pub label: CString<'a>,
        pub flag_b: u8,
        pub vec_a: [f32; 3],
        pub vec_b: [f32; 3],
        pub flag_c: u8,
        pub flag_d: u8,
    }
}

/// `sub_141106AE0` — `Option<StagePlatformEntry>`. 88 mem bytes when
/// present; just a presence flag on the wire (0 → None, 1 → present).
#[derive(Debug)]
pub struct OptStagePlatformEntry<'a> {
    pub inner: Option<StagePlatformEntry<'a>>,
}

impl<'a> BinaryRead<'a> for OptStagePlatformEntry<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(StagePlatformEntry::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl<'a> BinaryWrite for OptStagePlatformEntry<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => { 1u8.write_to(w)?; v.write_to(w) }
            None => 0u8.write_to(w),
        }
    }
}

impl<'a> ToJsonValue for OptStagePlatformEntry<'a> {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }
}

impl<'a> WriteJsonValue for OptStagePlatformEntry<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)
        } else {
            1u8.write_to(w)?;
            <StagePlatformEntry as WriteJsonValue>::write_from_json(w, v)
        }
    }
}

/// `sub_141108C30` — `Option<{ OptStagePlatformEntry + u16 + u32 + u32 }>`.
#[derive(Debug)]
pub struct OptStageOpt52<'a> {
    pub inner: Option<StageOpt52Inner<'a>>,
}

#[derive(Debug)]
pub struct StageOpt52Inner<'a> {
    pub platform: OptStagePlatformEntry<'a>,
    pub lookup: u16,    // sub_141107C70 → qword_145F0E9D8 (wire u16)
    pub raw_a: u32,
    pub raw_b: u32,
}

impl<'a> BinaryRead<'a> for OptStageOpt52<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(StageOpt52Inner {
                platform: OptStagePlatformEntry::read_from(data, offset)?,
                lookup: u16::read_from(data, offset)?,
                raw_a: u32::read_from(data, offset)?,
                raw_b: u32::read_from(data, offset)?,
            })
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl<'a> BinaryWrite for OptStageOpt52<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => {
                1u8.write_to(w)?;
                v.platform.write_to(w)?;
                v.lookup.write_to(w)?;
                v.raw_a.write_to(w)?;
                v.raw_b.write_to(w)?;
                Ok(())
            }
            None => 0u8.write_to(w),
        }
    }
}

impl<'a> ToJsonValue for OptStageOpt52<'a> {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => {
                let mut m = Map::new();
                m.insert("platform".to_string(), v.platform.to_json_value());
                m.insert("lookup".to_string(), v.lookup.to_json_value());
                m.insert("raw_a".to_string(), v.raw_a.to_json_value());
                m.insert("raw_b".to_string(), v.raw_b.to_json_value());
                Value::Object(m)
            }
            None => Value::Null,
        }
    }
}

impl<'a> WriteJsonValue for OptStageOpt52<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)?;
            return Ok(());
        }
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "OptStageOpt52: expected object or null",
        ))?;
        1u8.write_to(w)?;
        OptStagePlatformEntry::write_from_json(w, json_get_field(obj, "platform")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StageInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub name: LocalizableString<'a>,
    pub stage_desc: LocalizableString<'a>,
    pub complete_log: LocalizableString<'a>,
    pub sequencer_desc: SequencerStageChartDescPartial<'a>,
    pub spawn_faction_spawn_data_info: u32,
    pub spawn_faction_node_info: u32,
    pub disable_faction_spawn_party_name_hash_list: CArray<u32>,
    pub raw_a: u64,
    pub raw_b: u64,
    pub raw_c: u64,
    pub list_a: CArray<u32>,
    pub flag_a: u8,
    pub flag_b: u8,
    pub lookup_c: u32,
    pub lookup_d: u32,
    pub lookup_e: u32,
    pub close_filter_a: CArray<u32>,
    pub close_filter_b: CArray<u32>,
    pub close_filter_c: CArray<u32>,
    pub filter_entry_list: CArray<StageFilterEntry>,
    pub lookup_f: u32,
    pub lookup_g: u32,
    pub lookup_h: u32,
    pub list_b: CArray<u32>,
    pub list_c: CArray<u32>,
    pub lookup_i: u32,
    pub raw_d: u32,
    pub cstring_a: CString<'a>,
    pub flag_c: u8,
    pub flag_d: u8,
    pub raw_e: u32,
    pub raw_f: u32,
    pub pair_a: u32,
    pub pair_b: u32,
    pub raw_g: u64,
    pub raw_h: u32,
    pub raw_i: u16,
    pub mob_map_list: CArray<StageMobMapEntry>,
    pub lookup_j: u32,
    pub string_entry_list: CArray<StageU32StringEntry<'a>>,
    pub adjacency_mob_list_a: CArray<FactionAdjacencyMobItem>,
    pub adjacency_mob_list_b: CArray<FactionAdjacencyMobItem>,
    pub adjacency_mob_list_c: CArray<FactionAdjacencyMobItem>,
    pub adjacency_mob_list_d: CArray<FactionAdjacencyMobItem>,
    pub close_filter_d_a: CArray<u32>,
    pub close_filter_d_b: CArray<u32>,
    pub close_filter_d_c: CArray<u32>,
    pub close_filter_d_d: CArray<u32>,
    pub list_d: CArray<u32>,
    pub platform_entry: OptStageOpt52<'a>,
    pub lookup_k: u32,
    pub lookup_l: u32,
    pub lookup_m: u32,
    pub lookup_n: u32,
    pub lookup_o: u32,
    pub lookup_p: u32,
    pub lookup_q: u32,
    pub lookup_r: u32,
    pub label_b: LocalizableString<'a>,
    pub lookup_s: u32,
    pub flag_e: u8,
    pub flag_f: u8,
    pub lookup_t: u32,
    pub behavior_entry_list: CArray<StageBehaviorEntry>,
    pub raw_j: u32,
    pub lookup_u: u16,
    pub lookup_v: u32,
    pub lookup_w: u32,
    pub raw_k: u32,
    pub raw_l: u32,
    pub raw_m: u32,
    pub raw_n: u32,
    pub raw_o: u32,
    pub raw_p: u32,
    pub flag_g: u8,
    pub flag_h: u8,
    pub flag_i: u8,
    pub flag_j: u8,
    pub flag_k: u8,
    pub flag_l: u8,
    pub flag_m: u8,
    pub flag_n: u8,
    pub flag_o: u8,
    pub flag_p: u8,
    pub flag_q: u8,
    pub flag_r: u8,
    pub flag_s: u8,
    pub flag_t: u8,
    pub flag_u: u8,
}

impl<'a> StageInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let name = LocalizableString::read_from(data, offset)?;
        let stage_desc = LocalizableString::read_from(data, offset)?;
        let complete_log = LocalizableString::read_from(data, offset)?;
        let sequencer_desc = SequencerStageChartDescPartial::read_from(data, offset)?;
        let spawn_faction_spawn_data_info = u32::read_from(data, offset)?;
        let spawn_faction_node_info = u32::read_from(data, offset)?;
        let disable_faction_spawn_party_name_hash_list = CArray::<u32>::read_from(data, offset)?;
        let raw_a = u64::read_from(data, offset)?;
        let raw_b = u64::read_from(data, offset)?;
        let raw_c = u64::read_from(data, offset)?;
        let list_a = CArray::<u32>::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let lookup_c = u32::read_from(data, offset)?;
        let lookup_d = u32::read_from(data, offset)?;
        let lookup_e = u32::read_from(data, offset)?;
        let close_filter_a = CArray::<u32>::read_from(data, offset)?;
        let close_filter_b = CArray::<u32>::read_from(data, offset)?;
        let close_filter_c = CArray::<u32>::read_from(data, offset)?;
        let filter_entry_list = CArray::<StageFilterEntry>::read_from(data, offset)?;
        let lookup_f = u32::read_from(data, offset)?;
        let lookup_g = u32::read_from(data, offset)?;
        let lookup_h = u32::read_from(data, offset)?;
        let list_b = CArray::<u32>::read_from(data, offset)?;
        let list_c = CArray::<u32>::read_from(data, offset)?;
        let lookup_i = u32::read_from(data, offset)?;
        let raw_d = u32::read_from(data, offset)?;
        let cstring_a = CString::read_from(data, offset)?;
        let flag_c = u8::read_from(data, offset)?;
        let flag_d = u8::read_from(data, offset)?;
        let raw_e = u32::read_from(data, offset)?;
        let raw_f = u32::read_from(data, offset)?;
        let pair_a = u32::read_from(data, offset)?;
        let pair_b = u32::read_from(data, offset)?;
        let raw_g = u64::read_from(data, offset)?;
        let raw_h = u32::read_from(data, offset)?;
        let raw_i = u16::read_from(data, offset)?;
        let mob_map_list = CArray::<StageMobMapEntry>::read_from(data, offset)?;
        let lookup_j = u32::read_from(data, offset)?;
        let string_entry_list = CArray::<StageU32StringEntry>::read_from(data, offset)?;
        let adjacency_mob_list_a = CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?;
        let adjacency_mob_list_b = CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?;
        let adjacency_mob_list_c = CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?;
        let adjacency_mob_list_d = CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?;
        let close_filter_d_a = CArray::<u32>::read_from(data, offset)?;
        let close_filter_d_b = CArray::<u32>::read_from(data, offset)?;
        let close_filter_d_c = CArray::<u32>::read_from(data, offset)?;
        let close_filter_d_d = CArray::<u32>::read_from(data, offset)?;
        let list_d = CArray::<u32>::read_from(data, offset)?;
        let platform_entry = OptStageOpt52::read_from(data, offset)?;
        let lookup_k = u32::read_from(data, offset)?;
        let lookup_l = u32::read_from(data, offset)?;
        let lookup_m = u32::read_from(data, offset)?;
        let lookup_n = u32::read_from(data, offset)?;
        let lookup_o = u32::read_from(data, offset)?;
        let lookup_p = u32::read_from(data, offset)?;
        let lookup_q = u32::read_from(data, offset)?;
        let lookup_r = u32::read_from(data, offset)?;
        let label_b = LocalizableString::read_from(data, offset)?;
        let lookup_s = u32::read_from(data, offset)?;
        let flag_e = u8::read_from(data, offset)?;
        let flag_f = u8::read_from(data, offset)?;
        let lookup_t = u32::read_from(data, offset)?;
        let behavior_entry_list = CArray::<StageBehaviorEntry>::read_from(data, offset)?;
        let raw_j = u32::read_from(data, offset)?;
        let lookup_u = u16::read_from(data, offset)?;
        let lookup_v = u32::read_from(data, offset)?;
        let lookup_w = u32::read_from(data, offset)?;
        let raw_k = u32::read_from(data, offset)?;
        let raw_l = u32::read_from(data, offset)?;
        let raw_m = u32::read_from(data, offset)?;
        let raw_n = u32::read_from(data, offset)?;
        let raw_o = u32::read_from(data, offset)?;
        let raw_p = u32::read_from(data, offset)?;
        let flag_g = u8::read_from(data, offset)?;
        let flag_h = u8::read_from(data, offset)?;
        let flag_i = u8::read_from(data, offset)?;
        let flag_j = u8::read_from(data, offset)?;
        let flag_k = u8::read_from(data, offset)?;
        let flag_l = u8::read_from(data, offset)?;
        let flag_m = u8::read_from(data, offset)?;
        let flag_n = u8::read_from(data, offset)?;
        let flag_o = u8::read_from(data, offset)?;
        let flag_p = u8::read_from(data, offset)?;
        let flag_q = u8::read_from(data, offset)?;
        let flag_r = u8::read_from(data, offset)?;
        let flag_s = u8::read_from(data, offset)?;
        let flag_t = u8::read_from(data, offset)?;
        let flag_u = u8::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "StageInfo: typed prefix under/over-read ({} expected {})",
                    *offset, entry_end
                ),
            ));
        }

        Ok(Self {
            key, string_key, is_blocked, name, stage_desc, complete_log,
            sequencer_desc, spawn_faction_spawn_data_info, spawn_faction_node_info,
            disable_faction_spawn_party_name_hash_list, raw_a, raw_b, raw_c,
            list_a, flag_a, flag_b, lookup_c, lookup_d, lookup_e,
            close_filter_a, close_filter_b, close_filter_c, filter_entry_list,
            lookup_f, lookup_g, lookup_h, list_b, list_c, lookup_i, raw_d,
            cstring_a, flag_c, flag_d, raw_e, raw_f, pair_a, pair_b,
            raw_g, raw_h, raw_i,
            mob_map_list, lookup_j, string_entry_list,
            adjacency_mob_list_a, adjacency_mob_list_b,
            adjacency_mob_list_c, adjacency_mob_list_d,
            close_filter_d_a, close_filter_d_b,
            close_filter_d_c, close_filter_d_d,
            list_d, platform_entry,
            lookup_k, lookup_l, lookup_m, lookup_n, lookup_o, lookup_p,
            lookup_q, lookup_r, label_b, lookup_s, flag_e, flag_f, lookup_t,
            behavior_entry_list, raw_j, lookup_u, lookup_v, lookup_w,
            raw_k, raw_l, raw_m, raw_n, raw_o, raw_p,
            flag_g, flag_h, flag_i, flag_j, flag_k, flag_l, flag_m, flag_n,
            flag_o, flag_p, flag_q, flag_r, flag_s, flag_t, flag_u,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.name.write_to(w)?;
        self.stage_desc.write_to(w)?;
        self.complete_log.write_to(w)?;
        self.sequencer_desc.write_to(w)?;
        self.spawn_faction_spawn_data_info.write_to(w)?;
        self.spawn_faction_node_info.write_to(w)?;
        self.disable_faction_spawn_party_name_hash_list.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.raw_c.write_to(w)?;
        self.list_a.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.lookup_d.write_to(w)?;
        self.lookup_e.write_to(w)?;
        self.close_filter_a.write_to(w)?;
        self.close_filter_b.write_to(w)?;
        self.close_filter_c.write_to(w)?;
        self.filter_entry_list.write_to(w)?;
        self.lookup_f.write_to(w)?;
        self.lookup_g.write_to(w)?;
        self.lookup_h.write_to(w)?;
        self.list_b.write_to(w)?;
        self.list_c.write_to(w)?;
        self.lookup_i.write_to(w)?;
        self.raw_d.write_to(w)?;
        self.cstring_a.write_to(w)?;
        self.flag_c.write_to(w)?;
        self.flag_d.write_to(w)?;
        self.raw_e.write_to(w)?;
        self.raw_f.write_to(w)?;
        self.pair_a.write_to(w)?;
        self.pair_b.write_to(w)?;
        self.raw_g.write_to(w)?;
        self.raw_h.write_to(w)?;
        self.raw_i.write_to(w)?;
        self.mob_map_list.write_to(w)?;
        self.lookup_j.write_to(w)?;
        self.string_entry_list.write_to(w)?;
        self.adjacency_mob_list_a.write_to(w)?;
        self.adjacency_mob_list_b.write_to(w)?;
        self.adjacency_mob_list_c.write_to(w)?;
        self.adjacency_mob_list_d.write_to(w)?;
        self.close_filter_d_a.write_to(w)?;
        self.close_filter_d_b.write_to(w)?;
        self.close_filter_d_c.write_to(w)?;
        self.close_filter_d_d.write_to(w)?;
        self.list_d.write_to(w)?;
        self.platform_entry.write_to(w)?;
        self.lookup_k.write_to(w)?;
        self.lookup_l.write_to(w)?;
        self.lookup_m.write_to(w)?;
        self.lookup_n.write_to(w)?;
        self.lookup_o.write_to(w)?;
        self.lookup_p.write_to(w)?;
        self.lookup_q.write_to(w)?;
        self.lookup_r.write_to(w)?;
        self.label_b.write_to(w)?;
        self.lookup_s.write_to(w)?;
        self.flag_e.write_to(w)?;
        self.flag_f.write_to(w)?;
        self.lookup_t.write_to(w)?;
        self.behavior_entry_list.write_to(w)?;
        self.raw_j.write_to(w)?;
        self.lookup_u.write_to(w)?;
        self.lookup_v.write_to(w)?;
        self.lookup_w.write_to(w)?;
        self.raw_k.write_to(w)?;
        self.raw_l.write_to(w)?;
        self.raw_m.write_to(w)?;
        self.raw_n.write_to(w)?;
        self.raw_o.write_to(w)?;
        self.raw_p.write_to(w)?;
        self.flag_g.write_to(w)?;
        self.flag_h.write_to(w)?;
        self.flag_i.write_to(w)?;
        self.flag_j.write_to(w)?;
        self.flag_k.write_to(w)?;
        self.flag_l.write_to(w)?;
        self.flag_m.write_to(w)?;
        self.flag_n.write_to(w)?;
        self.flag_o.write_to(w)?;
        self.flag_p.write_to(w)?;
        self.flag_q.write_to(w)?;
        self.flag_r.write_to(w)?;
        self.flag_s.write_to(w)?;
        self.flag_t.write_to(w)?;
        self.flag_u.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("name".to_string(), self.name.to_json_value());
        m.insert("stage_desc".to_string(), self.stage_desc.to_json_value());
        m.insert("complete_log".to_string(), self.complete_log.to_json_value());
        m.insert("sequencer_desc".to_string(), self.sequencer_desc.to_json_value());
        m.insert("spawn_faction_spawn_data_info".to_string(), self.spawn_faction_spawn_data_info.to_json_value());
        m.insert("spawn_faction_node_info".to_string(), self.spawn_faction_node_info.to_json_value());
        m.insert("disable_faction_spawn_party_name_hash_list".to_string(), self.disable_faction_spawn_party_name_hash_list.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("raw_b".to_string(), self.raw_b.to_json_value());
        m.insert("raw_c".to_string(), self.raw_c.to_json_value());
        m.insert("list_a".to_string(), self.list_a.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("lookup_d".to_string(), self.lookup_d.to_json_value());
        m.insert("lookup_e".to_string(), self.lookup_e.to_json_value());
        m.insert("close_filter_a".to_string(), self.close_filter_a.to_json_value());
        m.insert("close_filter_b".to_string(), self.close_filter_b.to_json_value());
        m.insert("close_filter_c".to_string(), self.close_filter_c.to_json_value());
        m.insert("filter_entry_list".to_string(), self.filter_entry_list.to_json_value());
        m.insert("lookup_f".to_string(), self.lookup_f.to_json_value());
        m.insert("lookup_g".to_string(), self.lookup_g.to_json_value());
        m.insert("lookup_h".to_string(), self.lookup_h.to_json_value());
        m.insert("list_b".to_string(), self.list_b.to_json_value());
        m.insert("list_c".to_string(), self.list_c.to_json_value());
        m.insert("lookup_i".to_string(), self.lookup_i.to_json_value());
        m.insert("raw_d".to_string(), self.raw_d.to_json_value());
        m.insert("cstring_a".to_string(), self.cstring_a.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        m.insert("flag_d".to_string(), self.flag_d.to_json_value());
        m.insert("raw_e".to_string(), self.raw_e.to_json_value());
        m.insert("raw_f".to_string(), self.raw_f.to_json_value());
        m.insert("pair_a".to_string(), self.pair_a.to_json_value());
        m.insert("pair_b".to_string(), self.pair_b.to_json_value());
        m.insert("raw_g".to_string(), self.raw_g.to_json_value());
        m.insert("raw_h".to_string(), self.raw_h.to_json_value());
        m.insert("raw_i".to_string(), self.raw_i.to_json_value());
        m.insert("mob_map_list".to_string(), self.mob_map_list.to_json_value());
        m.insert("lookup_j".to_string(), self.lookup_j.to_json_value());
        m.insert("string_entry_list".to_string(), self.string_entry_list.to_json_value());
        m.insert("adjacency_mob_list_a".to_string(), self.adjacency_mob_list_a.to_json_value());
        m.insert("adjacency_mob_list_b".to_string(), self.adjacency_mob_list_b.to_json_value());
        m.insert("adjacency_mob_list_c".to_string(), self.adjacency_mob_list_c.to_json_value());
        m.insert("adjacency_mob_list_d".to_string(), self.adjacency_mob_list_d.to_json_value());
        m.insert("close_filter_d_a".to_string(), self.close_filter_d_a.to_json_value());
        m.insert("close_filter_d_b".to_string(), self.close_filter_d_b.to_json_value());
        m.insert("close_filter_d_c".to_string(), self.close_filter_d_c.to_json_value());
        m.insert("close_filter_d_d".to_string(), self.close_filter_d_d.to_json_value());
        m.insert("list_d".to_string(), self.list_d.to_json_value());
        m.insert("platform_entry".to_string(), self.platform_entry.to_json_value());
        m.insert("lookup_k".to_string(), self.lookup_k.to_json_value());
        m.insert("lookup_l".to_string(), self.lookup_l.to_json_value());
        m.insert("lookup_m".to_string(), self.lookup_m.to_json_value());
        m.insert("lookup_n".to_string(), self.lookup_n.to_json_value());
        m.insert("lookup_o".to_string(), self.lookup_o.to_json_value());
        m.insert("lookup_p".to_string(), self.lookup_p.to_json_value());
        m.insert("lookup_q".to_string(), self.lookup_q.to_json_value());
        m.insert("lookup_r".to_string(), self.lookup_r.to_json_value());
        m.insert("label_b".to_string(), self.label_b.to_json_value());
        m.insert("lookup_s".to_string(), self.lookup_s.to_json_value());
        m.insert("flag_e".to_string(), self.flag_e.to_json_value());
        m.insert("flag_f".to_string(), self.flag_f.to_json_value());
        m.insert("lookup_t".to_string(), self.lookup_t.to_json_value());
        m.insert("behavior_entry_list".to_string(), self.behavior_entry_list.to_json_value());
        m.insert("raw_j".to_string(), self.raw_j.to_json_value());
        m.insert("lookup_u".to_string(), self.lookup_u.to_json_value());
        m.insert("lookup_v".to_string(), self.lookup_v.to_json_value());
        m.insert("lookup_w".to_string(), self.lookup_w.to_json_value());
        m.insert("raw_k".to_string(), self.raw_k.to_json_value());
        m.insert("raw_l".to_string(), self.raw_l.to_json_value());
        m.insert("raw_m".to_string(), self.raw_m.to_json_value());
        m.insert("raw_n".to_string(), self.raw_n.to_json_value());
        m.insert("raw_o".to_string(), self.raw_o.to_json_value());
        m.insert("raw_p".to_string(), self.raw_p.to_json_value());
        m.insert("flag_g".to_string(), self.flag_g.to_json_value());
        m.insert("flag_h".to_string(), self.flag_h.to_json_value());
        m.insert("flag_i".to_string(), self.flag_i.to_json_value());
        m.insert("flag_j".to_string(), self.flag_j.to_json_value());
        m.insert("flag_k".to_string(), self.flag_k.to_json_value());
        m.insert("flag_l".to_string(), self.flag_l.to_json_value());
        m.insert("flag_m".to_string(), self.flag_m.to_json_value());
        m.insert("flag_n".to_string(), self.flag_n.to_json_value());
        m.insert("flag_o".to_string(), self.flag_o.to_json_value());
        m.insert("flag_p".to_string(), self.flag_p.to_json_value());
        m.insert("flag_q".to_string(), self.flag_q.to_json_value());
        m.insert("flag_r".to_string(), self.flag_r.to_json_value());
        m.insert("flag_s".to_string(), self.flag_s.to_json_value());
        m.insert("flag_t".to_string(), self.flag_t.to_json_value());
        m.insert("flag_u".to_string(), self.flag_u.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_desc")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "complete_log")?)?;
        <SequencerStageChartDescPartial as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sequencer_desc")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "spawn_faction_spawn_data_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "spawn_faction_node_info")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "disable_faction_spawn_party_name_hash_list")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_c")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_e")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_a")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_b")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_c")?)?;
        <CArray<StageFilterEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "filter_entry_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_f")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_g")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_h")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_b")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_i")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_d")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cstring_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_e")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_f")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "pair_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "pair_b")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_g")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_h")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_i")?)?;
        <CArray<StageMobMapEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "mob_map_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_j")?)?;
        <CArray<StageU32StringEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_entry_list")?)?;
        <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "adjacency_mob_list_a")?)?;
        <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "adjacency_mob_list_b")?)?;
        <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "adjacency_mob_list_c")?)?;
        <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "adjacency_mob_list_d")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_d_a")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_d_b")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_d_c")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "close_filter_d_d")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_d")?)?;
        OptStageOpt52::write_from_json(w, json_get_field(obj, "platform_entry")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_k")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_l")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_m")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_n")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_o")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_p")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_q")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_r")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "label_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_s")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_e")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_f")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_t")?)?;
        <CArray<StageBehaviorEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "behavior_entry_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_j")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_u")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_v")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_w")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_k")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_l")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_m")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_n")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_o")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_p")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_g")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_h")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_i")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_j")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_k")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_l")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_m")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_n")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_o")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_p")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_q")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_r")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_s")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_t")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_u")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\stageinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\stageinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                StageInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "stageinfo roundtrip mismatch");
    }

    // The previous `empty_tail_on_vanilla` test asserted `tail_blob` was
    // always empty; the field was now removed so the assertion has been
    // folded into `read_with_size` itself (under/over-read returns Err).

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = StageInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            StageInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
