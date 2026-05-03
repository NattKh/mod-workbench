// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Full typed wrapper for SequencerStageChartDesc (sub_141D8C6D0).
//!
//! The per-element reader has 26 wire fields / 232 mem bytes — all
//! reverse-engineered and field-level addressable as of this commit.
//! `opaque_tail` stays in the struct for graceful degradation but is
//! always empty on vanilla data. Wire layout:
//!
//!   1. CString name
//!   2. u32 raw
//!   3. CString prefab_path
//!   4. [f32; 3] position (Vec3)
//!   5. u32 raw
//!   6-13. 8× u8 flag
//!  14. u32 lookup_a (sub_141106210, qword_145F113B8 hash)
//!  15. OptionalGameCondition cond_a (sub_141103B30 — u8 presence +
//!      optional GameCondition tree + 3 footer bytes)
//!  16. CString cstring_a
//!  17. CString cstring_b
//!  18. CArray<(CString, CString)> string_pair_list
//!  19. CArray<ChartTrackChangeElement> track_change_list — each
//!      element is OptionalGameCondition + 3 fixed-class CArrays
//!      (Character / Gimmick / Item subclasses of
//!      SequencerStageTrackChangeData), all reverse-engineered.
//!  20. CArray<CArray<SequencerStageSpawnData>> spawn_data_lists —
//!      sub_14110E010 outer + sub_14110BCC0 inner builder; each
//!      SequencerStageSpawnData (sub_1410F3220) is OptionalGame-
//!      Condition + u64 + 5 lookups + u8 flag + Optional<{CArray<u64>,
//!      u32}>. Reverse-engineered.
//!  21. CArray<u16> list_a (sub_1410FFAC0)
//!  22. CArray<u16> list_b (sub_1410FFAC0)
//!  23. CArray<u32> list_c (sub_1410FEF40)
//!  24. CArray<u32> list_d (sub_1410FEF40)
//!  25. CArray<u32> list_e (sub_141102FF0)
//!  26. CArray<u32> list_f (sub_141102FF0)
//!
//! `SequencerStageChartDescPartial` reads all 26 fields explicitly.
//! `opaque_tail` is preserved for forward compatibility but holds zero
//! bytes for every vanilla SequencerStageChartDesc.

use crate::binary::optional_game_condition::OptionalGameCondition;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Inner element of `string_pair_list` — wire is 2× CString,
    /// 16-byte mem stride per element (sub_141D8C6D0's loop body).
    pub struct StringPair<'a> {
        pub key: CString<'a>,
        pub value: CString<'a>,
    }
}

/// `SequencerStageTrackChangeData_Character` element (sub_1410F27B0,
/// 40 mem bytes). Wire reads:
///   1. OptionalGameCondition cond     (sub_141103B30)
///   2. u64 raw                        (8 wire bytes)
///   3. u32 lookup_a                   (sub_1410FF340 → qword_145F0DA08)
///   4. u32 lookup_b                   (sub_1410FF340)
///   5. u16 lookup_c                   (sub_1411003E0 → qword_145F12668)
///   6. u8 has_extra
///   7. if has_extra != 0: u64 extra
#[derive(Debug)]
pub struct TrackChangeCharacter<'a> {
    pub cond: OptionalGameCondition<'a>,
    pub raw_a: u64,
    pub lookup_a: u32,
    pub lookup_b: u32,
    pub lookup_c: u16,
    pub has_extra: u8,
    pub extra: Option<u64>,
}

impl<'a> BinaryRead<'a> for TrackChangeCharacter<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let cond = OptionalGameCondition::read_from(data, offset)?;
        let raw_a = u64::read_from(data, offset)?;
        let lookup_a = u32::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let lookup_c = u16::read_from(data, offset)?;
        let has_extra = u8::read_from(data, offset)?;
        let extra = if has_extra != 0 {
            Some(u64::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { cond, raw_a, lookup_a, lookup_b, lookup_c, has_extra, extra })
    }
}

impl<'a> BinaryWrite for TrackChangeCharacter<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.has_extra.write_to(w)?;
        if let Some(v) = &self.extra { v.write_to(w)?; }
        Ok(())
    }
}

impl<'a> ToJsonValue for TrackChangeCharacter<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond".to_string(), self.cond.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("has_extra".to_string(), self.has_extra.to_json_value());
        m.insert("extra".to_string(), match &self.extra {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        });
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for TrackChangeCharacter<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "TrackChangeCharacter: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        let has_extra_v = json_get_field(obj, "has_extra")?;
        <u8 as WriteJsonValue>::write_from_json(w, has_extra_v)?;
        let has_extra = has_extra_v.as_u64().unwrap_or(0);
        if has_extra != 0 {
            <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "extra")?)?;
        }
        Ok(())
    }
}

/// `SequencerStageTrackChangeData_Gimmick` element (sub_1410F2A30,
/// 32 mem bytes). Wire = OptionalGameCondition + u64 + 2× u32 lookup
/// (sub_141100740 → qword_145F0DA38).
#[derive(Debug)]
pub struct TrackChangeGimmick<'a> {
    pub cond: OptionalGameCondition<'a>,
    pub raw_a: u64,
    pub lookup_a: u32,
    pub lookup_b: u32,
}

impl<'a> BinaryRead<'a> for TrackChangeGimmick<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            cond: OptionalGameCondition::read_from(data, offset)?,
            raw_a: u64::read_from(data, offset)?,
            lookup_a: u32::read_from(data, offset)?,
            lookup_b: u32::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for TrackChangeGimmick<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for TrackChangeGimmick<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond".to_string(), self.cond.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for TrackChangeGimmick<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "TrackChangeGimmick: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        Ok(())
    }
}

/// `SequencerStageTrackChangeData_Item` element (sub_1410F2B50, 32 mem
/// bytes). Same wire shape as Gimmick — different runtime hash table.
#[derive(Debug)]
pub struct TrackChangeItem<'a> {
    pub cond: OptionalGameCondition<'a>,
    pub raw_a: u64,
    pub lookup_a: u32,
    pub lookup_b: u32,
}

impl<'a> BinaryRead<'a> for TrackChangeItem<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            cond: OptionalGameCondition::read_from(data, offset)?,
            raw_a: u64::read_from(data, offset)?,
            lookup_a: u32::read_from(data, offset)?,
            lookup_b: u32::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for TrackChangeItem<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for TrackChangeItem<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond".to_string(), self.cond.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for TrackChangeItem<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "TrackChangeItem: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        Ok(())
    }
}

/// `sub_14110BE50` — `Option<{CArray<u64>, u32}>`. 24 mem bytes when
/// present. Wire: u8 presence + (if present: CArray<u64> + u32).
#[derive(Debug)]
pub struct OptionalU64ListAndU32 {
    pub inner: Option<U64ListAndU32>,
}

#[derive(Debug)]
pub struct U64ListAndU32 {
    pub list: CArray<u64>,
    pub raw: u32,
}

impl<'a> BinaryRead<'a> for OptionalU64ListAndU32 {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(U64ListAndU32 {
                list: CArray::<u64>::read_from(data, offset)?,
                raw: u32::read_from(data, offset)?,
            })
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl BinaryWrite for OptionalU64ListAndU32 {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => {
                1u8.write_to(w)?;
                v.list.write_to(w)?;
                v.raw.write_to(w)?;
            }
            None => 0u8.write_to(w)?,
        }
        Ok(())
    }
}

impl ToJsonValue for OptionalU64ListAndU32 {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => {
                let mut m = Map::new();
                m.insert("list".to_string(), v.list.to_json_value());
                m.insert("raw".to_string(), v.raw.to_json_value());
                Value::Object(m)
            }
            None => Value::Null,
        }
    }
}

impl WriteJsonValue for OptionalU64ListAndU32 {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)?;
            return Ok(());
        }
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "OptionalU64ListAndU32: expected object or null",
        ))?;
        1u8.write_to(w)?;
        <CArray<u64> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw")?)?;
        Ok(())
    }
}

/// `SequencerStageSpawnData` element (sub_1410F3220, 48 mem bytes).
/// Wire: OptionalGameCondition + u64 + 2× u32 lookup + 2× u16 lookup
/// + u32 lookup + u8 + Optional<{CArray<u64>, u32}>.
#[derive(Debug)]
pub struct SequencerStageSpawnData<'a> {
    pub cond: OptionalGameCondition<'a>,
    pub raw_a: u64,
    pub lookup_a: u32,
    pub lookup_b: u16,
    pub lookup_c: u32,
    pub lookup_d: u16,
    pub lookup_e: u32,
    pub flag: u8,
    pub extra: OptionalU64ListAndU32,
}

impl<'a> BinaryRead<'a> for SequencerStageSpawnData<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            cond: OptionalGameCondition::read_from(data, offset)?,
            raw_a: u64::read_from(data, offset)?,
            lookup_a: u32::read_from(data, offset)?,
            lookup_b: u16::read_from(data, offset)?,
            lookup_c: u32::read_from(data, offset)?,
            lookup_d: u16::read_from(data, offset)?,
            lookup_e: u32::read_from(data, offset)?,
            flag: u8::read_from(data, offset)?,
            extra: OptionalU64ListAndU32::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for SequencerStageSpawnData<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.lookup_d.write_to(w)?;
        self.lookup_e.write_to(w)?;
        self.flag.write_to(w)?;
        self.extra.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for SequencerStageSpawnData<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond".to_string(), self.cond.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("lookup_d".to_string(), self.lookup_d.to_json_value());
        m.insert("lookup_e".to_string(), self.lookup_e.to_json_value());
        m.insert("flag".to_string(), self.flag.to_json_value());
        m.insert("extra".to_string(), self.extra.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for SequencerStageSpawnData<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "SequencerStageSpawnData: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_e")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag")?)?;
        OptionalU64ListAndU32::write_from_json(w, json_get_field(obj, "extra")?)?;
        Ok(())
    }
}

/// `sub_1410F2F90` per-element of field 19's outer CArray (56 mem
/// bytes). Wire = OptionalGameCondition + 3 inner CArrays.
#[derive(Debug)]
pub struct ChartTrackChangeElement<'a> {
    pub cond: OptionalGameCondition<'a>,
    pub character_list: CArray<TrackChangeCharacter<'a>>,
    pub gimmick_list: CArray<TrackChangeGimmick<'a>>,
    pub item_list: CArray<TrackChangeItem<'a>>,
}

impl<'a> BinaryRead<'a> for ChartTrackChangeElement<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            cond: OptionalGameCondition::read_from(data, offset)?,
            character_list: CArray::<TrackChangeCharacter>::read_from(data, offset)?,
            gimmick_list: CArray::<TrackChangeGimmick>::read_from(data, offset)?,
            item_list: CArray::<TrackChangeItem>::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for ChartTrackChangeElement<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond.write_to(w)?;
        self.character_list.write_to(w)?;
        self.gimmick_list.write_to(w)?;
        self.item_list.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for ChartTrackChangeElement<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond".to_string(), self.cond.to_json_value());
        m.insert("character_list".to_string(), self.character_list.to_json_value());
        m.insert("gimmick_list".to_string(), self.gimmick_list.to_json_value());
        m.insert("item_list".to_string(), self.item_list.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for ChartTrackChangeElement<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "ChartTrackChangeElement: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond")?)?;
        <CArray<TrackChangeCharacter> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "character_list")?,
        )?;
        <CArray<TrackChangeGimmick> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "gimmick_list")?,
        )?;
        <CArray<TrackChangeItem> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "item_list")?,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SequencerStageChartDescPartial<'a> {
    pub name: CString<'a>,
    pub raw_a: u32,
    pub prefab_path: CString<'a>,
    pub position: [f32; 3],
    pub raw_b: u32,
    pub flag_a: u8,
    pub flag_b: u8,
    pub flag_c: u8,
    pub flag_d: u8,
    pub flag_e: u8,
    pub flag_f: u8,
    pub flag_g: u8,
    pub flag_h: u8,
    /// u32 wire / u16 mem hash (sub_141106210 → qword_145F113B8).
    pub lookup_a: u32,
    /// `OptionalGameCondition` (sub_141103B30 — u8 presence + optional
    /// recursive GameCondition tree + 3 footer bytes). When the tree
    /// hits an anti-disassembly tag, the typed read fails; consumers
    /// fall back to opaque-tail mode in that case via
    /// `read_with_size`'s outer error path.
    pub cond_a: OptionalGameCondition<'a>,
    pub cstring_a: CString<'a>,
    pub cstring_b: CString<'a>,
    pub string_pair_list: CArray<StringPair<'a>>,
    /// `CArray<sub_1410F2F90 element>` — field 19. Each element is
    /// OptionalGameCondition + 3 sub-CArrays of fixed-class
    /// `SequencerStageTrackChangeData_*` elements (Character /
    /// Gimmick / Item subclasses, all reverse-engineered).
    pub track_change_list: CArray<ChartTrackChangeElement<'a>>,
    /// `CArray<CArray<SequencerStageSpawnData>>` — field 20
    /// (sub_14110E010 outer, sub_14110BCC0 inner CArray builder,
    /// sub_1410F3220 per-element reader).
    pub spawn_data_lists: CArray<CArray<SequencerStageSpawnData<'a>>>,
    /// Field 21 — `CArray<u16>` via sub_1410FFAC0 (qword_145F0DA80
    /// hash). Wire: u32 count + count× u16.
    pub list_a: CArray<u16>,
    /// Field 22 — same shape as `list_a`.
    pub list_b: CArray<u16>,
    /// Field 23 — `CArray<u32>` via sub_1410FEF40 (qword_145F0DA30
    /// hash). Wire: u32 count + count× u32.
    pub list_c: CArray<u32>,
    /// Field 24 — same shape as `list_c`.
    pub list_d: CArray<u32>,
    /// Field 25 — `CArray<u32>` via sub_141102FF0 (qword_145F0EEE8
    /// hash). Same wire as `list_c`/`list_d` but different runtime
    /// hash table.
    pub list_e: CArray<u32>,
    /// Field 26 — same shape as `list_e`.
    pub list_f: CArray<u32>,
    /// SequencerStageChartDesc is fully decoded — opaque_tail is now
    /// always empty in vanilla data. Kept around so the wrapper still
    /// degrades gracefully on unrecognized future appendages.
    pub opaque_tail: Vec<u8>,
}

impl<'a> SequencerStageChartDescPartial<'a> {
    /// Read a SequencerStageChartDesc whose total wire size on disk is
    /// known via `total_size`. All 26 wire fields are typed; any
    /// leftover bytes (zero on vanilla) trail into `opaque_tail` for
    /// graceful future-format degradation.
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        total_size: usize,
    ) -> io::Result<Self> {
        let blob_start = *offset;
        let blob_end = blob_start
            .checked_add(total_size)
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "SequencerStageChartDescPartial: total_size overflow",
            ))?;
        if blob_end > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "SequencerStageChartDescPartial: blob extends past data ({} > {})",
                    blob_end, data.len()
                ),
            ));
        }

        let name = CString::read_from(data, offset)?;
        let raw_a = u32::read_from(data, offset)?;
        let prefab_path = CString::read_from(data, offset)?;
        let position = <[f32; 3]>::read_from(data, offset)?;
        let raw_b = u32::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let flag_c = u8::read_from(data, offset)?;
        let flag_d = u8::read_from(data, offset)?;
        let flag_e = u8::read_from(data, offset)?;
        let flag_f = u8::read_from(data, offset)?;
        let flag_g = u8::read_from(data, offset)?;
        let flag_h = u8::read_from(data, offset)?;
        let lookup_a = u32::read_from(data, offset)?;
        let cond_a = OptionalGameCondition::read_from(data, offset)?;
        let cstring_a = CString::read_from(data, offset)?;
        let cstring_b = CString::read_from(data, offset)?;
        let string_pair_list = CArray::<StringPair>::read_from(data, offset)?;
        let track_change_list = CArray::<ChartTrackChangeElement>::read_from(data, offset)?;
        let spawn_data_lists = CArray::<CArray<SequencerStageSpawnData>>::read_from(data, offset)?;
        let list_a = CArray::<u16>::read_from(data, offset)?;
        let list_b = CArray::<u16>::read_from(data, offset)?;
        let list_c = CArray::<u32>::read_from(data, offset)?;
        let list_d = CArray::<u32>::read_from(data, offset)?;
        let list_e = CArray::<u32>::read_from(data, offset)?;
        let list_f = CArray::<u32>::read_from(data, offset)?;

        if *offset > blob_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SequencerStageChartDescPartial: typed prefix overran blob ({} > {})",
                    *offset, blob_end
                ),
            ));
        }
        let opaque_tail = data[*offset..blob_end].to_vec();
        *offset = blob_end;

        Ok(Self {
            name, raw_a, prefab_path, position, raw_b,
            flag_a, flag_b, flag_c, flag_d, flag_e, flag_f, flag_g, flag_h,
            lookup_a, cond_a, cstring_a, cstring_b, string_pair_list,
            track_change_list, spawn_data_lists,
            list_a, list_b, list_c, list_d, list_e, list_f,
            opaque_tail,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.name.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.prefab_path.write_to(w)?;
        self.position.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)?;
        self.flag_d.write_to(w)?;
        self.flag_e.write_to(w)?;
        self.flag_f.write_to(w)?;
        self.flag_g.write_to(w)?;
        self.flag_h.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.cond_a.write_to(w)?;
        self.cstring_a.write_to(w)?;
        self.cstring_b.write_to(w)?;
        self.string_pair_list.write_to(w)?;
        self.track_change_list.write_to(w)?;
        self.spawn_data_lists.write_to(w)?;
        self.list_a.write_to(w)?;
        self.list_b.write_to(w)?;
        self.list_c.write_to(w)?;
        self.list_d.write_to(w)?;
        self.list_e.write_to(w)?;
        self.list_f.write_to(w)?;
        w.write_all(&self.opaque_tail)?;
        Ok(())
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".to_string(), self.name.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("prefab_path".to_string(), self.prefab_path.to_json_value());
        m.insert("position".to_string(), self.position.to_json_value());
        m.insert("raw_b".to_string(), self.raw_b.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        m.insert("flag_d".to_string(), self.flag_d.to_json_value());
        m.insert("flag_e".to_string(), self.flag_e.to_json_value());
        m.insert("flag_f".to_string(), self.flag_f.to_json_value());
        m.insert("flag_g".to_string(), self.flag_g.to_json_value());
        m.insert("flag_h".to_string(), self.flag_h.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("cond_a".to_string(), self.cond_a.to_json_value());
        m.insert("cstring_a".to_string(), self.cstring_a.to_json_value());
        m.insert("cstring_b".to_string(), self.cstring_b.to_json_value());
        m.insert("string_pair_list".to_string(), self.string_pair_list.to_json_value());
        m.insert("track_change_list".to_string(), self.track_change_list.to_json_value());
        m.insert("spawn_data_lists".to_string(), self.spawn_data_lists.to_json_value());
        m.insert("list_a".to_string(), self.list_a.to_json_value());
        m.insert("list_b".to_string(), self.list_b.to_json_value());
        m.insert("list_c".to_string(), self.list_c.to_json_value());
        m.insert("list_d".to_string(), self.list_d.to_json_value());
        m.insert("list_e".to_string(), self.list_e.to_json_value());
        m.insert("list_f".to_string(), self.list_f.to_json_value());
        m.insert("_opaque_tail_b64".to_string(), Value::String(B64.encode(&self.opaque_tail)));
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "SequencerStageChartDescPartial: expected object",
        ))?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "prefab_path")?)?;
        <[f32; 3] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "position")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_d")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_e")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_f")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_g")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_h")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond_a")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cstring_a")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cstring_b")?)?;
        <CArray<StringPair> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_pair_list")?)?;
        <CArray<ChartTrackChangeElement> as WriteJsonValue>::write_from_json(
            w,
            json_get_field(obj, "track_change_list")?,
        )?;
        <CArray<CArray<SequencerStageSpawnData>> as WriteJsonValue>::write_from_json(
            w,
            json_get_field(obj, "spawn_data_lists")?,
        )?;
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_a")?)?;
        <CArray<u16> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_b")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_c")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_d")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_e")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_f")?)?;
        let b64 = json_get_field(obj, "_opaque_tail_b64")?
            .as_str()
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "SequencerStageChartDescPartial: _opaque_tail_b64 must be a string",
            ))?;
        let bytes = B64.decode(b64).map_err(|e| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SequencerStageChartDescPartial: _opaque_tail_b64 invalid base64: {}", e),
        ))?;
        w.extend_from_slice(&bytes);
        Ok(())
    }
}

// Stream-mode trait impls — used when the desc is embedded inside a
// CArray (sequencer_spawn_info, stage_info field 7, etc.) where there
// is no per-element size bound. opaque_tail stays empty in that mode;
// any future-format leftover bytes would surface as a parser-error
// downstream rather than going into the desc's blob.
impl<'a> BinaryRead<'a> for SequencerStageChartDescPartial<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            name: CString::read_from(data, offset)?,
            raw_a: u32::read_from(data, offset)?,
            prefab_path: CString::read_from(data, offset)?,
            position: <[f32; 3]>::read_from(data, offset)?,
            raw_b: u32::read_from(data, offset)?,
            flag_a: u8::read_from(data, offset)?,
            flag_b: u8::read_from(data, offset)?,
            flag_c: u8::read_from(data, offset)?,
            flag_d: u8::read_from(data, offset)?,
            flag_e: u8::read_from(data, offset)?,
            flag_f: u8::read_from(data, offset)?,
            flag_g: u8::read_from(data, offset)?,
            flag_h: u8::read_from(data, offset)?,
            lookup_a: u32::read_from(data, offset)?,
            cond_a: OptionalGameCondition::read_from(data, offset)?,
            cstring_a: CString::read_from(data, offset)?,
            cstring_b: CString::read_from(data, offset)?,
            string_pair_list: CArray::<StringPair>::read_from(data, offset)?,
            track_change_list: CArray::<ChartTrackChangeElement>::read_from(data, offset)?,
            spawn_data_lists: CArray::<CArray<SequencerStageSpawnData>>::read_from(data, offset)?,
            list_a: CArray::<u16>::read_from(data, offset)?,
            list_b: CArray::<u16>::read_from(data, offset)?,
            list_c: CArray::<u32>::read_from(data, offset)?,
            list_d: CArray::<u32>::read_from(data, offset)?,
            list_e: CArray::<u32>::read_from(data, offset)?,
            list_f: CArray::<u32>::read_from(data, offset)?,
            opaque_tail: Vec::new(),
        })
    }
}

impl<'a> BinaryWrite for SequencerStageChartDescPartial<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        Self::write_to(self, w)
    }
}

impl<'a> ToJsonValue for SequencerStageChartDescPartial<'a> {
    fn to_json_value(&self) -> Value {
        Self::to_json_value(self)
    }
}

impl<'a> WriteJsonValue for SequencerStageChartDescPartial<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        Self::write_from_json(w, v)
    }
}
