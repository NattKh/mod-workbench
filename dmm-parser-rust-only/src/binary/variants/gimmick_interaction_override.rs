// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Per-element types for `sub_141118470`, the
//! `CArray<COptional<GimmickInteractionOverrideData>>` payload that
//! gates field 7 of gimmick_info and field 133 of character_info.
//!
//! The inner `sub_1410DF770` reader has 15 wire fields (144 mem bytes)
//! including an embedded `BareConditionPairCArray` which routes through
//! the same stream-mode GameCondition path that interaction_info uses.

use crate::binary::*;
use crate::binary::variants::condition_pair::BareConditionPairCArray;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use crate::tables::faction_node_info::info::FactionAdjacencyMobItem;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Inner of GimmickInteractionOverrideData field 4 (8-byte stride).
    /// Wire = u32 hash (sub_1410A9D40 — wire CString) + u32 raw.
    pub struct StringHashU32Pair<'a> {
        pub key: CString<'a>,
        pub raw: u32,
    }
}

py_binary_struct! {
    /// `sub_1410DF4C0` per-element (sub_141114FC0 inner). 48 mem bytes.
    /// Wire: u32 + CString-hash + CString + u32 + Vec3 + 3× u32.
    pub struct InteractionOverrideField5Element<'a> {
        pub raw_a: u32,
        pub key_hash: CString<'a>,    // sub_1410A9D40 — wire CString
        pub label: CString<'a>,
        pub raw_b: u32,
        pub vec_a: [f32; 3],
        pub raw_c: u32,
        pub raw_d: u32,
        pub raw_e: u32,
    }
}

/// `sub_1410DF770` — 15 wire fields / 144 mem bytes per element.
#[derive(Debug)]
pub struct GimmickInteractionOverrideData<'a> {
    pub lookup_a: u32,
    pub label: LocalizableString<'a>,
    pub raw_a: u32,
    pub hash_pair_list: CArray<StringHashU32Pair<'a>>,
    pub override_field5_list: CArray<InteractionOverrideField5Element<'a>>,
    pub cond_pair_list: BareConditionPairCArray<'a>,
    pub mob_list: CArray<FactionAdjacencyMobItem>,
    pub list_a: CArray<u32>,
    pub lookup_b: u32,
    pub lookup_c: u32,
    pub flag_a: u8,
    pub flag_b: u8,
    pub flag_c: u8,
    pub flag_d: u8,
    pub flag_e: u8,
}

impl<'a> BinaryRead<'a> for GimmickInteractionOverrideData<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            lookup_a: u32::read_from(data, offset)?,
            label: LocalizableString::read_from(data, offset)?,
            raw_a: u32::read_from(data, offset)?,
            hash_pair_list: CArray::<StringHashU32Pair>::read_from(data, offset)?,
            override_field5_list: CArray::<InteractionOverrideField5Element>::read_from(data, offset)?,
            cond_pair_list: BareConditionPairCArray::read_from(data, offset)?,
            mob_list: CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?,
            list_a: CArray::<u32>::read_from(data, offset)?,
            lookup_b: u32::read_from(data, offset)?,
            lookup_c: u32::read_from(data, offset)?,
            flag_a: u8::read_from(data, offset)?,
            flag_b: u8::read_from(data, offset)?,
            flag_c: u8::read_from(data, offset)?,
            flag_d: u8::read_from(data, offset)?,
            flag_e: u8::read_from(data, offset)?,
        })
    }
}

impl<'a> BinaryWrite for GimmickInteractionOverrideData<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.lookup_a.write_to(w)?;
        self.label.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.hash_pair_list.write_to(w)?;
        self.override_field5_list.write_to(w)?;
        self.cond_pair_list.write_to(w)?;
        self.mob_list.write_to(w)?;
        self.list_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)?;
        self.flag_d.write_to(w)?;
        self.flag_e.write_to(w)?;
        Ok(())
    }
}

impl<'a> ToJsonValue for GimmickInteractionOverrideData<'a> {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("label".to_string(), self.label.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("hash_pair_list".to_string(), self.hash_pair_list.to_json_value());
        m.insert("override_field5_list".to_string(), self.override_field5_list.to_json_value());
        m.insert("cond_pair_list".to_string(), self.cond_pair_list.to_json_value());
        m.insert("mob_list".to_string(), self.mob_list.to_json_value());
        m.insert("list_a".to_string(), self.list_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        m.insert("flag_d".to_string(), self.flag_d.to_json_value());
        m.insert("flag_e".to_string(), self.flag_e.to_json_value());
        Value::Object(m)
    }
}

impl<'a> WriteJsonValue for GimmickInteractionOverrideData<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "GimmickInteractionOverrideData: expected object",
        ))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "label")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <CArray<StringHashU32Pair> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_pair_list")?)?;
        <CArray<InteractionOverrideField5Element> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "override_field5_list")?)?;
        <BareConditionPairCArray as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cond_pair_list")?)?;
        <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "mob_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_d")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_e")?)?;
        Ok(())
    }
}

/// `u8 presence + (if present: GimmickInteractionOverrideData)` —
/// inner element of `sub_141118470`.
#[derive(Debug)]
pub struct OptionalGimmickInteractionOverrideData<'a> {
    pub inner: Option<GimmickInteractionOverrideData<'a>>,
}

impl<'a> BinaryRead<'a> for OptionalGimmickInteractionOverrideData<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(GimmickInteractionOverrideData::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl<'a> BinaryWrite for OptionalGimmickInteractionOverrideData<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => { 1u8.write_to(w)?; v.write_to(w) }
            None => 0u8.write_to(w),
        }
    }
}

impl<'a> ToJsonValue for OptionalGimmickInteractionOverrideData<'a> {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }
}

impl<'a> WriteJsonValue for OptionalGimmickInteractionOverrideData<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)
        } else {
            1u8.write_to(w)?;
            <GimmickInteractionOverrideData as WriteJsonValue>::write_from_json(w, v)
        }
    }
}

/// `sub_141118470` — `CArray<COptional<GimmickInteractionOverrideData>>`.
/// Used by gimmick_info field 7 and character_info field 133.
#[derive(Debug)]
pub struct GimmickInteractionOverrideCArray<'a> {
    pub items: Vec<OptionalGimmickInteractionOverrideData<'a>>,
}

impl<'a> BinaryRead<'a> for GimmickInteractionOverrideCArray<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let count = u32::read_from(data, offset)?;
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(OptionalGimmickInteractionOverrideData::read_from(data, offset)?);
        }
        Ok(Self { items })
    }
}

impl<'a> BinaryWrite for GimmickInteractionOverrideCArray<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        (self.items.len() as u32).write_to(w)?;
        for it in &self.items { it.write_to(w)?; }
        Ok(())
    }
}

impl<'a> ToJsonValue for GimmickInteractionOverrideCArray<'a> {
    fn to_json_value(&self) -> Value {
        Value::Array(self.items.iter().map(|i| i.to_json_value()).collect())
    }
}

impl<'a> WriteJsonValue for GimmickInteractionOverrideCArray<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "GimmickInteractionOverrideCArray: expected array",
        ))?;
        (arr.len() as u32).write_to(w)?;
        for it in arr {
            OptionalGimmickInteractionOverrideData::write_from_json(w, it)?;
        }
        Ok(())
    }
}
