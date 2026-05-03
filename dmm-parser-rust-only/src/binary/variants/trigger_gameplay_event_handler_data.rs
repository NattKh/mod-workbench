// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! TriggerGamePlayEventHandlerData polymorphic family wrapper.
//!
//! Per Win-IDA dispatcher `sub_141D80A90`:
//!   1. read 1 byte dispatch_tag
//!   2. factory `sub_141D80500` allocates a per-tag struct (40/48/112/144 mem)
//!   3. vtable[85] body reader fills the wire fields
//!
//! All 8 cases mapped via Win-IDA decompile (2026-04-30):
//!
//! | tag | mem | class                                                | vtable[85]   | wire summary |
//! |-----|-----|------------------------------------------------------|--------------|--------------|
//! |  0  | 112 | TriggerGamePlayEventHandlerData_Gimmick              | sub_141D836E0| Helper(40 b) + 7×u32 + 1 u8 |
//! |  1  |  40 | …_IgnoreFallingDamageToTarget                        | no-op (0)    | 0 bytes |
//! |  2  |  48 | …_ApplyPassiveSkillToTarget                          | sub_141D84010| 1× u64 |
//! |  3  | 144 | …_ForceField                                         | sub_141D85660| u32+u32+u32 + u8 sub-dispatch + sub_141D84040 helper + per-sub body |
//! |  4  |  40 | …_MoveSyncGimmickWithPlatform                        | no-op (0)    | 0 bytes |
//! |  5  |  48 | …_DetectTriggerExpansion                             | sub_141D86960| 1× CString |
//! |  6  |  40 | …_TriggerRegionInfo                                  | no-op (0)    | 0 bytes |
//! |  7  |  40 | …_ElementalArea                                      | no-op (0)    | 0 bytes |
//!
//! Outer wrapper (sub_1411125E0, used by `gimmick_info::post_blob` field 17):
//!   `CArray<COptional<TriggerGamePlayEventHandlerData>>` —
//!   u32 count + per-element u8 presence + (if !=0) tag + body.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

// ── Helpers ───────────────────────────────────────────────────────────────

py_binary_struct! {
    /// `sub_1410AA1B0` helper used inside Tag 0 (Gimmick). Wire:
    /// 12 bytes (vec_a) + 4× u32 (block_a..d) + 12 bytes (vec_b).
    /// Reads occur in order: vec_a → block_a..d → vec_b for 40 wire bytes.
    pub struct GimmickHelperBlock {
        pub vec_a: [f32; 3],
        pub block_a: u32,
        pub block_b: u32,
        pub block_c: u32,
        pub block_d: u32,
        pub vec_b: [f32; 3],
    }
}

py_binary_struct! {
    /// `sub_141D84040` helper used inside Tag 3 (ForceField). Wire:
    /// u32 + u32 + u8 + u8 + u8 + CArray<u32>.
    pub struct ForceFieldHelperBlock {
        pub raw_a: u32,
        pub raw_b: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub list: CArray<u32>,
    }
}

py_binary_struct! {
    /// `sub_141D84190` helper used inside Tag 3 (ForceField) sub-case 4.
    /// 13× u32 + 2× u8 = 54 wire bytes.
    pub struct ForceFieldSubCase4Body {
        pub raw_00: u32, pub raw_04: u32, pub raw_08: u32, pub raw_12: u32,
        pub raw_16: u32, pub raw_20: u32, pub raw_24: u32, pub raw_28: u32,
        pub raw_32: u32, pub raw_36: u32, pub raw_40: u32, pub raw_44: u32,
        pub raw_48: u32,
        pub flag_52: u8,
        pub flag_53: u8,
    }
}

// ── Per-tag bodies ────────────────────────────────────────────────────────

py_binary_struct! {
    /// Tag 0 wire body (sub_141D836E0). 40 + 7×4 + 1 = 69 bytes.
    pub struct GimmickBody {
        pub helper: GimmickHelperBlock,
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u32,
        pub raw_e: u32,
        pub raw_f: u32,
        pub raw_g: u32,
        pub flag: u8,
    }
}

py_binary_struct! {
    /// Tag 2 wire body (sub_141D84010). 1× u64 = 8 bytes.
    pub struct ApplyPassiveSkillToTargetBody {
        pub value: u64,
    }
}

py_binary_struct! {
    /// Tag 5 wire body (sub_141D86960). 1× CString.
    pub struct DetectTriggerExpansionBody<'a> {
        pub value: CString<'a>,
    }
}

// Tag 3 ForceField — nested polymorphic body
py_binary_struct! {
    pub struct ForceFieldSubCase01230rOther {
        pub raw_88: u32,
        pub raw_92: u32,
        pub raw_96: u32,
        pub raw_100: u32,
        pub raw_104: u32,
        pub raw_108: u32,
        pub raw_112: u32,
        pub raw_116: u32,
        pub raw_120: u32,
        pub raw_124: u32,
        pub flag_128: u8,
    }
}

py_binary_struct! {
    pub struct ForceFieldSubCase5 {
        pub raw_88: u32,
        pub flag_92: u8,
    }
}

py_binary_struct! {
    pub struct ForceFieldSubCase7 {
        pub raw_88: u32,
        pub raw_92: u32,
        pub raw_96: u32,
    }
}

py_binary_struct! {
    pub struct ForceFieldSubCase8 {
        pub raw_88: u32,
        pub raw_92: u32,
        pub raw_96: u32,
        pub raw_100: u32,
        pub raw_104: u32,
        pub raw_108: u32,
        pub raw_112: u32,
        pub raw_116: u32,
        pub raw_120: u32,
        pub flag_124: u8,
    }
}

#[derive(Debug)]
pub enum ForceFieldSubBody {
    /// sub-cases 0/1/2/3 — 41 bytes
    StandardCase01_3(ForceFieldSubCase01230rOther),
    /// sub-case 4 — variable via ForceFieldSubCase4Body
    Case4(ForceFieldSubCase4Body),
    /// sub-case 5 — 5 bytes
    Case5(ForceFieldSubCase5),
    /// sub-case 7 — 12 bytes
    Case7(ForceFieldSubCase7),
    /// sub-case 8 — 41 bytes (different layout from 0-3)
    Case8(ForceFieldSubCase8),
    /// Default for unrecognized sub-tags — no body
    Other,
}

#[derive(Debug)]
pub struct ForceFieldBody {
    pub raw_a: u32,
    pub raw_b: u32,
    pub raw_c: u32,
    pub sub_dispatch: u8,
    pub helper: ForceFieldHelperBlock,
    pub sub_body: ForceFieldSubBody,
}

impl<'a> BinaryRead<'a> for ForceFieldBody {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let raw_a = u32::read_from(data, offset)?;
        let raw_b = u32::read_from(data, offset)?;
        let raw_c = u32::read_from(data, offset)?;
        let sub_dispatch = u8::read_from(data, offset)?;
        let helper = ForceFieldHelperBlock::read_from(data, offset)?;
        let sub_body = match sub_dispatch {
            0..=3 => {
                ForceFieldSubBody::StandardCase01_3(ForceFieldSubCase01230rOther::read_from(data, offset)?)
            }
            4 => ForceFieldSubBody::Case4(ForceFieldSubCase4Body::read_from(data, offset)?),
            5 => ForceFieldSubBody::Case5(ForceFieldSubCase5::read_from(data, offset)?),
            7 => ForceFieldSubBody::Case7(ForceFieldSubCase7::read_from(data, offset)?),
            8 => ForceFieldSubBody::Case8(ForceFieldSubCase8::read_from(data, offset)?),
            _ => ForceFieldSubBody::Other,
        };
        Ok(Self { raw_a, raw_b, raw_c, sub_dispatch, helper, sub_body })
    }
}

impl BinaryWrite for ForceFieldBody {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.raw_a.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.raw_c.write_to(w)?;
        self.sub_dispatch.write_to(w)?;
        self.helper.write_to(w)?;
        match &self.sub_body {
            ForceFieldSubBody::StandardCase01_3(b) => b.write_to(w),
            ForceFieldSubBody::Case4(b) => b.write_to(w),
            ForceFieldSubBody::Case5(b) => b.write_to(w),
            ForceFieldSubBody::Case7(b) => b.write_to(w),
            ForceFieldSubBody::Case8(b) => b.write_to(w),
            ForceFieldSubBody::Other => Ok(()),
        }
    }
}

impl ToJsonValue for ForceFieldBody {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("raw_a".into(), self.raw_a.to_json_value());
        m.insert("raw_b".into(), self.raw_b.to_json_value());
        m.insert("raw_c".into(), self.raw_c.to_json_value());
        m.insert("sub_dispatch".into(), self.sub_dispatch.to_json_value());
        m.insert("helper".into(), self.helper.to_json_value());
        let (sub_kind, sub_body) = match &self.sub_body {
            ForceFieldSubBody::StandardCase01_3(b) => ("standard_0_3", b.to_json_value()),
            ForceFieldSubBody::Case4(b) => ("case_4", b.to_json_value()),
            ForceFieldSubBody::Case5(b) => ("case_5", b.to_json_value()),
            ForceFieldSubBody::Case7(b) => ("case_7", b.to_json_value()),
            ForceFieldSubBody::Case8(b) => ("case_8", b.to_json_value()),
            ForceFieldSubBody::Other => ("other", Value::Null),
        };
        m.insert("sub_body_kind".into(), Value::String(sub_kind.into()));
        m.insert("sub_body".into(), sub_body);
        Value::Object(m)
    }
}

impl WriteJsonValue for ForceFieldBody {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ForceFieldBody: object"))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_c")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sub_dispatch")?)?;
        <ForceFieldHelperBlock as WriteJsonValue>::write_from_json(w, json_get_field(obj, "helper")?)?;
        let kind = json_get_field(obj, "sub_body_kind")?.as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sub_body_kind: string"))?;
        let body_v = json_get_field(obj, "sub_body")?;
        match kind {
            "standard_0_3" => <ForceFieldSubCase01230rOther as WriteJsonValue>::write_from_json(w, body_v)?,
            "case_4" => <ForceFieldSubCase4Body as WriteJsonValue>::write_from_json(w, body_v)?,
            "case_5" => <ForceFieldSubCase5 as WriteJsonValue>::write_from_json(w, body_v)?,
            "case_7" => <ForceFieldSubCase7 as WriteJsonValue>::write_from_json(w, body_v)?,
            "case_8" => <ForceFieldSubCase8 as WriteJsonValue>::write_from_json(w, body_v)?,
            "other" => {}
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ForceFieldBody.sub_body_kind: unknown {:?}", other))),
        }
        Ok(())
    }
}

// ── Top-level enum ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TriggerGamePlayEventHandlerData<'a> {
    Gimmick(GimmickBody),
    IgnoreFallingDamageToTarget,
    ApplyPassiveSkillToTarget(ApplyPassiveSkillToTargetBody),
    ForceField(ForceFieldBody),
    MoveSyncGimmickWithPlatform,
    DetectTriggerExpansion(DetectTriggerExpansionBody<'a>),
    TriggerRegionInfo,
    ElementalArea,
}

impl<'a> TriggerGamePlayEventHandlerData<'a> {
    pub fn dispatch_tag(&self) -> u8 {
        match self {
            Self::Gimmick(_) => 0,
            Self::IgnoreFallingDamageToTarget => 1,
            Self::ApplyPassiveSkillToTarget(_) => 2,
            Self::ForceField(_) => 3,
            Self::MoveSyncGimmickWithPlatform => 4,
            Self::DetectTriggerExpansion(_) => 5,
            Self::TriggerRegionInfo => 6,
            Self::ElementalArea => 7,
        }
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let tag = u8::read_from(data, offset)?;
        match tag {
            0 => Ok(Self::Gimmick(GimmickBody::read_from(data, offset)?)),
            1 => Ok(Self::IgnoreFallingDamageToTarget),
            2 => Ok(Self::ApplyPassiveSkillToTarget(ApplyPassiveSkillToTargetBody::read_from(data, offset)?)),
            3 => Ok(Self::ForceField(ForceFieldBody::read_from(data, offset)?)),
            4 => Ok(Self::MoveSyncGimmickWithPlatform),
            5 => Ok(Self::DetectTriggerExpansion(DetectTriggerExpansionBody::read_from(data, offset)?)),
            6 => Ok(Self::TriggerRegionInfo),
            7 => Ok(Self::ElementalArea),
            other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("TriggerGamePlayEventHandlerData: unknown tag {}", other))),
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.dispatch_tag().write_to(w)?;
        match self {
            Self::Gimmick(b) => b.write_to(w),
            Self::IgnoreFallingDamageToTarget => Ok(()),
            Self::ApplyPassiveSkillToTarget(b) => b.write_to(w),
            Self::ForceField(b) => b.write_to(w),
            Self::MoveSyncGimmickWithPlatform => Ok(()),
            Self::DetectTriggerExpansion(b) => b.write_to(w),
            Self::TriggerRegionInfo => Ok(()),
            Self::ElementalArea => Ok(()),
        }
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("tag".into(), self.dispatch_tag().to_json_value());
        let (kind, body) = match self {
            Self::Gimmick(b) => ("Gimmick", b.to_json_value()),
            Self::IgnoreFallingDamageToTarget => ("IgnoreFallingDamageToTarget", Value::Null),
            Self::ApplyPassiveSkillToTarget(b) => ("ApplyPassiveSkillToTarget", b.to_json_value()),
            Self::ForceField(b) => ("ForceField", b.to_json_value()),
            Self::MoveSyncGimmickWithPlatform => ("MoveSyncGimmickWithPlatform", Value::Null),
            Self::DetectTriggerExpansion(b) => ("DetectTriggerExpansion", b.to_json_value()),
            Self::TriggerRegionInfo => ("TriggerRegionInfo", Value::Null),
            Self::ElementalArea => ("ElementalArea", Value::Null),
        };
        m.insert("kind".into(), Value::String(kind.into()));
        m.insert("body".into(), body);
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TGPEHD: object"))?;
        let tag = json_get_field(obj, "tag")?.as_u64().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TGPEHD.tag: u8"))? as u8;
        w.push(tag);
        let body = json_get_field(obj, "body")?;
        match tag {
            0 => <GimmickBody as WriteJsonValue>::write_from_json(w, body)?,
            1 => {}
            2 => <ApplyPassiveSkillToTargetBody as WriteJsonValue>::write_from_json(w, body)?,
            3 => <ForceFieldBody as WriteJsonValue>::write_from_json(w, body)?,
            4 => {}
            5 => <DetectTriggerExpansionBody as WriteJsonValue>::write_from_json(w, body)?,
            6 => {}
            7 => {}
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("TGPEHD: unknown tag {}", other))),
        }
        Ok(())
    }
}

// ── COptional wrapper used by sub_1411125E0's CArray ──────────────────────

#[derive(Debug)]
pub struct OptionalTriggerGamePlayEventHandlerData<'a> {
    pub inner: Option<TriggerGamePlayEventHandlerData<'a>>,
}

impl<'a> BinaryRead<'a> for OptionalTriggerGamePlayEventHandlerData<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(TriggerGamePlayEventHandlerData::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl<'a> BinaryReadTracked<'a> for OptionalTriggerGamePlayEventHandlerData<'a> {
    fn read_tracked(data: &'a [u8], offset: &mut usize, _path: &mut String, _ranges: &mut Vec<FieldRange>) -> io::Result<Self> {
        Self::read_from(data, offset)
    }
}

impl BinaryWrite for OptionalTriggerGamePlayEventHandlerData<'_> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(d) => { 1u8.write_to(w)?; d.write_to(w) }
            None => 0u8.write_to(w),
        }
    }
}

impl ToJsonValue for OptionalTriggerGamePlayEventHandlerData<'_> {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(d) => d.to_json_value(),
            None => Value::Null,
        }
    }
}

impl WriteJsonValue for OptionalTriggerGamePlayEventHandlerData<'_> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)
        } else {
            1u8.write_to(w)?;
            TriggerGamePlayEventHandlerData::write_from_json(w, v)
        }
    }
}

