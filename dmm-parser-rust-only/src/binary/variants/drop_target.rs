// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Typed decoder for the per-element payload of `sub_141102760`, the
//! `CArray<COptional<sub_141600210>>` wire shared by `DropSetInfo._list`
//! and `ItemUseInfo` RandomBox `inner_data` (sub_141D03AA0 wraps the
//! same 128-byte allocation + sub_141600210 reader).
//!
//! ## Wire layout (sub_141600210)
//!
//! Per element when present (after the u8 presence byte from
//! sub_141D03AA0): 63 fixed bytes + variant tail.
//!
//! Fixed prefix (in wire order; mem offsets shown for cross-reference
//! against the IDA decompile):
//!   1.  u64 raw_at_120         (wire 0..7,  mem +120)
//!   2.  u8  dispatch_tag       (wire 8,     mem +112)
//!   3.  u32 lookup_4           (wire 9..12, mem +4,  sub_1410FF430)
//!   4.  u32 lookup_6           (wire 13..16, mem +6,  sub_1410FF430)
//!   5.  u32 lookup_8           (wire 17..20, mem +8,  sub_1410FF430)
//!   6.  u32 raw_12             (wire 21..24, mem +12)
//!   7.  u64 raw_16             (wire 25..32, mem +16)
//!   8.  u32 raw_24             (wire 33..36, mem +24)
//!   9.  u64 raw_32             (wire 37..44, mem +32)
//!  10.  u64 raw_40             (wire 45..52, mem +40)
//!  11.  u64 raw_48             (wire 53..60, mem +48)
//!  12.  u16 raw_56             (wire 61..62, mem +56)
//!
//! Variant tail (dispatched on `dispatch_tag` from step 2):
//!   tag 0       : u32 (sub_1410FF5C0,  qword_DA00 hash)
//!   tag 1, 2, 3 : u32 (sub_1410FF340,  qword_DA08 hash)
//!   tag 4       : u32 (sub_1411006D0,  qword_DA28 hash)
//!   tag 5       : u32 (sub_1411060F0,  qword_15030 hash)
//!   tag 6       : u32 (sub_141103770)
//!   tag 7, 8    : 32-byte DropTargetItemRef (sub_1410DB4C0)
//!   tag 9       : u32 (sub_141100740,  qword_DA38 hash)
//!   tag A       : u32 + u32 (sub_141100860 + sub_1410FF340)
//!   tag B       : 0 bytes (pure discriminator)
//!   tag C       : u32 (sub_1410FEBE0)
//!   tag D       : u32 + u8 (sub_141102E00 + raw u8)
//!
//! All u32 lookups in the variant tail are u32-wire / u16-mem hashes
//! (4 wire bytes each). Modeling them as `u32` preserves the wire
//! value losslessly for round-trip.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// Tag 7 / Tag 8 payload for `DropTargetVariant`. 32 wire bytes
    /// (sub_1410DB4C0 inner). Field names follow the wire order in
    /// sub_1410DB4C0; mem offsets are documented in the master module
    /// docstring.
    pub struct DropTargetItemRef {
        pub flag_a: u8,        // 1 byte at  mem +8
        pub raw_b: u64,        // 8 bytes at mem +16
        pub lookup_c: u32,     // sub_141100860 (u32 wire / u16 mem)
        pub lookup_d: u32,     // sub_1410FF340 (u32 wire / u16 mem)
        pub flag_e: u8,        // 1 byte at  mem +28
        pub lookup_f: u32,     // sub_1411026F0 (u32 wire / u16 mem)
        pub raw_g: u64,        // 8 bytes at mem +32
        pub flag_h: u8,        // 1 byte at  mem +40
        pub flag_i: u8,        // 1 byte at  mem +41
    }
}

/// Tag-dispatched payload following the 63-byte fixed prefix of
/// sub_141600210.
#[derive(Debug)]
pub enum DropTargetVariant {
    Tag0(u32),
    Tag1(u32),
    Tag2(u32),
    Tag3(u32),
    Tag4(u32),
    Tag5(u32),
    Tag6(u32),
    Tag7(DropTargetItemRef),
    Tag8(DropTargetItemRef),
    Tag9(u32),
    TagA { lookup_a: u32, lookup_b: u32 },
    TagB,
    TagC(u32),
    TagD { lookup: u32, flag: u8 },
}

impl DropTargetVariant {
    fn read_from(tag: u8, data: &[u8], offset: &mut usize) -> io::Result<Self> {
        Ok(match tag {
            0 => Self::Tag0(u32::read_from(data, offset)?),
            1 => Self::Tag1(u32::read_from(data, offset)?),
            2 => Self::Tag2(u32::read_from(data, offset)?),
            3 => Self::Tag3(u32::read_from(data, offset)?),
            4 => Self::Tag4(u32::read_from(data, offset)?),
            5 => Self::Tag5(u32::read_from(data, offset)?),
            6 => Self::Tag6(u32::read_from(data, offset)?),
            7 => Self::Tag7(DropTargetItemRef::read_from(data, offset)?),
            8 => Self::Tag8(DropTargetItemRef::read_from(data, offset)?),
            9 => Self::Tag9(u32::read_from(data, offset)?),
            0xA => {
                let lookup_a = u32::read_from(data, offset)?;
                let lookup_b = u32::read_from(data, offset)?;
                Self::TagA { lookup_a, lookup_b }
            }
            0xB => Self::TagB,
            0xC => Self::TagC(u32::read_from(data, offset)?),
            0xD => {
                let lookup = u32::read_from(data, offset)?;
                let flag = u8::read_from(data, offset)?;
                Self::TagD { lookup, flag }
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("DropTargetVariant: unknown tag {}", other))),
        })
    }

    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Tag0(v) | Self::Tag1(v) | Self::Tag2(v) | Self::Tag3(v)
            | Self::Tag4(v) | Self::Tag5(v) | Self::Tag6(v) | Self::Tag9(v)
            | Self::TagC(v) => v.write_to(w),
            Self::Tag7(p) | Self::Tag8(p) => p.write_to(w),
            Self::TagA { lookup_a, lookup_b } => {
                lookup_a.write_to(w)?;
                lookup_b.write_to(w)
            }
            Self::TagB => Ok(()),
            Self::TagD { lookup, flag } => {
                lookup.write_to(w)?;
                flag.write_to(w)
            }
        }
    }

    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::Tag0(v) => { m.insert("tag".into(), 0.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag1(v) => { m.insert("tag".into(), 1.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag2(v) => { m.insert("tag".into(), 2.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag3(v) => { m.insert("tag".into(), 3.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag4(v) => { m.insert("tag".into(), 4.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag5(v) => { m.insert("tag".into(), 5.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag6(v) => { m.insert("tag".into(), 6.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::Tag7(p) => { m.insert("tag".into(), 7.into()); m.insert("data".into(), Value::Object(p.to_json_dict())); }
            Self::Tag8(p) => { m.insert("tag".into(), 8.into()); m.insert("data".into(), Value::Object(p.to_json_dict())); }
            Self::Tag9(v) => { m.insert("tag".into(), 9.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::TagA { lookup_a, lookup_b } => {
                m.insert("tag".into(), 0xA.into());
                m.insert("lookup_a".into(), lookup_a.to_json_value());
                m.insert("lookup_b".into(), lookup_b.to_json_value());
            }
            Self::TagB => { m.insert("tag".into(), 0xB.into()); }
            Self::TagC(v) => { m.insert("tag".into(), 0xC.into()); m.insert("lookup".into(), v.to_json_value()); }
            Self::TagD { lookup, flag } => {
                m.insert("tag".into(), 0xD.into());
                m.insert("lookup".into(), lookup.to_json_value());
                m.insert("flag".into(), flag.to_json_value());
            }
        }
        Value::Object(m)
    }

    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "DropTargetVariant: expected object"))?;
        let tag = json_get_field(obj, "tag")?
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "DropTargetVariant.tag: expected u8"))? as u8;
        match tag {
            0..=6 | 9 | 0xC => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup")?)
            }
            7 | 8 => {
                <DropTargetItemRef as WriteJsonValue>::write_from_json(w, json_get_field(obj, "data")?)
            }
            0xA => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)
            }
            0xB => Ok(()),
            0xD => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag")?)
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("DropTargetVariant: unknown tag {}", other))),
        }
    }
}

/// Per-element payload of `sub_141600210` (the inner reader of
/// sub_141D03AA0). 63 fixed wire bytes + variant tail.
#[derive(Debug)]
pub struct DropTargetData {
    pub raw_at_120: u64,
    pub dispatch_tag: u8,
    pub lookup_4: u32,
    pub lookup_6: u32,
    pub lookup_8: u32,
    pub raw_12: u32,
    pub raw_16: u64,
    pub raw_24: u32,
    pub raw_32: u64,
    pub raw_40: u64,
    pub raw_48: u64,
    pub raw_56: u16,
    pub variant: DropTargetVariant,
}

impl<'a> BinaryRead<'a> for DropTargetData {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let raw_at_120 = u64::read_from(data, offset)?;
        let dispatch_tag = u8::read_from(data, offset)?;
        let lookup_4 = u32::read_from(data, offset)?;
        let lookup_6 = u32::read_from(data, offset)?;
        let lookup_8 = u32::read_from(data, offset)?;
        let raw_12 = u32::read_from(data, offset)?;
        let raw_16 = u64::read_from(data, offset)?;
        let raw_24 = u32::read_from(data, offset)?;
        let raw_32 = u64::read_from(data, offset)?;
        let raw_40 = u64::read_from(data, offset)?;
        let raw_48 = u64::read_from(data, offset)?;
        let raw_56 = u16::read_from(data, offset)?;
        let variant = DropTargetVariant::read_from(dispatch_tag, data, offset)?;
        Ok(Self {
            raw_at_120, dispatch_tag, lookup_4, lookup_6, lookup_8,
            raw_12, raw_16, raw_24, raw_32, raw_40, raw_48, raw_56, variant,
        })
    }
}

impl BinaryWrite for DropTargetData {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.raw_at_120.write_to(w)?;
        self.dispatch_tag.write_to(w)?;
        self.lookup_4.write_to(w)?;
        self.lookup_6.write_to(w)?;
        self.lookup_8.write_to(w)?;
        self.raw_12.write_to(w)?;
        self.raw_16.write_to(w)?;
        self.raw_24.write_to(w)?;
        self.raw_32.write_to(w)?;
        self.raw_40.write_to(w)?;
        self.raw_48.write_to(w)?;
        self.raw_56.write_to(w)?;
        self.variant.write_to(w)
    }
}

impl ToJsonValue for DropTargetData {
    fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("raw_at_120".into(), self.raw_at_120.to_json_value());
        m.insert("dispatch_tag".into(), self.dispatch_tag.to_json_value());
        m.insert("lookup_4".into(), self.lookup_4.to_json_value());
        m.insert("lookup_6".into(), self.lookup_6.to_json_value());
        m.insert("lookup_8".into(), self.lookup_8.to_json_value());
        m.insert("raw_12".into(), self.raw_12.to_json_value());
        m.insert("raw_16".into(), self.raw_16.to_json_value());
        m.insert("raw_24".into(), self.raw_24.to_json_value());
        m.insert("raw_32".into(), self.raw_32.to_json_value());
        m.insert("raw_40".into(), self.raw_40.to_json_value());
        m.insert("raw_48".into(), self.raw_48.to_json_value());
        m.insert("raw_56".into(), self.raw_56.to_json_value());
        m.insert("variant".into(), self.variant.to_json_value());
        Value::Object(m)
    }
}

impl WriteJsonValue for DropTargetData {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "DropTargetData: expected object"))?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_at_120")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dispatch_tag")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_4")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_6")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_8")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_12")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_16")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_24")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_32")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_40")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_48")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_56")?)?;
        DropTargetVariant::write_from_json(w, json_get_field(obj, "variant")?)
    }
}

/// `sub_141D03AA0` per-element: u8 presence + (if present:
/// `DropTargetData` populated by sub_141600210).
#[derive(Debug)]
pub struct OptionalDropTarget {
    pub inner: Option<DropTargetData>,
}

impl<'a> BinaryRead<'a> for OptionalDropTarget {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(DropTargetData::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }
}

impl BinaryWrite for OptionalDropTarget {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(d) => { 1u8.write_to(w)?; d.write_to(w) }
            None => 0u8.write_to(w),
        }
    }
}

impl ToJsonValue for OptionalDropTarget {
    fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(d) => d.to_json_value(),
            None => Value::Null,
        }
    }
}

impl WriteJsonValue for OptionalDropTarget {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            0u8.write_to(w)
        } else {
            1u8.write_to(w)?;
            DropTargetData::write_from_json(w, v)
        }
    }
}

impl<'a> BinaryReadTracked<'a> for OptionalDropTarget {
    fn read_tracked(data: &'a [u8], offset: &mut usize, _path: &mut String, _ranges: &mut Vec<FieldRange>) -> io::Result<Self> {
        Self::read_from(data, offset)
    }
}

