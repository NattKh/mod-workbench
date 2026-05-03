// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Stream-mode wrapper for the `(GameCondition, GameCondition, u8, u16
//! lookup, u32, u8, u8)` shape used in multiple tables:
//!
//!   - `sub_1410DF630` — InteractionInfo's _interactionConditionDataList
//!     element (via sub_141114DD0 outer `CArray<COptional<...>>`).
//!   - `sub_141E2C900` inner — GimmickInteractionOverrideData's condition
//!     list element. Verified via Win-IDA decompile: outer wrapper is
//!     `CArray<ConditionPair>` (32-byte stride per element, NO
//!     per-element COptional flag — distinct from sub_141114DD0's
//!     `CArray<COptional<...>>` shape).
//!
//! Wire layout (all 7 fields read sequentially):
//!   1. OptionalGameCondition cond_a    (sub_141103B30 — u8 presence +
//!      tree + 3 trailing bytes)
//!   2. OptionalGameCondition cond_b    (sub_141103B30)
//!   3. u8 flag_a                       (mem +16)
//!   4. u32 lookup                      (sub_1410FF050 — wire u32 / mem u16)
//!   5. u32 raw                         (mem +20)
//!   6. u8 flag_b                       (mem +24)
//!   7. u8 flag_c                       (mem +25)
//!
//! `ConditionPair` is the inner struct after the outer COptional flag is
//! consumed. Use `OptionalConditionPair` for the typical
//! `CArray<COptional<ConditionPair>>` pattern (sub_141114DD0,
//! sub_1410DF770's slot 6 use, etc.).

use crate::binary::optional_game_condition::OptionalGameCondition;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct ConditionPair<'a> {
    pub cond_a: OptionalGameCondition<'a>,
    pub cond_b: OptionalGameCondition<'a>,
    pub flag_a: u8,
    pub lookup: u32,
    pub raw: u32,
    pub flag_b: u8,
    pub flag_c: u8,
}

impl<'a> ConditionPair<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok(Self {
            cond_a: OptionalGameCondition::read_from(data, offset)?,
            cond_b: OptionalGameCondition::read_from(data, offset)?,
            flag_a: u8::read_from(data, offset)?,
            lookup: u32::read_from(data, offset)?,
            raw: u32::read_from(data, offset)?,
            flag_b: u8::read_from(data, offset)?,
            flag_c: u8::read_from(data, offset)?,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.cond_a.write_to(w)?;
        self.cond_b.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.lookup.write_to(w)?;
        self.raw.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)?;
        Ok(())
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cond_a".to_string(), self.cond_a.to_json_value());
        m.insert("cond_b".to_string(), self.cond_b.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("lookup".to_string(), self.lookup.to_json_value());
        m.insert("raw".to_string(), self.raw.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "ConditionPair: expected object",
        ))?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond_a")?)?;
        OptionalGameCondition::write_from_json(w, json_get_field(obj, "cond_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        Ok(())
    }
}

/// `u8 presence + (if presence: ConditionPair)` — sub_141114DD0 outer
/// element shape.
#[derive(Debug)]
pub struct OptionalConditionPair<'a> {
    pub inner: Option<ConditionPair<'a>>,
}

impl<'a> OptionalConditionPair<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(ConditionPair::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(c) => {
                1u8.write_to(w)?;
                c.write_to(w)
            }
            None => 0u8.write_to(w),
        }
    }

    pub fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(c) => c.to_json_value(),
            None => Value::Null,
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            w.push(0);
            Ok(())
        } else {
            w.push(1);
            ConditionPair::write_from_json(w, v)
        }
    }
}

/// `CArray<OptionalConditionPair>` — sub_141114DD0 (interaction_info's
/// _interactionConditionDataList) and sub_141E2C900 inner (gimmick's
/// override condition list). Both share the same wire layout: u32 count
/// + count× (u8 presence + optional ConditionPair).
#[derive(Debug)]
pub struct ConditionPairCArray<'a> {
    pub items: Vec<OptionalConditionPair<'a>>,
}

impl<'a> BinaryRead<'a> for ConditionPairCArray<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let count = u32::read_from(data, offset)?;
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(OptionalConditionPair::read_from(data, offset)?);
        }
        Ok(Self { items })
    }
}

impl<'a> BinaryWrite for ConditionPairCArray<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        (self.items.len() as u32).write_to(w)?;
        for item in &self.items {
            item.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryReadTracked<'a> for ConditionPairCArray<'a> {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let start = *offset;
        let item = <Self as BinaryRead>::read_from(data, offset)?;
        ranges.push(FieldRange { path: path.clone(), start, end: *offset, ty: "ConditionPairCArray" });
        Ok(item)
    }
}

impl<'a> ToJsonValue for ConditionPairCArray<'a> {
    fn to_json_value(&self) -> Value {
        Value::Array(self.items.iter().map(|i| i.to_json_value()).collect())
    }
}

impl<'a> WriteJsonValue for ConditionPairCArray<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "ConditionPairCArray: expected array",
        ))?;
        (arr.len() as u32).write_to(w)?;
        for item in arr {
            OptionalConditionPair::write_from_json(w, item)?;
        }
        Ok(())
    }
}

/// `CArray<ConditionPair>` — sub_141E2C900 (used inside
/// GimmickInteractionOverrideData via sub_1410DF770). Distinct from
/// `ConditionPairCArray`: each element is a bare `ConditionPair`
/// (32-byte mem stride) with NO per-element COptional flag.
#[derive(Debug)]
pub struct BareConditionPairCArray<'a> {
    pub items: Vec<ConditionPair<'a>>,
}

impl<'a> BinaryRead<'a> for BareConditionPairCArray<'a> {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let count = u32::read_from(data, offset)?;
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(ConditionPair::read_from(data, offset)?);
        }
        Ok(Self { items })
    }
}

impl<'a> BinaryWrite for BareConditionPairCArray<'a> {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        (self.items.len() as u32).write_to(w)?;
        for item in &self.items {
            item.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryReadTracked<'a> for BareConditionPairCArray<'a> {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let start = *offset;
        let item = <Self as BinaryRead>::read_from(data, offset)?;
        ranges.push(FieldRange { path: path.clone(), start, end: *offset, ty: "BareConditionPairCArray" });
        Ok(item)
    }
}

impl<'a> ToJsonValue for BareConditionPairCArray<'a> {
    fn to_json_value(&self) -> Value {
        Value::Array(self.items.iter().map(|i| i.to_json_value()).collect())
    }
}

impl<'a> WriteJsonValue for BareConditionPairCArray<'a> {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "BareConditionPairCArray: expected array",
        ))?;
        (arr.len() as u32).write_to(w)?;
        for item in arr {
            ConditionPair::write_from_json(w, item)?;
        }
        Ok(())
    }
}
