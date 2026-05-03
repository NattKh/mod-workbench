// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! pa::IVariantItem polymorphic reader (per sub_141DA38D0).
//! Used by ConditionData_StageChart_Event (case 7 branch B of GameCondition tree).
//!
//! The selector tag is read by the OUTER caller (StageChart_Event) and passed
//! in. Tag determines the byte layout (semantic field names from the IDA
//! decompile of sub_141DA38D0):
//!
//!   0,2,3,4,5,14,15,16,17,18 → empty (no payload bytes)
//!   1                         → CString (staticstringA)
//!   6, 11                     → CString (staticstringA)
//!   7                         → CString + CString (staticstringA × 2)
//!   8                         → u32 + u32 + u32 (uint32, InteractionKey, HashCode32)
//!   9                         → u32 + u32 (uint32, InteractionKey)
//!   10                        → CString + CString (staticstringA × 2)
//!   12                        → u32 + u8 (uint32, StageBranchType)
//!   13                        → u32 (uint32)
//!   19                        → u32 (HashCode32)
//!   default                   → error
//!
//! Variants are split per-tag-with-distinct-semantics so JSON consumers see
//! semantic field names (e.g. `interaction_key` vs `hash_code`) instead of
//! positional `0`/`1`/`2`. Wire layout is unchanged — round-trip preserved.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub enum IVariantItemPayload<'a> {
    /// Tags 0, 2, 3, 4, 5, 14, 15, 16, 17, 18 — no payload bytes.
    Empty,
    /// Tags 1, 6, 11 — single staticstringA.
    StaticString { value: CString<'a> },
    /// Tag 7 — pair of staticstringA.
    StaticStringPair {
        first: CString<'a>,
        second: CString<'a>,
    },
    /// Tag 10 — pair of staticstringA (separate from tag 7 since the
    /// caller's semantic differs even though the wire layout matches).
    StaticStringPairAlt {
        first: CString<'a>,
        second: CString<'a>,
    },
    /// Tag 8 — uint32 value + InteractionKey + HashCode32.
    InteractionWithHash {
        value: u32,
        interaction_key: u32,
        hash_code: u32,
    },
    /// Tag 9 — uint32 value + InteractionKey.
    Interaction { value: u32, interaction_key: u32 },
    /// Tag 12 — uint32 value + StageBranchType (u8 enum).
    StageBranch { value: u32, branch_type: u8 },
    /// Tag 13 — bare uint32 numeric value.
    Uint32 { value: u32 },
    /// Tag 19 — bare HashCode32.
    HashCode { hash_code: u32 },
}

#[derive(Debug)]
pub struct IVariantItem<'a> {
    pub tag: u8,
    pub payload: IVariantItemPayload<'a>,
}

impl<'a> IVariantItem<'a> {
    pub fn read_from_with_tag(
        data: &'a [u8],
        offset: &mut usize,
        tag: u8,
    ) -> io::Result<Self> {
        let payload = match tag {
            0 | 2 | 3 | 4 | 5 | 14 | 15 | 16 | 17 | 18 => IVariantItemPayload::Empty,
            1 | 6 | 11 => IVariantItemPayload::StaticString {
                value: CString::read_from(data, offset)?,
            },
            7 => IVariantItemPayload::StaticStringPair {
                first: CString::read_from(data, offset)?,
                second: CString::read_from(data, offset)?,
            },
            10 => IVariantItemPayload::StaticStringPairAlt {
                first: CString::read_from(data, offset)?,
                second: CString::read_from(data, offset)?,
            },
            8 => IVariantItemPayload::InteractionWithHash {
                value: u32::read_from(data, offset)?,
                interaction_key: u32::read_from(data, offset)?,
                hash_code: u32::read_from(data, offset)?,
            },
            9 => IVariantItemPayload::Interaction {
                value: u32::read_from(data, offset)?,
                interaction_key: u32::read_from(data, offset)?,
            },
            12 => IVariantItemPayload::StageBranch {
                value: u32::read_from(data, offset)?,
                branch_type: u8::read_from(data, offset)?,
            },
            13 => IVariantItemPayload::Uint32 {
                value: u32::read_from(data, offset)?,
            },
            19 => IVariantItemPayload::HashCode {
                hash_code: u32::read_from(data, offset)?,
            },
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown IVariantItem tag: {}", other),
                ))
            }
        };
        Ok(Self { tag, payload })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.payload {
            IVariantItemPayload::Empty => Ok(()),
            IVariantItemPayload::StaticString { value } => value.write_to(w),
            IVariantItemPayload::StaticStringPair { first, second }
            | IVariantItemPayload::StaticStringPairAlt { first, second } => {
                first.write_to(w)?;
                second.write_to(w)
            }
            IVariantItemPayload::InteractionWithHash {
                value,
                interaction_key,
                hash_code,
            } => {
                value.write_to(w)?;
                interaction_key.write_to(w)?;
                hash_code.write_to(w)
            }
            IVariantItemPayload::Interaction {
                value,
                interaction_key,
            } => {
                value.write_to(w)?;
                interaction_key.write_to(w)
            }
            IVariantItemPayload::StageBranch { value, branch_type } => {
                value.write_to(w)?;
                branch_type.write_to(w)
            }
            IVariantItemPayload::Uint32 { value } => value.write_to(w),
            IVariantItemPayload::HashCode { hash_code } => hash_code.write_to(w),
        }
    }

    /// JSON shape: {tag: u8, payload: {kind: "Empty"|"StaticString"|...,
    /// ...payload-specific fields}}.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("tag".into(), self.tag.to_json_value());
        let mut p = Map::new();
        match &self.payload {
            IVariantItemPayload::Empty => {
                p.insert("kind".into(), Value::String("Empty".into()));
            }
            IVariantItemPayload::StaticString { value } => {
                p.insert("kind".into(), Value::String("StaticString".into()));
                p.insert("value".into(), value.to_json_value());
            }
            IVariantItemPayload::StaticStringPair { first, second } => {
                p.insert("kind".into(), Value::String("StaticStringPair".into()));
                p.insert("first".into(), first.to_json_value());
                p.insert("second".into(), second.to_json_value());
            }
            IVariantItemPayload::StaticStringPairAlt { first, second } => {
                p.insert("kind".into(), Value::String("StaticStringPairAlt".into()));
                p.insert("first".into(), first.to_json_value());
                p.insert("second".into(), second.to_json_value());
            }
            IVariantItemPayload::InteractionWithHash { value, interaction_key, hash_code } => {
                p.insert("kind".into(), Value::String("InteractionWithHash".into()));
                p.insert("value".into(), value.to_json_value());
                p.insert("interaction_key".into(), interaction_key.to_json_value());
                p.insert("hash_code".into(), hash_code.to_json_value());
            }
            IVariantItemPayload::Interaction { value, interaction_key } => {
                p.insert("kind".into(), Value::String("Interaction".into()));
                p.insert("value".into(), value.to_json_value());
                p.insert("interaction_key".into(), interaction_key.to_json_value());
            }
            IVariantItemPayload::StageBranch { value, branch_type } => {
                p.insert("kind".into(), Value::String("StageBranch".into()));
                p.insert("value".into(), value.to_json_value());
                p.insert("branch_type".into(), branch_type.to_json_value());
            }
            IVariantItemPayload::Uint32 { value } => {
                p.insert("kind".into(), Value::String("Uint32".into()));
                p.insert("value".into(), value.to_json_value());
            }
            IVariantItemPayload::HashCode { hash_code } => {
                p.insert("kind".into(), Value::String("HashCode".into()));
                p.insert("hash_code".into(), hash_code.to_json_value());
            }
        }
        m.insert("payload".into(), Value::Object(p));
        m
    }

    /// Inverse of to_json_dict. Tag is read from JSON (not the outer
    /// caller as in read_from_with_tag) since the JSON dict carries
    /// it explicitly.
    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        // Tag is informational here; the outer StageChart caller emits
        // its own ivariant_selector byte before this call.
        let payload_v = json_get_field(obj, "payload")?;
        let p = payload_v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "IVariantItem.payload: expected object",
        ))?;
        let kind = json_get_field(p, "kind")?.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                "IVariantItem.payload.kind: expected string")
        })?;
        match kind {
            "Empty" => {}
            "StaticString" => {
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(p, "value")?)?;
            }
            "StaticStringPair" | "StaticStringPairAlt" => {
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(p, "first")?)?;
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(p, "second")?)?;
            }
            "InteractionWithHash" => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "value")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "interaction_key")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "hash_code")?)?;
            }
            "Interaction" => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "value")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "interaction_key")?)?;
            }
            "StageBranch" => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "value")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(p, "branch_type")?)?;
            }
            "Uint32" => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "value")?)?;
            }
            "HashCode" => {
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(p, "hash_code")?)?;
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("IVariantItem.payload.kind: unknown {:?}", other))),
        }
        Ok(())
    }
}
