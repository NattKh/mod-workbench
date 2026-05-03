// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Recursive GameCondition expression tree.
//!
//! Per the meta-dispatcher (sub_141E65330) decompiled from CrimsonDesert.exe,
//! the tree has 9 case tags. Cases 0/1/2 are recursive operator nodes;
//! cases 3-8 are leaf nodes (cases 3 and 4 are themselves polymorphic families,
//! case 7 dispatches into GameExpression + IVariantItem sub-families).
//!
//! Stream layout per node: [u8 case_tag][case_specific_payload].
//! The tree is depth-first: cases 0/1 recurse twice (left, right), case 2 once.

use super::branch_condition_data::BranchConditionData;
use super::condition_data::ConditionData;
use super::condition_data_stage_chart::ConditionDataStageChart;
use super::condition_gimmick_data::ConditionGimmickData;
use super::global_effect_condition_data::GlobalEffectConditionData;
use super::schedule_complete_condition_data::ScheduleCompleteConditionData;
use crate::binary::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

fn decode_b64(v: &Value, ctx: &str) -> io::Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: expected base64 string", ctx))
    })?;
    B64.decode(s).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid base64: {}", ctx, e))
    })
}

fn get_field<'a>(obj: &'a Map<String, Value>, name: &str) -> io::Result<&'a Value> {
    obj.get(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("missing field {:?}", name))
    })
}

/// Full GameCondition wire format: a recursive tree + a 3-byte footer.
///
/// Per IDA `sub_101021408` (the reader called from ConditionInfo's parser):
///   1. Construct the tree node and read it from the stream.
///   2. Read three u8 fields at struct offsets +8, +9, +10.
///
/// The footer applies to every table that consumes GameCondition (not just
/// ConditionInfo). Wrapping the tree + footer into a single type keeps the
/// recursive `GameConditionNode` clean of the table-level trailing bytes.
#[derive(Debug)]
pub enum GameCondition<'a> {
    /// Successfully decoded into typed tree + 3-byte footer.
    Decoded {
        tree: GameConditionNode<'a>,
        tail_a: u8,
        tail_b: u8,
        tail_c: u8,
    },
    /// Decoder fell back to raw bytes — preserves byte-perfect round-trip
    /// even when a nested ConditionData variant has an unknown recipe.
    /// Used for the ~0.2% of entries with anti-disassembly-obfuscated
    /// readers (tags 54/286) or truncated/edge-case data.
    Raw(Vec<u8>),
}

impl<'a> GameCondition<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let start = *offset;
        // Try typed decode first; on failure or under-consume, fall back
        // to raw-bytes capture so wrapper round-trip stays byte-perfect.
        let mut probe = start;
        let typed = (|| -> io::Result<(GameConditionNode<'a>, u8, u8, u8)> {
            let tree = GameConditionNode::read_from(data, &mut probe)?;
            let tail_a = u8::read_from(data, &mut probe)?;
            let tail_b = u8::read_from(data, &mut probe)?;
            let tail_c = u8::read_from(data, &mut probe)?;
            Ok((tree, tail_a, tail_b, tail_c))
        })();
        match typed {
            Ok((tree, tail_a, tail_b, tail_c)) if probe == data.len() => {
                *offset = probe;
                Ok(Self::Decoded { tree, tail_a, tail_b, tail_c })
            }
            _ => {
                // Capture remaining bytes verbatim. Assumption: GameCondition
                // is always called with `data` sized to exactly the wrapper
                // (table-level tail_blob). If a future caller violates this,
                // this fallback may over-capture — fix at the consumer.
                let raw = data[start..].to_vec();
                *offset = data.len();
                Ok(Self::Raw(raw))
            }
        }
    }
    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Decoded { tree, tail_a, tail_b, tail_c } => {
                tree.write_to(w)?;
                tail_a.write_to(w)?;
                tail_b.write_to(w)?;
                tail_c.write_to(w)?;
                Ok(())
            }
            Self::Raw(bytes) => w.write_all(bytes),
        }
    }

    /// JSON shape:
    /// - `kind`: "decoded" | "raw"
    /// - when "decoded": `tree` (recursive node JSON), `tail_a`, `tail_b`, `tail_c` (u8s)
    /// - when "raw": `raw_b64` (base64 string of full wrapper bytes)
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::Decoded { tree, tail_a, tail_b, tail_c } => {
                m.insert("kind".into(), Value::String("decoded".into()));
                m.insert("tree".into(), tree.to_json_value());
                m.insert("tail_a".into(), Value::Number((*tail_a).into()));
                m.insert("tail_b".into(), Value::Number((*tail_b).into()));
                m.insert("tail_c".into(), Value::Number((*tail_c).into()));
            }
            Self::Raw(bytes) => {
                m.insert("kind".into(), Value::String("raw".into()));
                m.insert("raw_b64".into(), Value::String(B64.encode(bytes)));
            }
        }
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "GameCondition: expected object")
        })?;
        let kind = get_field(obj, "kind")?
            .as_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "GameCondition.kind: expected string")
            })?;
        match kind {
            "decoded" => {
                GameConditionNode::write_from_json(w, get_field(obj, "tree")?)?;
                for name in ["tail_a", "tail_b", "tail_c"] {
                    let n = get_field(obj, name)?.as_u64().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("GameCondition.{}: expected u8", name),
                        )
                    })?;
                    if n > u8::MAX as u64 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("GameCondition.{}: {} out of u8 range", name, n),
                        ));
                    }
                    w.push(n as u8);
                }
            }
            "raw" => {
                let bytes = decode_b64(get_field(obj, "raw_b64")?, "GameCondition.raw_b64")?;
                w.extend_from_slice(&bytes);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("GameCondition.kind: unknown {:?}", other),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum GameConditionNode<'a> {
    /// Case 0: BinaryOp_A (operator constructor 0x141E65450, likely AND).
    BinaryOpA {
        left: Box<GameConditionNode<'a>>,
        right: Box<GameConditionNode<'a>>,
    },
    /// Case 1: BinaryOp_B (operator constructor 0x141E65B30, likely OR).
    BinaryOpB {
        left: Box<GameConditionNode<'a>>,
        right: Box<GameConditionNode<'a>>,
    },
    /// Case 2: UnaryOp (operator constructor 0x141E660F0, likely NOT).
    UnaryOp { child: Box<GameConditionNode<'a>> },
    /// Case 3: leaf ConditionData (405 variants).
    ConditionData(ConditionData<'a>),
    /// Case 4: leaf BranchConditionData (14 variants).
    BranchConditionData(BranchConditionData<'a>),
    /// Case 5: leaf ScheduleCompleteConditionData_CheckDeadOrRetreat.
    ScheduleCompleteConditionData(ScheduleCompleteConditionData<'a>),
    /// Case 6: leaf ConditionGimmickData_CheckProperty.
    ConditionGimmickData(ConditionGimmickData),
    /// Case 7: ConditionData_StageChart / ConditionData_StageChart_Event.
    StageChart(ConditionDataStageChart<'a>),
    /// Case 8: leaf GlobalEffectConditionData.
    GlobalEffectConditionData(GlobalEffectConditionData),
}

impl<'a> GameConditionNode<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let case_tag = u8::read_from(data, offset)?;
        match case_tag {
            0 => {
                let left = Box::new(Self::read_from(data, offset)?);
                let right = Box::new(Self::read_from(data, offset)?);
                Ok(Self::BinaryOpA { left, right })
            }
            1 => {
                let left = Box::new(Self::read_from(data, offset)?);
                let right = Box::new(Self::read_from(data, offset)?);
                Ok(Self::BinaryOpB { left, right })
            }
            2 => {
                let child = Box::new(Self::read_from(data, offset)?);
                Ok(Self::UnaryOp { child })
            }
            3 => Ok(Self::ConditionData(ConditionData::read_from(data, offset)?)),
            4 => Ok(Self::BranchConditionData(BranchConditionData::read_from(data, offset)?)),
            5 => Ok(Self::ScheduleCompleteConditionData(
                ScheduleCompleteConditionData::read_from(data, offset)?,
            )),
            6 => Ok(Self::ConditionGimmickData(ConditionGimmickData::read_from(data, offset)?)),
            7 => Ok(Self::StageChart(ConditionDataStageChart::read_from(data, offset)?)),
            8 => Ok(Self::GlobalEffectConditionData(GlobalEffectConditionData::read_from(data, offset)?)),
            other => {
                // Capture surrounding wire bytes to help debug whether
                // this is a real unhandled tag or a misalignment surfacing
                // garbage. case_tag was at offset (*offset - 1).
                let tag_off = offset.saturating_sub(1);
                let ctx_start = tag_off.saturating_sub(8);
                let ctx_end = (tag_off + 16).min(data.len());
                let ctx = &data[ctx_start..ctx_end];
                let ctx_hex: String = ctx.iter().map(|b| format!("{:02x}", b)).collect();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unknown GameCondition case_tag: {} at offset {} \
                         (8 bytes before+16 after = {})",
                        other, tag_off, ctx_hex,
                    ),
                ))
            }
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::BinaryOpA { left, right } => {
                0u8.write_to(w)?;
                left.write_to(w)?;
                right.write_to(w)
            }
            Self::BinaryOpB { left, right } => {
                1u8.write_to(w)?;
                left.write_to(w)?;
                right.write_to(w)
            }
            Self::UnaryOp { child } => {
                2u8.write_to(w)?;
                child.write_to(w)
            }
            Self::ConditionData(c) => {
                3u8.write_to(w)?;
                c.write_to(w)
            }
            Self::BranchConditionData(b) => {
                4u8.write_to(w)?;
                b.write_to(w)
            }
            Self::ScheduleCompleteConditionData(s) => {
                5u8.write_to(w)?;
                s.write_to(w)
            }
            Self::ConditionGimmickData(g) => {
                6u8.write_to(w)?;
                g.write_to(w)
            }
            Self::StageChart(s) => {
                7u8.write_to(w)?;
                s.write_to(w)
            }
            Self::GlobalEffectConditionData(g) => {
                8u8.write_to(w)?;
                g.write_to(w)
            }
        }
    }

    /// Tree-navigable JSON. Operator nodes recurse into typed children;
    /// leaf nodes route through their family's typed `to_json_dict()`
    /// (ConditionData, BranchConditionData, ScheduleCompleteConditionData,
    /// ConditionGimmickData, StageChart, GlobalEffectConditionData).
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::BinaryOpA { left, right } => {
                m.insert("case".into(), Value::String("BinaryOpA".into()));
                m.insert("left".into(), left.to_json_value());
                m.insert("right".into(), right.to_json_value());
            }
            Self::BinaryOpB { left, right } => {
                m.insert("case".into(), Value::String("BinaryOpB".into()));
                m.insert("left".into(), left.to_json_value());
                m.insert("right".into(), right.to_json_value());
            }
            Self::UnaryOp { child } => {
                m.insert("case".into(), Value::String("UnaryOp".into()));
                m.insert("child".into(), child.to_json_value());
            }
            Self::ConditionData(c) => {
                m.insert("case".into(), Value::String("ConditionData".into()));
                m.insert("data".into(), Value::Object(c.to_json_dict()));
            }
            Self::BranchConditionData(b) => {
                m.insert("case".into(), Value::String("BranchConditionData".into()));
                m.insert("data".into(), Value::Object(b.to_json_dict()));
            }
            Self::ScheduleCompleteConditionData(s) => {
                m.insert("case".into(), Value::String("ScheduleCompleteConditionData".into()));
                m.insert("data".into(), Value::Object(s.to_json_dict()));
            }
            Self::ConditionGimmickData(g) => {
                m.insert("case".into(), Value::String("ConditionGimmickData".into()));
                m.insert("data".into(), Value::Object(g.to_json_dict()));
            }
            Self::StageChart(s) => {
                m.insert("case".into(), Value::String("StageChart".into()));
                m.insert("data".into(), Value::Object(s.to_json_dict()));
            }
            Self::GlobalEffectConditionData(g) => {
                m.insert("case".into(), Value::String("GlobalEffectConditionData".into()));
                m.insert("data".into(), Value::Object(g.to_json_dict()));
            }
        }
        Value::Object(m)
    }

    /// Inverse of `to_json_value`. For operator nodes, recursively
    /// constructs children. For leaf nodes, base64-decodes the wire
    /// bytes and emits them after the case_tag byte.
    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "GameConditionNode: expected object")
        })?;
        let case = get_field(obj, "case")?.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "GameConditionNode.case: expected string")
        })?;
        match case {
            "BinaryOpA" => {
                w.push(0u8);
                Self::write_from_json(w, get_field(obj, "left")?)?;
                Self::write_from_json(w, get_field(obj, "right")?)?;
            }
            "BinaryOpB" => {
                w.push(1u8);
                Self::write_from_json(w, get_field(obj, "left")?)?;
                Self::write_from_json(w, get_field(obj, "right")?)?;
            }
            "UnaryOp" => {
                w.push(2u8);
                Self::write_from_json(w, get_field(obj, "child")?)?;
            }
            "ConditionData" => {
                w.push(3u8);
                let data_v = get_field(obj, "data")?;
                let data_obj = data_v.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GameConditionNode.ConditionData.data: expected object",
                ))?;
                ConditionData::write_from_json_dict(w, data_obj)?;
            }
            "BranchConditionData" => {
                w.push(4u8);
                let data_v = get_field(obj, "data")?;
                let data_obj = data_v.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GameConditionNode.BranchConditionData.data: expected object",
                ))?;
                BranchConditionData::write_from_json_dict(w, data_obj)?;
            }
            "ScheduleCompleteConditionData" => {
                w.push(5u8);
                let data_obj = get_field(obj, "data")?.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ScheduleCompleteConditionData.data: expected object",
                ))?;
                ScheduleCompleteConditionData::write_from_json_dict(w, data_obj)?;
            }
            "ConditionGimmickData" => {
                w.push(6u8);
                let data_obj = get_field(obj, "data")?.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ConditionGimmickData.data: expected object",
                ))?;
                ConditionGimmickData::write_from_json_dict(w, data_obj)?;
            }
            "StageChart" => {
                w.push(7u8);
                let data_obj = get_field(obj, "data")?.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "StageChart.data: expected object",
                ))?;
                ConditionDataStageChart::write_from_json_dict(w, data_obj)?;
            }
            "GlobalEffectConditionData" => {
                w.push(8u8);
                let data_obj = get_field(obj, "data")?.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GlobalEffectConditionData.data: expected object",
                ))?;
                GlobalEffectConditionData::write_from_json_dict(w, data_obj)?;
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("GameConditionNode.case: unknown {:?}", other),
                ));
            }
        }
        Ok(())
    }
}
