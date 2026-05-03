// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! pa::GameExpression family — recursive expression tree (7 inner variants).
//! Used by ConditionData_StageChart (case 7 branch A of GameCondition tree).
//!
//! Per IDA decompile of sub_1411712B0 (the GameExpression dispatcher):
//!   stream byte 0 (outer presence): u8.
//!   if outer == 0: empty node, stop.
//!   else: stream byte 1 (inner tag): u8 selecting one of 7 GameExpression
//!     subclasses. The body for each is read by vftable slot 7 of that subclass.
//!
//! Variants (inner_tag values):
//!   0  GameExpression_UnaryOperator  (slot7: 0x141171A20) — u8 op_kind + recursive child
//!   1  GameExpression_BinaryOperator (slot7: 0x141172120) — recursive left + recursive right + u8 op_kind
//!   2  GameExpression_MemberFunction (slot7: 0x141172AC0) — recursive receiver + u32 method_id + u32 arg_count + N×recursive args
//!   3  GameExpression_Actor          (slot7: 0x141172DD0) — u8 actor_kind
//!   4  GameExpression_Primitive      (slot7: 0x1411731C0) — wraps GameValue_Primitive (u8 presence + u8 kind + value bytes)
//!   5  GameExpression_ConstObject    (slot7: 0x141173470) — u8 presence + (CString type + CString value if presence != 0)
//!   6  GameExpression_Value          (slot7: 0x1411738F0) — CString name

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub enum GameExpression<'a> {
    /// outer_presence == 0: empty node, no further bytes.
    Empty,
    UnaryOperator {
        op_kind: u8,
        child: Box<GameExpression<'a>>,
    },
    BinaryOperator {
        left: Box<GameExpression<'a>>,
        right: Box<GameExpression<'a>>,
        op_kind: u8,
    },
    MemberFunction {
        receiver: Box<GameExpression<'a>>,
        method_id: u32,
        args: Vec<GameExpression<'a>>,
    },
    Actor {
        actor_kind: u8,
    },
    Primitive(GameValuePrimitive<'a>),
    ConstObject(GameExpressionConstObject<'a>),
    Value(CString<'a>),
}

#[derive(Debug)]
pub struct GameValuePrimitive<'a> {
    /// 0 = no body, non-0 = has GameValue body
    pub presence: u8,
    pub body: Option<GameValueBody<'a>>,
}

#[derive(Debug)]
pub struct GameValueBody<'a> {
    /// 0 = u8 value at +20, 1 = u32 at +20, 2 = CString at +24, other = no value bytes
    pub value_kind: u8,
    pub data: GameValueData<'a>,
}

#[derive(Debug)]
pub enum GameValueData<'a> {
    U8(u8),
    U32(u32),
    Str(CString<'a>),
    None,
}

#[derive(Debug)]
pub struct GameExpressionConstObject<'a> {
    pub presence: u8,
    pub type_name: Option<CString<'a>>,
    pub value_name: Option<CString<'a>>,
}

impl<'a> GameExpression<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let outer_presence = u8::read_from(data, offset)?;
        if outer_presence == 0 {
            return Ok(Self::Empty);
        }
        let inner_tag = u8::read_from(data, offset)?;
        match inner_tag {
            0 => {
                let op_kind = u8::read_from(data, offset)?;
                let child = Box::new(Self::read_from(data, offset)?);
                Ok(Self::UnaryOperator { op_kind, child })
            }
            1 => {
                let left = Box::new(Self::read_from(data, offset)?);
                let right = Box::new(Self::read_from(data, offset)?);
                let op_kind = u8::read_from(data, offset)?;
                Ok(Self::BinaryOperator { left, right, op_kind })
            }
            2 => {
                let receiver = Box::new(Self::read_from(data, offset)?);
                let method_id = u32::read_from(data, offset)?;
                let arg_count = u32::read_from(data, offset)? as usize;
                let mut args = Vec::with_capacity(arg_count);
                for _ in 0..arg_count {
                    args.push(Self::read_from(data, offset)?);
                }
                Ok(Self::MemberFunction { receiver, method_id, args })
            }
            3 => {
                let actor_kind = u8::read_from(data, offset)?;
                Ok(Self::Actor { actor_kind })
            }
            4 => {
                let presence = u8::read_from(data, offset)?;
                let body = if presence != 0 {
                    let value_kind = u8::read_from(data, offset)?;
                    let data_field = match value_kind {
                        0 => GameValueData::U8(u8::read_from(data, offset)?),
                        1 => GameValueData::U32(u32::read_from(data, offset)?),
                        2 => GameValueData::Str(CString::read_from(data, offset)?),
                        _ => GameValueData::None,
                    };
                    Some(GameValueBody { value_kind, data: data_field })
                } else {
                    None
                };
                Ok(Self::Primitive(GameValuePrimitive { presence, body }))
            }
            5 => {
                let presence = u8::read_from(data, offset)?;
                let (type_name, value_name) = if presence != 0 {
                    let t = CString::read_from(data, offset)?;
                    let v = CString::read_from(data, offset)?;
                    (Some(t), Some(v))
                } else {
                    (None, None)
                };
                Ok(Self::ConstObject(GameExpressionConstObject { presence, type_name, value_name }))
            }
            6 => {
                let name = CString::read_from(data, offset)?;
                Ok(Self::Value(name))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown GameExpression inner_tag: {}", other),
            )),
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Empty => 0u8.write_to(w),
            Self::UnaryOperator { op_kind, child } => {
                1u8.write_to(w)?;
                0u8.write_to(w)?;
                op_kind.write_to(w)?;
                child.write_to(w)
            }
            Self::BinaryOperator { left, right, op_kind } => {
                1u8.write_to(w)?;
                1u8.write_to(w)?;
                left.write_to(w)?;
                right.write_to(w)?;
                op_kind.write_to(w)
            }
            Self::MemberFunction { receiver, method_id, args } => {
                1u8.write_to(w)?;
                2u8.write_to(w)?;
                receiver.write_to(w)?;
                method_id.write_to(w)?;
                (args.len() as u32).write_to(w)?;
                for arg in args {
                    arg.write_to(w)?;
                }
                Ok(())
            }
            Self::Actor { actor_kind } => {
                1u8.write_to(w)?;
                3u8.write_to(w)?;
                actor_kind.write_to(w)
            }
            Self::Primitive(p) => {
                1u8.write_to(w)?;
                4u8.write_to(w)?;
                p.presence.write_to(w)?;
                if let Some(body) = &p.body {
                    body.value_kind.write_to(w)?;
                    match &body.data {
                        GameValueData::U8(v) => v.write_to(w)?,
                        GameValueData::U32(v) => v.write_to(w)?,
                        GameValueData::Str(s) => s.write_to(w)?,
                        GameValueData::None => {}
                    }
                }
                Ok(())
            }
            Self::ConstObject(c) => {
                1u8.write_to(w)?;
                5u8.write_to(w)?;
                c.presence.write_to(w)?;
                if let Some(t) = &c.type_name {
                    t.write_to(w)?;
                }
                if let Some(v) = &c.value_name {
                    v.write_to(w)?;
                }
                Ok(())
            }
            Self::Value(s) => {
                1u8.write_to(w)?;
                6u8.write_to(w)?;
                s.write_to(w)
            }
        }
    }

    /// Tree-navigable JSON. Each variant emits {kind: <name>, ...} with
    /// recursive children for tree-shaped variants. Empty maps to
    /// {kind: "Empty"}.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        match self {
            Self::Empty => {
                m.insert("kind".into(), Value::String("Empty".into()));
            }
            Self::UnaryOperator { op_kind, child } => {
                m.insert("kind".into(), Value::String("UnaryOperator".into()));
                m.insert("op_kind".into(), op_kind.to_json_value());
                m.insert("child".into(), Value::Object(child.to_json_dict()));
            }
            Self::BinaryOperator { left, right, op_kind } => {
                m.insert("kind".into(), Value::String("BinaryOperator".into()));
                m.insert("left".into(), Value::Object(left.to_json_dict()));
                m.insert("right".into(), Value::Object(right.to_json_dict()));
                m.insert("op_kind".into(), op_kind.to_json_value());
            }
            Self::MemberFunction { receiver, method_id, args } => {
                m.insert("kind".into(), Value::String("MemberFunction".into()));
                m.insert("receiver".into(), Value::Object(receiver.to_json_dict()));
                m.insert("method_id".into(), method_id.to_json_value());
                let arg_arr: Vec<Value> = args.iter()
                    .map(|a| Value::Object(a.to_json_dict()))
                    .collect();
                m.insert("args".into(), Value::Array(arg_arr));
            }
            Self::Actor { actor_kind } => {
                m.insert("kind".into(), Value::String("Actor".into()));
                m.insert("actor_kind".into(), actor_kind.to_json_value());
            }
            Self::Primitive(p) => {
                m.insert("kind".into(), Value::String("Primitive".into()));
                m.insert("presence".into(), p.presence.to_json_value());
                m.insert(
                    "body".into(),
                    match &p.body {
                        Some(body) => {
                            let mut bm = Map::new();
                            bm.insert("value_kind".into(), body.value_kind.to_json_value());
                            match &body.data {
                                GameValueData::U8(v) => {
                                    bm.insert("data_kind".into(), Value::String("u8".into()));
                                    bm.insert("value".into(), v.to_json_value());
                                }
                                GameValueData::U32(v) => {
                                    bm.insert("data_kind".into(), Value::String("u32".into()));
                                    bm.insert("value".into(), v.to_json_value());
                                }
                                GameValueData::Str(s) => {
                                    bm.insert("data_kind".into(), Value::String("str".into()));
                                    bm.insert("value".into(), s.to_json_value());
                                }
                                GameValueData::None => {
                                    bm.insert("data_kind".into(), Value::String("none".into()));
                                }
                            }
                            Value::Object(bm)
                        }
                        None => Value::Null,
                    },
                );
            }
            Self::ConstObject(c) => {
                m.insert("kind".into(), Value::String("ConstObject".into()));
                m.insert("presence".into(), c.presence.to_json_value());
                m.insert(
                    "type_name".into(),
                    match &c.type_name {
                        Some(s) => s.to_json_value(),
                        None => Value::Null,
                    },
                );
                m.insert(
                    "value_name".into(),
                    match &c.value_name {
                        Some(s) => s.to_json_value(),
                        None => Value::Null,
                    },
                );
            }
            Self::Value(s) => {
                m.insert("kind".into(), Value::String("Value".into()));
                m.insert("name".into(), s.to_json_value());
            }
        }
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        let kind = json_get_field(obj, "kind")?.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                "GameExpression.kind: expected string")
        })?;
        match kind {
            "Empty" => {
                w.push(0u8);
            }
            "UnaryOperator" => {
                w.push(1u8); w.push(0u8);
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "op_kind")?)?;
                let child_obj = json_get_field(obj, "child")?.as_object().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData,
                        "UnaryOperator.child: expected object")
                })?;
                Self::write_from_json_dict(w, child_obj)?;
            }
            "BinaryOperator" => {
                w.push(1u8); w.push(1u8);
                let left_obj = json_get_field(obj, "left")?.as_object().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "BinaryOperator.left: expected object")
                })?;
                Self::write_from_json_dict(w, left_obj)?;
                let right_obj = json_get_field(obj, "right")?.as_object().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "BinaryOperator.right: expected object")
                })?;
                Self::write_from_json_dict(w, right_obj)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "op_kind")?)?;
            }
            "MemberFunction" => {
                w.push(1u8); w.push(2u8);
                let recv_obj = json_get_field(obj, "receiver")?.as_object().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "MemberFunction.receiver: expected object")
                })?;
                Self::write_from_json_dict(w, recv_obj)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "method_id")?)?;
                let args = json_get_field(obj, "args")?.as_array().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "MemberFunction.args: expected array")
                })?;
                (args.len() as u32).write_to(w)?;
                for (i, arg) in args.iter().enumerate() {
                    let arg_obj = arg.as_object().ok_or_else(|| io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("MemberFunction.args[{}]: expected object", i),
                    ))?;
                    Self::write_from_json_dict(w, arg_obj)?;
                }
            }
            "Actor" => {
                w.push(1u8); w.push(3u8);
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "actor_kind")?)?;
            }
            "Primitive" => {
                w.push(1u8); w.push(4u8);
                let presence = json_get_field(obj, "presence")?.as_u64().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Primitive.presence: expected u8")
                })?;
                if presence > u8::MAX as u64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("Primitive.presence: {} out of u8 range", presence)));
                }
                w.push(presence as u8);
                if presence != 0 {
                    let body_obj = json_get_field(obj, "body")?.as_object().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData,
                            "Primitive.body: expected object when presence!=0")
                    })?;
                    <u8 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "value_kind")?)?;
                    let data_kind = json_get_field(body_obj, "data_kind")?.as_str().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData,
                            "Primitive.body.data_kind: expected string")
                    })?;
                    match data_kind {
                        "u8" => <u8 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "value")?)?,
                        "u32" => <u32 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "value")?)?,
                        "str" => <CString as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "value")?)?,
                        "none" => {}
                        other => return Err(io::Error::new(io::ErrorKind::InvalidData,
                            format!("Primitive.body.data_kind: unknown {:?}", other))),
                    }
                }
            }
            "ConstObject" => {
                w.push(1u8); w.push(5u8);
                let presence = json_get_field(obj, "presence")?.as_u64().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "ConstObject.presence: expected u8")
                })?;
                if presence > u8::MAX as u64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("ConstObject.presence: {} out of u8 range", presence)));
                }
                w.push(presence as u8);
                if presence != 0 {
                    <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "type_name")?)?;
                    <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "value_name")?)?;
                }
            }
            "Value" => {
                w.push(1u8); w.push(6u8);
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name")?)?;
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("GameExpression.kind: unknown {:?}", other))),
        }
        Ok(())
    }
}
