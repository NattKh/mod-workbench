// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Stream-mode wrapper around `GameConditionNode` (lane A's recursive
//! tree decoder) for tables that embed `sub_141103B30` — i.e., a
//! `u8 presence + (if presence: GameConditionNode + 3 footer bytes)`
//! wire pattern.
//!
//! Lane A's `GameCondition::read_from` uses a slice-bounded probe
//! (checks `probe == data.len()`) to fall back to `Raw` capture for
//! the 0.2% of ConditionInfo entries with anti-disassembly tags. That
//! API can't compose stream-style. This wrapper instead calls
//! `GameConditionNode::read_from` directly — every leaf variant is
//! self-delimiting via tag dispatch, so it parses correctly inside a
//! larger struct. The trade-off: if a vanilla entry hits one of the
//! anti-disassembly tags (54/286), parsing fails here. The roundtrip
//! tests on consumer tables surface that immediately if it ever
//! happens.

use crate::binary::variants::game_condition::GameConditionNode;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct OptionalGameCondition<'a> {
    pub inner: Option<GameConditionWrapper<'a>>,
}

#[derive(Debug)]
pub struct GameConditionWrapper<'a> {
    pub tree: GameConditionNode<'a>,
    pub tail_a: u8,
    pub tail_b: u8,
    pub tail_c: u8,
}

impl<'a> OptionalGameCondition<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            let tree = GameConditionNode::read_from(data, offset)?;
            let tail_a = u8::read_from(data, offset)?;
            let tail_b = u8::read_from(data, offset)?;
            let tail_c = u8::read_from(data, offset)?;
            Some(GameConditionWrapper { tree, tail_a, tail_b, tail_c })
        } else {
            None
        };
        Ok(Self { inner })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(g) => {
                1u8.write_to(w)?;
                g.tree.write_to(w)?;
                g.tail_a.write_to(w)?;
                g.tail_b.write_to(w)?;
                g.tail_c.write_to(w)?;
            }
            None => {
                0u8.write_to(w)?;
            }
        }
        Ok(())
    }

    pub fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(g) => {
                let mut m = Map::new();
                m.insert("tree".to_string(), g.tree.to_json_value());
                m.insert("tail_a".to_string(), g.tail_a.to_json_value());
                m.insert("tail_b".to_string(), g.tail_b.to_json_value());
                m.insert("tail_c".to_string(), g.tail_c.to_json_value());
                Value::Object(m)
            }
            None => Value::Null,
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            w.push(0);
            return Ok(());
        }
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "OptionalGameCondition: expected object or null",
        ))?;
        w.push(1);
        GameConditionNode::write_from_json(w, json_get_field(obj, "tree")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_c")?)?;
        Ok(())
    }
}
