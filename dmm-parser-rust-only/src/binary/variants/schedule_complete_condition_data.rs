// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! GameCondition tree case 5: pa::ScheduleCompleteConditionData_CheckDeadOrRetreat.
//!
//! Hand-written from IDA decompile of sub_141D8B1A0.
//! Stream layout: [u8 presence_flag] then if presence_flag == 0:
//!   CString + u8 + u64 + u8 + u8

use crate::binary::*;
use crate::json_traits::{ToJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct ScheduleCompletePayload<'a> {
        pub label: CString<'a>,
        pub byte_a: u8,
        pub qword_b: u64,
        pub byte_c: u8,
        pub byte_d: u8,
    }
}

#[derive(Debug)]
pub struct ScheduleCompleteConditionData<'a> {
    pub presence_flag: u8,
    pub payload: Option<ScheduleCompletePayload<'a>>,
}

impl<'a> ScheduleCompleteConditionData<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let presence_flag = u8::read_from(data, offset)?;
        let payload = if presence_flag == 0 {
            Some(ScheduleCompletePayload::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { presence_flag, payload })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.presence_flag.write_to(w)?;
        if let Some(p) = &self.payload {
            p.write_to(w)?;
        }
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("presence_flag".into(), self.presence_flag.to_json_value());
        m.insert(
            "payload".into(),
            match &self.payload {
                Some(p) => Value::Object(p.to_json_dict()),
                None => Value::Null,
            },
        );
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        let presence = json_get_field(obj, "presence_flag")?
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "ScheduleCompleteConditionData.presence_flag: expected u8"))?;
        if presence > u8::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("presence_flag {} out of u8 range", presence)));
        }
        (presence as u8).write_to(w)?;
        if presence == 0 {
            let payload_v = json_get_field(obj, "payload")?;
            let payload_obj = payload_v.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "ScheduleCompleteConditionData.payload: expected object when presence_flag==0",
            ))?;
            ScheduleCompletePayload::write_from_json_dict(w, payload_obj)?;
        }
        Ok(())
    }
}
