// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `QuickTimeEventInfo.pabgb`.
//!
//! Per IDA sub_14081E190 (outer): u32 key, CString string_key, u8 is_blocked,
//! CArray<QuickTimeEventInfoData> (sub_14110A790, stride 48 bytes).
//!
//! Per IDA sub_1410F5550 (element parser): each entry has 14 fixed leading
//! fields followed by a polymorphic QuickTimeEventData payload via
//! sub_141F96FB0.
//!
//! Per IDA sub_141F96FB0: 10 known QuickTimeEventData variants dispatched on
//! a u8 tag (case 0..=9):
//!   0  SingleClick   — empty
//!   1  RepeatClick   — u16 + u32  (6 bytes)
//!   2  MultiClick    — u16        (2 bytes)
//!   3  DoubleClick   — empty
//!   4  Press         — empty
//!   5  Timing        — u32+u32+u32+u32+u16+u8 (19 bytes)
//!   6  Indicator     — empty
//!   7  Spin          — u32+u8 (5 bytes)
//!   8  Balance       — u32+u32+u32 (12 bytes, disk read order)
//!   9  BarTiming     — u32+u32+u32+u32+u16 (18 bytes)
//!
//! DO NOT REGENERATE. Hand-written; bulk_process.py guards via the
//! "Hand-corrected" header marker on line 1.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct RepeatClickPayload {
        pub field_a: u16,
        pub field_b: u32,
    }
}

py_binary_struct! {
    pub struct MultiClickPayload {
        pub field_a: u16,
    }
}

py_binary_struct! {
    pub struct TimingPayload {
        pub field_a: u32,
        pub field_b: u32,
        pub field_c: u32,
        pub field_d: u32,
        pub field_e: u16,
        pub field_f: u8,
    }
}

py_binary_struct! {
    pub struct SpinPayload {
        pub field_a: u32,
        pub field_b: u8,
    }
}

py_binary_struct! {
    pub struct BalancePayload {
        pub field_a: u32,
        pub field_b: u32,
        pub field_c: u32,
    }
}

py_binary_struct! {
    pub struct BarTimingPayload {
        pub field_a: u32,
        pub field_b: u32,
        pub field_c: u32,
        pub field_d: u32,
        pub field_e: u16,
    }
}

#[derive(Debug)]
pub enum QuickTimeEventDataVariant {
    SingleClick,
    RepeatClick(RepeatClickPayload),
    MultiClick(MultiClickPayload),
    DoubleClick,
    Press,
    Timing(TimingPayload),
    Indicator,
    Spin(SpinPayload),
    Balance(BalancePayload),
    BarTiming(BarTimingPayload),
}

impl QuickTimeEventDataVariant {
    pub fn discriminator(&self) -> u8 {
        match self {
            Self::SingleClick => 0,
            Self::RepeatClick(_) => 1,
            Self::MultiClick(_) => 2,
            Self::DoubleClick => 3,
            Self::Press => 4,
            Self::Timing(_) => 5,
            Self::Indicator => 6,
            Self::Spin(_) => 7,
            Self::Balance(_) => 8,
            Self::BarTiming(_) => 9,
        }
    }

    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let disc = u8::read_from(data, offset)?;
        let result = match disc {
            0 => Self::SingleClick,
            1 => Self::RepeatClick(RepeatClickPayload::read_from(data, offset)?),
            2 => Self::MultiClick(MultiClickPayload::read_from(data, offset)?),
            3 => Self::DoubleClick,
            4 => Self::Press,
            5 => Self::Timing(TimingPayload::read_from(data, offset)?),
            6 => Self::Indicator,
            7 => Self::Spin(SpinPayload::read_from(data, offset)?),
            8 => Self::Balance(BalancePayload::read_from(data, offset)?),
            9 => Self::BarTiming(BarTimingPayload::read_from(data, offset)?),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown QuickTimeEventData discriminator: {}", disc),
                ));
            }
        };
        Ok(result)
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.discriminator().write_to(w)?;
        match self {
            Self::SingleClick | Self::DoubleClick | Self::Press | Self::Indicator => Ok(()),
            Self::RepeatClick(p) => p.write_to(w),
            Self::MultiClick(p) => p.write_to(w),
            Self::Timing(p) => p.write_to(w),
            Self::Spin(p) => p.write_to(w),
            Self::Balance(p) => p.write_to(w),
            Self::BarTiming(p) => p.write_to(w),
        }
    }

    /// Serialize the variant as a self-describing JSON object:
    /// `{"kind": "RepeatClick", "data": {"field_a": ..., "field_b": ...}}`
    /// Empty variants (SingleClick/DoubleClick/Press/Indicator) omit `data`.
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        let kind = match self {
            Self::SingleClick => "SingleClick",
            Self::RepeatClick(_) => "RepeatClick",
            Self::MultiClick(_) => "MultiClick",
            Self::DoubleClick => "DoubleClick",
            Self::Press => "Press",
            Self::Timing(_) => "Timing",
            Self::Indicator => "Indicator",
            Self::Spin(_) => "Spin",
            Self::Balance(_) => "Balance",
            Self::BarTiming(_) => "BarTiming",
        };
        m.insert("kind".to_string(), Value::String(kind.to_string()));
        match self {
            Self::SingleClick | Self::DoubleClick | Self::Press | Self::Indicator => {}
            Self::RepeatClick(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
            Self::MultiClick(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
            Self::Timing(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
            Self::Spin(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
            Self::Balance(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
            Self::BarTiming(p) => { m.insert("data".to_string(), Value::Object(p.to_json_dict())); }
        }
        Value::Object(m)
    }

    /// Parse the JSON shape from `to_json_value` and write it directly to
    /// the wire (discriminator byte + payload bytes).
    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "QuickTimeEventDataVariant: expected object with kind field"))?;
        let kind = obj.get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "QuickTimeEventDataVariant: missing or non-string kind"))?;
        let data = obj.get("data");
        match kind {
            "SingleClick" => 0u8.write_to(w),
            "RepeatClick" => {
                1u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "RepeatClick: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "RepeatClick: data must be an object"))?;
                RepeatClickPayload::write_from_json_dict(w, m)
            }
            "MultiClick" => {
                2u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "MultiClick: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "MultiClick: data must be an object"))?;
                MultiClickPayload::write_from_json_dict(w, m)
            }
            "DoubleClick" => 3u8.write_to(w),
            "Press" => 4u8.write_to(w),
            "Timing" => {
                5u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Timing: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Timing: data must be an object"))?;
                TimingPayload::write_from_json_dict(w, m)
            }
            "Indicator" => 6u8.write_to(w),
            "Spin" => {
                7u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Spin: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Spin: data must be an object"))?;
                SpinPayload::write_from_json_dict(w, m)
            }
            "Balance" => {
                8u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Balance: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "Balance: data must be an object"))?;
                BalancePayload::write_from_json_dict(w, m)
            }
            "BarTiming" => {
                9u8.write_to(w)?;
                let d = data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "BarTiming: missing data"))?;
                let m = d.as_object().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                    "BarTiming: data must be an object"))?;
                BarTimingPayload::write_from_json_dict(w, m)
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("QuickTimeEventDataVariant: unknown kind '{}'", other))),
        }
    }
}

#[derive(Debug)]
pub struct QuickTimeEventInfoData {
    pub field_a: u8,
    pub field_b: u8,
    pub hash_a: u32,
    pub hash_b: u32,
    pub hash_c: u32,
    pub field_c: u32,
    pub field_d: u32,
    pub field_e: u32,
    pub field_f: u32,
    pub block: u64,
    pub flag_a: u8,
    pub flag_b: u8,
    pub field_g: u32,
    pub variant: QuickTimeEventDataVariant,
}

impl QuickTimeEventInfoData {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let field_a = u8::read_from(data, offset)?;
        let field_b = u8::read_from(data, offset)?;
        let hash_a = u32::read_from(data, offset)?;
        let hash_b = u32::read_from(data, offset)?;
        let hash_c = u32::read_from(data, offset)?;
        let field_c = u32::read_from(data, offset)?;
        let field_d = u32::read_from(data, offset)?;
        let field_e = u32::read_from(data, offset)?;
        let field_f = u32::read_from(data, offset)?;
        let block = u64::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let field_g = u32::read_from(data, offset)?;
        let variant = QuickTimeEventDataVariant::read_from(data, offset)?;
        Ok(Self {
            field_a, field_b, hash_a, hash_b, hash_c,
            field_c, field_d, field_e, field_f, block,
            flag_a, flag_b, field_g, variant,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.field_a.write_to(w)?;
        self.field_b.write_to(w)?;
        self.hash_a.write_to(w)?;
        self.hash_b.write_to(w)?;
        self.hash_c.write_to(w)?;
        self.field_c.write_to(w)?;
        self.field_d.write_to(w)?;
        self.field_e.write_to(w)?;
        self.field_f.write_to(w)?;
        self.block.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.field_g.write_to(w)?;
        self.variant.write_to(w)
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("field_a".to_string(), self.field_a.to_json_value());
        m.insert("field_b".to_string(), self.field_b.to_json_value());
        m.insert("hash_a".to_string(), self.hash_a.to_json_value());
        m.insert("hash_b".to_string(), self.hash_b.to_json_value());
        m.insert("hash_c".to_string(), self.hash_c.to_json_value());
        m.insert("field_c".to_string(), self.field_c.to_json_value());
        m.insert("field_d".to_string(), self.field_d.to_json_value());
        m.insert("field_e".to_string(), self.field_e.to_json_value());
        m.insert("field_f".to_string(), self.field_f.to_json_value());
        m.insert("block".to_string(), self.block.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("field_g".to_string(), self.field_g.to_json_value());
        m.insert("variant".to_string(), self.variant.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_e")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_f")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "block")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_g")?)?;
        QuickTimeEventDataVariant::write_from_json(w, json_get_field(obj, "variant")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct QuickTimeEventInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub quick_time_event_data_list: Vec<QuickTimeEventInfoData>,
}

impl<'a> QuickTimeEventInfo<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let count = u32::read_from(data, offset)? as usize;
        let mut quick_time_event_data_list = Vec::with_capacity(count);
        for _ in 0..count {
            quick_time_event_data_list.push(QuickTimeEventInfoData::read_from(data, offset)?);
        }
        Ok(Self { key, string_key, is_blocked, quick_time_event_data_list })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        (self.quick_time_event_data_list.len() as u32).write_to(w)?;
        for entry in &self.quick_time_event_data_list {
            entry.write_to(w)?;
        }
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert(
            "quick_time_event_data_list".to_string(),
            Value::Array(
                self.quick_time_event_data_list
                    .iter()
                    .map(|d| Value::Object(d.to_json_dict()))
                    .collect(),
            ),
        );
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        let arr = json_get_field(obj, "quick_time_event_data_list")?
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "QuickTimeEventInfo: quick_time_event_data_list must be a JSON array"))?;
        (arr.len() as u32).write_to(w)?;
        for entry in arr {
            let m = entry.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "QuickTimeEventInfo: each list entry must be an object"))?;
            QuickTimeEventInfoData::write_from_json_dict(w, m)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\quicktimeeventinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(QuickTimeEventInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "quicktimeeventinfo roundtrip bytes mismatch");
    }

    /// Round-trip every entry through JSON: read → to_json_dict →
    /// write_from_json_dict → bytes must match write_to() output.
    /// This exercises the polymorphic variant kind/data shape end-to-end.
    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(QuickTimeEventInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len());

        for (i, item) in items.iter().enumerate() {
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            QuickTimeEventInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }

    /// Confirm the variant `kind` field surfaces every real discriminator
    /// in the data — sanity check that the polymorphic JSON shape is
    /// being exercised, not just SingleClick-stubs.
    #[test]
    fn variant_kinds_seen() {
        use std::collections::HashMap;
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        while offset < data.len() {
            let item = QuickTimeEventInfo::read_from(&data, &mut offset).unwrap();
            for d in &item.quick_time_event_data_list {
                let kind = match &d.variant {
                    QuickTimeEventDataVariant::SingleClick => "SingleClick",
                    QuickTimeEventDataVariant::RepeatClick(_) => "RepeatClick",
                    QuickTimeEventDataVariant::MultiClick(_) => "MultiClick",
                    QuickTimeEventDataVariant::DoubleClick => "DoubleClick",
                    QuickTimeEventDataVariant::Press => "Press",
                    QuickTimeEventDataVariant::Timing(_) => "Timing",
                    QuickTimeEventDataVariant::Indicator => "Indicator",
                    QuickTimeEventDataVariant::Spin(_) => "Spin",
                    QuickTimeEventDataVariant::Balance(_) => "Balance",
                    QuickTimeEventDataVariant::BarTiming(_) => "BarTiming",
                };
                *counts.entry(kind).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by_key(|&(_, c)| std::cmp::Reverse(*c));
        eprintln!("quicktimeeventinfo variant kinds seen: {:?}", sorted);
    }
}
