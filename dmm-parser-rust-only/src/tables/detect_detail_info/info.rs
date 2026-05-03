// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `DetectDetailInfo.pabgb`.
//!
//! Per IDA sub_1415BE000: u16 key, CString string_key, u8 is_blocked,
//! fixed-size array of 0x3B (59) DetectSenseData entries via sub_1410D9B70.
//!
//! DetectSenseData is the same recursive type from `tables::detect_info`.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::tables::detect_info::DetectSenseData;
use serde_json::{Map, Value};
use std::io::{self, Write};

const DETAIL_LIST_LEN: usize = 0x3B; // 59 fixed entries per IDA sub_1415BE000

#[derive(Debug)]
pub struct DetectDetailInfo<'a> {
    pub key: u16,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub detect_detail_data_list_new: Vec<DetectSenseData>,
}

impl<'a> DetectDetailInfo<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u16::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let mut detect_detail_data_list_new = Vec::with_capacity(DETAIL_LIST_LEN);
        for _ in 0..DETAIL_LIST_LEN {
            detect_detail_data_list_new.push(DetectSenseData::read_from(data, offset)?);
        }
        Ok(Self { key, string_key, is_blocked, detect_detail_data_list_new })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        if self.detect_detail_data_list_new.len() != DETAIL_LIST_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "detect_detail_data_list_new must have exactly {} entries (got {})",
                    DETAIL_LIST_LEN,
                    self.detect_detail_data_list_new.len()
                ),
            ));
        }
        for entry in &self.detect_detail_data_list_new {
            entry.write_to(w)?;
        }
        Ok(())
    }

    /// Fully typed JSON: 59 DetectSenseData entries are individually
    /// editable as a JSON array.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("detect_detail_data_list_new".to_string(),
            Value::Array(self.detect_detail_data_list_new.iter().map(|e| e.to_json_value()).collect()));
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        let entries = json_get_field(obj, "detect_detail_data_list_new")?
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "DetectDetailInfo: detect_detail_data_list_new must be a JSON array"))?;
        if entries.len() != DETAIL_LIST_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("DetectDetailInfo: detect_detail_data_list_new must have exactly {} entries (got {})",
                    DETAIL_LIST_LEN, entries.len())));
        }
        for e in entries {
            <DetectSenseData as WriteJsonValue>::write_from_json(w, e)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\detectdetailinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(DetectDetailInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "detectdetailinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(DetectDetailInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            DetectDetailInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
