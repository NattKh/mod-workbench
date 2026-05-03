// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `PlatformAchievementInfo.pabgb`.
//!
//! Per IDA sub_1410F3AD0: 10 fields. Two fixed-size [CString; 8] arrays
//! (_platformAchievementIds, _questGroupPlatformId) and one CArray<entry>
//! at the end (sub_14110BA60 with 8-CString-per-element entry).

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct QuestLinkInfoEntry<'a> {
        pub level: u32,
        pub label_a: CString<'a>,
        pub label_b: CString<'a>,
        pub label_c: CString<'a>,
        pub label_d: CString<'a>,
        pub label_e: CString<'a>,
        pub label_f: CString<'a>,
        pub label_g: CString<'a>,
        pub label_h: CString<'a>,
    }
}

#[derive(Debug)]
pub struct PlatformAchievementInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub mission_info: u32,
    pub platform_achievement_ids: [CString<'a>; 8],
    pub type_: u8,
    pub questkey: u32,
    pub quest_group_key: u16,
    pub quest_group_platform_id: [CString<'a>; 8],
    pub quest_link_info_list: CArray<QuestLinkInfoEntry<'a>>,
}

fn read_cstring_array8<'a>(data: &'a [u8], offset: &mut usize) -> io::Result<[CString<'a>; 8]> {
    Ok([
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
        CString::read_from(data, offset)?,
    ])
}

fn write_cstring_array8(arr: &[CString; 8], w: &mut dyn Write) -> io::Result<()> {
    for s in arr { s.write_to(w)?; }
    Ok(())
}

impl<'a> PlatformAchievementInfo<'a> {
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let mission_info = u32::read_from(data, offset)?;
        let platform_achievement_ids = read_cstring_array8(data, offset)?;
        let type_ = u8::read_from(data, offset)?;
        let questkey = u32::read_from(data, offset)?;
        let quest_group_key = u16::read_from(data, offset)?;
        let quest_group_platform_id = read_cstring_array8(data, offset)?;
        let quest_link_info_list = CArray::<QuestLinkInfoEntry>::read_from(data, offset)?;

        Ok(Self {
            key, string_key, is_blocked, mission_info,
            platform_achievement_ids, type_, questkey, quest_group_key,
            quest_group_platform_id, quest_link_info_list,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.mission_info.write_to(w)?;
        write_cstring_array8(&self.platform_achievement_ids, w)?;
        self.type_.write_to(w)?;
        self.questkey.write_to(w)?;
        self.quest_group_key.write_to(w)?;
        write_cstring_array8(&self.quest_group_platform_id, w)?;
        self.quest_link_info_list.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("mission_info".to_string(), self.mission_info.to_json_value());
        m.insert(
            "platform_achievement_ids".to_string(),
            Value::Array(self.platform_achievement_ids.iter().map(|s| s.to_json_value()).collect()),
        );
        m.insert("type_".to_string(), self.type_.to_json_value());
        m.insert("questkey".to_string(), self.questkey.to_json_value());
        m.insert("quest_group_key".to_string(), self.quest_group_key.to_json_value());
        m.insert(
            "quest_group_platform_id".to_string(),
            Value::Array(self.quest_group_platform_id.iter().map(|s| s.to_json_value()).collect()),
        );
        m.insert("quest_link_info_list".to_string(), self.quest_link_info_list.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "mission_info")?)?;
        write_cstring_array8_from_json(w, json_get_field(obj, "platform_achievement_ids")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "type_")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "questkey")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "quest_group_key")?)?;
        write_cstring_array8_from_json(w, json_get_field(obj, "quest_group_platform_id")?)?;
        <CArray<QuestLinkInfoEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "quest_link_info_list")?)?;
        Ok(())
    }
}

fn write_cstring_array8_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
    let arr = v.as_array().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData,
        "expected array of 8 strings for [CString; 8]",
    ))?;
    if arr.len() != 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("expected 8 elements for [CString; 8], got {}", arr.len())));
    }
    for elem in arr {
        <CString as WriteJsonValue>::write_from_json(w, elem)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\platformachievementinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(PlatformAchievementInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len());
        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "platformachievementinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(PlatformAchievementInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len());

        for (i, item) in items.iter().enumerate() {
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            PlatformAchievementInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
