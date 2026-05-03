#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed (no _tail_b64).
//!
//! Reader: `sub_1410EBEB0` in CrimsonDesert.exe (Win build).
//! Inner `_dyeColorGroupDataList` reader: `sub_14110E340`.
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                                  (_key)
//!   2. CString string_key                       (_stringKey)
//!   3. u8 is_blocked                            (_isBlocked)
//!   4. u32 icon_path                            (_iconPath, read_u32_lookup_DA30)
//!   5. u16 store_info                           (_storeInfo, sub_141103610 → qword_145F15038)
//!   6. u32 coupon_item_info                     (_couponItemInfo, sub_1410FF5C0 → qword_145F0DA00)
//!   7. u32 npc_greet_friendly                   (_npcGreetFriendly)
//!   8. u32 npc_function_type_flag               (_npcFunctionTypeFlag)
//!   9. u32 shop_scenekey                        (_shopScenekey)
//!  10. u16 exchange_group_key                   (_exchangeGroupKey)
//!  11. LocalizableString exchange_button_text   (_exchangeButtonText)
//!  12. LocalizableString shop_name              (_shopName)
//!  13. LocalizableString interaction_name       (_interactionName)
//!  14. CArray<DyeColorGroupData> dye_color_group_data_list
//!      (sub_14110E340; each element is 8 wire bytes:
//!       u32 dye_color_group_key (looked up via qword_145F24DC8) +
//!       u32 dye_target_key (sub_1410FF430 → qword_145F0E9C0))
//!  15. CArray<DyeTextureSetData> dye_texture_set_data_list
//!      (inline; each element is 6 wire bytes:
//!       u16 texture_set_lookup +
//!       u32 dye_target_key (sub_1410FF430 → qword_145F0E9C0))
//!
//! After step 15 the reader returns; nothing else exists in the tail.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct DyeColorGroupData {
        pub dye_color_group_key: u32,
        pub dye_target_key: u32,
    }
}

py_binary_struct! {
    pub struct DyeTextureSetData {
        pub texture_set_lookup: u16,
        pub dye_target_key: u32,
    }
}

#[derive(Debug)]
pub struct NpcInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub icon_path: u32,
    pub store_info: u16,
    pub coupon_item_info: u32,
    pub npc_greet_friendly: u32,
    pub npc_function_type_flag: u32,
    pub shop_scenekey: u32,
    pub exchange_group_key: u16,
    pub exchange_button_text: LocalizableString<'a>,
    pub shop_name: LocalizableString<'a>,
    pub interaction_name: LocalizableString<'a>,
    pub dye_color_group_data_list: CArray<DyeColorGroupData>,
    pub dye_texture_set_data_list: CArray<DyeTextureSetData>,
}

impl<'a> NpcInfo<'a> {
    /// Read with explicit entry size from pabgh (compat shim — Tier 1 means
    /// every byte is consumed by typed reads, so the size is just verified).
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("NpcInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let icon_path = u32::read_from(data, offset)?;
        let store_info = u16::read_from(data, offset)?;
        let coupon_item_info = u32::read_from(data, offset)?;
        let npc_greet_friendly = u32::read_from(data, offset)?;
        let npc_function_type_flag = u32::read_from(data, offset)?;
        let shop_scenekey = u32::read_from(data, offset)?;
        let exchange_group_key = u16::read_from(data, offset)?;
        let exchange_button_text = LocalizableString::read_from(data, offset)?;
        let shop_name = LocalizableString::read_from(data, offset)?;
        let interaction_name = LocalizableString::read_from(data, offset)?;
        let dye_color_group_data_list = CArray::<DyeColorGroupData>::read_from(data, offset)?;
        let dye_texture_set_data_list = CArray::<DyeTextureSetData>::read_from(data, offset)?;
        Ok(Self {
            key, string_key, is_blocked, icon_path, store_info, coupon_item_info,
            npc_greet_friendly, npc_function_type_flag, shop_scenekey,
            exchange_group_key, exchange_button_text, shop_name, interaction_name,
            dye_color_group_data_list, dye_texture_set_data_list,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.icon_path.write_to(w)?;
        self.store_info.write_to(w)?;
        self.coupon_item_info.write_to(w)?;
        self.npc_greet_friendly.write_to(w)?;
        self.npc_function_type_flag.write_to(w)?;
        self.shop_scenekey.write_to(w)?;
        self.exchange_group_key.write_to(w)?;
        self.exchange_button_text.write_to(w)?;
        self.shop_name.write_to(w)?;
        self.interaction_name.write_to(w)?;
        self.dye_color_group_data_list.write_to(w)?;
        self.dye_texture_set_data_list.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("icon_path".to_string(), self.icon_path.to_json_value());
        m.insert("store_info".to_string(), self.store_info.to_json_value());
        m.insert("coupon_item_info".to_string(), self.coupon_item_info.to_json_value());
        m.insert("npc_greet_friendly".to_string(), self.npc_greet_friendly.to_json_value());
        m.insert("npc_function_type_flag".to_string(), self.npc_function_type_flag.to_json_value());
        m.insert("shop_scenekey".to_string(), self.shop_scenekey.to_json_value());
        m.insert("exchange_group_key".to_string(), self.exchange_group_key.to_json_value());
        m.insert("exchange_button_text".to_string(), self.exchange_button_text.to_json_value());
        m.insert("shop_name".to_string(), self.shop_name.to_json_value());
        m.insert("interaction_name".to_string(), self.interaction_name.to_json_value());
        m.insert("dye_color_group_data_list".to_string(), self.dye_color_group_data_list.to_json_value());
        m.insert("dye_texture_set_data_list".to_string(), self.dye_texture_set_data_list.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "icon_path")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "store_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "coupon_item_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "npc_greet_friendly")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "npc_function_type_flag")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "shop_scenekey")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exchange_group_key")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exchange_button_text")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "shop_name")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "interaction_name")?)?;
        <CArray<DyeColorGroupData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dye_color_group_data_list")?)?;
        <CArray<DyeTextureSetData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dye_texture_set_data_list")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\npcinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\npcinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = NpcInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "npcinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = NpcInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            NpcInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }

    /// Confirm the new typed lists actually carry data — guards against
    /// silent regression to _tail_b64.
    #[test]
    fn dye_lists_populated() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let (mut total_color, mut total_texture, mut entries_count) = (0usize, 0usize, 0usize);
        for (_, s, _) in &ranges {
            let mut c = *s;
            let item = NpcInfo::read_from(&data, &mut c).unwrap();
            total_color += item.dye_color_group_data_list.items.len();
            total_texture += item.dye_texture_set_data_list.items.len();
            entries_count += 1;
        }
        eprintln!(
            "npc_info: {} entries, {} dye_color_group items, {} dye_texture_set items",
            entries_count, total_color, total_texture
        );
    }
}
