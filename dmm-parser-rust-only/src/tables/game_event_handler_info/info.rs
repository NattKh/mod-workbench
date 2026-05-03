// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: typed prefix + GameEventHandlerData wrapper + tail u8.
//!
//! Reader: `sub_1410E1E60` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u16 key                       (_key, pabgh format 2)
//!   2. CString string_key            (_stringKey)
//!   3. u8 is_blocked                 (_isBlocked)
//!   4. u8 game_event_type            (_gameEventType)
//!   5. u32 player_condition          (_playerCondition, sub_1410FF430
//!      → qword_145F0E9C0)
//!   6. u32 event_condition           (_eventCondition, sub_1410FF430)
//!   7. u32 target_condition          (_targetCondition, sub_1410FF430)
//!   8. _gameEventHandlerData (sub_1415BE5E0 → POLYMORPHIC family
//!      `GameEventHandlerData` with sub_tag dispatch:
//!      0=SetSceneObjectParameterBySceneLevel [32B],
//!      1=SetSceneObjectParameter [32B],
//!      2=SetUIPlayGuideParameter [32B],
//!      3=SetUIFullscreenGuideParameter [24B],
//!      4=MakeSnapshotForDev [24B])
//!   9. u8 is_pend_on_battle_state    (_isPendOnBattleState)
//!
//! ## Tier 1 — typed wrapper, byte-perfect round-trip
//!
//! `data` uses the typed `Decoded(Body) | Raw` enum from
//! `crate::binary::variants::game_event_handler_data`. Per-sub_tag bodies
//! are field-level typed (sub_tag 2 → SetUIPlayGuideParameter with u32+u32
//! +f32; sub_tag 3 → SetUIFullscreenGuideParameter with u16+u32). Field
//! shapes were recovered empirically from wire patterns since the C++
//! readers are anti-disassembly-protected. Raw is the byte-perfect
//! fallback for any unrecognized sub_tag.
//!
//! DO NOT REGENERATE. Hand-written; bulk_process.py guards via the
//! "Hand-corrected" header marker on line 1.

use crate::binary::variants::game_event_handler_data::GameEventHandlerData;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct GameEventHandlerInfo<'a> {
    pub key: u16,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub game_event_type: u8,
    pub player_condition: u32,
    pub event_condition: u32,
    pub target_condition: u32,
    /// Polymorphic event-handler-data wrapper. Decoded captures sub_tag
    /// + body bytes; Raw passes through verbatim. Either way, the
    /// wrapper round-trips byte-perfect.
    pub data: GameEventHandlerData,
    /// Trailing u8 read AFTER the polymorphic data block (per
    /// sub_1410E1E60).
    pub is_pend_on_battle_state: u8,
}

impl<'a> GameEventHandlerInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;

        let key = u16::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let game_event_type = u8::read_from(data, offset)?;
        let player_condition = u32::read_from(data, offset)?;
        let event_condition = u32::read_from(data, offset)?;
        let target_condition = u32::read_from(data, offset)?;

        // The variant + trailing u8 share the rest of the entry.
        // Subtract 1 for the trailing is_pend_on_battle_state, then pass
        // a sub-slice sized to exactly the variant wrapper.
        if entry_end < *offset + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GameEventHandlerInfo: entry too short for trailing u8",
            ));
        }
        let variant_end = entry_end - 1;
        let wrapper_bytes = &data[*offset..variant_end];
        let mut wrapper_cur = 0usize;
        let event_data = GameEventHandlerData::read_from(wrapper_bytes, &mut wrapper_cur)?;
        *offset = variant_end;
        let is_pend_on_battle_state = u8::read_from(data, offset)?;

        Ok(Self {
            key,
            string_key,
            is_blocked,
            game_event_type,
            player_condition,
            event_condition,
            target_condition,
            data: event_data,
            is_pend_on_battle_state,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.game_event_type.write_to(w)?;
        self.player_condition.write_to(w)?;
        self.event_condition.write_to(w)?;
        self.target_condition.write_to(w)?;
        self.data.write_to(w)?;
        self.is_pend_on_battle_state.write_to(w)?;
        Ok(())
    }

    /// JSON shape:
    /// - All scalars individually editable (key, string_key, is_blocked,
    ///   game_event_type, player_condition, event_condition,
    ///   target_condition, is_pend_on_battle_state).
    /// - `data`: typed object with `kind` + sub_tag-specific `body` fields
    ///   (or `raw_b64` for the Raw fallback). See
    ///   `GameEventHandlerData::to_json_value` for the per-variant schema.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("game_event_type".to_string(), self.game_event_type.to_json_value());
        m.insert(
            "player_condition".to_string(),
            self.player_condition.to_json_value(),
        );
        m.insert(
            "event_condition".to_string(),
            self.event_condition.to_json_value(),
        );
        m.insert(
            "target_condition".to_string(),
            self.target_condition.to_json_value(),
        );
        m.insert("data".to_string(), self.data.to_json_value());
        m.insert(
            "is_pend_on_battle_state".to_string(),
            self.is_pend_on_battle_state.to_json_value(),
        );
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "game_event_type")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "player_condition")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "event_condition")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "target_condition")?)?;
        GameEventHandlerData::write_from_json(w, json_get_field(obj, "data")?)?;
        <u8 as WriteJsonValue>::write_from_json(
            w,
            json_get_field(obj, "is_pend_on_battle_state")?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variants::game_event_handler_data::GameEventHandlerDataBody;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gameeventhandler.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gameeventhandler.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                GameEventHandlerInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items {
            it.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "gameeventhandler roundtrip mismatch");
    }

    #[test]
    fn data_kinds() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        let mut sub_tag_2 = 0;
        let mut sub_tag_3 = 0;
        let mut sub_tag_4 = 0;
        let mut raw = 0;
        for (_k, s, e) in ranges.iter() {
            let mut c = *s;
            let it = GameEventHandlerInfo::read_with_size(&data, &mut c, e - s).unwrap();
            match &it.data {
                GameEventHandlerData::Decoded(body) => match body {
                    GameEventHandlerDataBody::SetUIPlayGuideParameter(_) => sub_tag_2 += 1,
                    GameEventHandlerDataBody::SetUIFullscreenGuideParameter(_) => sub_tag_3 += 1,
                    GameEventHandlerDataBody::MakeSnapshotForDev => sub_tag_4 += 1,
                },
                GameEventHandlerData::Raw(_) => raw += 1,
            }
        }
        eprintln!(
            "gameeventhandler data: sub_tag_2={} sub_tag_3={} sub_tag_4={} raw={}",
            sub_tag_2, sub_tag_3, sub_tag_4, raw,
        );
    }

    /// JSON dict round-trip — typed write_to bytes must match
    /// write_from_json_dict bytes for every entry.
    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = GameEventHandlerInfo::read_with_size(&data, &mut c, e - s).unwrap();
            let dict = item.to_json_dict();
            let mut typed = Vec::new();
            item.write_to(&mut typed).unwrap();
            let mut from_json = Vec::new();
            GameEventHandlerInfo::write_from_json_dict(&mut from_json, &dict).unwrap_or_else(|er| {
                panic!("e{} k=0x{:x}: {}", i, k, er)
            });
            assert_eq!(
                from_json, typed,
                "entry {} key=0x{:x}: JSON round-trip diverges",
                i, k,
            );
        }
    }
}
