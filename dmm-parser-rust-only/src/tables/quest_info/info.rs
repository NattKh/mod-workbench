#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed parser with variant-boundary probe for the polymorphic
//! `_questDialogFilterDataList` field.
//!
//! Reader (Mac CrimsonDesert_Steam): entry-level `sub_1018545F0` at
//! 0x1018545F0. 35 wire fields total — all are now editable except the
//! polymorphic 29th field, which is captured as a verbatim byte blob
//! (`quest_dialog_filter_data_list_blob`) so round-trip stays byte-perfect
//! and authors can clone the blob between entries.
//!
//! Wire layout (in order; canonical names from Mac Korean error strings):
//!   1.  u32 key                        (sub_100F133BC, QuestKey, template
//!                                       `<...,unsigned int>`)
//!   2.  CString string_key
//!   3.  u8 is_blocked
//!   4.  u8 quest_type                  (sub_10136CA5C = vtable[2] width 1)
//!   5.  u8 quest_category              (vtable[2] width 1)
//!   6.  LocalizableString name
//!   7.  LocalizableString desc
//!   8.  u16 quest_group_info           (sub_10183DCC8, QuestGroupKey wire u16)
//!   9.  u32 faction_info               (FactionKey wire u32 hash, runtime u16)
//!  10. FactionStateData faction_state_data (sub_101848C10, fixed 4-field
//!       struct: CArray<u8> + u32 ConditionKey + u32 FactionKey + u8)
//!  11. BranchData branch_data          (sub_101652724, fixed 6-field struct,
//!       18 bytes wire: u32 QuestKey + u32 ConditionKey + u8 + u8 + u32 + u32)
//!  12. CArray<u32> start_player_list   (CharacterKey hash list)
//!  13. CArray<BranchData> branch_data_list  (sub_101885280)
//!  14. CArray<u32> executor_quest_list  (sub_10186F2C4, QuestKey hash)
//!  15. CArray<u32> gauge_list          (sub_101885460, QuestGaugeKey)
//!  16. CArray<u32> mission_list        (sub_10186E494, MissionKey hash)
//!  17. CArray<u32> stage_list          (sub_101667390, StageKey hash)
//!  18. u32 start_mission               (MissionKey hash)
//!  19. u32 start_stage                 (StageKey hash)
//!  20. u32 stage_icon_path             (StringInfoKey hash)
//!  21. u32 stage_text_icon_path        (StringInfoKey)
//!  22. u32 stage_image_path            (StringInfoKey)
//!  23. u32 playable_mission_count
//!  24. u32 playable_stage_count
//!  25. CString test_tag
//!  26. u32 game_start_stage            (StageKey hash)
//!  27. CString game_start_sub_timeline (sub_1006B40F4: u32 length + N raw
//!       bytes wire, runtime hashes to u32 stored at struct +268)
//!  28. CString memo
//!  --- variant-boundary probe captures the bytes from here through ---
//!  --- the start of `_dialogMustMissionInfoList` as `quest_dialog_filter_data_list_blob` ---
//!  29. _questDialogFilterDataList (CArray of 144-byte QuestDialog_FilterData;
//!       FilterCondition has 11 tagged variants discriminated by u8 with
//!       0-8 byte payloads — out of scope for this commit, captured as bytes)
//!  30. CArray<u32> dialog_must_mission_info_list (sub_10186E494, MissionKey)
//!  31. u32 npc_dialog_must_condition   (sub_100C93238, ConditionKey hash)
//!  32. u8 is_save
//!  33. u8 is_continuous_mission
//!  34. u8 is_repeatable
//!  35. u32 debug_color                 (sub_1006B4CD0, vtable[2] width 4)

use crate::binary::variant::find_variant_boundary;
use crate::binary::variants::filter_condition::QuestDialogFilterData;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};

/// Decoded|Raw fallback for `_questDialogFilterDataList`. The
/// `QuestDialogFilterData` decoder (binary::variants::filter_condition,
/// shipped via lane-b) covers all 18 wire fields, but some entries may
/// hit unmapped FilterCondition tags or nested helpers. The Raw arm
/// preserves byte-perfect round-trip in those cases. (lane-c, 2026-04-30:
/// initial wiring on top of lane-b's filter_condition family decoder.)
#[derive(Debug)]
pub enum QuestDialogFilterDataList<'a> {
    Decoded(CArray<QuestDialogFilterData<'a>>),
    Raw(Vec<u8>),
}

impl<'a> QuestDialogFilterDataList<'a> {
    fn read_with_size(data: &'a [u8], offset: &mut usize, region_end: usize) -> io::Result<Self> {
        let region_start = *offset;
        let mut probe = region_start;
        match <CArray<QuestDialogFilterData>>::read_from(data, &mut probe) {
            Ok(list) if probe == region_end => {
                *offset = probe;
                Ok(Self::Decoded(list))
            }
            _ => {
                let bytes = data[region_start..region_end].to_vec();
                *offset = region_end;
                Ok(Self::Raw(bytes))
            }
        }
    }

    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Decoded(list) => list.write_to(w),
            Self::Raw(b) => w.write_all(b),
        }
    }

    fn to_json_value(&self) -> Value {
        match self {
            Self::Decoded(list) => {
                let mut m = Map::new();
                m.insert("kind".into(), Value::String("Decoded".into()));
                m.insert("list".into(), list.to_json_value());
                Value::Object(m)
            }
            Self::Raw(b) => {
                let mut m = Map::new();
                m.insert("kind".into(), Value::String("Raw".into()));
                m.insert("_b64".into(), Value::String(B64.encode(b)));
                Value::Object(m)
            }
        }
    }

    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "QuestDialogFilterDataList: expected object"))?;
        let kind = json_get_field(obj, "kind")?.as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "QuestDialogFilterDataList.kind: expected string"))?;
        match kind {
            "Decoded" => <CArray<QuestDialogFilterData> as WriteJsonValue>::write_from_json(
                w, json_get_field(obj, "list")?,
            ),
            "Raw" => {
                let b64 = json_get_field(obj, "_b64")?.as_str()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                        "QuestDialogFilterDataList.Raw._b64: expected string"))?;
                let bytes = B64.decode(b64).map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("QuestDialogFilterDataList.Raw._b64: invalid base64: {}", e)))?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("QuestDialogFilterDataList.kind: unknown variant {:?}", other))),
        }
    }
}
use std::io::{self, Write};

py_binary_struct! {
    pub struct FactionStateData {
        pub activate_faction_state_list: CArray<u8>,
        pub player_condition_info: u32,
        pub relation_target_faction_info: u32,
        pub relation_type: u8,
    }
}

py_binary_struct! {
    pub struct BranchData {
        pub quest_key: u32,
        pub condition_key: u32,
        pub byte_a: u8,
        pub byte_b: u8,
        pub u32_a: u32,
        pub u32_b: u32,
    }
}

#[derive(Debug)]
pub struct QuestInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub quest_type: u8,
    pub quest_category: u8,
    pub name: LocalizableString<'a>,
    pub desc: LocalizableString<'a>,
    pub quest_group_info: u16,
    pub faction_info: u32,
    pub faction_state_data: FactionStateData,
    pub branch_data: BranchData,
    pub start_player_list: CArray<u32>,
    pub branch_data_list: CArray<BranchData>,
    pub executor_quest_list: CArray<u32>,
    pub gauge_list: CArray<u32>,
    pub mission_list: CArray<u32>,
    pub stage_list: CArray<u32>,
    pub start_mission: u32,
    pub start_stage: u32,
    pub stage_icon_path: u32,
    pub stage_text_icon_path: u32,
    pub stage_image_path: u32,
    pub playable_mission_count: u32,
    pub playable_stage_count: u32,
    pub test_tag: CString<'a>,
    pub game_start_stage: u32,
    pub game_start_sub_timeline: CString<'a>,
    pub memo: CString<'a>,
    /// Polymorphic CArray<QuestDialog_FilterData> with Decoded|Raw fallback.
    /// Lane-c 2026-04-30: wired to consume the FilterCondition family decoder
    /// (binary::variants::filter_condition::QuestDialogFilterData) shipped by
    /// lane-b. Decoded entries get full field-level access via 18 typed wire
    /// fields per QuestDialogFilterData; Raw fallbacks preserve byte-perfect
    /// round-trip when an entry hits an unmapped FilterCondition tag.
    pub quest_dialog_filter_data_list: QuestDialogFilterDataList<'a>,
    pub dialog_must_mission_info_list: CArray<u32>,
    pub npc_dialog_must_condition: u32,
    pub is_save: u8,
    pub is_continuous_mission: u8,
    pub is_repeatable: u8,
    pub debug_color: u32,
}

/// Probe the trailing fields after the polymorphic blob. Returns the number
/// of bytes consumed by the trailing fields if the layout parses cleanly,
/// or None to signal "this offset isn't the right boundary."
fn try_read_trailer(data: &[u8], start: usize, end: usize) -> Option<usize> {
    let mut cursor = start;
    // CArray<u32> dialog_must_mission_info_list
    if cursor + 4 > end { return None; }
    let cnt = u32::from_le_bytes(data[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    // Sanity bound: realistic mission lists per quest are <= 4096
    if cnt > 4096 { return None; }
    if cursor + cnt * 4 > end { return None; }
    cursor += cnt * 4;
    // u32 npc_dialog_must_condition
    if cursor + 4 > end { return None; }
    cursor += 4;
    // u8 is_save, u8 is_continuous_mission, u8 is_repeatable
    if cursor + 3 > end { return None; }
    let is_save = data[cursor];
    let is_continuous = data[cursor + 1];
    let is_repeatable = data[cursor + 2];
    // Boolean fields are 0 or 1 only
    if is_save > 1 || is_continuous > 1 || is_repeatable > 1 {
        return None;
    }
    cursor += 3;
    // u32 debug_color
    if cursor + 4 > end { return None; }
    cursor += 4;
    Some(cursor - start)
}

impl<'a> QuestInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let quest_type = u8::read_from(data, offset)?;
        let quest_category = u8::read_from(data, offset)?;
        let name = LocalizableString::read_from(data, offset)?;
        let desc = LocalizableString::read_from(data, offset)?;
        let quest_group_info = u16::read_from(data, offset)?;
        let faction_info = u32::read_from(data, offset)?;
        let faction_state_data = FactionStateData::read_from(data, offset)?;
        let branch_data = BranchData::read_from(data, offset)?;
        let start_player_list = CArray::<u32>::read_from(data, offset)?;
        let branch_data_list = CArray::<BranchData>::read_from(data, offset)?;
        let executor_quest_list = CArray::<u32>::read_from(data, offset)?;
        let gauge_list = CArray::<u32>::read_from(data, offset)?;
        let mission_list = CArray::<u32>::read_from(data, offset)?;
        let stage_list = CArray::<u32>::read_from(data, offset)?;
        let start_mission = u32::read_from(data, offset)?;
        let start_stage = u32::read_from(data, offset)?;
        let stage_icon_path = u32::read_from(data, offset)?;
        let stage_text_icon_path = u32::read_from(data, offset)?;
        let stage_image_path = u32::read_from(data, offset)?;
        let playable_mission_count = u32::read_from(data, offset)?;
        let playable_stage_count = u32::read_from(data, offset)?;
        let test_tag = CString::read_from(data, offset)?;
        let game_start_stage = u32::read_from(data, offset)?;
        let game_start_sub_timeline = CString::read_from(data, offset)?;
        let memo = CString::read_from(data, offset)?;

        // Probe for the boundary: scan forward through the polymorphic
        // _questDialogFilterDataList blob until the trailing 6 fields parse
        // cleanly all the way to entry_end.
        let post_pre = *offset;
        let blob_size = find_variant_boundary(data, post_pre, entry_end, 0, |probe| {
            try_read_trailer(data, probe, entry_end)
        })?;
        let region_end = post_pre + blob_size;
        let quest_dialog_filter_data_list =
            QuestDialogFilterDataList::read_with_size(data, offset, region_end)?;

        let dialog_must_mission_info_list = CArray::<u32>::read_from(data, offset)?;
        let npc_dialog_must_condition = u32::read_from(data, offset)?;
        let is_save = u8::read_from(data, offset)?;
        let is_continuous_mission = u8::read_from(data, offset)?;
        let is_repeatable = u8::read_from(data, offset)?;
        let debug_color = u32::read_from(data, offset)?;

        Ok(Self {
            key,
            string_key,
            is_blocked,
            quest_type,
            quest_category,
            name,
            desc,
            quest_group_info,
            faction_info,
            faction_state_data,
            branch_data,
            start_player_list,
            branch_data_list,
            executor_quest_list,
            gauge_list,
            mission_list,
            stage_list,
            start_mission,
            start_stage,
            stage_icon_path,
            stage_text_icon_path,
            stage_image_path,
            playable_mission_count,
            playable_stage_count,
            test_tag,
            game_start_stage,
            game_start_sub_timeline,
            memo,
            quest_dialog_filter_data_list,
            dialog_must_mission_info_list,
            npc_dialog_must_condition,
            is_save,
            is_continuous_mission,
            is_repeatable,
            debug_color,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.quest_type.write_to(w)?;
        self.quest_category.write_to(w)?;
        self.name.write_to(w)?;
        self.desc.write_to(w)?;
        self.quest_group_info.write_to(w)?;
        self.faction_info.write_to(w)?;
        self.faction_state_data.write_to(w)?;
        self.branch_data.write_to(w)?;
        self.start_player_list.write_to(w)?;
        self.branch_data_list.write_to(w)?;
        self.executor_quest_list.write_to(w)?;
        self.gauge_list.write_to(w)?;
        self.mission_list.write_to(w)?;
        self.stage_list.write_to(w)?;
        self.start_mission.write_to(w)?;
        self.start_stage.write_to(w)?;
        self.stage_icon_path.write_to(w)?;
        self.stage_text_icon_path.write_to(w)?;
        self.stage_image_path.write_to(w)?;
        self.playable_mission_count.write_to(w)?;
        self.playable_stage_count.write_to(w)?;
        self.test_tag.write_to(w)?;
        self.game_start_stage.write_to(w)?;
        self.game_start_sub_timeline.write_to(w)?;
        self.memo.write_to(w)?;
        self.quest_dialog_filter_data_list.write_to(w)?;
        self.dialog_must_mission_info_list.write_to(w)?;
        self.npc_dialog_must_condition.write_to(w)?;
        self.is_save.write_to(w)?;
        self.is_continuous_mission.write_to(w)?;
        self.is_repeatable.write_to(w)?;
        self.debug_color.write_to(w)?;
        Ok(())
    }

    /// JSON shape: every typed field is field-addressable. The polymorphic
    /// 29th field rides as `_quest_dialog_filter_data_list_blob_b64` (the
    /// raw wire bytes, base64) — clone-between-entries works, but the
    /// per-variant typed exposure is gated on the FilterCondition family
    /// decoder (task #66, see header doc).
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("quest_type".to_string(), self.quest_type.to_json_value());
        m.insert("quest_category".to_string(), self.quest_category.to_json_value());
        m.insert("name".to_string(), self.name.to_json_value());
        m.insert("desc".to_string(), self.desc.to_json_value());
        m.insert("quest_group_info".to_string(), self.quest_group_info.to_json_value());
        m.insert("faction_info".to_string(), self.faction_info.to_json_value());
        m.insert("faction_state_data".to_string(), self.faction_state_data.to_json_value());
        m.insert("branch_data".to_string(), self.branch_data.to_json_value());
        m.insert("start_player_list".to_string(), self.start_player_list.to_json_value());
        m.insert("branch_data_list".to_string(), self.branch_data_list.to_json_value());
        m.insert("executor_quest_list".to_string(), self.executor_quest_list.to_json_value());
        m.insert("gauge_list".to_string(), self.gauge_list.to_json_value());
        m.insert("mission_list".to_string(), self.mission_list.to_json_value());
        m.insert("stage_list".to_string(), self.stage_list.to_json_value());
        m.insert("start_mission".to_string(), self.start_mission.to_json_value());
        m.insert("start_stage".to_string(), self.start_stage.to_json_value());
        m.insert("stage_icon_path".to_string(), self.stage_icon_path.to_json_value());
        m.insert("stage_text_icon_path".to_string(), self.stage_text_icon_path.to_json_value());
        m.insert("stage_image_path".to_string(), self.stage_image_path.to_json_value());
        m.insert("playable_mission_count".to_string(), self.playable_mission_count.to_json_value());
        m.insert("playable_stage_count".to_string(), self.playable_stage_count.to_json_value());
        m.insert("test_tag".to_string(), self.test_tag.to_json_value());
        m.insert("game_start_stage".to_string(), self.game_start_stage.to_json_value());
        m.insert("game_start_sub_timeline".to_string(), self.game_start_sub_timeline.to_json_value());
        m.insert("memo".to_string(), self.memo.to_json_value());
        m.insert(
            "quest_dialog_filter_data_list".to_string(),
            self.quest_dialog_filter_data_list.to_json_value(),
        );
        m.insert("dialog_must_mission_info_list".to_string(), self.dialog_must_mission_info_list.to_json_value());
        m.insert("npc_dialog_must_condition".to_string(), self.npc_dialog_must_condition.to_json_value());
        m.insert("is_save".to_string(), self.is_save.to_json_value());
        m.insert("is_continuous_mission".to_string(), self.is_continuous_mission.to_json_value());
        m.insert("is_repeatable".to_string(), self.is_repeatable.to_json_value());
        m.insert("debug_color".to_string(), self.debug_color.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "quest_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "quest_category")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "desc")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "quest_group_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "faction_info")?)?;
        <FactionStateData as WriteJsonValue>::write_from_json(w, json_get_field(obj, "faction_state_data")?)?;
        <BranchData as WriteJsonValue>::write_from_json(w, json_get_field(obj, "branch_data")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "start_player_list")?)?;
        <CArray<BranchData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "branch_data_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "executor_quest_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "gauge_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "mission_list")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "start_mission")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "start_stage")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_icon_path")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_text_icon_path")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "stage_image_path")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "playable_mission_count")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "playable_stage_count")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "test_tag")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "game_start_stage")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "game_start_sub_timeline")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "memo")?)?;
        QuestDialogFilterDataList::write_from_json(
            w, json_get_field(obj, "quest_dialog_filter_data_list")?,
        )?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dialog_must_mission_info_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "npc_dialog_must_condition")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_save")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_continuous_mission")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_repeatable")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "debug_color")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = QuestInfo::read_with_size(&data, &mut c, e - s)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "entry {} k=0x{:x} consumed {} of {} bytes", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "questinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = QuestInfo::read_with_size(&data, &mut c, e - s)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            QuestInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: write_from_json_dict: {}", i, k, er));
            assert_eq!(
                from_json, from_typed,
                "entry {} k=0x{:x}: JSON round-trip diverges from typed write",
                i, k
            );
        }
    }
}
