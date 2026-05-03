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
//! Reader: `sub_1410FD200` in CrimsonDesert.exe (Win build).
//! Inner sub-readers (all decoded for the Tier 1.5 → 1 promotion):
//!   - sub_141108870 → CArray<SubLevelExpData> (each element wraps
//!     two nested CArrays — sub_141103310 + sub_1411142E0)
//!   - sub_1411086D0 → CArray<VaryExpPerDonationData> (20 wire bytes)
//!   - sub_1410E2030 → 13 wire bytes (NOT polymorphic — flat
//!     u8 + 3× u32 lookups; the leading u8 was the source of the
//!     earlier "polymorphic dispatch" misclassification)
//!   - sub_141103310 → CArray<{u32 + 8 raw}> (12 wire bytes per element)
//!   - sub_1411142E0 → CArray<{u32 + LocalizableString}>
//!
//! Wire reads, in order (canonical names from
//! `docs/449_TABLE_CATALOG.md`, SubLevelInfo section, 23 fields):
//!   1.  u32 key                                   (_key)
//!   2.  CString string_key                        (_stringKey)
//!   3.  u8 is_blocked                             (_isBlocked)
//!   4.  u32 min_level                             (_minLevel)
//!   5.  u32 max_level                             (_maxLevel)
//!   6.  [u8; 28] exp                              (_exp; sub_141E2BB80
//!       reads u64+u64+u64+u32 — 3 large identifiers + a flag/count;
//!       kept as raw bytes for round-trip integrity)
//!   7.  u32 condition_info                        (_conditionInfo,
//!       sub_1410FF430 → qword_145F0E9C0)
//!   8.  u32 alert_component_name                  (_alertComponentName,
//!       read_u32_lookup_DA30 → qword_145F0DA30)
//!   9.  u32 alert_component_name_for_vary_exp     (_alertComponentNameForVaryExp)
//!  10.  u32 knowledge_info                        (_knowledgeInfo,
//!       sub_1411006D0 → qword_145F0DA28)
//!  11.  u32 buff_info                             (_buffInfo,
//!       sub_141101A40 → qword_145F15058)
//!  12.  u32 money_info                            (_moneyInfo,
//!       sub_1410FF5C0 → qword_145F0DA00)
//!  13.  u32 reward_drop_set_info                  (_rewardDropSetInfo,
//!       sub_141100370 → qword_145F113C8)
//!  14.  CArray<SubLevelExpData> sub_level_exp_data_list
//!       (_subLevelExpDataList, sub_141108870)
//!  15.  CArray<SubLevelAdditionalReward> additional_reward_list
//!       (_additionalRewardList, inline u32 count + 8 wire bytes per
//!       element: u32 reward_lookup + u32 amount_lookup via sub_141100370)
//!  16.  CArray<VaryExperienceData> vary_experience_list
//!       (_varyExperienceList, inline u32 count + 21 wire bytes per
//!       element via sub_1410E2030 + 8 raw bytes)
//!  17.  CArray<VaryExpPerDonationData> vary_exp_per_donation_data_list
//!       (_varyExpPerDonationDataList, sub_1411086D0; 20 wire bytes
//!       per element: u32 lookup + 8 raw + 8 raw)
//!  18.  u8 additional_buff_apply_mercenary_info   (_additionalBuffApplyMercenaryInfo,
//!       sub_141100950 → qword_145F123D0; ONE wire byte!)
//!  19.  u32 faction_info_for_contribution         (_factionInfoForContribution,
//!       sub_141100860 → qword_145F0DA48)
//!  20.  u32 global_stage_sequencer_info           (_globalStageSequencerInfo,
//!       sub_141104340 → qword_145F0E9B8)
//!  21.  u8 buff_add_percent_type                  (_buffAddPercentType)
//!  22.  u32 exp_icon_path                         (_expIconPath, read_u32_lookup_DA30)
//!  23.  u8 is_relative_with_camp                  (_isRelativeWithCamp)

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

// SubLevelExpInnerLookupItem: per sub_141103310 (12 wire bytes).
//   u32 lookup (sub_1410FF5C0 → ItemInfoKey)
//   8 raw bytes (paired f32/f32 most likely)
py_binary_struct! {
    pub struct SubLevelExpInnerLookupItem {
        pub lookup: u32,
        pub raw_8: u64,
    }
}

// SubLevelExpInnerLabelItem: per sub_1411142E0.
//   u32 lookup (sub_1410FF430)
//   LocalizableString label
py_binary_struct! {
    pub struct SubLevelExpInnerLabelItem<'a> {
        pub lookup: u32,
        pub label: LocalizableString<'a>,
    }
}

// SubLevelExpData: per sub_141108870.
//   u32 outer_lookup (raw u32 from disk)
//   CArray<SubLevelExpInnerLookupItem>
//   8 raw bytes
//   CArray<SubLevelExpInnerLabelItem>
py_binary_struct! {
    pub struct SubLevelExpData<'a> {
        pub outer_lookup: u32,
        pub inner_lookup_list: CArray<SubLevelExpInnerLookupItem>,
        pub raw_8: u64,
        pub inner_label_list: CArray<SubLevelExpInnerLabelItem<'a>>,
    }
}

// SubLevelAdditionalReward: inline CArray element (8 wire bytes).
py_binary_struct! {
    pub struct SubLevelAdditionalReward {
        pub reward_lookup: u32,
        pub amount_lookup: u32,
    }
}

// VaryExperienceData: inline CArray element (21 wire bytes).
//   sub_1410E2030 = 13 wire bytes (u8 flag + 3× u32 lookups via
//   sub_1410FF430, all → qword_145F0E9C0).
//   + 8 raw bytes (paired f32/f32 most likely).
py_binary_struct! {
    pub struct VaryExperienceData {
        pub flag: u8,
        pub lookup_a: u32,
        pub lookup_b: u32,
        pub lookup_c: u32,
        pub raw_8: u64,
    }
}

// VaryExpPerDonationData: per sub_1411086D0 (20 wire bytes).
//   u32 lookup (sub_1410FF5C0 → ItemInfoKey)
//   8 raw + 8 raw
py_binary_struct! {
    pub struct VaryExpPerDonationData {
        pub lookup: u32,
        pub raw_a: u64,
        pub raw_b: u64,
    }
}

#[derive(Debug)]
pub struct SubLevelInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub min_level: u32,
    pub max_level: u32,
    /// 28-byte exp composite: 3× u64 + u32. Empirical sweep shows
    /// values like (100000, 10000000, 100000, 100) — looks like
    /// experience thresholds + count.
    pub exp_a: u64,
    pub exp_b: u64,
    pub exp_c: u64,
    pub exp_d: u32,
    pub condition_info: u32,
    pub alert_component_name: u32,
    pub alert_component_name_for_vary_exp: u32,
    pub knowledge_info: u32,
    pub buff_info: u32,
    pub money_info: u32,
    pub reward_drop_set_info: u32,
    pub sub_level_exp_data_list: CArray<SubLevelExpData<'a>>,
    pub additional_reward_list: CArray<SubLevelAdditionalReward>,
    pub vary_experience_list: CArray<VaryExperienceData>,
    pub vary_exp_per_donation_data_list: CArray<VaryExpPerDonationData>,
    pub additional_buff_apply_mercenary_info: u8,
    pub faction_info_for_contribution: u32,
    pub global_stage_sequencer_info: u32,
    pub buff_add_percent_type: u8,
    pub exp_icon_path: u32,
    pub is_relative_with_camp: u8,
}

impl<'a> SubLevelInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SubLevelInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let min_level = u32::read_from(data, offset)?;
        let max_level = u32::read_from(data, offset)?;
        let exp_a = u64::read_from(data, offset)?;
        let exp_b = u64::read_from(data, offset)?;
        let exp_c = u64::read_from(data, offset)?;
        let exp_d = u32::read_from(data, offset)?;
        let condition_info = u32::read_from(data, offset)?;
        let alert_component_name = u32::read_from(data, offset)?;
        let alert_component_name_for_vary_exp = u32::read_from(data, offset)?;
        let knowledge_info = u32::read_from(data, offset)?;
        let buff_info = u32::read_from(data, offset)?;
        let money_info = u32::read_from(data, offset)?;
        let reward_drop_set_info = u32::read_from(data, offset)?;
        let sub_level_exp_data_list = CArray::<SubLevelExpData>::read_from(data, offset)?;
        let additional_reward_list = CArray::<SubLevelAdditionalReward>::read_from(data, offset)?;
        let vary_experience_list = CArray::<VaryExperienceData>::read_from(data, offset)?;
        let vary_exp_per_donation_data_list = CArray::<VaryExpPerDonationData>::read_from(data, offset)?;
        let additional_buff_apply_mercenary_info = u8::read_from(data, offset)?;
        let faction_info_for_contribution = u32::read_from(data, offset)?;
        let global_stage_sequencer_info = u32::read_from(data, offset)?;
        let buff_add_percent_type = u8::read_from(data, offset)?;
        let exp_icon_path = u32::read_from(data, offset)?;
        let is_relative_with_camp = u8::read_from(data, offset)?;
        Ok(Self {
            key, string_key, is_blocked, min_level, max_level, exp_a, exp_b, exp_c, exp_d,
            condition_info, alert_component_name, alert_component_name_for_vary_exp,
            knowledge_info, buff_info, money_info, reward_drop_set_info,
            sub_level_exp_data_list, additional_reward_list, vary_experience_list,
            vary_exp_per_donation_data_list, additional_buff_apply_mercenary_info,
            faction_info_for_contribution, global_stage_sequencer_info,
            buff_add_percent_type, exp_icon_path, is_relative_with_camp,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.min_level.write_to(w)?;
        self.max_level.write_to(w)?;
        self.exp_a.write_to(w)?;
        self.exp_b.write_to(w)?;
        self.exp_c.write_to(w)?;
        self.exp_d.write_to(w)?;
        self.condition_info.write_to(w)?;
        self.alert_component_name.write_to(w)?;
        self.alert_component_name_for_vary_exp.write_to(w)?;
        self.knowledge_info.write_to(w)?;
        self.buff_info.write_to(w)?;
        self.money_info.write_to(w)?;
        self.reward_drop_set_info.write_to(w)?;
        self.sub_level_exp_data_list.write_to(w)?;
        self.additional_reward_list.write_to(w)?;
        self.vary_experience_list.write_to(w)?;
        self.vary_exp_per_donation_data_list.write_to(w)?;
        self.additional_buff_apply_mercenary_info.write_to(w)?;
        self.faction_info_for_contribution.write_to(w)?;
        self.global_stage_sequencer_info.write_to(w)?;
        self.buff_add_percent_type.write_to(w)?;
        self.exp_icon_path.write_to(w)?;
        self.is_relative_with_camp.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("min_level".to_string(), self.min_level.to_json_value());
        m.insert("max_level".to_string(), self.max_level.to_json_value());
        m.insert("exp_a".to_string(), self.exp_a.to_json_value());
        m.insert("exp_b".to_string(), self.exp_b.to_json_value());
        m.insert("exp_c".to_string(), self.exp_c.to_json_value());
        m.insert("exp_d".to_string(), self.exp_d.to_json_value());
        m.insert("condition_info".to_string(), self.condition_info.to_json_value());
        m.insert("alert_component_name".to_string(), self.alert_component_name.to_json_value());
        m.insert("alert_component_name_for_vary_exp".to_string(), self.alert_component_name_for_vary_exp.to_json_value());
        m.insert("knowledge_info".to_string(), self.knowledge_info.to_json_value());
        m.insert("buff_info".to_string(), self.buff_info.to_json_value());
        m.insert("money_info".to_string(), self.money_info.to_json_value());
        m.insert("reward_drop_set_info".to_string(), self.reward_drop_set_info.to_json_value());
        m.insert("sub_level_exp_data_list".to_string(), self.sub_level_exp_data_list.to_json_value());
        m.insert("additional_reward_list".to_string(), self.additional_reward_list.to_json_value());
        m.insert("vary_experience_list".to_string(), self.vary_experience_list.to_json_value());
        m.insert("vary_exp_per_donation_data_list".to_string(), self.vary_exp_per_donation_data_list.to_json_value());
        m.insert("additional_buff_apply_mercenary_info".to_string(), self.additional_buff_apply_mercenary_info.to_json_value());
        m.insert("faction_info_for_contribution".to_string(), self.faction_info_for_contribution.to_json_value());
        m.insert("global_stage_sequencer_info".to_string(), self.global_stage_sequencer_info.to_json_value());
        m.insert("buff_add_percent_type".to_string(), self.buff_add_percent_type.to_json_value());
        m.insert("exp_icon_path".to_string(), self.exp_icon_path.to_json_value());
        m.insert("is_relative_with_camp".to_string(), self.is_relative_with_camp.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "min_level")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "max_level")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exp_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exp_b")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exp_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exp_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "condition_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "alert_component_name")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "alert_component_name_for_vary_exp")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "knowledge_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "buff_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "money_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "reward_drop_set_info")?)?;
        <CArray<SubLevelExpData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sub_level_exp_data_list")?)?;
        <CArray<SubLevelAdditionalReward> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "additional_reward_list")?)?;
        <CArray<VaryExperienceData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "vary_experience_list")?)?;
        <CArray<VaryExpPerDonationData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "vary_exp_per_donation_data_list")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "additional_buff_apply_mercenary_info")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "faction_info_for_contribution")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "global_stage_sequencer_info")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "buff_add_percent_type")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exp_icon_path")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_relative_with_camp")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sublevelinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sublevelinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = SubLevelInfo::read_from(&data, &mut c)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-read {}/{}", i, k, c - s, e - s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "sublevelinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = SubLevelInfo::read_from(&data, &mut cursor).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            SubLevelInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }

    #[test]
    fn fields_addressable() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let Some((_, s, _)) = ranges.first() else { eprintln!("SKIP: no entries"); return; };
        let mut c = *s;
        let item = SubLevelInfo::read_from(&data, &mut c).unwrap();
        let dict = item.to_json_dict();
        for f in [
            "key", "string_key", "is_blocked", "min_level", "max_level",
            "exp_a", "exp_b", "exp_c", "exp_d",
            "condition_info", "alert_component_name",
            "alert_component_name_for_vary_exp", "knowledge_info", "buff_info",
            "money_info", "reward_drop_set_info", "sub_level_exp_data_list",
            "additional_reward_list", "vary_experience_list",
            "vary_exp_per_donation_data_list",
            "additional_buff_apply_mercenary_info",
            "faction_info_for_contribution", "global_stage_sequencer_info",
            "buff_add_percent_type", "exp_icon_path", "is_relative_with_camp",
        ] {
            assert!(dict.contains_key(f), "missing field `{}` in JSON dict", f);
        }
        assert!(!dict.contains_key("_tail_b64"), "Tier 1.5 _tail_b64 leaked");
    }
}
