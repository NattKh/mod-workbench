// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 (with Decoded|Raw fallback) — typed prefix plus a per-entry
//! enum that exposes the full body. As of 2026-04-30 with the
//! Mac-IDA tag 54/214 recipe fixes (`5fa0b06`), **all 363/363 vanilla
//! entries route through Decoded** (100% Decoded, down from 57 Raw at
//! the start of recipe-verification). The Raw fallback path is kept
//! for byte-perfect resilience if a future build introduces
//! unresolved ConditionPair variants.
//!
//! Reader: `sub_1410DFBA0` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order:
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. u8 interaction_type
//!   5. u8 interaction_show_ui_type
//!   6. u8 preemption_type
//!   7. LocalizableString interaction_name
//!   8. u8 pivot_selection_target
//!   9. CArray<InteractionPivotData> interaction_pivot_list
//!     ← typed prefix ends here; tail follows
//!  10. ConditionPairCArray cond_data_list (sub_141114DD0)
//!  11. u8 auto_interaction_type
//!  12. u16 category_info        (sub_141103CA0 → qword_145F290B0)
//!  13. u32 input_key_map_name   (read_u32_lookup_DA30)
//!  14. u8 button_click_type
//!  15. u8 keyboard_click_type
//!  16-19. 4× u8 unknown_flags
//!  20. SequencerStageChartDescPartial sequencer_desc (sub_141D8C6D0)
//!  21. u32 raw_a
//!  22. u32 some_name            (read_u32_lookup_DA30)
//!  23. u32 lookup_b             (sub_141100370 → qword_145F113C8)
//!  24. CArray<FactionAdjacencyMobItem> mob_list (sub_141100E90)
//!  25. u32 lookup_c             (sub_141103C30 → qword_145F1A720)
//!  26. CArray<u32> list_a       (sub_1410FEF40 → qword_145F0DA30)
//!  27. CString cstring_a
//!  28. CString cstring_b
//!  29-38. 10× u8 trailing flags
//!
//! **All 363 / 363 vanilla entries (100%)** route through `Decoded`.
//! The Raw fallback path is preserved for byte-perfect resilience
//! against future builds. Tag 54 (`CheckCurrentEquipType_OrTag54`,
//! TwoU32BodyPayload) and tag 214 (`CheckExistStealItem`,
//! `ConditionData_CheckExistStealItemPayload`) — formerly the only
//! anti-disassembly blockers — were resolved via Mac-IDA in
//! `5fa0b06`.

use crate::binary::*;
use crate::binary::variants::condition_pair::ConditionPairCArray;
use crate::binary::variants::sequencer_stage_chart_desc::SequencerStageChartDescPartial;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use crate::tables::faction_node_info::info::FactionAdjacencyMobItem;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    pub struct InteractionPivotData<'a> {
        pub key: u32,
        pub tag_a: CString<'a>,
        pub vec_a: [f32; 3],
        pub tag_b: CString<'a>,
        pub vec_b: [f32; 3],
        pub tag_c: CString<'a>,
        pub vec_c: [f32; 3],
        pub tag_d: CString<'a>,
        pub vec_d: [f32; 3],
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub vec_e: [f32; 3],
        pub raw_e_3: u32,
        pub raw_f: u32,
        pub raw_f_1: u32,
        pub raw_g: u32,
        pub raw_g_1: u32,
        pub raw_h: u32,
        pub raw_i: u32,
        pub name: CString<'a>,
        pub vec_f: [f32; 3],
        pub raw_j: u32,
        pub raw_k: u64,
        pub raw_l: u64,
        pub faction_group_info: u32,
    }
}

#[derive(Debug)]
pub struct InteractionTailDecoded<'a> {
    pub cond_data_list: ConditionPairCArray<'a>,
    pub auto_interaction_type: u8,
    pub category_info: u16,
    pub input_key_map_name: u32,
    pub button_click_type: u8,
    pub keyboard_click_type: u8,
    pub unknown_flag_a: u8,
    pub unknown_flag_b: u8,
    pub unknown_flag_c: u8,
    pub unknown_flag_d: u8,
    pub sequencer_desc: SequencerStageChartDescPartial<'a>,
    pub raw_a: u32,
    pub some_name: u32,
    pub lookup_b: u32,
    pub mob_list: CArray<FactionAdjacencyMobItem>,
    pub lookup_c: u32,
    pub list_a: CArray<u32>,
    pub cstring_a: CString<'a>,
    pub cstring_b: CString<'a>,
    pub flag_a: u8,
    pub flag_b: u8,
    pub flag_c: u8,
    pub flag_d: u8,
    pub flag_e: u8,
    pub flag_f: u8,
    pub flag_g: u8,
    pub flag_h: u8,
    pub flag_i: u8,
    pub flag_j: u8,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum InteractionTail<'a> {
    Decoded(InteractionTailDecoded<'a>),
    Raw(Vec<u8>),
}

impl<'a> InteractionTail<'a> {
    fn try_read_decoded(data: &'a [u8], offset: &mut usize, end: usize) -> io::Result<InteractionTailDecoded<'a>> {
        let cond_data_list = ConditionPairCArray::read_from(data, offset)?;
        let auto_interaction_type = u8::read_from(data, offset)?;
        let category_info = u16::read_from(data, offset)?;
        let input_key_map_name = u32::read_from(data, offset)?;
        let button_click_type = u8::read_from(data, offset)?;
        let keyboard_click_type = u8::read_from(data, offset)?;
        let unknown_flag_a = u8::read_from(data, offset)?;
        let unknown_flag_b = u8::read_from(data, offset)?;
        let unknown_flag_c = u8::read_from(data, offset)?;
        let unknown_flag_d = u8::read_from(data, offset)?;
        let sequencer_desc = SequencerStageChartDescPartial::read_from(data, offset)?;
        let raw_a = u32::read_from(data, offset)?;
        let some_name = u32::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let mob_list = CArray::<FactionAdjacencyMobItem>::read_from(data, offset)?;
        let lookup_c = u32::read_from(data, offset)?;
        let list_a = CArray::<u32>::read_from(data, offset)?;
        let cstring_a = CString::read_from(data, offset)?;
        let cstring_b = CString::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let flag_c = u8::read_from(data, offset)?;
        let flag_d = u8::read_from(data, offset)?;
        let flag_e = u8::read_from(data, offset)?;
        let flag_f = u8::read_from(data, offset)?;
        let flag_g = u8::read_from(data, offset)?;
        let flag_h = u8::read_from(data, offset)?;
        let flag_i = u8::read_from(data, offset)?;
        let flag_j = u8::read_from(data, offset)?;
        if *offset != end {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("InteractionTail decoded under/over-read ({} != {})", *offset, end)));
        }
        Ok(InteractionTailDecoded {
            cond_data_list, auto_interaction_type, category_info, input_key_map_name,
            button_click_type, keyboard_click_type,
            unknown_flag_a, unknown_flag_b, unknown_flag_c, unknown_flag_d,
            sequencer_desc, raw_a, some_name, lookup_b, mob_list, lookup_c, list_a,
            cstring_a, cstring_b,
            flag_a, flag_b, flag_c, flag_d, flag_e, flag_f, flag_g, flag_h, flag_i, flag_j,
        })
    }

    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_end: usize) -> io::Result<Self> {
        let tail_start = *offset;
        let mut probe = tail_start;
        match Self::try_read_decoded(data, &mut probe, entry_end) {
            Ok(d) => {
                *offset = entry_end;
                Ok(InteractionTail::Decoded(d))
            }
            Err(_) => {
                let blob = data[tail_start..entry_end].to_vec();
                *offset = entry_end;
                Ok(InteractionTail::Raw(blob))
            }
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            InteractionTail::Decoded(d) => {
                d.cond_data_list.write_to(w)?;
                d.auto_interaction_type.write_to(w)?;
                d.category_info.write_to(w)?;
                d.input_key_map_name.write_to(w)?;
                d.button_click_type.write_to(w)?;
                d.keyboard_click_type.write_to(w)?;
                d.unknown_flag_a.write_to(w)?;
                d.unknown_flag_b.write_to(w)?;
                d.unknown_flag_c.write_to(w)?;
                d.unknown_flag_d.write_to(w)?;
                d.sequencer_desc.write_to(w)?;
                d.raw_a.write_to(w)?;
                d.some_name.write_to(w)?;
                d.lookup_b.write_to(w)?;
                d.mob_list.write_to(w)?;
                d.lookup_c.write_to(w)?;
                d.list_a.write_to(w)?;
                d.cstring_a.write_to(w)?;
                d.cstring_b.write_to(w)?;
                d.flag_a.write_to(w)?;
                d.flag_b.write_to(w)?;
                d.flag_c.write_to(w)?;
                d.flag_d.write_to(w)?;
                d.flag_e.write_to(w)?;
                d.flag_f.write_to(w)?;
                d.flag_g.write_to(w)?;
                d.flag_h.write_to(w)?;
                d.flag_i.write_to(w)?;
                d.flag_j.write_to(w)?;
                Ok(())
            }
            InteractionTail::Raw(b) => w.write_all(b),
        }
    }

    pub fn to_json_value(&self) -> Value {
        match self {
            InteractionTail::Decoded(d) => {
                let mut m = Map::new();
                m.insert("kind".to_string(), Value::String("Decoded".to_string()));
                m.insert("cond_data_list".to_string(), d.cond_data_list.to_json_value());
                m.insert("auto_interaction_type".to_string(), d.auto_interaction_type.to_json_value());
                m.insert("category_info".to_string(), d.category_info.to_json_value());
                m.insert("input_key_map_name".to_string(), d.input_key_map_name.to_json_value());
                m.insert("button_click_type".to_string(), d.button_click_type.to_json_value());
                m.insert("keyboard_click_type".to_string(), d.keyboard_click_type.to_json_value());
                m.insert("unknown_flag_a".to_string(), d.unknown_flag_a.to_json_value());
                m.insert("unknown_flag_b".to_string(), d.unknown_flag_b.to_json_value());
                m.insert("unknown_flag_c".to_string(), d.unknown_flag_c.to_json_value());
                m.insert("unknown_flag_d".to_string(), d.unknown_flag_d.to_json_value());
                m.insert("sequencer_desc".to_string(), d.sequencer_desc.to_json_value());
                m.insert("raw_a".to_string(), d.raw_a.to_json_value());
                m.insert("some_name".to_string(), d.some_name.to_json_value());
                m.insert("lookup_b".to_string(), d.lookup_b.to_json_value());
                m.insert("mob_list".to_string(), d.mob_list.to_json_value());
                m.insert("lookup_c".to_string(), d.lookup_c.to_json_value());
                m.insert("list_a".to_string(), d.list_a.to_json_value());
                m.insert("cstring_a".to_string(), d.cstring_a.to_json_value());
                m.insert("cstring_b".to_string(), d.cstring_b.to_json_value());
                m.insert("flag_a".to_string(), d.flag_a.to_json_value());
                m.insert("flag_b".to_string(), d.flag_b.to_json_value());
                m.insert("flag_c".to_string(), d.flag_c.to_json_value());
                m.insert("flag_d".to_string(), d.flag_d.to_json_value());
                m.insert("flag_e".to_string(), d.flag_e.to_json_value());
                m.insert("flag_f".to_string(), d.flag_f.to_json_value());
                m.insert("flag_g".to_string(), d.flag_g.to_json_value());
                m.insert("flag_h".to_string(), d.flag_h.to_json_value());
                m.insert("flag_i".to_string(), d.flag_i.to_json_value());
                m.insert("flag_j".to_string(), d.flag_j.to_json_value());
                Value::Object(m)
            }
            InteractionTail::Raw(b) => {
                let mut m = Map::new();
                m.insert("kind".to_string(), Value::String("Raw".to_string()));
                m.insert("_b64".to_string(), Value::String(B64.encode(b)));
                Value::Object(m)
            }
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "InteractionTail: expected object",
        ))?;
        let kind = json_get_field(obj, "kind")?
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "InteractionTail.kind: expected string"))?;
        match kind {
            "Decoded" => {
                <ConditionPairCArray as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cond_data_list")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "auto_interaction_type")?)?;
                <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "category_info")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "input_key_map_name")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "button_click_type")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "keyboard_click_type")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "unknown_flag_a")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "unknown_flag_b")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "unknown_flag_c")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "unknown_flag_d")?)?;
                <SequencerStageChartDescPartial as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sequencer_desc")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "some_name")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
                <CArray<FactionAdjacencyMobItem> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "mob_list")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
                <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "list_a")?)?;
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cstring_a")?)?;
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "cstring_b")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_d")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_e")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_f")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_g")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_h")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_i")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_j")?)?;
                Ok(())
            }
            "Raw" => {
                let b64 = json_get_field(obj, "_b64")?.as_str()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                        "InteractionTail.Raw._b64: expected string"))?;
                let bytes = B64.decode(b64).map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("InteractionTail.Raw._b64: invalid base64: {}", e)))?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("InteractionTail.kind: unknown variant {:?}", other))),
        }
    }
}

#[derive(Debug)]
pub struct InteractionInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub interaction_type: u8,
    pub interaction_show_ui_type: u8,
    pub preemption_type: u8,
    pub interaction_name: LocalizableString<'a>,
    pub pivot_selection_target: u8,
    pub interaction_pivot_list: CArray<InteractionPivotData<'a>>,
    pub tail: InteractionTail<'a>,
}

impl<'a> InteractionInfo<'a> {
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
        let interaction_type = u8::read_from(data, offset)?;
        let interaction_show_ui_type = u8::read_from(data, offset)?;
        let preemption_type = u8::read_from(data, offset)?;
        let interaction_name = LocalizableString::read_from(data, offset)?;
        let pivot_selection_target = u8::read_from(data, offset)?;
        let interaction_pivot_list = CArray::<InteractionPivotData>::read_from(data, offset)?;
        let tail = InteractionTail::read_with_size(data, offset, entry_end)?;

        Ok(Self {
            key, string_key, is_blocked, interaction_type, interaction_show_ui_type,
            preemption_type, interaction_name, pivot_selection_target,
            interaction_pivot_list, tail,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.interaction_type.write_to(w)?;
        self.interaction_show_ui_type.write_to(w)?;
        self.preemption_type.write_to(w)?;
        self.interaction_name.write_to(w)?;
        self.pivot_selection_target.write_to(w)?;
        self.interaction_pivot_list.write_to(w)?;
        self.tail.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("interaction_type".to_string(), self.interaction_type.to_json_value());
        m.insert("interaction_show_ui_type".to_string(), self.interaction_show_ui_type.to_json_value());
        m.insert("preemption_type".to_string(), self.preemption_type.to_json_value());
        m.insert("interaction_name".to_string(), self.interaction_name.to_json_value());
        m.insert("pivot_selection_target".to_string(), self.pivot_selection_target.to_json_value());
        m.insert("interaction_pivot_list".to_string(), self.interaction_pivot_list.to_json_value());
        m.insert("tail".to_string(), self.tail.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "interaction_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "interaction_show_ui_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "preemption_type")?)?;
        <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "interaction_name")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "pivot_selection_target")?)?;
        <CArray<InteractionPivotData> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "interaction_pivot_list")?)?;
        InteractionTail::write_from_json(w, json_get_field(obj, "tail")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB_PATH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\interactioninfo.pabgb";
    const PABGH_PATH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\interactioninfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        let mut decoded = 0usize;
        let mut raw = 0usize;
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = match InteractionInfo::read_with_size(&data, &mut c, e - s) {
                Ok(it) => it,
                Err(er) => {
                    let tag = crate::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|x| x.get());
                    let trail = crate::binary::variants::condition_data::TAG_TRAIL.with(|t| t.borrow().clone());
                    let trail_strs: Vec<String> = trail.iter().map(|(t, off)| format!("tag={} after_body_abs={}", t, off)).collect();
                    panic!("entry {} k=0x{:x}: {} (LAST_ATTEMPTED_TAG = {:?}, TRAIL = [{}])", i, k, er, tag, trail_strs.join(" | "));
                }
            };
            assert_eq!(c, *e);
            match &item.tail {
                InteractionTail::Decoded(_) => decoded += 1,
                InteractionTail::Raw(_) => raw += 1,
            }
            items.push(item);
        }
        eprintln!("interactioninfo: decoded={} raw={} (total={})", decoded, raw, ranges.len());
        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "interactioninfo roundtrip mismatch");
    }

    /// Diagnostic: for each Raw fallback, re-run the typed decode on the
    /// preserved raw bytes and capture the failing ConditionData tag.
    #[test]
    #[ignore]
    fn diag_raw_entries() {
        use std::collections::BTreeMap;
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut hist: BTreeMap<u16, usize> = BTreeMap::new();
        let mut count = 0usize;
        for (i, (k, _s, _e)) in ranges.iter().enumerate() {
            let mut cursor = *_s;
            let item = InteractionInfo::read_with_size(&data, &mut cursor, _e - _s).unwrap();
            if let InteractionTail::Raw(blob) = &item.tail {
                // Re-run the typed decode on these tail bytes.
                let mut probe = 0usize;
                let end = blob.len();
                crate::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|x| x.set(None));
                crate::binary::variants::condition_data::TAG_TRAIL.with(|t| t.borrow_mut().clear());
                let _ = InteractionTail::try_read_decoded(blob, &mut probe, end);
                let tag = crate::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|x| x.get());
                if let Some(t) = tag {
                    *hist.entry(t).or_insert(0) += 1;
                }
                count += 1;
                if count <= 3 {
                    let trail = crate::binary::variants::condition_data::TAG_TRAIL.with(|t| t.borrow().clone());
                    let trail_str: Vec<String> = trail.iter().map(|(t, off)| format!("{}@{}", t, off)).collect();
                    let last_off = trail.last().map(|(_, o)| *o).unwrap_or(0);
                    let next_bytes: Vec<String> = blob[last_off..(last_off + 8).min(blob.len())].iter().map(|b| format!("{:02x}", b)).collect();
                    eprintln!("entry {} k=0x{:x} LAST={:?}: TRAIL=[{}], next_bytes=[{}]", i, k, tag, trail_str.join(", "), next_bytes.join(" "));
                }
            }
        }
        eprintln!("\n=== Failure tag histogram (n={}) ===", count);
        for (tag, c) in &hist {
            eprintln!("  tag {:>4}: {} entries", tag, c);
        }
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: missing fixture {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: missing pabgh fixture {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = InteractionInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            InteractionInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
