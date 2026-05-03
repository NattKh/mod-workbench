// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: typed prefix + GlobalGameEventExecuteData wrapper.
//!
//! Reader: `sub_1410E5840` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u16 key                              (_key, pabgh format 2)
//!   2. CString string_key                   (_stringKey)
//!   3. u8 is_blocked                        (_isBlocked)
//!   4. u16 global_game_event_group_info     (_globalGameEventGroupInfo,
//!      inline u16 hash-key at qword_145F0E9C8)
//!   5. _executeData (sub_141156680 → POLYMORPHIC family
//!      `GlobalGameEventExecuteData` with sub_tag dispatch:
//!      0=VaryTradeItemPrice [88B], 1=OpenRoyalSupply [32B], 2=in-place,
//!      0=absent presence byte → no-op)
//!
//! ## Tier 1 — typed wrapper, byte-perfect round-trip
//!
//! `execute_data` uses the typed `Decoded(Body) | Raw` enum from
//! `crate::binary::variants::global_game_event_execute_data`. Per-sub_tag
//! payloads are field-level typed (CArray<u16>, items, lookup, description),
//! so the JSON shape exposes editable fields rather than just an opaque
//! `_execute_data_b64` blob. Raw is the verbatim-bytes fallback for any
//! decode failure or sub_tag the typed path doesn't recognize.
//!
//! DO NOT REGENERATE. Hand-written; bulk_process.py guards via the
//! "Hand-corrected" header marker on line 1.

use crate::binary::variants::global_game_event_execute_data::GlobalGameEventExecuteData;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct GlobalGameEventInfo<'a> {
    pub key: u16,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub global_game_event_group_info: u16,
    /// Polymorphic execute_data wrapper. Decoded captures presence +
    /// sub_tag + typed body fields; Raw passes through verbatim. Either
    /// way, round-trip is byte-perfect.
    pub execute_data: GlobalGameEventExecuteData<'a>,
}

impl<'a> GlobalGameEventInfo<'a> {
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
        let global_game_event_group_info = u16::read_from(data, offset)?;

        // GlobalGameEventExecuteData::read_from expects `data` sized to
        // exactly the wrapper. Pass a sub-slice of just the tail bytes.
        let wrapper_bytes = &data[*offset..entry_end];
        let mut wrapper_cur = 0usize;
        let execute_data = GlobalGameEventExecuteData::read_from(wrapper_bytes, &mut wrapper_cur)?;
        *offset = entry_end;

        Ok(Self {
            key,
            string_key,
            is_blocked,
            global_game_event_group_info,
            execute_data,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.global_game_event_group_info.write_to(w)?;
        self.execute_data.write_to(w)?;
        Ok(())
    }

    /// JSON shape:
    /// - Scalars (`key`, `string_key`, `is_blocked`,
    ///   `global_game_event_group_info`): individually editable.
    /// - `execute_data`: typed object with `kind` + sub_tag-specific
    ///   `body` fields (or `raw_b64` for the Raw fallback). See
    ///   `GlobalGameEventExecuteData::to_json_value` for the per-variant
    ///   schema.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert(
            "global_game_event_group_info".to_string(),
            self.global_game_event_group_info.to_json_value(),
        );
        m.insert("execute_data".to_string(), self.execute_data.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u16 as WriteJsonValue>::write_from_json(
            w,
            json_get_field(obj, "global_game_event_group_info")?,
        )?;
        GlobalGameEventExecuteData::write_from_json(w, json_get_field(obj, "execute_data")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    use crate::binary::variants::global_game_event_execute_data::GlobalGameEventExecuteDataBody;
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalgameevent.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\globalgameevent.pabgh";

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
                GlobalGameEventInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items {
            it.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "globalgameevent roundtrip mismatch");
    }

    /// Sanity check: most entries should be Decoded (Absent/Present), not Raw.
    /// Raw is the byte-perfect fallback but we expect the dispatcher
    /// recipe to handle the common case cleanly.
    #[test]
    fn execute_data_kinds() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        let mut absent = 0;
        let mut sub_tag_0 = 0;
        let mut sub_tag_1 = 0;
        let mut sub_tag_2 = 0;
        let mut raw = 0;
        for (_k, s, e) in ranges.iter() {
            let mut c = *s;
            let it = GlobalGameEventInfo::read_with_size(&data, &mut c, e - s).unwrap();
            match &it.execute_data {
                GlobalGameEventExecuteData::Absent => absent += 1,
                GlobalGameEventExecuteData::Present(body) => match body {
                    GlobalGameEventExecuteDataBody::VaryTradeItemPrice(_) => sub_tag_0 += 1,
                    GlobalGameEventExecuteDataBody::OpenRoyalSupply(_) => sub_tag_1 += 1,
                    GlobalGameEventExecuteDataBody::InPlace => sub_tag_2 += 1,
                },
                GlobalGameEventExecuteData::Raw(_) => raw += 1,
            }
        }
        eprintln!(
            "globalgameevent execute_data: absent={} sub_tag_0={} sub_tag_1={} sub_tag_2={} raw={}",
            absent, sub_tag_0, sub_tag_1, sub_tag_2, raw,
        );
    }

    /// Sanity: confirm min_price ≤ max_price across every typed item.
    /// Justifies the field naming (`_minPrice`/`_maxPrice` from Mac-binary
    /// reflection metadata).
    #[test]
    fn price_ordering_invariant() {
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        let mut checked = 0;
        for (k, s, e) in ranges.iter() {
            let mut c = *s;
            let it = GlobalGameEventInfo::read_with_size(&data, &mut c, e - s).unwrap();
            if let GlobalGameEventExecuteData::Present(
                GlobalGameEventExecuteDataBody::VaryTradeItemPrice(p),
            ) = &it.execute_data
            {
                for (i, item) in p.price_list.items.iter().enumerate() {
                    assert!(
                        item.min_price <= item.max_price,
                        "k=0x{:x} item[{}]: min={} > max={}",
                        k, i, item.min_price, item.max_price,
                    );
                    checked += 1;
                }
            }
        }
        eprintln!("checked min_price ≤ max_price across {} items", checked);
    }

    /// Round-trip through the JSON dict bridge — must match the typed
    /// byte output exactly. Catches any divergence between
    /// `to_json_dict`/`write_from_json_dict` and the binary path.
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
            let item = GlobalGameEventInfo::read_with_size(&data, &mut c, e - s).unwrap();
            let dict = item.to_json_dict();
            let mut typed = Vec::new();
            item.write_to(&mut typed).unwrap();
            let mut from_json = Vec::new();
            GlobalGameEventInfo::write_from_json_dict(&mut from_json, &dict).unwrap_or_else(|er| {
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
