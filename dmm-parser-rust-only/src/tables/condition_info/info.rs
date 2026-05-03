// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `ConditionInfo.pabgb`.
//!
//! Per IDA sub_1410D9F60: u32 key, CString string_key, u8 is_blocked,
//! GameCondition (sub_141CEA810 → recursive variant tree via meta-dispatcher
//! sub_141E65330), CString original_string, u8 parser_type.
//!
//! ## Status: Tier 1 — typed GameCondition, 100% round-trip
//!
//! `game_condition` is the typed `GameCondition` wrapper (Decoded|Raw enum).
//! 99.8% of entries decode into a structured tree (recursive expression
//! with 9 root cases, 405 ConditionData variants). The 0.2% that hit
//! anti-disassembly-obfuscated readers (tags 54/286), tag 272 sub_tag
//! holes, or other edge cases fall back to `Raw(Vec<u8>)` — bytes pass
//! through verbatim, round-trip stays byte-perfect.
//!
//! See `dmm-parser/src/binary/variants/game_condition.rs` for the wrapper
//! and `condition_data.rs` for the 405 variant decoders.
//!
//! ### JSON exposure
//!
//! All six fields are field-addressable. `game_condition` ships as a
//! tree-navigable object: `kind: "decoded"` exposes the recursive node
//! tree (BinaryOpA/B, UnaryOp, and per-family leaf cases with fully
//! typed `data` objects via `to_json_dict()`), plus `tail_a`/`b`/`c`
//! u8s. `kind: "raw"` exposes `raw_b64` for the 0.2% of entries that
//! hit anti-disassembly variants.
//!
//! DO NOT REGENERATE. Hand-written; bulk_process.py guards via the
//! "Hand-corrected" header marker on line 1.

use crate::binary::variant::find_cstring_u8_trailer;
use crate::binary::variants::game_condition::GameCondition;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Debug)]
pub struct ConditionInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    /// Recursive expression tree wrapper. `Decoded` for 99.8% of entries
    /// (typed access to the tree), `Raw` for the 0.2% with unknown variant
    /// recipes (still round-trips byte-perfect).
    pub game_condition: GameCondition<'a>,
    pub original_string: CString<'a>,
    pub parser_type: u8,
}

impl<'a> ConditionInfo<'a> {
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

        let post_pre = *offset;
        let variant_size = find_cstring_u8_trailer(data, post_pre, entry_end)?;
        // GameCondition::read_from assumes `data` is sized to exactly the
        // wrapper. Pass a sub-slice of just the variant bytes so the
        // Decoded|Raw fallback can detect under-consume correctly.
        let wrapper_bytes = &data[post_pre..post_pre + variant_size];
        let mut wrapper_cur = 0usize;
        let game_condition = GameCondition::read_from(wrapper_bytes, &mut wrapper_cur)?;
        *offset = post_pre + variant_size;

        let original_string = CString::read_from(data, offset)?;
        let parser_type = u8::read_from(data, offset)?;

        Ok(Self {
            key,
            string_key,
            is_blocked,
            game_condition,
            original_string,
            parser_type,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.game_condition.write_to(w)?;
        self.original_string.write_to(w)?;
        self.parser_type.write_to(w)?;
        Ok(())
    }

    /// JSON shape:
    /// - `key`, `string_key`, `is_blocked`, `original_string`, `parser_type`:
    ///   field-addressable.
    /// - `game_condition`: tree-navigable JSON. For `kind: "decoded"` it
    ///   exposes the recursive `tree` (BinaryOpA/B, UnaryOp, leaf cases
    ///   with their family name + typed `data` dict via `to_json_dict()`)
    ///   plus `tail_a`/`b`/`c` u8s. For `kind: "raw"` it exposes
    ///   `raw_b64` for the 0.2% of entries hitting anti-disassembly
    ///   variants.
    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("game_condition".to_string(), self.game_condition.to_json_value());
        m.insert("original_string".to_string(), self.original_string.to_json_value());
        m.insert("parser_type".to_string(), self.parser_type.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        GameCondition::write_from_json(w, json_get_field(obj, "game_condition")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "original_string")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "parser_type")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str =
        r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\conditioninfo.pabgb";
    const PABGH_PATH: &str =
        r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\conditioninfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing pabgb fixture {}", PABGB_PATH);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
            eprintln!("SKIP: missing/unparseable pabgh fixture {}", PABGH_PATH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        let mut decoded = 0usize;
        let mut raw = 0usize;
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = ConditionInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| {
                    panic!(
                        "parse failed at entry {} (key=0x{:x}, offset 0x{:x}, size {}): {}",
                        i,
                        key,
                        start,
                        end - start,
                        e
                    )
                });
            assert_eq!(
                cursor, *end,
                "entry {} (key 0x{:x}) under/over-consumed: read {} bytes, expected {}",
                i,
                key,
                cursor - start,
                end - start
            );
            match &item.game_condition {
                crate::binary::variants::game_condition::GameCondition::Decoded { .. } => decoded += 1,
                crate::binary::variants::game_condition::GameCondition::Raw(_) => raw += 1,
            }
            items.push(item);
        }
        eprintln!("conditioninfo: decoded={} raw={} (total={})", decoded, raw, ranges.len());

        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out.len(), data.len(), "conditioninfo roundtrip size mismatch");
        assert_eq!(out, data, "conditioninfo roundtrip bytes mismatch");
    }

    /// Diagnostic: for each `GameCondition::Raw` fallback, re-run the
    /// typed decode and capture the failing ConditionData tag. Prints
    /// a histogram so each remaining Raw entry can be traced back to
    /// the variant family that under/over-read.
    #[test]
    #[ignore]
    fn diag_raw_entries() {
        use std::collections::BTreeMap;
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut hist: BTreeMap<u16, usize> = BTreeMap::new();
        let mut count = 0usize;
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut cursor = *s;
            let item = ConditionInfo::read_with_size(&data, &mut cursor, e - s).unwrap();
            if let crate::binary::variants::game_condition::GameCondition::Raw(blob) = &item.game_condition {
                let mut probe = 0usize;
                let end = blob.len();
                crate::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|x| x.set(None));
                crate::binary::variants::condition_data::TAG_TRAIL.with(|t| t.borrow_mut().clear());
                let _ = (|| -> io::Result<()> {
                    let _tree = crate::binary::variants::game_condition::GameConditionNode::read_from(blob, &mut probe)?;
                    let _ta = u8::read_from(blob, &mut probe)?;
                    let _tb = u8::read_from(blob, &mut probe)?;
                    let _tc = u8::read_from(blob, &mut probe)?;
                    if probe != end { return Err(io::Error::new(io::ErrorKind::InvalidData, "under-consume")); }
                    Ok(())
                })();
                let tag = crate::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|x| x.get());
                if let Some(t) = tag { *hist.entry(t).or_insert(0) += 1; }
                count += 1;
                if count <= 16 {
                    let trail = crate::binary::variants::condition_data::TAG_TRAIL.with(|t| t.borrow().clone());
                    let trail_str: Vec<String> = trail.iter().map(|(t, off)| format!("{}@{}", t, off)).collect();
                    let last_off = trail.last().map(|(_, o)| *o).unwrap_or(0);
                    let next_bytes: Vec<String> = blob[last_off..(last_off + 12).min(blob.len())].iter().map(|b| format!("{:02x}", b)).collect();
                    let head_bytes: Vec<String> = blob[..16.min(blob.len())].iter().map(|b| format!("{:02x}", b)).collect();
                    eprintln!("entry {} k=0x{:x} blob_len={} LAST={:?}: TRAIL=[{}], head=[{}], next_bytes=[{}]",
                        i, k, blob.len(), tag, trail_str.join(", "), head_bytes.join(" "), next_bytes.join(" "));
                }
            }
        }
        eprintln!("\n=== Failure tag histogram (n={}) ===", count);
        for (tag, c) in &hist { eprintln!("  tag {:>4}: {} entries", tag, c); }
    }

    /// JSON dict round-trip — typed write_to bytes must match
    /// write_from_json_dict bytes for every entry. Validates the
    /// tree-navigable GameCondition JSON shape preserves bytes.
    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing pabgb fixture");
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
            eprintln!("SKIP: missing pabgh fixture");
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = ConditionInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            ConditionInfo::write_from_json_dict(&mut from_json, &dict).unwrap_or_else(|e| {
                panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e)
            });
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, key,
            );
        }
    }
}
