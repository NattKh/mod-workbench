// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Diagnostic tool: walks every ConditionInfo entry's GameCondition tree,
//! records actual byte consumption per ConditionData tag, and writes a
//! corrections.json proposal for variants whose recipe `tail_bytes` is wrong.
//!
//! Run with:
//!   cargo test --release diagnose_conditiondata_variants -- --nocapture
//!
//! This test is expected to "pass" after writing diagnostic output; it does
//! NOT enforce round-trip (that's what `tables::condition_info::tests::roundtrip`
//! does).

#![cfg(test)]

use crate::binary::variant::{entry_ranges, find_cstring_u8_trailer, load_pabgh_offsets};
use crate::binary::*;
use std::collections::BTreeMap;

const PABGB_PATH: &str =
    r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\conditioninfo.pabgb";
const PABGH_PATH: &str =
    r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\conditioninfo.pabgh";

/// One walk of the GameCondition blob, recording byte counts per ConditionData tag.
/// Returns Ok with the cursor position if the walk completed without overshooting
/// the blob_end. Aborts on first error.
fn walk_blob(
    data: &[u8],
    start: usize,
    end: usize,
    tag_byte_counts: &mut BTreeMap<u16, Vec<usize>>,
    case_byte_counts: &mut BTreeMap<u8, Vec<usize>>,
) -> Result<usize, String> {
    let mut cursor = start;
    walk_node(data, &mut cursor, end, tag_byte_counts, case_byte_counts)?;
    Ok(cursor)
}

fn walk_node(
    data: &[u8],
    cursor: &mut usize,
    end: usize,
    tag_byte_counts: &mut BTreeMap<u16, Vec<usize>>,
    case_byte_counts: &mut BTreeMap<u8, Vec<usize>>,
) -> Result<(), String> {
    if *cursor >= end {
        return Err(format!("walk_node: cursor {} past end {}", cursor, end));
    }
    let case_tag = data[*cursor];
    let node_start = *cursor;
    *cursor += 1;
    match case_tag {
        0 | 1 => {
            walk_node(data, cursor, end, tag_byte_counts, case_byte_counts)?;
            walk_node(data, cursor, end, tag_byte_counts, case_byte_counts)?;
        }
        2 => {
            walk_node(data, cursor, end, tag_byte_counts, case_byte_counts)?;
        }
        3 => {
            // ConditionData: u16 tag + variable-size body. We don't know body size,
            // so we have to BOUND-ANALYZE: this case ends right before the next
            // recognizable case_tag OR at end.
            //
            // Heuristic for diagnostic: assume this ConditionData node consumes
            // until the end of the blob (only useful if it's the only node).
            // For multi-node trees, we need the actual recipe.
            if *cursor + 2 > end {
                return Err(format!("ConditionData: not enough data for u16 tag at {}", cursor));
            }
            let tag = u16::from_le_bytes([data[*cursor], data[*cursor + 1]]);
            *cursor += 2;
            // Without a recipe, we can't advance further safely. Leave cursor at
            // start of variant body so caller can compute "remaining bytes assigned
            // to this tag".
            let remaining = end - *cursor;
            tag_byte_counts.entry(tag).or_insert_with(Vec::new).push(remaining);
            *cursor = end; // claim all remaining
        }
        4 => {
            // BranchConditionData: u8 tag + 3 base bytes + variant body
            // Similar problem — record remaining and consume.
            if *cursor >= end {
                return Err(format!("BranchConditionData: no data at {}", cursor));
            }
            let _btag = data[*cursor];
            // Without a recipe, assume rest of blob.
            let remaining = end - *cursor;
            *cursor = end;
            case_byte_counts.entry(4).or_insert_with(Vec::new).push(remaining);
            return Ok(());
        }
        5 => {
            // ScheduleComplete: u8 + (cstring + u8 + u64 + u8 + u8 if 0)
            if *cursor >= end {
                return Err("case 5: no data".to_string());
            }
            let presence = data[*cursor];
            *cursor += 1;
            if presence == 0 {
                let _label = CString::read_from(data, cursor)
                    .map_err(|e| format!("case 5 label: {}", e))?;
                if *cursor + 11 > end {
                    return Err("case 5: not enough for tail".to_string());
                }
                *cursor += 11;
            }
            let consumed = *cursor - node_start;
            case_byte_counts.entry(5).or_insert_with(Vec::new).push(consumed);
        }
        6 => {
            if *cursor + 4 > end {
                return Err("case 6: not enough for u32".to_string());
            }
            *cursor += 4;
            case_byte_counts.entry(6).or_insert_with(Vec::new).push(5);
        }
        7 => {
            if *cursor >= end {
                return Err("case 7: no data".to_string());
            }
            let outer = data[*cursor];
            *cursor += 1;
            if outer != 0 {
                let _label = CString::read_from(data, cursor)
                    .map_err(|e| format!("case 7A cstring: {}", e))?;
                if *cursor + 9 > end {
                    return Err("case 7A: not enough for u8+u64".to_string());
                }
                *cursor += 9;
                walk_game_expression(data, cursor, end)?;
            } else {
                if *cursor >= end {
                    return Err("case 7B: no selector".to_string());
                }
                let selector = data[*cursor];
                *cursor += 1;
                walk_ivariant(data, cursor, end, selector)?;
            }
            let consumed = *cursor - node_start;
            case_byte_counts.entry(7).or_insert_with(Vec::new).push(consumed);
        }
        8 => {
            if *cursor + 6 > end {
                return Err("case 8: not enough for u32+u8+u8".to_string());
            }
            *cursor += 6;
            case_byte_counts.entry(8).or_insert_with(Vec::new).push(7);
        }
        other => return Err(format!("unknown case tag {} at offset {}", other, node_start)),
    }
    Ok(())
}

fn walk_game_expression(data: &[u8], cursor: &mut usize, end: usize) -> Result<(), String> {
    if *cursor >= end {
        return Err("GE: no data".into());
    }
    let outer = data[*cursor];
    *cursor += 1;
    if outer == 0 {
        return Ok(());
    }
    if *cursor >= end {
        return Err("GE: no inner".into());
    }
    let inner = data[*cursor];
    *cursor += 1;
    match inner {
        0 => {
            if *cursor >= end { return Err("GE0".into()); }
            *cursor += 1;
            walk_game_expression(data, cursor, end)?;
        }
        1 => {
            walk_game_expression(data, cursor, end)?;
            walk_game_expression(data, cursor, end)?;
            if *cursor >= end { return Err("GE1".into()); }
            *cursor += 1;
        }
        2 => {
            walk_game_expression(data, cursor, end)?;
            if *cursor + 8 > end { return Err("GE2".into()); }
            *cursor += 4;
            let n = u32::from_le_bytes([data[*cursor], data[*cursor+1], data[*cursor+2], data[*cursor+3]]) as usize;
            *cursor += 4;
            for _ in 0..n {
                walk_game_expression(data, cursor, end)?;
            }
        }
        3 => {
            if *cursor >= end { return Err("GE3".into()); }
            *cursor += 1;
        }
        4 => {
            if *cursor >= end { return Err("GE4".into()); }
            let p = data[*cursor];
            *cursor += 1;
            if p != 0 {
                if *cursor >= end { return Err("GE4 kind".into()); }
                let kind = data[*cursor];
                *cursor += 1;
                match kind {
                    0 => { if *cursor >= end { return Err("GE4 u8".into()); } *cursor += 1; }
                    1 => { if *cursor + 4 > end { return Err("GE4 u32".into()); } *cursor += 4; }
                    2 => { let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?; }
                    _ => {}
                }
            }
        }
        5 => {
            if *cursor >= end { return Err("GE5".into()); }
            let p = data[*cursor];
            *cursor += 1;
            if p != 0 {
                let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
                let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
            }
        }
        6 => {
            let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown GE inner tag {}", other)),
    }
    Ok(())
}

fn walk_ivariant(data: &[u8], cursor: &mut usize, end: usize, tag: u8) -> Result<(), String> {
    match tag {
        0 | 2 | 3 | 4 | 5 | 14 | 15 | 16 | 17 | 18 => Ok(()),
        1 | 6 | 11 => {
            let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
            Ok(())
        }
        7 | 10 => {
            let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
            let _ = CString::read_from(data, cursor).map_err(|e| e.to_string())?;
            Ok(())
        }
        8 => {
            if *cursor + 12 > end { return Err("IV8".into()); }
            *cursor += 12;
            Ok(())
        }
        9 => {
            if *cursor + 8 > end { return Err("IV9".into()); }
            *cursor += 8;
            Ok(())
        }
        12 => {
            if *cursor + 5 > end { return Err("IV12".into()); }
            *cursor += 5;
            Ok(())
        }
        13 | 19 => {
            if *cursor + 4 > end { return Err("IV13/19".into()); }
            *cursor += 4;
            Ok(())
        }
        other => Err(format!("unknown IVariant tag {}", other)),
    }
}

#[test]
fn diagnose_conditiondata_variants() {
    let Ok(data) = std::fs::read(PABGB_PATH) else {
        eprintln!("SKIP: missing {}", PABGB_PATH);
        return;
    };
    let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
        eprintln!("SKIP: missing pabgh");
        return;
    };
    let ranges = entry_ranges(&entries, data.len());

    let mut tag_byte_counts: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    let mut case_byte_counts: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    let mut entries_walked_clean = 0usize;
    let mut entries_walk_err = 0usize;
    let mut first_err = String::new();

    let mut blob_size_per_case_only: BTreeMap<u8, Vec<usize>> = BTreeMap::new();

    for (_i, (_key, start, end)) in ranges.iter().enumerate() {
        let mut cursor = *start;
        // Skip pre-fields: u32 + cstring + u8
        cursor += 4;
        let cs_len = u32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]) as usize;
        cursor += 4 + cs_len + 1;
        let blob_start = cursor;
        let Ok(blob_size) = find_cstring_u8_trailer(&data, blob_start, *end) else {
            entries_walk_err += 1;
            continue;
        };
        let blob_end = blob_start + blob_size;

        // Record blob_size when it consists of a single case (peek first byte).
        if blob_size > 0 {
            let case0 = data[blob_start];
            blob_size_per_case_only.entry(case0).or_insert_with(Vec::new).push(blob_size);
        }

        match walk_blob(&data, blob_start, blob_end, &mut tag_byte_counts, &mut case_byte_counts) {
            Ok(consumed) => {
                if consumed == blob_end {
                    entries_walked_clean += 1;
                } else {
                    entries_walk_err += 1;
                    if first_err.is_empty() {
                        first_err = format!("under-consume: cursor={} blob_end={}", consumed, blob_end);
                    }
                }
            }
            Err(e) => {
                entries_walk_err += 1;
                if first_err.is_empty() {
                    first_err = e;
                }
            }
        }
    }

    eprintln!("\n=== ConditionData walk diagnostics ===");
    eprintln!("Entries walked clean: {}", entries_walked_clean);
    eprintln!("Entries with walk err: {}", entries_walk_err);
    if !first_err.is_empty() {
        eprintln!("First err: {}", first_err);
    }

    eprintln!("\n=== blob size by first case tag ===");
    for (case, sizes) in &blob_size_per_case_only {
        let min = *sizes.iter().min().unwrap_or(&0);
        let max = *sizes.iter().max().unwrap_or(&0);
        eprintln!("  case {}: {} entries, size range {}..{}", case, sizes.len(), min, max);
    }

    eprintln!("\n=== ConditionData tag observations (single-leaf entries) ===");
    eprintln!("(Note: 'remaining bytes after u16 tag' is the variant body + optional subcond combined)");
    eprintln!("Tag | count | min | max | unique-sizes");
    for (tag, sizes) in &tag_byte_counts {
        let min = *sizes.iter().min().unwrap();
        let max = *sizes.iter().max().unwrap();
        let mut unique: Vec<_> = sizes.iter().copied().collect();
        unique.sort_unstable();
        unique.dedup();
        let unique_str = if unique.len() <= 5 {
            format!("{:?}", unique)
        } else {
            format!("{} unique values", unique.len())
        };
        eprintln!("  {:5} | {:5} | {:3} | {:3} | {}", tag, sizes.len(), min, max, unique_str);
    }

    // Write a JSON corrections proposal alongside the recipes.
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"_meta\": {\n");
    json.push_str("    \"description\": \"Empirical observations from walking real ConditionInfo data. For each ConditionData tag, the byte count of variant body + optional subcond. Single-unique-value tags are CONSTANT (safe to set tail_bytes directly). Multi-unique-value tags are VARIABLE (have internal CString/CArray; need per-variant IDA decompile).\",\n");
    json.push_str(&format!("    \"entries_walked_clean\": {},\n", entries_walked_clean));
    json.push_str(&format!("    \"entries_walk_err\": {},\n", entries_walk_err));
    json.push_str(&format!("    \"total_entries\": {}\n", ranges.len()));
    json.push_str("  },\n");
    json.push_str("  \"observations\": {\n");
    let mut first = true;
    for (tag, sizes) in &tag_byte_counts {
        let min = *sizes.iter().min().unwrap();
        let max = *sizes.iter().max().unwrap();
        let mut unique: Vec<_> = sizes.iter().copied().collect();
        unique.sort_unstable();
        unique.dedup();
        let kind = if unique.len() == 1 { "CONSTANT" } else { "VARIABLE" };
        if !first { json.push_str(",\n"); }
        first = false;
        json.push_str(&format!(
            "    \"{}\": {{ \"count\": {}, \"min\": {}, \"max\": {}, \"unique_sizes\": {:?}, \"kind\": \"{}\" }}",
            tag, sizes.len(), min, max, unique, kind
        ));
    }
    json.push_str("\n  }\n}\n");
    let out_path = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\mac_extract\conditiondata_empirical_observations.json";
    if let Err(e) = std::fs::write(out_path, &json) {
        eprintln!("\nWARNING: failed to write {}: {}", out_path, e);
    } else {
        eprintln!("\nWrote empirical observations to {}", out_path);
    }
}
