// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Variant validator for BuffData. Iterates every BuffInfo entry's
//! buff_data_list, attempts to parse each BuffDataEntry, and reports which
//! variants successfully decoded vs which had byte-count mismatches.
//!
//! Drop-in test (#[test] fn validate_buffdata) — run with:
//!   cargo test --release --features dev validate_buffdata -- --nocapture

#![cfg(test)]

use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
use crate::binary::variants::buff_data::BuffData;
use crate::binary::*;
use std::collections::BTreeMap;

const PABGB_PATH: &str =
    r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\buffinfo.pabgb";
const PABGH_PATH: &str =
    r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\buffinfo.pabgh";

/// Tail layout (post buff_data_list) per sub_1410D6510:
///   u32 min_level (4) + u32 max_level (4) + CString sequencer_file_name +
///   u8 + u32 + u32 + u32 + u8 + u8
/// Fixed bytes = 4+4+4+1+4+4+4+1+1 = 27
const POST_TAIL_FIXED: usize = 27;

/// Validate that bytes at [probe..entry_end] form a valid post-tail (matches
/// the BuffInfo post-list schema). Returns true if so.
fn is_valid_post_tail(data: &[u8], probe: usize, entry_end: usize) -> bool {
    if probe + POST_TAIL_FIXED > entry_end {
        return false;
    }
    let cs_off = probe + 8;
    let Some(cs_len_bytes) = data.get(cs_off..cs_off + 4) else { return false };
    let Ok(cs_len_arr) = cs_len_bytes.try_into() else { return false };
    let cs_len = u32::from_le_bytes(cs_len_arr) as usize;
    let total = POST_TAIL_FIXED + cs_len;
    if probe + total != entry_end {
        return false;
    }
    let cs_content_start = cs_off + 4;
    let cs_content_end = cs_content_start + cs_len;
    let Some(cs_bytes) = data.get(cs_content_start..cs_content_end) else { return false };
    std::str::from_utf8(cs_bytes).is_ok()
}

#[test]
fn validate_buffdata_manifest() {
    let Ok(data) = std::fs::read(PABGB_PATH) else {
        eprintln!("SKIP: missing fixture");
        return;
    };
    let Some(entries) = load_pabgh_offsets(PABGH_PATH) else {
        eprintln!("SKIP: missing pabgh");
        return;
    };
    let ranges = entry_ranges(&entries, data.len());

    // Stats per variant tag:
    let mut tag_seen: BTreeMap<u8, usize> = BTreeMap::new();
    let mut tag_passed: BTreeMap<u8, usize> = BTreeMap::new();
    let mut tag_failed: BTreeMap<u8, Vec<(u32, String)>> = BTreeMap::new();
    let mut tag_byte_counts: BTreeMap<u8, Vec<usize>> = BTreeMap::new();

    let mut entries_clean: usize = 0;
    let mut entries_dirty: usize = 0;
    let mut entries_post_tail_invalid: usize = 0;

    for (key, start, end) in &ranges {
        // Read pre-fields manually to find buff_data_list start.
        let mut o = *start;
        let _key = u32::read_from(&data, &mut o).unwrap();
        let _string_key = CString::read_from(&data, &mut o).unwrap();
        let _is_blocked = u8::read_from(&data, &mut o).unwrap();

        // Read the CArray<BuffDataEntry> count
        let count = u32::read_from(&data, &mut o).unwrap() as usize;

        // PARSE-FIRST APPROACH: parse all elements per the manifest and treat
        // the resulting cursor as the proposed list_end. Then verify the
        // post-tail is valid at that position. This avoids the
        // probe-finds-wrong-boundary issue when multiple valid post-tail
        // positions exist.

        let mut tag_sequence: Vec<u8> = Vec::with_capacity(count);
        let mut entry_had_failure = false;

        for elem_idx in 0..count {
            // Each entry: u32 leading + u8 absent + (if present) BuffData
            if o + 5 > *end {
                tag_failed.entry(0).or_insert_with(Vec::new).push((*key,
                    format!("list overflow: cursor 0x{:x} +5 > entry_end 0x{:x} at elem #{} (seq {:?})",
                        o, *end, elem_idx, tag_sequence)));
                entry_had_failure = true;
                break;
            }
            let _leading = u32::read_from(&data, &mut o).unwrap();
            let absent = u8::read_from(&data, &mut o).unwrap();
            if absent != 0 {
                continue;
            }
            // peek tag
            let tag_offset = o;
            let tag = data[o];
            tag_sequence.push(tag);
            *tag_seen.entry(tag).or_insert(0) += 1;
            // try to parse
            let pre_o = o;
            match BuffData::read_from(&data, &mut o) {
                Ok(_) => {
                    *tag_passed.entry(tag).or_insert(0) += 1;
                    let consumed = o - pre_o;
                    tag_byte_counts.entry(tag).or_insert_with(Vec::new).push(consumed);
                }
                Err(e) => {
                    tag_failed.entry(tag).or_insert_with(Vec::new).push((*key,
                        format!("at off 0x{:x} (tag@0x{:x}): {} | seq before: {:?}",
                            pre_o, tag_offset, e, &tag_sequence[..tag_sequence.len() - 1])));
                    entry_had_failure = true;
                    break;
                }
            }
            // Validate we didn't overshoot the entry
            if o > *end {
                let overshoot = o - *end;
                tag_failed.entry(tag).or_insert_with(Vec::new).push((*key,
                    format!("tag {} overshot entry_end by {} bytes (seq: {:?})", tag, overshoot, tag_sequence)));
                entry_had_failure = true;
                break;
            }
        }

        if entry_had_failure {
            entries_dirty += 1;
            continue;
        }

        // After parsing, cursor should land exactly at the start of post-tail.
        // Validate the post-tail at this position.
        let proposed_list_end = o;
        if !is_valid_post_tail(&data, proposed_list_end, *end) {
            entries_post_tail_invalid += 1;
            // Search for the nearest VALID post-tail position to identify drift
            let mut found_offsets: Vec<usize> = Vec::new();
            let search_min = proposed_list_end.saturating_sub(64);
            let search_max = (proposed_list_end + 64).min(*end);
            for p in search_min..=search_max {
                if is_valid_post_tail(&data, p, *end) {
                    found_offsets.push(p);
                }
            }
            let last_tag = tag_sequence.last().copied().unwrap_or(0);
            let drift_msg = if found_offsets.is_empty() {
                format!("no valid post-tail nearby; cursor=0x{:x}, entry_end=0x{:x}", proposed_list_end, *end)
            } else {
                let drifts: Vec<isize> = found_offsets.iter()
                    .map(|p| *p as isize - proposed_list_end as isize)
                    .collect();
                format!("post-tail invalid; cursor=0x{:x}, valid offsets at drifts={:?}", proposed_list_end, drifts)
            };
            tag_failed.entry(last_tag).or_insert_with(Vec::new).push((*key,
                format!("{} | seq: {:?}", drift_msg, tag_sequence)));
            entries_dirty += 1;
        } else {
            entries_clean += 1;
        }
    }

    eprintln!("\n=== BuffData manifest validation ===");
    eprintln!("Variant | Seen | Passed | Failed | min/max bytes (per call)");
    eprintln!("--------|------|--------|--------|------------------------");
    for (tag, count) in &tag_seen {
        let passed = tag_passed.get(tag).copied().unwrap_or(0);
        let failed = tag_failed.get(tag).map(|v| v.len()).unwrap_or(0);
        let bc = tag_byte_counts.get(tag);
        let (min_b, max_b) = match bc {
            Some(v) if !v.is_empty() => (*v.iter().min().unwrap(), *v.iter().max().unwrap()),
            _ => (0, 0),
        };
        eprintln!("  {:3}   | {:4} | {:6} | {:5}  | {:5}..{:<5}", tag, count, passed, failed, min_b, max_b);
    }
    eprintln!();
    eprintln!("Total tags seen: {}", tag_seen.len());
    eprintln!(
        "Total entries parsed: {} passed / {} failed (entries: {} clean / {} dirty / {} post-tail invalid)",
        tag_passed.values().sum::<usize>(),
        tag_failed.values().map(|v| v.len()).sum::<usize>(),
        entries_clean,
        entries_dirty,
        entries_post_tail_invalid,
    );

    if !tag_failed.is_empty() {
        eprintln!("\n=== Failed variants (showing first 4 per tag) ===");
        for (tag, failures) in &tag_failed {
            eprintln!("  Tag {} ({} failures):", tag, failures.len());
            for (key, msg) in failures.iter().take(4) {
                eprintln!("    key=0x{:x}: {}", key, msg);
            }
        }
    }
}
