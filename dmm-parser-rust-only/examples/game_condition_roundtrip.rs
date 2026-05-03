// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Round-trip validator for the typed GameCondition decoder.
//!
//! For each ConditionInfo entry's GameCondition blob:
//!   1. Read with GameConditionNode::read_from
//!   2. Write back with GameConditionNode::write_to
//!   3. Byte-compare against original
//!
//! Reports per-tag pass/fail counts so we know which ConditionData variants
//! still have wrong byte recipes.

use dmm_parser::binary::variants::game_condition::GameCondition;
use dmm_parser::binary::variant::{entry_ranges, find_cstring_u8_trailer, load_pabgh_offsets};
use std::collections::BTreeMap;
use std::path::Path;

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\conditioninfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\conditioninfo.pabgh";

fn main() {
    let data = std::fs::read(Path::new(PABGB)).unwrap();
    let entries = load_pabgh_offsets(PABGH).unwrap();
    let ranges = entry_ranges(&entries, data.len());
    println!("ConditionInfo: {} entries", ranges.len());

    // Each ConditionInfo entry layout:
    //   u32 key, CString string_key, u8 is_blocked, GameCondition blob,
    //   CString original_string, u8 parser_type
    // The GameCondition blob runs from end-of-(key/string_key/is_blocked)
    // to start-of-(original_string/parser_type). We use find_cstring_u8_trailer
    // to find where the trailing CString starts.

    let mut total = 0usize;
    let mut decode_ok = 0usize;
    let mut decode_err = 0usize;
    let mut roundtrip_ok = 0usize;
    let mut roundtrip_mismatch = 0usize;
    let mut mismatch_examples: Vec<(u32, usize, usize)> = Vec::new();
    // Capture full hex of the first 5 case-3 mismatches for inspection.
    // Each entry: (key, vanilla_blob, our_buf, parse_cursor, tag)
    let mut case3_dumps: Vec<(u32, Vec<u8>, Vec<u8>, usize, u16)> = Vec::new();
    let mut case_other_dumps: Vec<(u32, Vec<u8>, Vec<u8>, usize, u8)> = Vec::new();
    // Tag → count of decode failures attributed (last-attempted tag at err)
    let mut failing_tag_stats: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    // Optional per-tag focus: dump only mismatches for these specific u16 tags.
    // Empty = no filter. Set via env var GC_DUMP_TAG (single tag, decimal).
    let dump_tag_filter: Option<u16> = std::env::var("GC_DUMP_TAG").ok()
        .and_then(|s| s.parse::<u16>().ok());
    // GC_DUMP_TAGS=15,31,113,214 — multi-tag filter for batch inspection
    let dump_tag_filters: Vec<u16> = std::env::var("GC_DUMP_TAGS")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse::<u16>().ok()).collect())
        .unwrap_or_default();
    let dump_per_tag = std::env::var("GC_DUMP_PER_TAG").ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);
    let mut dump_count_per_tag: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();

    // Track per-root-case tag: total / pass / fail
    let mut case_stats: BTreeMap<u8, (usize, usize, usize)> = BTreeMap::new();
    // For case=3 (ConditionData) entries: per-u16-tag (rt_pass, rt_fail, decode_err)
    let mut cdata_tag_stats: BTreeMap<u16, (usize, usize, usize)> = BTreeMap::new();

    for (k, s, e) in &ranges {
        total += 1;
        // Skip prefix: u32 key, CString string_key, u8 is_blocked (matches diagnose_conditiondata)
        let mut cursor = *s + 4;
        let cs_len = u32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]) as usize;
        cursor += 4 + cs_len + 1;
        let blob_start = cursor;
        let blob_size = match find_cstring_u8_trailer(&data, blob_start, *e) {
            Ok(sz) => sz,
            Err(_) => { decode_err += 1; continue; }
        };
        let blob_end = blob_start + blob_size;
        if blob_end <= blob_start {
            decode_err += 1;
            continue;
        }
        let blob = &data[blob_start..blob_end];

        // Capture root case_tag for stats
        let root_case = blob.first().copied().unwrap_or(255);
        let entry = case_stats.entry(root_case).or_insert((0, 0, 0));
        entry.0 += 1;
        // For case=3 (ConditionData root), peek the u16 tag at bytes [1..3]
        let cdata_tag = if root_case == 3 && blob.len() >= 3 {
            Some(u16::from_le_bytes([blob[1], blob[2]]))
        } else {
            None
        };

        // Try to decode the full GameCondition (tree + 3-byte footer per
        // sub_101021408). Treating it as a wrapper means the validator
        // exercises the same shape every consumer of GameCondition uses.
        let mut parse_cur = 0usize;
        // Reset last-attempted tag tracker; if decode fails, this tells us
        // which ConditionData variant's recipe is broken.
        dmm_parser::binary::variants::condition_data::LAST_ATTEMPTED_TAG.with(|c| c.set(None));
        let node = match GameCondition::read_from(blob, &mut parse_cur) {
            Ok(n) => n,
            Err(e) => {
                decode_err += 1;
                entry.2 += 1;
                let last_tag = dmm_parser::binary::variants::condition_data::LAST_ATTEMPTED_TAG
                    .with(|c| c.get());
                if let Some(t) = last_tag {
                    *failing_tag_stats.entry(t).or_insert(0) += 1;
                }
                if let Some(t) = cdata_tag {
                    cdata_tag_stats.entry(t).or_insert((0,0,0)).2 += 1;
                }
                // Capture decode_err entries for the targeted tag too —
                // useful when fixing a variant whose recipe is wrong.
                let want_err_dump = if root_case != 3 { false }
                    else if !dump_tag_filters.is_empty() {
                        cdata_tag.map_or(false, |t|
                            dump_tag_filters.contains(&t) &&
                            *dump_count_per_tag.get(&t).unwrap_or(&0) < dump_per_tag)
                    } else if let Some(filt) = dump_tag_filter {
                        cdata_tag == Some(filt) && case3_dumps.len() < 5
                    } else { case3_dumps.len() < 5 };
                if want_err_dump {
                    if let Some(t) = cdata_tag {
                        *dump_count_per_tag.entry(t).or_insert(0) += 1;
                    }
                    let tag_for_dump = cdata_tag.unwrap_or(0xFFFF);
                    let _ = e;
                    case3_dumps.push((*k, blob.to_vec(), Vec::new(), parse_cur, tag_for_dump));
                }
                // Dump decode_err for non-case-3 too (cascading children)
                if root_case != 3 && root_case <= 2 && case_other_dumps.len() < 5 {
                    case_other_dumps.push((*k, blob.to_vec(), Vec::new(), parse_cur, root_case));
                }
                continue;
            }
        };
        decode_ok += 1;

        if parse_cur != blob.len() {
            // Decoder under/over-consumed
            roundtrip_mismatch += 1;
            entry.2 += 1;
            if let Some(t) = cdata_tag {
                cdata_tag_stats.entry(t).or_insert((0,0,0)).1 += 1;
            }
            if mismatch_examples.len() < 10 {
                mismatch_examples.push((*k, parse_cur, blob.len()));
            }
            // Also dump for underconsume case
            let want_dump = if root_case != 3 { false }
                else if !dump_tag_filters.is_empty() {
                    cdata_tag.map_or(false, |t|
                        dump_tag_filters.contains(&t) &&
                        *dump_count_per_tag.get(&t).unwrap_or(&0) < dump_per_tag)
                } else if let Some(filt) = dump_tag_filter {
                    cdata_tag == Some(filt) && case3_dumps.len() < 5
                } else { case3_dumps.len() < 5 };
            if want_dump {
                if let Some(t) = cdata_tag {
                    *dump_count_per_tag.entry(t).or_insert(0) += 1;
                }
                let tag_for_dump = cdata_tag.unwrap_or(0xFFFF);
                let mut buf: Vec<u8> = Vec::with_capacity(blob.len());
                let _ = node.write_to(&mut buf);
                case3_dumps.push((*k, blob.to_vec(), buf, parse_cur, tag_for_dump));
            }
            continue;
        }

        // Round-trip: re-encode and compare
        let mut buf: Vec<u8> = Vec::with_capacity(blob.len());
        if let Err(_) = node.write_to(&mut buf) {
            roundtrip_mismatch += 1;
            entry.2 += 1;
            continue;
        }
        if buf == blob {
            roundtrip_ok += 1;
            entry.1 += 1;
            if let Some(t) = cdata_tag {
                cdata_tag_stats.entry(t).or_insert((0,0,0)).0 += 1;
            }
        } else {
            roundtrip_mismatch += 1;
            entry.2 += 1;
            if let Some(t) = cdata_tag {
                cdata_tag_stats.entry(t).or_insert((0,0,0)).1 += 1;
            }
            if mismatch_examples.len() < 10 {
                let diff_at = buf.iter().zip(blob.iter()).position(|(a, b)| a != b).unwrap_or(buf.len().min(blob.len()));
                mismatch_examples.push((*k, diff_at, blob.len()));
            }
            // Hex-dump the first 5 case-3 mismatches with their tag for inspection.
            let want_dump = if root_case != 3 { false }
                else if !dump_tag_filters.is_empty() {
                    cdata_tag.map_or(false, |t|
                        dump_tag_filters.contains(&t) &&
                        *dump_count_per_tag.get(&t).unwrap_or(&0) < dump_per_tag)
                } else if let Some(filt) = dump_tag_filter {
                    cdata_tag == Some(filt) && case3_dumps.len() < 5
                } else { case3_dumps.len() < 5 };
            if want_dump {
                if let Some(t) = cdata_tag {
                    *dump_count_per_tag.entry(t).or_insert(0) += 1;
                }
                let tag_for_dump = cdata_tag.unwrap_or(0xFFFF);
                case3_dumps.push((*k, blob.to_vec(), buf.clone(), parse_cur, tag_for_dump));
            }
            // Dump first 5 mismatches in cases 0/1/2 — these often cascade
            // from a child variant; the byte-level diff is still informative.
            if root_case != 3 && root_case <= 2 && case_other_dumps.len() < 5 {
                case_other_dumps.push((*k, blob.to_vec(), buf.clone(), parse_cur, root_case));
            }
        }
    }

    if !case_other_dumps.is_empty() {
        println!("\n=== First {} case-0/1/2 mismatch hex dumps (vanilla vs ours) ===", case_other_dumps.len());
        for (k, vanilla, ours, cur, root_case) in &case_other_dumps {
            println!("\nkey=0x{:08X} root_case={} parse_cur={} vanilla_len={} our_len={}",
                k, root_case, cur, vanilla.len(), ours.len());
            println!("  vanilla: {}", vanilla.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            println!("  ours:    {}", ours.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            let diff_at = ours.iter().zip(vanilla.iter()).position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(vanilla.len()));
            println!("  diff_at: {} (0x{:X})", diff_at, diff_at);
        }
    }

    if !case3_dumps.is_empty() {
        println!("\n=== First {} case-3 mismatch hex dumps (vanilla vs ours) ===", case3_dumps.len());
        for (k, vanilla, ours, cur, tag) in &case3_dumps {
            println!("\nkey=0x{:08X} tag={} parse_cur={} vanilla_len={} our_len={}",
                k, tag, cur, vanilla.len(), ours.len());
            println!("  vanilla: {}", vanilla.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            println!("  ours:    {}", ours.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            // Highlight where they diverge
            let diff_at = ours.iter().zip(vanilla.iter()).position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(vanilla.len()));
            println!("  diff_at: {} (0x{:x})", diff_at, diff_at);
            if vanilla.len() > ours.len() {
                let trail = &vanilla[ours.len()..];
                println!("  vanilla trailing extra: {} bytes [{}]",
                    trail.len(),
                    trail.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total entries:        {}", total);
    println!("Decode OK:            {}", decode_ok);
    println!("Decode err:           {}", decode_err);
    println!("Round-trip OK:        {} ({:.1}%)", roundtrip_ok, roundtrip_ok as f64 * 100.0 / total as f64);
    println!("Round-trip mismatch:  {}", roundtrip_mismatch);

    println!("\n=== Per-root-case tag stats ===");
    println!("case | total | pass | fail | pass%");
    for (case, (tot, pass, fail)) in &case_stats {
        let pct = if *tot > 0 { *pass as f64 * 100.0 / *tot as f64 } else { 0.0 };
        println!("  {:3}  | {:5} | {:4} | {:4} | {:5.1}%", case, tot, pass, fail, pct);
    }

    if !mismatch_examples.is_empty() {
        println!("\n=== First {} mismatch examples (key, parsed_or_diff_byte, blob_len) ===", mismatch_examples.len());
        for (k, p, l) in &mismatch_examples {
            println!("  key=0x{:08X}: cursor/diff={}, blob_len={}", k, p, l);
        }
    }

    // Per-ConditionData-tag breakdown (case 3 only)
    println!("\n=== ConditionData (case 3) per-u16-tag round-trip stats ===");
    println!("tag  | total | pass | fail | pass%");
    let mut tags: Vec<(u16, (usize, usize, usize))> = cdata_tag_stats.into_iter().collect();
    tags.sort_by_key(|(_, (_p, f, e))| -((*f + *e) as isize));  // sort by total failures desc
    let mut shown = 0usize;
    for (tag, (pass, fail, decode_err)) in &tags {
        let total = pass + fail + decode_err;
        if *fail == 0 && *decode_err == 0 { continue; }  // skip clean tags
        let pct = if total > 0 { *pass as f64 * 100.0 / total as f64 } else { 0.0 };
        println!("  {:4} | {:5} | {:4} | {:4} (mm) + {:4} (err) | {:5.1}%",
            tag, total, pass, fail, decode_err, pct);
        shown += 1;
        if shown >= 50 { break; }
    }
    if shown < tags.len() {
        let remaining_failures: usize = tags.iter().skip(shown)
            .filter(|(_, (_, f, e))| *f > 0 || *e > 0).count();
        if remaining_failures > 0 {
            println!("  ... {} more failing tags suppressed", remaining_failures);
        }
    }
    let clean_tags: usize = tags.iter()
        .filter(|(_, (_, f, e))| *f == 0 && *e == 0).count();
    println!("\nClean tags (always round-trip):  {}", clean_tags);

    // Dump tags that triggered decode errors (last-attempted tag at err point).
    // This is the smoking gun: each row tells us "tag X's recipe was wrong N times".
    if !failing_tag_stats.is_empty() {
        println!("\n=== Failing tags (last-attempted at decode_err) ===");
        let mut failing_sorted: Vec<(u16, usize)> = failing_tag_stats.into_iter().collect();
        failing_sorted.sort_by_key(|(_, c)| -(*c as isize));
        for (tag, count) in failing_sorted.iter().take(40) {
            println!("  tag {:4} (0x{:04X}): {} decode failures", tag, tag, count);
        }
    }
}
