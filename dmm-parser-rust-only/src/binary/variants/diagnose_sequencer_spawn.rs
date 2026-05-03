// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! One-shot diagnostic: walk SequencerSpawnInfo entry 0 (key=0x3E9)
//! step-by-step through its `_sequencerSpawnDataList`, tracing the
//! chart_desc structure to identify exactly which inner GameCondition
//! tree drifts (currently fails at offset 249 with tag 119 = 'w').
//!
//! Approach: replicate the typed read using SequencerSpawnDataElement
//! wrapper but with per-field offset reporting.

#[cfg(test)]
mod tests {
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    use crate::binary::variants::buff_data::GameConditionOptional;
    use crate::binary::*;

    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sequencerspawninfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sequencerspawninfo.pabgh";

    /// Minimal chart_desc walker: parse fields one at a time and report
    /// offsets. Stops on first error.
    fn walk_chart_desc(data: &[u8], offset: &mut usize, label: &str) -> std::io::Result<()> {
        let _name = CString::read_from(data, offset)?;
        eprintln!("    {}: after name, off={}", label, offset);
        let _field_16 = u32::read_from(data, offset)?;
        let _label = CString::read_from(data, offset)?;
        eprintln!("    {}: after label, off={}", label, offset);
        let _pos = <[f32; 3]>::read_from(data, offset)?;
        let _field_44 = u32::read_from(data, offset)?;
        for _ in 0..8 { let _ = u8::read_from(data, offset)?; }
        let _lookup_56 = u32::read_from(data, offset)?;
        eprintln!("    {}: before chart_desc.game_condition, off={}", label, offset);
        let _gc = GameConditionOptional::read_from(data, offset)?;
        eprintln!("    {}: after chart_desc.game_condition, off={}", label, offset);
        let _string_a = CString::read_from(data, offset)?;
        let _string_b = CString::read_from(data, offset)?;
        let pair_count = u32::read_from(data, offset)?;
        for _ in 0..pair_count {
            let _ = CString::read_from(data, offset)?;
            let _ = CString::read_from(data, offset)?;
        }
        eprintln!("    {}: after string_pairs, off={}", label, offset);
        let inner_count = u32::read_from(data, offset)?;
        eprintln!("    {}: inner_list count={}, starts at off={}", label, inner_count, offset);
        for i in 0..inner_count {
            let inner_start = *offset;
            let _ = GameConditionOptional::read_from(data, offset).map_err(|e| {
                std::io::Error::new(e.kind(), format!("inner_list[{}].game_condition at off {}: {}", i, inner_start, e))
            })?;
            eprintln!("      inner_list[{}].game_condition: ok ({}-{})", i, inner_start, offset);
            // 3 sub-CArrays per inner_list element (Character/Gimmick/Item)
            for sub_label in &["character", "gimmick", "item"] {
                let cnt = u32::read_from(data, offset)?;
                eprintln!("      inner_list[{}].{}_list count={} at off {}", i, sub_label, cnt, *offset - 4);
                for j in 0..cnt {
                    let elem_start = *offset;
                    // Each sub-list element: GCO + sub-fields per type
                    let _ = GameConditionOptional::read_from(data, offset).map_err(|e| {
                        std::io::Error::new(e.kind(), format!("inner_list[{}].{}[{}].game_condition at off {}: {}", i, sub_label, j, elem_start, e))
                    })?;
                    eprintln!("        {}[{}].game_condition: ok ({}-{})", sub_label, j, elem_start, offset);
                    // Skip remaining fields per sub-type:
                    //   character: u64 + u32 + u32 + u16 + u8 + SequencerStageOptionalU64 = 19 + opt
                    //   gimmick: u64 + u32 + u32 = 16
                    //   item: u64 + u32 + u32 = 16
                    let _ = u64::read_from(data, offset)?;
                    let _ = u32::read_from(data, offset)?;
                    let _ = u32::read_from(data, offset)?;
                    if *sub_label == "character" {
                        let _ = u16::read_from(data, offset)?;
                        // SequencerStageOptionalU64: u8 presence + (if !=0) u64
                        let pres = u8::read_from(data, offset)?;
                        if pres != 0 { let _ = u64::read_from(data, offset)?; }
                    }
                    eprintln!("        {}[{}] complete, off={}", sub_label, j, offset);
                }
            }
        }
        eprintln!("    {}: walk complete, off={}", label, offset);
        Ok(())
    }

    #[test]
    fn bisect_entry_0() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let target_idx = 0;
        let (k, s, e) = ranges[target_idx];
        eprintln!("entry {}: k=0x{:x}, range [{}..{}], size {}", target_idx, k, s, e, e - s);

        let mut off = s;
        // Skip leading scalars: u32 key + CString string_key + u8 is_blocked + CString description
        let _ = u32::read_from(&data, &mut off);
        let _ = CString::read_from(&data, &mut off);
        let _ = u8::read_from(&data, &mut off);
        let _ = CString::read_from(&data, &mut off);
        eprintln!("after leading scalars, off={}", off);

        // CArray<element> count
        let count = u32::read_from(&data, &mut off).unwrap_or(0);
        eprintln!("data_list count={}", count);

        for i in 0..count as usize {
            let elem_start = off;
            eprintln!("--- data_list[{}] starts at off={} ---", i, off);

            // 8-byte prefix per IDA sub_141DAE6A0
            let h_a = u32::read_from(&data, &mut off).unwrap();
            let h_b = u32::read_from(&data, &mut off).unwrap();
            eprintln!("  prefix: hash_a=0x{:08x}, hash_b=0x{:08x}", h_a, h_b);

            // chart_desc
            let label = format!("data_list[{}].chart_desc", i);
            match walk_chart_desc(&data, &mut off, &label) {
                Ok(_) => eprintln!("  chart_desc done"),
                Err(err) => {
                    eprintln!("  chart_desc FAILED: {}", err);
                    eprintln!("  elem_start={}, current_off={}", elem_start, off);
                    return;
                }
            }
        }
        eprintln!("END off={} entry_end={}", off, e);
    }
}
