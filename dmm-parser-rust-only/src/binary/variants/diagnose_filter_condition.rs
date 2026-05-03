// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! One-shot diagnostic: walk QuestInfo entry 287 (k=0xf424f) step-by-step
//! through its `_questDialogFilterDataList`, printing offsets as we go,
//! to identify which sub-reader misaligns.

#[cfg(test)]
mod tests {
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    use crate::binary::variants::filter_condition::{
        FilterCondition, FilterDataElement, FilterDataElementWithHash006D0,
        FilterDataElementWithHashDA30,
    };
    use crate::binary::*;

    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\questinfo.pabgh";

    /// Parse the leading scalar fields of QuestInfo to advance the cursor
    /// to the start of `_questDialogFilterDataList`.
    fn skip_to_filter_list<'a>(data: &'a [u8], offset: &mut usize) -> std::io::Result<()> {
        use crate::binary::types::LocalizableString;
        let _key = u32::read_from(data, offset)?;
        let _string_key = CString::read_from(data, offset)?;
        let _is_blocked = u8::read_from(data, offset)?;
        let _quest_type = u8::read_from(data, offset)?;
        let _quest_category = u8::read_from(data, offset)?;
        let _name = LocalizableString::read_from(data, offset)?;
        let _desc = LocalizableString::read_from(data, offset)?;
        let _quest_group_info = u16::read_from(data, offset)?;
        let _faction_info = u32::read_from(data, offset)?;
        // FactionStateData = CArray<u8> + u32 + u32 + u8
        let _ = CArray::<u8>::read_from(data, offset)?;
        let _ = u32::read_from(data, offset)?;
        let _ = u32::read_from(data, offset)?;
        let _ = u8::read_from(data, offset)?;
        // BranchData = u32 + u32 + u8 + u8 + u32 + u32 = 18 bytes
        for _ in 0..2 { let _ = u32::read_from(data, offset)?; }
        for _ in 0..2 { let _ = u8::read_from(data, offset)?; }
        for _ in 0..2 { let _ = u32::read_from(data, offset)?; }
        // 6 CArrays
        let _ = CArray::<u32>::read_from(data, offset)?;
        // BranchData CArray: each element 18 bytes
        let n = u32::read_from(data, offset)? as usize;
        for _ in 0..n {
            for _ in 0..2 { let _ = u32::read_from(data, offset)?; }
            for _ in 0..2 { let _ = u8::read_from(data, offset)?; }
            for _ in 0..2 { let _ = u32::read_from(data, offset)?; }
        }
        for _ in 0..4 { let _ = CArray::<u32>::read_from(data, offset)?; }
        // start_mission..debug_color (8 u32s pre-blob)
        for _ in 0..5 { let _ = u32::read_from(data, offset)?; }
        for _ in 0..2 { let _ = u32::read_from(data, offset)?; }
        let _ = CString::read_from(data, offset)?;       // test_tag
        let _ = u32::read_from(data, offset)?;            // game_start_stage
        let _ = CString::read_from(data, offset)?;       // game_start_sub_timeline
        let _ = CString::read_from(data, offset)?;       // memo
        Ok(())
    }

    #[test]
    fn bisect_entry_287() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let target_idx = 287;
        let (k, s, e) = ranges[target_idx];
        eprintln!("entry {}: k=0x{:x}, range [{}..{}], size {}", target_idx, k, s, e, e - s);

        let mut off = s;
        if let Err(err) = skip_to_filter_list(&data, &mut off) {
            eprintln!("skip_to_filter_list FAILED: {}", err);
            return;
        }
        eprintln!("  after scalars, offset = {} (relative {})", off, off - s);

        // Read filter_data list count
        let count = u32::read_from(&data, &mut off).unwrap();
        eprintln!("  filter_data_list count = {}", count);

        for i in 0..count as usize {
            let elem_start = off;
            eprintln!("  --- filter_data[{}] starts at offset {} ---", i, off);

            // u8 + u8 + u32 + u32 + u32 + u32
            let _ = u8::read_from(&data, &mut off);
            let _ = u8::read_from(&data, &mut off);
            let _ = u32::read_from(&data, &mut off);
            let _ = u32::read_from(&data, &mut off);
            let _ = u32::read_from(&data, &mut off);
            let _ = u32::read_from(&data, &mut off);
            eprintln!("    after head: off={}", off);

            // 2x CArray<FilterCondition>
            for j in 0..2 {
                let cond_count = u32::read_from(&data, &mut off).unwrap_or(0);
                eprintln!("    cond_list_{} count={} at off pre={}", j, cond_count, off - 4);
                for ci in 0..cond_count {
                    let cstart = off;
                    match FilterCondition::read_from(&data, &mut off) {
                        Ok(_) => {
                            eprintln!("      cond[{}] OK, consumed {} bytes ({}-{})",
                                ci, off - cstart, cstart, off);
                        }
                        Err(err) => {
                            eprintln!("      cond[{}] at off {}: ERR {}", ci, cstart, err);
                            return;
                        }
                    }
                }
            }

            // CArray<CArray<FilterDataElement>>
            let outer_count = u32::read_from(&data, &mut off).unwrap_or(0);
            eprintln!("    outer_lists count={} at off pre={}", outer_count, off - 4);
            for li in 0..outer_count {
                let inner_count = u32::read_from(&data, &mut off).unwrap_or(0);
                eprintln!("      outer[{}] inner count={} at off pre={}", li, inner_count, off - 4);
                for ei in 0..inner_count {
                    let estart = off;
                    match FilterDataElement::read_from(&data, &mut off) {
                        Ok(_) => {
                            eprintln!("        elem[{}] OK ({}-{})", ei, estart, off);
                        }
                        Err(err) => {
                            eprintln!("        elem[{}] at off {}: ERR {}", ei, estart, err);
                            return;
                        }
                    }
                }
            }

            // 2x CArray<FilterDataElement>
            for j in 0..2 {
                let cnt = u32::read_from(&data, &mut off).unwrap_or(0);
                eprintln!("    elem_list_{} count={} at off pre={}", j, cnt, off - 4);
                for ei in 0..cnt {
                    let estart = off;
                    match FilterDataElement::read_from(&data, &mut off) {
                        Ok(_) => {
                            eprintln!("      elem[{}] OK ({}-{})", ei, estart, off);
                        }
                        Err(err) => {
                            eprintln!("      elem[{}] at off {}: ERR {}", ei, estart, err);
                            return;
                        }
                    }
                }
            }

            // CArray<FilterDataElementWithHash006D0>
            let kc = u32::read_from(&data, &mut off).unwrap_or(0);
            eprintln!("    keyed_006d0 count={} at off pre={}", kc, off - 4);
            for ei in 0..kc {
                let estart = off;
                match FilterDataElementWithHash006D0::read_from(&data, &mut off) {
                    Ok(_) => eprintln!("      kelem[{}] OK ({}-{})", ei, estart, off),
                    Err(err) => {
                        eprintln!("      kelem[{}] at off {}: ERR {}", ei, estart, err);
                        return;
                    }
                }
            }

            // CArray<FilterDataElementWithHashDA30>
            let kc2 = u32::read_from(&data, &mut off).unwrap_or(0);
            eprintln!("    keyed_da30 count={} at off pre={}", kc2, off - 4);
            for ei in 0..kc2 {
                let estart = off;
                match FilterDataElementWithHashDA30::read_from(&data, &mut off) {
                    Ok(_) => eprintln!("      kelem[{}] OK ({}-{})", ei, estart, off),
                    Err(err) => {
                        eprintln!("      kelem[{}] at off {}: ERR {}", ei, estart, err);
                        return;
                    }
                }
            }

            let _ = u32::read_from(&data, &mut off);
            for _ in 0..4 { let _ = u8::read_from(&data, &mut off); }
            eprintln!("  filter_data[{}] consumed {} bytes ({}-{})", i, off - elem_start, elem_start, off);
        }
        eprintln!("END off={} (entry end {})", off, e);
    }
}
