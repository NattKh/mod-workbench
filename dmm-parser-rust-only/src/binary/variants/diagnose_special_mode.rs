// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Probe special_mode_info tail to determine if vanilla data has small
//! enough variety to type.

#[cfg(test)]
mod tests {
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\specialmode.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\specialmode.pabgh";

    #[test]
    fn dump_records() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        eprintln!("{} records", ranges.len());
        for (i, (k, s, e)) in ranges.iter().take(2).enumerate() {
            let size = e - s;
            eprintln!("\n=== record [{}] k=0x{:x} size={} ===", i, k, size);
            // Print all bytes
            for j in (0..size).step_by(16) {
                eprint!("  +{:04x}: ", j);
                for kk in 0..16 {
                    if j + kk < size { eprint!("{:02x} ", data[s + j + kk]); }
                }
                eprintln!();
            }
        }
    }
}
