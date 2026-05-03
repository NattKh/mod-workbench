// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Smoke-test the .paatt parser on every extracted PHM/PHW file.
//!
//! Reports per-file: parse OK/fail, info_count, version histogram,
//! string-table sizes, frame-event-buffer size, and trailing bytes.

use dmm_parser::binary::paatt::PaattFile;
use std::collections::BTreeMap;
use std::path::Path;

const ROOT: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\Chart-System\xml_dumps\0010\actionchart\bin__\attackinfo";

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("paatt") {
            out.push(p);
        }
    }
}

fn main() {
    let mut files = vec![];
    walk(Path::new(ROOT), &mut files);
    files.sort();
    println!("Found {} .paatt files\n", files.len());

    let mut total_ok = 0;
    let mut total_fail = 0;
    let mut total_trailing = 0;
    let mut version_hist: BTreeMap<u8, usize> = BTreeMap::new();

    for f in &files {
        let data = match std::fs::read(f) {
            Ok(d) => d,
            Err(e) => {
                println!("READ FAIL  {}: {}", f.display(), e);
                continue;
            }
        };

        let rel = f.display().to_string();
        let rel = rel.trim_start_matches(ROOT).trim_start_matches('\\').to_string();

        match PaattFile::parse_strict(&data) {
            Ok((paatt, trailing)) => {
                total_ok += 1;
                if trailing != 0 { total_trailing += 1; }

                let mut versions: BTreeMap<u8, usize> = BTreeMap::new();
                for info in &paatt.infos {
                    *versions.entry(info.version).or_insert(0) += 1;
                    *version_hist.entry(info.version).or_insert(0) += 1;
                }

                let v_summary: Vec<String> = versions.iter()
                    .map(|(v, c)| format!("v{}={}", v, c))
                    .collect();
                let trailing_marker = if trailing != 0 {
                    format!("  ⚠️ trailing={}", trailing)
                } else {
                    String::new()
                };
                println!(
                    "OK  {:<55}  {:>3} infos [{}]  st={} en={} ek={} sn={} pn={} sq={} pf={}  feb={}{}",
                    rel,
                    paatt.infos.len(),
                    v_summary.join(","),
                    paatt.string_table.len(),
                    paatt.effect_name_table.len(),
                    paatt.effect_info_key_table.len(),
                    paatt.socket_name_table.len(),
                    paatt.part_name_table.len(),
                    paatt.sequencer_name_table.len(),
                    paatt.prefab_name_table.len(),
                    paatt.frame_event_buffer.len(),
                    trailing_marker,
                );
            }
            Err(e) => {
                total_fail += 1;
                println!("FAIL {:<55}  {}", rel, e);
            }
        }
    }

    println!("\n=== Summary ===");
    println!("OK:           {}", total_ok);
    println!("FAIL:         {}", total_fail);
    println!("With trailing bytes: {}", total_trailing);
    println!("\n=== Global version histogram ===");
    for (v, c) in &version_hist {
        println!("  v{} = {} attack infos", v, c);
    }
}
