// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Empirical byte-pattern analyzer for AttackInfoDataDesc BaseData.
//!
//! For each byte offset in 264-byte v0 BaseData (and 528/296/288 for
//! v1/v2/v3), aggregates byte values across every parsed attack info
//! to identify:
//!   - Constant bytes (likely padding or always-default fields)
//!   - Variable bytes (likely actual data fields)
//!   - 4-byte aligned floats (look for 0x3F800000=1.0f, 0x40000000=2.0f)
//!   - Boolean-like (only 0/1)
//!
//! Produces JSON with per-offset stats so we can manually map fields.

use dmm_parser::binary::paatt::PaattFile;
use std::collections::BTreeMap;
use std::path::Path;

const ROOT: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\Chart-System\xml_dumps\0010\actionchart\bin__\attackinfo";

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() { walk(&p, out); }
        else if p.extension().and_then(|s| s.to_str()) == Some("paatt") { out.push(p); }
    }
}

#[derive(Default)]
struct ByteStats {
    histogram: BTreeMap<u8, u64>,
}

impl ByteStats {
    fn record(&mut self, b: u8) {
        *self.histogram.entry(b).or_insert(0) += 1;
    }
    fn total(&self) -> u64 {
        self.histogram.values().sum()
    }
    fn unique_count(&self) -> usize {
        self.histogram.len()
    }
    fn most_common(&self) -> (u8, u64) {
        self.histogram.iter().max_by_key(|(_, c)| *c).map(|(b, c)| (*b, *c)).unwrap_or((0, 0))
    }
}

fn analyze_version(version: u8, base_size: usize, data: &[Vec<u8>]) {
    println!("\n=== VERSION {} (BaseData size {}) — {} samples ===",
        version, base_size, data.len());

    let mut per_offset: Vec<ByteStats> = (0..base_size).map(|_| ByteStats::default()).collect();
    for sample in data {
        for (i, b) in sample.iter().enumerate() {
            per_offset[i].record(*b);
        }
    }

    // Group bytes into varying segments
    let mut segments: Vec<(usize, usize, &str)> = vec![];  // (start, end, kind)
    let mut i = 0;
    while i < base_size {
        let s = &per_offset[i];
        let n = s.total();
        if n == 0 { i += 1; continue; }
        let unique = s.unique_count();
        let (mc_byte, mc_count) = s.most_common();
        let pct_constant = (mc_count as f64 / n as f64) * 100.0;

        let kind = if unique == 1 {
            "CONST"
        } else if pct_constant > 99.0 {
            "MOSTLY_CONST"
        } else if unique == 2 && (s.histogram.contains_key(&0) && s.histogram.contains_key(&1)) {
            "BOOL"
        } else if unique <= 8 {
            "ENUM_LOW"
        } else {
            "VARIES"
        };

        // Extend segment of same kind
        let start = i;
        let mut end = i + 1;
        while end < base_size {
            let s2 = &per_offset[end];
            let u2 = s2.unique_count();
            let n2 = s2.total();
            if n2 == 0 { break; }
            let (_, mc2) = s2.most_common();
            let pct2 = (mc2 as f64 / n2 as f64) * 100.0;
            let kind2 = if u2 == 1 { "CONST" }
                else if pct2 > 99.0 { "MOSTLY_CONST" }
                else if u2 == 2 && (s2.histogram.contains_key(&0) && s2.histogram.contains_key(&1)) { "BOOL" }
                else if u2 <= 8 { "ENUM_LOW" }
                else { "VARIES" };
            if kind2 != kind { break; }
            end += 1;
        }
        segments.push((start, end, kind));
        if kind == "CONST" {
            print!("[{:3}..{:3}] CONST=0x{:02x}                 ({}b)", start, end - 1, mc_byte, end - start);
        } else if kind == "MOSTLY_CONST" {
            print!("[{:3}..{:3}] MOSTLY_CONST 0x{:02x} ({:.1}%)   ({}b)",
                start, end - 1, mc_byte, pct_constant, end - start);
        } else if kind == "BOOL" {
            print!("[{:3}..{:3}] BOOL                       ({}b)", start, end - 1, end - start);
        } else if kind == "ENUM_LOW" {
            print!("[{:3}..{:3}] ENUM (≤8 vals)             ({}b)", start, end - 1, end - start);
        } else {
            print!("[{:3}..{:3}] VARIES ({} unique vals)    ({}b)",
                start, end - 1, unique, end - start);
        }
        // If aligned 4-byte block, check for f32 patterns
        if end - start == 4 && start % 4 == 0 {
            let one_count = data.iter().filter(|d| {
                let s = &d[start..start + 4];
                u32::from_le_bytes(s.try_into().unwrap()) == 0x3F800000
            }).count();
            if one_count > 0 {
                print!("  (~{:.0}% are 1.0f)", (one_count as f64 / data.len() as f64) * 100.0);
            }
        }
        println!();
        i = end;
    }
}

fn main() {
    let mut files = vec![];
    walk(Path::new(ROOT), &mut files);
    files.sort();

    let mut by_version: BTreeMap<u8, Vec<Vec<u8>>> = BTreeMap::new();
    let mut total = 0usize;
    for f in &files {
        let data = match std::fs::read(f) { Ok(d) => d, Err(_) => continue };
        let paatt = match PaattFile::parse(&data) { Ok(p) => p, Err(_) => continue };
        for info in paatt.infos {
            by_version.entry(info.version).or_default().push(info.base_data);
            total += 1;
        }
    }
    println!("Loaded {} attack infos across {} versions", total, by_version.len());

    let sizes = [(0u8, 264), (1, 528), (2, 296), (3, 288), (4, 264)];
    for (v, sz) in sizes.iter() {
        if let Some(samples) = by_version.get(v) {
            if !samples.is_empty() {
                analyze_version(*v, *sz, samples);
            }
        }
    }
}
