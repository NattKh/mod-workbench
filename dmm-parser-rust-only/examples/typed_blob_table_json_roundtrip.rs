// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Round-trip test of the new pabgh_typed_blob_table! JSON methods.
//!
//! Drives sub_level_info through:
//!   raw bytes → parse_typed_blob_table_to_json_with_pabgh → JSON values
//!   JSON values → serialize_typed_blob_table_from_json → raw bytes
//! Then compares back to vanilla bytes. Any drift means the macro's new
//! to_json_dict / write_from_json_dict aren't byte-perfect.

use dmm_parser::tables::blob_runtime::{
    parse_typed_blob_table_to_json_with_pabgh,
    serialize_typed_blob_table_from_json,
};
use dmm_parser::tables::sub_level_info::SubLevelInfo;
use std::path::Path;

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sublevelinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\sublevelinfo.pabgh";

fn main() {
    let body = std::fs::read(Path::new(PABGB)).expect("vanilla pabgb");
    let pabgh = std::fs::read(Path::new(PABGH)).expect("vanilla pabgh");
    println!("vanilla body: {} bytes, pabgh: {} bytes", body.len(), pabgh.len());

    // Decode → JSON dicts.
    let dicts = parse_typed_blob_table_to_json_with_pabgh(&body, &pabgh, |data, off, size| {
        Ok(SubLevelInfo::read_with_size(data, off, size)?.to_json_dict())
    }).expect("parse to json");
    println!("parsed {} sub_level_info entries to JSON", dicts.len());

    // Show one sample so we can see what the typed prefix exposes.
    if let Some(first) = dicts.first() {
        println!("\nfirst entry as JSON:");
        println!("{}", serde_json::to_string_pretty(first).unwrap());
    }

    // Re-serialize.
    let out = serialize_typed_blob_table_from_json(&dicts, |w, obj| {
        SubLevelInfo::write_from_json_dict(w, obj)
    }).expect("serialize from json");
    println!("\nre-serialized: {} bytes (vanilla {} bytes)", out.len(), body.len());

    if out == body {
        println!("✅ ROUND-TRIP CLEAN — every byte matches vanilla");
    } else {
        let diff_at = out.iter().zip(body.iter()).position(|(a, b)| a != b)
            .unwrap_or(out.len().min(body.len()));
        println!("❌ MISMATCH at byte {} (out_len={}, vanilla_len={})", diff_at, out.len(), body.len());
        let s = diff_at.saturating_sub(8);
        let e = (diff_at + 24).min(out.len()).min(body.len());
        println!("  vanilla[{:#X}..{:#X}]: {:02x?}", s, e, &body[s..e]);
        println!("  ours[{:#X}..{:#X}]:    {:02x?}", s, e, &out[s..e]);
    }
}
