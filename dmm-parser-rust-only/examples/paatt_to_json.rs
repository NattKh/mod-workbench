// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Export a .paatt file to JSON for analysis. Strings get fully exposed;
//! BaseData and FrameEventBuffer remain hex-encoded until those layers
//! are reverse-engineered field-by-field.
//!
//! Usage:
//!   cargo run --release --example paatt_to_json -- <path-to-paatt> [output.json]

use dmm_parser::binary::paatt::PaattFile;
use serde_json::{json, Value};
use std::path::PathBuf;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let in_path = args.next().expect("usage: paatt_to_json <path-to-paatt> [output.json]");
    let out_path = args.next().unwrap_or_else(|| {
        let mut p = PathBuf::from(&in_path);
        p.set_extension("json");
        p.to_string_lossy().to_string()
    });

    let data = std::fs::read(&in_path).expect("read .paatt");
    let (paatt, trailing) = PaattFile::parse_strict(&data).expect("parse .paatt");

    let infos: Vec<Value> = paatt.infos.iter().enumerate().map(|(i, info)| {
        let cf: Vec<Value> = info.child_frames.iter().enumerate().map(|(idx, cf)| {
            json!({
                "slot": idx,
                "count": cf.count,
                "hex": hex(&cf.data),
            })
        }).collect();
        json!({
            "index": i,
            "version": info.version,
            "base_data_size": info.base_data.len(),
            "base_data_hex": hex(&info.base_data),
            "child_frames": cf,
        })
    }).collect();

    let out = json!({
        "summary": {
            "info_count": paatt.infos.len(),
            "string_table_count": paatt.string_table.len(),
            "effect_name_table_count": paatt.effect_name_table.len(),
            "effect_info_key_table_count": paatt.effect_info_key_table.len(),
            "socket_name_table_count": paatt.socket_name_table.len(),
            "part_name_table_count": paatt.part_name_table.len(),
            "sequencer_name_table_count": paatt.sequencer_name_table.len(),
            "prefab_name_table_count": paatt.prefab_name_table.len(),
            "frame_event_buffer_size": paatt.frame_event_buffer.len(),
            "trailing_bytes": trailing,
        },
        "string_table": paatt.string_table,
        "effect_name_table": paatt.effect_name_table,
        "effect_info_key_table": paatt.effect_info_key_table,
        "socket_name_table": paatt.socket_name_table,
        "part_name_table": paatt.part_name_table,
        "sequencer_name_table": paatt.sequencer_name_table,
        "prefab_name_table": paatt.prefab_name_table,
        "frame_event_buffer_hex": hex(&paatt.frame_event_buffer),
        "infos": infos,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&out).unwrap()).expect("write");
    println!("Wrote {} ({} infos, {} bytes JSON)",
        out_path, paatt.infos.len(), serde_json::to_string(&out).unwrap().len());
}
