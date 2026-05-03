// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Diagnostic that mirrors dmm-api-test/src-tauri/src/commands.rs::read_pamt
//! and build_file_index byte-for-byte. Verifies whether DMM's parser produces
//! the deep canonical path for cd_phm_02_sword_0036.pac.

use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug)]
struct PamtFileRecord {
    name_offset: u32,
    flags: u16,
}

struct PamtInfo {
    dir_data: Vec<u8>,
    fn_data: Vec<u8>,
    hash_entries: Vec<(u32, u32, u32, u32)>,
    file_records: Vec<PamtFileRecord>,
}

fn read_pamt(data: &[u8]) -> Result<PamtInfo, String> {
    if data.len() < 12 { return Err("too small".into()); }
    let _ = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let paz_count = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let _ = u32::from_le_bytes(data[8..12].try_into().unwrap());

    let mut pos = 12usize;
    for _ in 0..paz_count {
        if pos + 12 > data.len() { return Err("paz".into()); }
        pos += 12;
    }

    let dir_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let dir_data = data[pos..pos + dir_size].to_vec();
    pos += dir_size;

    let fn_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let fn_data = data[pos..pos + fn_size].to_vec();
    pos += fn_size;

    let hash_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut hash_entries = Vec::new();
    for _ in 0..hash_count {
        let folder_hash = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let name_offset = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let file_start = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        let file_count = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
        hash_entries.push((folder_hash, name_offset, file_start, file_count));
        pos += 16;
    }

    let file_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut file_records = Vec::new();
    for _ in 0..file_count {
        let name_offset = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let flags = u16::from_le_bytes(data[pos + 18..pos + 20].try_into().unwrap());
        file_records.push(PamtFileRecord { name_offset, flags });
        pos += 20;
    }

    Ok(PamtInfo { dir_data, fn_data, hash_entries, file_records })
}

fn resolve_name(block_data: &[u8], name_offset: u32) -> String {
    let mut segments: Vec<String> = Vec::new();
    let mut offset = name_offset as usize;
    let mut guard = 0;
    while offset != 0xFFFFFFFF_usize && guard < 64 {
        if offset + 5 > block_data.len() { break; }
        let parent = u32::from_le_bytes(block_data[offset..offset + 4].try_into().unwrap());
        let name_len = block_data[offset + 4] as usize;
        if offset + 5 + name_len > block_data.len() { break; }
        let seg = String::from_utf8_lossy(&block_data[offset + 5..offset + 5 + name_len]).to_string();
        segments.push(seg);
        offset = if parent == 0xFFFFFFFF { 0xFFFFFFFF_usize } else { parent as usize };
        guard += 1;
    }
    segments.reverse();
    segments.join("")
}

fn build_file_index(pamt: &PamtInfo) -> HashMap<String, PamtFileRecord> {
    let mut index = HashMap::new();
    let mut dir_names: HashMap<u32, String> = HashMap::new();
    for &(folder_hash, name_offset, _, _) in &pamt.hash_entries {
        dir_names.insert(folder_hash, resolve_name(&pamt.dir_data, name_offset));
    }
    for (i, rec) in pamt.file_records.iter().enumerate() {
        let filename = resolve_name(&pamt.fn_data, rec.name_offset);
        for &(folder_hash, _, file_start, file_count) in &pamt.hash_entries {
            let start = file_start as usize;
            let count = file_count as usize;
            if i >= start && i < start + count {
                let dirname = dir_names.get(&folder_hash).cloned().unwrap_or_default();
                let full_path = if dirname.is_empty() {
                    filename.clone()
                } else {
                    format!("{}/{}", dirname, filename)
                };
                index.insert(full_path, rec.clone());
                break;
            }
        }
    }
    index
}

fn main() {
    let game = Path::new(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert");
    let needles = [
        "cd_phm_02_sword_0036.pac",
        "cd_phm_02_sword_0036.pac_xml",
        "itemicon_prefab_cd_phm_02_sword_0036.dds",
    ];

    let mut groups: Vec<String> = std::fs::read_dir(game).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    groups.sort();

    // Mirror DMM's global_fn_index population — first writer wins
    let mut global_fn_index: HashMap<String, String> = HashMap::new();
    for g in &groups {
        if g == "0036" || g == "0037" { continue; }
        let pamt_path = game.join(g).join("0.pamt");
        if !pamt_path.exists() { continue; }
        let Ok(data) = std::fs::read(&pamt_path) else { continue };
        let Ok(pamt_info) = read_pamt(&data) else {
            eprintln!("Group {} parse error", g);
            continue;
        };
        let file_idx = build_file_index(&pamt_info);

        // For each needle, check this group's contribution
        for needle in &needles {
            for (full_path, rec) in &file_idx {
                let lower = full_path.to_lowercase().replace('\\', "/");
                if let Some(last_slash) = lower.rfind('/') {
                    let fname = &lower[last_slash + 1..];
                    if fname == *needle {
                        println!("[GROUP {}] full_path={} dir={} flags=0x{:04x}",
                            g, full_path, &lower[..last_slash], rec.flags);
                    }
                }
            }
        }

        // Build global index
        for (full_path, _) in &file_idx {
            let lower = full_path.to_lowercase().replace('\\', "/");
            if let Some(last_slash) = lower.rfind('/') {
                let dir = &lower[..last_slash];
                let fname = &lower[last_slash + 1..];
                global_fn_index.entry(fname.to_string())
                    .or_insert_with(|| dir.to_string());
            }
        }
    }

    println!("\n=== global_fn_index resolution ===");
    for needle in &needles {
        match global_fn_index.get(*needle) {
            Some(dir) => println!("{} -> {}", needle, dir),
            None => println!("{} -> MISSING", needle),
        }
    }
    println!("\nTotal global_fn_index entries: {}", global_fn_index.len());
}
