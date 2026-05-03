#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.


pub mod binary;
pub mod crypto;
pub mod dispatch;
pub mod item_info;
pub mod json_traits;
pub mod tables;

pub use dispatch::{
    is_supported_table, parse_table_to_json, serialize_table_from_json,
    supported_tables,
};

#[cfg(test)]
mod tests {
    use crate::binary::BinaryRead;
    use crate::binary::BinaryWrite;
    use crate::binary::papgt::PackGroupTreeMeta;
    use crate::binary::pamt::PackMeta;
    use crate::binary::paloc::LocalizationFile;
    use crate::item_info::ItemInfo;
    // Multi-table tests live in src/tables/<name>/info.rs as inline #[cfg(test)] mods.
    // Removed the BuffInfo/BreakableObjectInfo/WantedInfo blocks here (replaced by
    // inline tests during the IDA-driven generation pass).

    // Cross-platform fixture resolution.
    //
    // Tests check, in order:
    //   1. Env var (`DMM_PARSER_<NAME>_PATH`) — explicit override
    //   2. The path baked into the test (Linux convention from Porter's dev box)
    //   3. A Windows fallback path
    //
    // If none of the paths exist the test prints "SKIP: <name>" and returns
    // success. This lets the suite stay green on machines that don't have the
    // game installed (e.g. CI), while still catching real regressions when the
    // fixtures ARE present.
    fn first_existing(env_var: &str, candidates: &[&str]) -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var(env_var) {
            let pb = std::path::PathBuf::from(p);
            if pb.exists() {
                return Some(pb);
            }
        }
        for c in candidates {
            let pb = std::path::PathBuf::from(c);
            if pb.exists() {
                return Some(pb);
            }
        }
        None
    }

    fn find_iteminfo_pabgb() -> Option<std::path::PathBuf> {
        first_existing(
            "DMM_PARSER_ITEMINFO_PATH",
            &[
                "/mnt/e/OpensourceGame/CrimsonDesert/Godmod/backups/iteminfo_1.0.4.0.pabgb",
                r"C:\Users\corin\Desktop\CD DUMPING TOOLS\1.0.4 PABGB_PABGH\iteminfo.pabgb",
                r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\iteminfo.pabgb",
            ],
        )
    }

    fn find_papgt() -> Option<std::path::PathBuf> {
        first_existing(
            "DMM_PARSER_PAPGT_PATH",
            &[
                "/mnt/e/OpensourceGame/CrimsonDesert/Crimson Browser/Original/0.papgt",
                r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.papgt",
            ],
        )
    }

    fn find_pamt() -> Option<std::path::PathBuf> {
        first_existing(
            "DMM_PARSER_PAMT_PATH",
            &[
                "/mnt/e/OpensourceGame/CrimsonDesert/Crimson Browser/Original/0.pamt",
                r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\meta\0.pamt",
                r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\0020\0.pamt",
            ],
        )
    }

    fn find_game_dir() -> Option<std::path::PathBuf> {
        first_existing(
            "DMM_PARSER_GAME_DIR",
            &[
                "/mnt/f/Program/Steam/steamapps/common/Crimson Desert",
                r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert",
            ],
        )
    }

    macro_rules! fixture_or_skip {
        ($finder:ident, $name:literal) => {
            match $finder() {
                Some(p) => p,
                None => {
                    eprintln!("SKIP: {} fixture not found (set env var or install game)", $name);
                    return;
                }
            }
        };
    }

    #[test]
    fn test_full_roundtrip() {
        let path = fixture_or_skip!(find_iteminfo_pabgb, "iteminfo.pabgb");
        let data = std::fs::read(&path).expect("binary file not found");
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            let last_offset = offset;
            match ItemInfo::read_from(&data, &mut offset) {
                Ok(item) => items.push(item),
                Err(e) => panic!(
                    "parse failed at item #{}, offset 0x{:x}: {}\nfirst 32 bytes of item: {:02x?}",
                    items.len(), last_offset, e,
                    &data[last_offset..(last_offset + 32).min(data.len())],
                ),
            }
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out.len(), data.len(), "size mismatch");
        assert_eq!(out, data, "roundtrip bytes mismatch");
    }

    #[test]
    fn test_papgt_parse() {
        let path = fixture_or_skip!(find_papgt, "0.papgt");
        let data = std::fs::read(&path).expect("papgt file not found");
        let papgt = PackGroupTreeMeta::parse(&data).unwrap();
        println!("PAPGT: {} entries", papgt.entries.len());
        for entry in &papgt.entries {
            println!(
                "  group={}, optional={}, language={:#06x}, checksum={:#010x}",
                entry.group_name,
                entry.entry.is_optional,
                entry.entry.language.0,
                entry.entry.pack_meta_checksum,
            );
        }
        assert!(!papgt.entries.is_empty(), "should have entries");
    }

    #[test]
    fn test_papgt_roundtrip() {
        let path = fixture_or_skip!(find_papgt, "0.papgt");
        let data = std::fs::read(&path).expect("papgt file not found");
        let papgt = PackGroupTreeMeta::parse(&data).unwrap();
        println!("PAPGT: {} entries", papgt.entries.len());
        let written = papgt.to_bytes().unwrap();
        assert_eq!(written.len(), data.len(), "papgt roundtrip size mismatch");
        assert_eq!(written, data, "papgt roundtrip bytes mismatch");
    }

    #[test]
    fn test_pamt_parse() {
        let path = fixture_or_skip!(find_pamt, "0.pamt");
        let data = std::fs::read(&path).expect("pamt file not found");
        let pamt = PackMeta::parse(&data, None).unwrap();
        println!("PAMT: {} chunks, {} directories", pamt.chunks.len(), pamt.directories.len());
        for dir in &pamt.directories {
            println!("  dir={}, {} files", dir.path, dir.files.len());
            for f in dir.files.iter().take(3) {
                println!(
                    "    file={}, compressed={}, uncompressed={}, chunk_id={}",
                    f.name, f.file.compressed_size, f.file.uncompressed_size, f.file.chunk_id
                );
            }
        }
        assert!(!pamt.directories.is_empty(), "should have directories");
    }

    #[test]
    fn test_pamt_roundtrip() {
        let path = fixture_or_skip!(find_pamt, "0.pamt");
        let data = std::fs::read(&path).expect("pamt file not found");
        let pamt = PackMeta::parse(&data, None).unwrap();
        let written = pamt.to_bytes().unwrap();
        assert_eq!(written.len(), data.len(), "pamt roundtrip size mismatch");
        assert_eq!(written, data, "pamt roundtrip bytes mismatch");
    }

    fn extract_paloc_data() -> Option<Vec<u8>> {
        extract_paloc_from_archive("0020", "localizationstring_eng.paloc")
    }

    fn extract_paloc_from_archive(group: &str, file_name: &str) -> Option<Vec<u8>> {
        use crate::binary::paz;

        let game_dir = find_game_dir()?;
        let group_dir = game_dir.join(group);
        let pamt_path = group_dir.join("0.pamt");
        if !pamt_path.exists() {
            return None;
        }
        let pamt_data = std::fs::read(&pamt_path)
            .unwrap_or_else(|e| panic!("{}: {}", pamt_path.display(), e));
        let pamt = PackMeta::parse(&pamt_data, None).unwrap();

        let dir = pamt.directories.iter()
            .find(|d| d.path == "gamedata/stringtable/binary__")
            .expect("directory not found in pamt");
        let file = dir.files.iter()
            .find(|f| f.name == file_name)
            .unwrap_or_else(|| panic!("{} not found", file_name));

        Some(paz::extract_file(
            &group_dir,
            file,
            "gamedata/stringtable/binary__",
            &pamt.header.encrypt_info.encrypt_info,
        ).unwrap())
    }

    #[test]
    fn test_paloc_parse() {
        let Some(data) = extract_paloc_data() else {
            eprintln!("SKIP: paloc fixture (game dir or 0020/0.pamt not found)");
            return;
        };
        let paloc = LocalizationFile::parse(&data).unwrap();
        println!("PALOC: {} entries", paloc.entries.len());
        for entry in paloc.entries.iter().take(5) {
            println!(
                "  id={}, key={}, value={}",
                entry.unk_id,
                entry.string_key.data,
                &entry.string_value.data[..entry.string_value.data.len().min(80)],
            );
        }
        assert!(!paloc.entries.is_empty(), "should have entries");
    }

    #[test]
    fn test_paloc_roundtrip() {
        let Some(data) = extract_paloc_data() else {
            eprintln!("SKIP: paloc fixture (game dir or 0020/0.pamt not found)");
            return;
        };
        let paloc = LocalizationFile::parse(&data).unwrap();
        let written = paloc.to_bytes().unwrap();
        assert_eq!(written.len(), data.len(), "paloc roundtrip size mismatch");
        assert_eq!(written, data, "paloc roundtrip bytes mismatch");
    }

    #[test]
    fn test_paloc_kor_parse() {
        let Some(data) = extract_paloc_from_archive("0019", "localizationstring_kor.paloc") else {
            eprintln!("SKIP: paloc-kor fixture (game dir or 0019/0.pamt not found)");
            return;
        };
        let paloc = LocalizationFile::parse(&data).unwrap();
        println!("PALOC KOR: {} entries", paloc.entries.len());
        for entry in paloc.entries.iter().take(5) {
            let preview: String = entry.string_value.data.chars().take(40).collect();
            println!(
                "  id={}, key={}, value={}",
                entry.unk_id,
                entry.string_key.data,
                preview,
            );
        }
        assert!(!paloc.entries.is_empty(), "should have entries");
    }

    #[test]
    fn test_paloc_kor_roundtrip() {
        let Some(data) = extract_paloc_from_archive("0019", "localizationstring_kor.paloc") else {
            eprintln!("SKIP: paloc-kor fixture (game dir or 0019/0.pamt not found)");
            return;
        };
        let paloc = LocalizationFile::parse(&data).unwrap();
        let written = paloc.to_bytes().unwrap();
        assert_eq!(written.len(), data.len(), "paloc kor roundtrip size mismatch");
        assert_eq!(written, data, "paloc kor roundtrip bytes mismatch");
    }

    #[test]
    fn test_game_dir_papgt_pamt_checksums() {
        use crate::crypto::checksum;

        let game_dir = fixture_or_skip!(find_game_dir, "Crimson Desert game dir");
        let papgt_path = game_dir.join("meta/0.papgt");
        let papgt_data = std::fs::read(&papgt_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", papgt_path.display(), e));
        let papgt = PackGroupTreeMeta::parse(&papgt_data).unwrap();

        println!("Validating {} PAPGT entries against game directory...", papgt.entries.len());

        let mut validated = 0;
        let mut skipped = 0;
        for entry in &papgt.entries {
            let pamt_path = game_dir
                .join(&entry.group_name)
                .join("0.pamt");

            if !pamt_path.exists() {
                println!("  SKIP group={} (no 0.pamt found)", entry.group_name);
                skipped += 1;
                continue;
            }

            let pamt_data = std::fs::read(&pamt_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", pamt_path.display(), e));

            // Compute checksum of entire pamt file data after header (8 bytes header)
            // The PAPGT stores pack_meta_checksum which is validated against post-header data
            let pamt_header_size = 4 + 2 + 2 + 1 + 3; // checksum + count + unknown0 + encrypt_info
            let post_header = &pamt_data[pamt_header_size..];
            let computed = checksum::calculate_checksum(post_header);

            assert_eq!(
                computed, entry.entry.pack_meta_checksum,
                "Checksum mismatch for group={}: computed={:#010x}, papgt expected={:#010x}",
                entry.group_name, computed, entry.entry.pack_meta_checksum,
            );

            // Also verify full parse with the expected CRC succeeds
            PackMeta::parse(&pamt_data, Some(entry.entry.pack_meta_checksum))
                .unwrap_or_else(|e| panic!("parse failed for group={}: {}", entry.group_name, e));

            println!("  OK   group={}, checksum={:#010x}", entry.group_name, computed);
            validated += 1;
        }

        println!("Validated: {}, Skipped: {}", validated, skipped);
        assert!(validated > 0, "should have validated at least one pamt file");
    }
}
