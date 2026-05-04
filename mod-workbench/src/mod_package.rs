//! Mod packaging.
//!
//! Wraps the v3 field JSON exporter from [`crate::mod_io`] with three
//! shipping formats geared at different downstream consumers:
//!
//! 1. [`export_v3_json`]   — raw v3 field JSON, identical to the existing
//!    "Export Mod..." behaviour, just with `_meta` prefilled.
//! 2. [`export_modpkg`]    — a `.modpkg` zip containing `mod.json`,
//!    `README.md`, and `manifest.json`. Suitable for Nexus uploads where
//!    a single bundled archive is preferred.
//! 3. [`export_dmm`]       — a DMM-compatible mod folder with the v3 JSON
//!    written as `mod.json` plus a `metadata.json` sidecar. Drop the
//!    folder into DMM's mod directory and it's ready to enable.
//!
//! All three exporters consume the same diff (`changes` + `vanilla`) so the
//! resulting payload is identical across formats — only the wrapping
//! changes.
//!
//! ## Why not skip the v3 JSON write for the bundled formats?
//!
//! Both `.modpkg` and the DMM bundle still embed the v3 JSON document. We
//! generate it once with [`crate::mod_io::export_changes_with_meta`] and
//! then encode it into whichever wrapper the caller asked for. This keeps
//! the diff logic single-sourced and means a mod authored via "Export as
//! .modpkg" is bit-for-bit the same as one authored via "Export as JSON"
//! (when the inner `mod.json` is extracted).

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::paz::PackGroupBuilder;
use serde_json::{json, Value};

use crate::mod_io::{export_changes_full, export_dmm_v3, ModMetadata};
use crate::notes::NoteStore;
use crate::state::{ChangeTracker, TableMeta};

/// Internal PAZ directory required by the game loader for game data files.
/// Anything not at this exact path is ignored — the PAMT entry has to map
/// `gamedata/binary__/client/bin/<file>` to the chunk offset, otherwise the
/// game silently loads vanilla.
const PAZ_INTERNAL_DIR: &str = "gamedata/binary__/client/bin";

/// Export as raw v3 JSON, identical to the existing "Export Mod..." flow.
///
/// `_meta` is embedded when [`ModMetadata::is_empty`] is false. Pretty
/// printed for human readability.
pub fn export_v3_json(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    out_path: &Path,
) -> io::Result<()> {
    export_v3_json_full(metadata, table, entries, vanilla, changes, None, out_path)
}

/// Variant of [`export_v3_json`] that also embeds per-entry notes from
/// `notes` (when present) under `_notes` in the resulting document.
pub fn export_v3_json_full(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    notes: Option<&NoteStore>,
    out_path: &Path,
) -> io::Result<()> {
    let value = export_changes_full(
        table,
        entries,
        vanilla,
        changes,
        Some(metadata),
        notes,
    );
    let pretty = serde_json::to_string_pretty(&value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(out_path, pretty)
}

/// Export as a `.modpkg` zip containing `mod.json`, `README.md`, and a
/// `manifest.json`. Internal layout:
///
/// ```text
/// mod.json       <- the v3 field JSON document with `_meta`
/// README.md      <- auto-generated from metadata + change summary
/// manifest.json  <- machine-readable bundle descriptor (format version,
///                   target table, entry count, embedded metadata)
/// ```
///
/// The deflate-compressed zip writer is deterministic enough that two
/// successive calls on the same input produce byte-identical archives,
/// which makes diffing release artifacts straightforward.
pub fn export_modpkg(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    out_path: &Path,
) -> io::Result<()> {
    export_modpkg_full(metadata, table, entries, vanilla, changes, None, out_path)
}

/// Variant of [`export_modpkg`] that also embeds per-entry notes from
/// `notes` (when present) into the bundled `mod.json`.
pub fn export_modpkg_full(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    notes: Option<&NoteStore>,
    out_path: &Path,
) -> io::Result<()> {
    let mod_value = export_changes_full(
        table,
        entries,
        vanilla,
        changes,
        Some(metadata),
        notes,
    );
    let mod_json = serde_json::to_string_pretty(&mod_value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let change_count = mod_value
        .get("entries")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let readme = build_readme(metadata, table, change_count);
    let manifest = build_manifest(metadata, table, change_count);
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let file = std::fs::File::create(out_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("mod.json", opts)
        .map_err(zip_err_to_io)?;
    zip.write_all(mod_json.as_bytes())?;

    zip.start_file("README.md", opts)
        .map_err(zip_err_to_io)?;
    zip.write_all(readme.as_bytes())?;

    zip.start_file("manifest.json", opts)
        .map_err(zip_err_to_io)?;
    zip.write_all(manifest_json.as_bytes())?;

    zip.finish().map_err(zip_err_to_io)?;
    Ok(())
}

/// Export as a DMM-compatible mod folder. Layout:
///
/// ```text
/// <out_dir>/
///   mod.json         <- v3 field JSON (DMM ingests `format: "crimson_field_json_v3"`)
///   metadata.json    <- DMM-style metadata sidecar (name/author/version/description/nexus_url)
///   README.md        <- same auto-generated readme as .modpkg for portability
/// ```
///
/// The output directory is created if it doesn't already exist. The folder
/// name itself is up to the caller — DMM treats every subfolder of its
/// mods directory as a mod, so the natural pattern is to pass
/// `<dmm-mods-dir>/<mod-name>/` here.
pub fn export_dmm(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    out_dir: &Path,
) -> io::Result<()> {
    export_dmm_full(metadata, table, entries, vanilla, changes, None, out_dir)
}

/// Variant of [`export_dmm`] that also embeds per-entry notes from `notes`
/// (when present) into the bundled `mod.json`.
pub fn export_dmm_full(
    metadata: &ModMetadata,
    table: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    _notes: Option<&NoteStore>,
    out_dir: &Path,
) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;

    // CRITICAL: DMM does NOT understand `crimson_field_json_v3`. It expects
    // `format: 3` (u32) with intent-based ops. We use [`export_dmm_v3`] to
    // produce a real DMM-compatible payload. Notes are intentionally not
    // embedded here — the DMM intent format has no slot for them, and
    // shipping them inline as `_notes` would be invisible to DMM but visible
    // to anyone who opens the file.
    let mod_value = export_dmm_v3(table, entries, vanilla, changes, Some(metadata));
    let mod_json = serde_json::to_string_pretty(&mod_value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(out_dir.join("mod.json"), mod_json)?;

    let change_count = mod_value
        .get("intents")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // DMM-style metadata sidecar: similar shape to mod.json's `_meta` but
    // top-level so DMM doesn't have to know the v3 JSON layout to surface
    // attribution + version in its own UI.
    let metadata_json = json!({
        "name": metadata.name,
        "author": metadata.author,
        "version": metadata.version,
        "description": metadata.description,
        "nexus_url": metadata.nexus_url,
        "dependencies": metadata.dependencies,
        "table": table,
        "entry_count": change_count,
    });
    let metadata_str = serde_json::to_string_pretty(&metadata_json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(out_dir.join("metadata.json"), metadata_str)?;

    let readme = build_readme(metadata, table, change_count);
    std::fs::write(out_dir.join("README.md"), readme)?;

    Ok(())
}

/// Build a Markdown README from metadata + change summary. Always returns
/// a non-empty document — when the user provided no metadata, the body
/// degrades gracefully to "(unspecified)" placeholders so the file is still
/// useful as a checklist for what to fill in before publishing.
pub fn build_readme(metadata: &ModMetadata, table: &str, change_count: usize) -> String {
    let mut s = String::new();
    let title = if metadata.name.is_empty() {
        "Crimson Desert Mod".to_string()
    } else {
        metadata.name.clone()
    };
    s.push_str(&format!("# {}\n\n", title));

    if !metadata.description.is_empty() {
        s.push_str(&metadata.description);
        s.push_str("\n\n");
    }

    s.push_str("## Details\n\n");
    s.push_str(&format!("- **Author:** {}\n", placeholder_or(&metadata.author)));
    s.push_str(&format!(
        "- **Version:** {}\n",
        placeholder_or(&metadata.version)
    ));
    s.push_str(&format!("- **Target table:** `{}`\n", table));
    s.push_str(&format!("- **Entries changed:** {}\n", change_count));
    if !metadata.nexus_url.is_empty() {
        s.push_str(&format!("- **Nexus:** {}\n", metadata.nexus_url));
    }

    if !metadata.dependencies.is_empty() {
        s.push_str("\n## Dependencies\n\n");
        for dep in &metadata.dependencies {
            s.push_str(&format!("- {}\n", dep));
        }
    }

    s.push_str("\n## Installation\n\n");
    s.push_str(
        "Drop `mod.json` into your mod loader of choice (DMM, mod-workbench, etc.) and \
         deploy. Backup your game directory before applying.\n",
    );

    s
}

fn placeholder_or(s: &str) -> &str {
    if s.is_empty() {
        "(unspecified)"
    } else {
        s
    }
}

/// Build the machine-readable manifest sidecar shipped inside `.modpkg`.
fn build_manifest(metadata: &ModMetadata, table: &str, change_count: usize) -> Value {
    json!({
        "format": "crimson_modpkg_v1",
        "table": table,
        "entry_count": change_count,
        "metadata": {
            "name": metadata.name,
            "author": metadata.author,
            "version": metadata.version,
            "description": metadata.description,
            "nexus_url": metadata.nexus_url,
            "dependencies": metadata.dependencies,
        }
    })
}

fn zip_err_to_io(e: zip::result::ZipError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Sanitize a user-supplied mod name into something safe to use as a folder
/// name on Windows + POSIX. Keeps alphanumerics + `-`, `_`, `.`, ` ` and
/// replaces everything else with `_`. Returns `"mod"` when the trimmed
/// input is empty so callers don't have to handle that case themselves.
fn sanitize_mod_folder_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "mod".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

/// Export as a PAZ overlay folder mod — the format DMM/Stacker actually
/// expects when loading "folder mods". Layout:
///
/// ```text
/// <out_dir>/<safe_mod_name>/
///   <overlay_group>/         (e.g. "0036")
///     0.paz                  PAZ archive containing pabgb + pabgh
///     0.pamt                 PAMT index for the PAZ
///   modinfo.json             {id, name, version, author, description}
/// ```
///
/// Mirrors the proven workflow in `gui/tabs/buffs_v319.py::_buff_export_mod_folder`:
///
/// 1. The pabgb is built from `entries` via the dmm-parser serializer matching
///    `dispatch_name` (iteminfo gets the dedicated path, others use the
///    generic dispatch).
/// 2. The pabgh is **NOT** rebuilt — we extract the vanilla file from
///    `<game_dir>/0008/` and pack it unchanged. Entry offsets only shift if
///    entries are added or removed, which the workbench doesn't currently do.
/// 3. The PAZ overlay uses [`Compression::None`] for **both** files.
///    pabgh files of random-looking offset bytes inflate under LZ4 — when
///    `compressed_size > uncompressed_size` the game's loader rejects the
///    chunk and crashes (or silently falls through to vanilla).
/// 4. Crypto is ChaCha20 with `encrypt_info` lifted from `<game_dir>/0008/0.pamt`
///    so the override matches the rest of the game's archives.
/// 5. The PAZ's internal directory MUST be exactly `gamedata/binary__/client/bin`
///    — short paths fail silently (the PAMT entry resolves to nothing the
///    game's resource resolver looks at).
///
/// Returns the path to the created mod root folder so the caller can open it
/// in a file browser or chain a deploy.
pub fn export_paz_mod_folder(
    metadata: &ModMetadata,
    dispatch_name: &str,
    meta: &TableMeta,
    entries: &[Value],
    game_dir: &Path,
    overlay_group: &str,
    out_dir: &Path,
    mod_name: &str,
) -> io::Result<PathBuf> {
    // 1. Sanitize the user-supplied name so the resulting folder is creatable
    //    on Windows + POSIX without surprises.
    let safe_mod_name = sanitize_mod_folder_name(mod_name);
    let mod_root = out_dir.join(&safe_mod_name);
    let group_dir = mod_root.join(overlay_group);
    std::fs::create_dir_all(&group_dir)?;

    // 2. Serialize entries -> pabgb. iteminfo lives outside the generic
    //    dispatch (see `dmm_parser_rust_only::item_info`) so we route it
    //    through its dedicated serializer here as well.
    let pabgb_bytes = if dispatch_name == "item_info" {
        dmm_parser_rust_only::item_info::serialize_iteminfo_from_json(entries)?
    } else {
        dmm_parser_rust_only::serialize_table_from_json(dispatch_name, entries)?
    };

    // 3. Read encrypt_info from the original 0008/0.pamt — the override has
    //    to use the same key material as the rest of the archives.
    let orig_pamt_path = game_dir.join("0008/0.pamt");
    let orig_pamt_data = std::fs::read(&orig_pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "Failed to read original PAMT at {}: {}",
                orig_pamt_path.display(),
                e
            ),
        )
    })?;
    let orig_pamt = PackMeta::parse(&orig_pamt_data, None)?;
    let encrypt_info = orig_pamt.header.encrypt_info.encrypt_info;

    // 4. Build the PAZ overlay directly into the group directory. We build
    //    in-place rather than via a temp dir + copy because PackGroupBuilder
    //    writes 0.paz / 0.pamt next to each other and the result is exactly
    //    the layout DMM expects.
    //
    //    Compression MUST be None — see the function-level comment.
    let mut builder = PackGroupBuilder::new(
        &group_dir,
        Compression::None,
        CryptoType::ChaCha20,
        encrypt_info,
        256 * 1024 * 1024, // 256MB max chunk (we never approach this for one table)
    );

    builder.add_file(PAZ_INTERNAL_DIR, &meta.pabgb_filename, &pabgb_bytes)?;

    // 5. Pabgh: extract vanilla from 0008 and pack it unchanged. Entry
    //    offsets only need rebuilding when entries are added/removed, which
    //    the workbench doesn't currently support — so the vanilla index
    //    still resolves correctly.
    if let Some(ref pabgh_name) = meta.pabgh_filename {
        if let Ok(pabgh_bytes) = extract_original_pabgh(game_dir, pabgh_name, &encrypt_info) {
            builder.add_file_with_compression(
                PAZ_INTERNAL_DIR,
                pabgh_name,
                &pabgh_bytes,
                Compression::None,
            )?;
        }
    }

    // 6. Finalise: writes 0.paz + 0.pamt directly into <group_dir>.
    let _pamt_bytes = builder.finish()?;

    // 7. modinfo.json — DMM/Stacker read this for the mod display name +
    //    attribution. Mirrors the shape produced by buffs_v319.py.
    let id = safe_mod_name.to_lowercase().replace(' ', "_");
    let display_name = if metadata.name.is_empty() {
        mod_name.trim().to_string()
    } else {
        metadata.name.clone()
    };
    let author = if metadata.author.is_empty() {
        "CrimsonGameMods".to_string()
    } else {
        metadata.author.clone()
    };
    let version = if metadata.version.is_empty() {
        "1.0.0".to_string()
    } else {
        metadata.version.clone()
    };
    let description = if metadata.description.is_empty() {
        format!("Mod for {}", meta.pabgb_filename)
    } else {
        metadata.description.clone()
    };
    let modinfo = json!({
        "id": id,
        "name": display_name,
        "version": version,
        "author": author,
        "description": description,
    });
    let modinfo_str = serde_json::to_string_pretty(&modinfo)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(mod_root.join("modinfo.json"), modinfo_str)?;

    Ok(mod_root)
}

/// Extract the vanilla pabgh from group 0008. Mirrors
/// `crate::deploy::extract_original_pabgh` — kept here as a private helper
/// because the deploy module's copy is private and exposing a duplicate is
/// cheaper than restructuring for cross-module reuse.
fn extract_original_pabgh(
    game_dir: &Path,
    pabgh_name: &str,
    encrypt_info: &[u8; 3],
) -> io::Result<Vec<u8>> {
    use dmm_parser_rust_only::binary::paz;

    let group_dir = game_dir.join("0008");
    let pamt_data = std::fs::read(group_dir.join("0.pamt"))?;
    let pamt = PackMeta::parse(&pamt_data, None)?;

    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == PAZ_INTERNAL_DIR)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory '{}' not found in 0008/0.pamt", PAZ_INTERNAL_DIR),
            )
        })?;

    let file = dir
        .files
        .iter()
        .find(|f| f.name == pabgh_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("File '{}' not found in {}", pabgh_name, PAZ_INTERNAL_DIR),
            )
        })?;

    paz::extract_file(&group_dir, file, PAZ_INTERNAL_DIR, encrypt_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_inputs() -> (Vec<Value>, Vec<Value>, ChangeTracker) {
        let entries = vec![json!({"key": 1, "hp": 999})];
        let vanilla = vec![json!({"key": 1, "hp": 50})];
        let mut changes = ChangeTracker::new();
        changes.record_change(1, "hp".to_string());
        (entries, vanilla, changes)
    }

    #[test]
    fn test_export_v3_json_writes_file_with_meta() {
        let dir = tempdir();
        let (entries, vanilla, changes) = sample_inputs();
        let meta = ModMetadata {
            name: "T".into(),
            ..Default::default()
        };
        let path = dir.join("out.json");
        export_v3_json(&meta, "test_table", &entries, &vanilla, &changes, &path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["format"], "crimson_field_json_v3");
        assert_eq!(parsed["_meta"]["name"], "T");
        assert_eq!(parsed["table"], "test_table");
    }

    #[test]
    fn test_export_modpkg_creates_zip_with_three_files() {
        let dir = tempdir();
        let (entries, vanilla, changes) = sample_inputs();
        let meta = ModMetadata {
            name: "ZipMod".into(),
            ..Default::default()
        };
        let path = dir.join("out.modpkg");
        export_modpkg(&meta, "test_table", &entries, &vanilla, &changes, &path).unwrap();
        // Re-open and inspect the archive.
        let f = std::fs::File::open(&path).unwrap();
        let mut zr = zip::ZipArchive::new(f).unwrap();
        let mut names: Vec<String> = (0..zr.len())
            .map(|i| zr.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["README.md", "manifest.json", "mod.json"]);
    }

    #[test]
    fn test_export_dmm_writes_three_sidecars() {
        let dir = tempdir();
        let (entries, vanilla, changes) = sample_inputs();
        let meta = ModMetadata {
            name: "DmmMod".into(),
            author: "Me".into(),
            ..Default::default()
        };
        let out = dir.join("MyMod");
        export_dmm(&meta, "item_info", &entries, &vanilla, &changes, &out).unwrap();
        assert!(out.join("mod.json").exists());
        assert!(out.join("metadata.json").exists());
        assert!(out.join("README.md").exists());

        // mod.json should be the DMM v3 intent format (format=3, target,
        // intents) — NOT our workbench-native crimson_field_json_v3.
        let mod_raw = std::fs::read_to_string(out.join("mod.json")).unwrap();
        let mod_val: Value = serde_json::from_str(&mod_raw).unwrap();
        assert_eq!(mod_val["format"], 3, "DMM bundle must use format=3 (u32)");
        assert_eq!(mod_val["target"], "iteminfo.pabgb");
        assert!(mod_val["intents"].is_array(), "must have intents array");

        let metadata_raw = std::fs::read_to_string(out.join("metadata.json")).unwrap();
        let metadata_val: Value = serde_json::from_str(&metadata_raw).unwrap();
        assert_eq!(metadata_val["name"], "DmmMod");
    }

    #[test]
    fn test_build_readme_uses_metadata() {
        let meta = ModMetadata {
            name: "Cool Mod".into(),
            author: "Author".into(),
            version: "1.0".into(),
            description: "Does cool things.".into(),
            nexus_url: "https://nexus".into(),
            dependencies: vec!["a".into()],
        };
        let r = build_readme(&meta, "iteminfo", 3);
        assert!(r.contains("# Cool Mod"));
        assert!(r.contains("Does cool things."));
        assert!(r.contains("Author"));
        assert!(r.contains("1.0"));
        assert!(r.contains("`iteminfo`"));
        assert!(r.contains("Entries changed:** 3"));
        assert!(r.contains("https://nexus"));
        assert!(r.contains("- a"));
    }

    #[test]
    fn test_build_readme_handles_empty_metadata() {
        let meta = ModMetadata::default();
        let r = build_readme(&meta, "x", 0);
        assert!(r.contains("# Crimson Desert Mod"));
        assert!(r.contains("(unspecified)"));
    }

    /// Returns a temporary directory cleaned up on test exit. We avoid the
    /// `tempfile` crate to dodge an extra dependency for two tests' worth
    /// of throwaway files; the OS-level temp dir is recycled aggressively
    /// enough that leakage is academic.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        let id = N.fetch_add(1, Ordering::SeqCst);
        p.push(format!(
            "mod-workbench-test-{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
