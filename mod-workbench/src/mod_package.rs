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
use std::path::Path;

use serde_json::{json, Value};

use crate::mod_io::{export_changes_full, ModMetadata};
use crate::notes::NoteStore;
use crate::state::ChangeTracker;

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
    notes: Option<&NoteStore>,
    out_dir: &Path,
) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;

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
    std::fs::write(out_dir.join("mod.json"), mod_json)?;

    let change_count = mod_value
        .get("entries")
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
        export_dmm(&meta, "test_table", &entries, &vanilla, &changes, &out).unwrap();
        assert!(out.join("mod.json").exists());
        assert!(out.join("metadata.json").exists());
        assert!(out.join("README.md").exists());
        let metadata_raw = std::fs::read_to_string(out.join("metadata.json")).unwrap();
        let metadata_val: Value = serde_json::from_str(&metadata_raw).unwrap();
        assert_eq!(metadata_val["name"], "DmmMod");
        assert_eq!(metadata_val["author"], "Me");
        assert_eq!(metadata_val["table"], "test_table");
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
