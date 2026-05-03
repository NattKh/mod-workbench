//! Local mod library — `%APPDATA%/Crimson/ModWorkbench/mods/`.
//!
//! Users drop mod JSON files into this directory (or import them via the
//! Library panel) and the workbench scans the dir, parsing each one through
//! [`crate::conflict::load_mod`] to harvest metadata + a per-table change
//! summary for the UI.
//!
//! ## On-disk layout
//!
//! ```text
//! %APPDATA%/Crimson/ModWorkbench/
//!   mods/
//!     foo_iteminfo_buff.json
//!     bar_storeinfo_unlock.json
//!   profiles.json
//! ```
//!
//! ## Why metadata is cached on `LibraryMod`
//!
//! The library panel renders mod cards (name, author, version, change count,
//! tables touched). Re-parsing every JSON every frame would be wasteful, so
//! [`scan_library`] resolves the metadata once at scan time and stuffs it into
//! [`LibraryMod`]; the panel renders straight off the snapshot. Re-running the
//! scan is the way to pick up edits to the JSON files on disk.
//!
//! Per-mod errors are demoted to "skip + log" — one malformed file in the
//! library shouldn't stop the rest from loading. The [`ScanReport`] returned
//! by [`scan_library`] surfaces both successes and failures so the UI can
//! show the user *why* a file is missing instead of silently dropping it.

use std::path::{Path, PathBuf};

use crate::conflict::{self, LoadedMod};

/// One mod sitting in the library directory, post-scan.
///
/// Wraps [`LoadedMod`] (the parsed change map + meta) with a couple of
/// summary fields the UI needs at render time. We deliberately don't surface
/// the raw `LoadedMod` to the UI because the panel never needs the full
/// per-field change map — it only needs counts and the list of touched
/// table names for the card.
#[derive(Clone)]
pub struct LibraryMod {
    /// Path on disk under [`library_dir`]. Used as the stable identifier in
    /// profiles (so `Profile::active_mods` can record "this exact file") and
    /// to delete or open the file.
    pub path: PathBuf,
    /// Display metadata harvested from the mod's `_meta` block, falling back
    /// to the file stem for `name`.
    pub metadata: ModMetadata,
    /// Total `(table, key, field)` triples this mod sets. Cheap "size"
    /// indicator for the UI card.
    pub change_count: usize,
    /// Sorted, deduped list of table dispatch names this mod touches.
    /// Renders as a comma-separated tag line on the card so a user can see
    /// at a glance whether a "buff mod" only edits iteminfo or also
    /// reaches into storeinfo / dropsetinfo.
    pub tables_touched: Vec<String>,
}

/// Display-only metadata pulled from a mod file.
#[derive(Clone)]
pub struct ModMetadata {
    pub name: String,
    pub author: Option<String>,
    pub version: Option<String>,
}

impl From<&LoadedMod> for ModMetadata {
    fn from(m: &LoadedMod) -> Self {
        Self {
            name: m.name.clone(),
            author: m.author.clone(),
            version: m.version.clone(),
        }
    }
}

/// Result of [`scan_library`].
///
/// The UI surfaces `errors` via toasts so a user with one broken mod in the
/// library still sees the rest of their collection.
pub struct ScanReport {
    pub mods: Vec<LibraryMod>,
    /// `(path, message)` for every file the scanner tried to load and failed
    /// on. Present so the UI can attribute the failure to a specific file.
    pub errors: Vec<(PathBuf, String)>,
}

/// Resolved library directory: `%APPDATA%/Crimson/ModWorkbench/mods/`.
///
/// Returns `None` only when the platform has no usable home/data dir —
/// callers should treat that as "library disabled" rather than an error.
pub fn library_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
    Some(dirs.data_dir().join("mods"))
}

/// Walk the library dir, parse every supported file, return a populated
/// [`ScanReport`].
///
/// Side effects:
/// - Creates the library directory if it doesn't already exist (so a fresh
///   install has somewhere to drop files).
///
/// Skips:
/// - Subdirectories (v1 is flat — no nested folders).
/// - Files whose extension isn't `.json` or `.modpkg` (the latter reserved
///   for a future bundle format; current parser still tries to load it as
///   JSON, since `load_mod` is shape-driven).
pub fn scan_library() -> std::io::Result<ScanReport> {
    let dir = match library_dir() {
        Some(d) => d,
        None => {
            return Ok(ScanReport {
                mods: Vec::new(),
                errors: Vec::new(),
            });
        }
    };

    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    let mut mods = Vec::new();
    let mut errors = Vec::new();

    for entry in std::fs::read_dir(&dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push((dir.clone(), e.to_string()));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                errors.push((path.clone(), e.to_string()));
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        // Filter by extension so we don't try to parse e.g. `.txt` notes a
        // user dropped next to their mod files.
        let supported = matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("json") | Some("modpkg")
        );
        if !supported {
            continue;
        }

        match conflict::load_mod(&path) {
            Ok(loaded) => mods.push(library_mod_from_loaded(path, loaded)),
            Err(e) => errors.push((path, e.to_string())),
        }
    }

    // Stable display order so the UI doesn't reshuffle on every refresh.
    // Sorting by name (case-insensitive) matches the user's mental model of
    // "alphabetical" without leaking filesystem order.
    mods.sort_by(|a, b| {
        a.metadata
            .name
            .to_lowercase()
            .cmp(&b.metadata.name.to_lowercase())
    });

    Ok(ScanReport { mods, errors })
}

/// Copy `source_path` (file or directory) into the library dir. Returns the
/// new path under the library so the caller can immediately add it to a
/// profile.
///
/// Rules:
/// - If `source_path` is already inside the library dir, this is a no-op
///   that returns the existing path (lets the UI use one button for "import
///   from disk" / "ensure in library").
/// - If a file with the same name already exists, we append `_<N>` to the
///   stem until we find a free slot, so importing the same file twice
///   produces `foo.json` and `foo_1.json` rather than overwriting.
/// - Directory imports recursively copy. Reserved for a future bundle
///   format; right now mods are single files but the API is shape-stable.
pub fn import_to_library(source_path: &Path) -> std::io::Result<PathBuf> {
    let dir = library_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no platform data directory available for the library",
        )
    })?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    // No-op when the source is already living under the library dir. We
    // canonicalize when possible because a user might pick a path with
    // different casing on Windows.
    let src_canon = std::fs::canonicalize(source_path).unwrap_or_else(|_| source_path.to_path_buf());
    let dir_canon = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    if src_canon.starts_with(&dir_canon) {
        return Ok(src_canon);
    }

    let file_name = source_path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("source path has no file name: {}", source_path.display()),
            )
        })?
        .to_owned();

    let dest = unique_dest_path(&dir, Path::new(&file_name));

    if source_path.is_dir() {
        copy_dir_recursive(source_path, &dest)?;
    } else {
        std::fs::copy(source_path, &dest)?;
    }

    Ok(dest)
}

/// Remove a mod file (or directory) from the library.
///
/// Returns `NotFound` rather than silently succeeding if the path doesn't
/// exist, so the UI can surface a "file already gone — refresh?" toast
/// instead of a misleading success.
pub fn delete_from_library(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", path.display()),
        ));
    }

    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Convert a parsed [`LoadedMod`] into the lightweight [`LibraryMod`] the
/// UI renders. Computes `tables_touched` once so the panel doesn't have to
/// dedup the change map every frame.
fn library_mod_from_loaded(path: PathBuf, loaded: LoadedMod) -> LibraryMod {
    let metadata = ModMetadata::from(&loaded);
    let change_count = loaded.change_count();

    let mut seen = std::collections::BTreeSet::new();
    for (table, _key) in loaded.changes.keys() {
        seen.insert(table.clone());
    }
    let tables_touched: Vec<String> = seen.into_iter().collect();

    LibraryMod {
        path,
        metadata,
        change_count,
        tables_touched,
    }
}

/// Pick a destination path under `dir` for a candidate file name, suffixing
/// the stem with `_1`, `_2`, ... until we find a free slot.
fn unique_dest_path(dir: &Path, candidate: &Path) -> PathBuf {
    let initial = dir.join(candidate);
    if !initial.exists() {
        return initial;
    }

    let stem = candidate
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mod".to_string());
    let ext = candidate
        .extension()
        .map(|s| s.to_string_lossy().into_owned());

    for i in 1..u32::MAX {
        let new_name = match &ext {
            Some(e) => format!("{}_{}.{}", stem, i, e),
            None => format!("{}_{}", stem, i),
        };
        let candidate = dir.join(new_name);
        if !candidate.exists() {
            return candidate;
        }
    }

    // Pathological case — fall back to the original; an io::Error from the
    // copy is preferable to looping forever.
    initial
}

/// Recursive directory copy — `std::fs` doesn't ship one. We only support a
/// shallow tree (mod folders are flat in v1), but writing it as a recursive
/// walker keeps us honest if a future bundle format introduces nesting.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: build a minimal valid v3 field JSON file at `path`.
    fn write_mod(path: &Path, name: &str, table: &str) {
        let body = serde_json::json!({
            "format": "crimson_field_json_v3",
            "table": table,
            "entries": [
                { "key": 1, "fields": { "hp": 100 } }
            ],
            "_meta": { "name": name, "author": "tester", "version": "1.0" }
        });
        fs::write(path, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    }

    #[test]
    fn unique_dest_path_returns_initial_when_free() {
        let tmp = std::env::temp_dir().join(format!(
            "mod_lib_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let candidate = Path::new("foo.json");
        let p = unique_dest_path(&tmp, candidate);
        assert_eq!(p, tmp.join("foo.json"));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn unique_dest_path_suffixes_on_collision() {
        let tmp = std::env::temp_dir().join(format!(
            "mod_lib_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        write_mod(&tmp.join("foo.json"), "Foo", "iteminfo");
        let p = unique_dest_path(&tmp, Path::new("foo.json"));
        assert_eq!(p, tmp.join("foo_1.json"));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn library_mod_collects_tables_touched() {
        let tmp = std::env::temp_dir().join(format!(
            "mod_lib_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("multi.json");
        let body = serde_json::json!({
            "format": 3,
            "targets": [
                {
                    "file": "iteminfo.pabgb",
                    "intents": [{ "key": 1, "field": "hp", "op": "set", "new": 99 }]
                },
                {
                    "file": "skill.pabgb",
                    "intents": [{ "key": 7, "field": "cd", "op": "set", "new": 0.5 }]
                },
            ]
        });
        fs::write(&p, body.to_string()).unwrap();
        let loaded = conflict::load_mod(&p).unwrap();
        let lm = library_mod_from_loaded(p, loaded);
        assert_eq!(lm.tables_touched, vec!["iteminfo".to_string(), "skill".to_string()]);
        assert_eq!(lm.change_count, 2);
        fs::remove_dir_all(&tmp).ok();
    }
}
