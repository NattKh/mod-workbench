//! Mod conflict detection.
//!
//! Loads multiple field-JSON mods from disk and produces a [`ConflictReport`]
//! describing which entries each mod touches and where they collide. This is
//! a viewer-only feature for v1 — the report exposes the conflicts but does
//! not perform any merging.
//!
//! ## Supported input formats
//!
//! Two on-disk shapes are accepted, both flattened into the same in-memory
//! [`LoadedMod::changes`] map keyed by `(table_name, entry_key)`:
//!
//! 1. **`crimson_field_json_v3`** (the format mod-workbench itself exports):
//!    ```json
//!    {
//!      "format": "crimson_field_json_v3",
//!      "table": "iteminfo",
//!      "entries": [
//!        { "key": 12345, "fields": { "cooltime": 5, "max_stack_count": 99 } }
//!      ]
//!    }
//!    ```
//!
//! 2. **DMM v3 intent format** (`format: 3`, single- or multi-target):
//!    ```json
//!    {
//!      "format": 3,
//!      "target": "iteminfo.pabgb",
//!      "intents": [
//!        { "entry": "Item_Foo", "key": 12345, "field": "cooltime",
//!          "op": "set", "new": 5 }
//!      ]
//!    }
//!    ```
//!    Multi-target uses `"targets": [{ "file": "...", "intents": [...] }]`
//!    instead of top-level `target`+`intents`.
//!
//! Both shapes converge on the same `(table, key) -> {field_path -> value}`
//! representation, so analysis treats them identically.
//!
//! ## Conflict semantics
//!
//! For every unordered pair of mods we walk the entries each one changes:
//!
//! - **DirectConflict**: both mods set the *same* `(table, key, field_path)`
//!   to *different* values. This is a real "last-writer-wins" collision —
//!   loading both will silently overwrite one mod's intent.
//! - **PartialOverlap**: both mods touch the same `(table, key)` but on
//!   disjoint field sets. Not a conflict — the edits compose cleanly — but
//!   surfaced so the user can sanity-check that two mods working on the same
//!   entry are doing what they expect.
//!
//! Pairs are reported with `mod_a_idx < mod_b_idx` so each conflict appears
//! exactly once in [`ConflictReport::conflicts`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// A single mod parsed from disk, normalized into a uniform change map.
///
/// `changes` maps `(table, entry_key) -> { field_path -> new_value }`. The
/// `field_path` strings use whatever shape the source format provides — flat
/// field names from `crimson_field_json_v3`, or dot/bracket paths from DMM
/// v3 intents. We don't try to reconcile the two shapes because conflict
/// detection only cares about exact-string equality of the path.
#[derive(Clone)]
pub struct LoadedMod {
    pub path: PathBuf,
    pub name: String,
    pub author: Option<String>,
    pub version: Option<String>,
    /// `(table, entry_key) -> { field_path -> new_value }`.
    ///
    /// `entry_key` is the numeric key from the mod entry. v3 single-target
    /// mods that only carry `entry` (string) without `key` are skipped — we
    /// can't compare them to keyed mods without a name -> key map.
    pub changes: HashMap<(String, u64), HashMap<String, Value>>,
}

impl LoadedMod {
    /// Total number of `(table, key, field)` triples this mod sets. Used by
    /// the UI as a quick "size" indicator next to each loaded mod.
    pub fn change_count(&self) -> usize {
        self.changes.values().map(|m| m.len()).sum()
    }

    /// Number of distinct `(table, entry)` pairs this mod touches.
    pub fn entry_count(&self) -> usize {
        self.changes.len()
    }
}

#[derive(Clone)]
pub enum ConflictKind {
    /// Both mods set the same field to different values. Last-writer-wins
    /// when both are loaded.
    DirectConflict {
        table: String,
        entry_key: u64,
        field_path: String,
        mod_a_value: Value,
        mod_b_value: Value,
    },
    /// Mods modify the same entry but disjoint field sets — the changes
    /// compose, so this is informational only.
    PartialOverlap {
        table: String,
        entry_key: u64,
        a_fields: Vec<String>,
        b_fields: Vec<String>,
    },
}

impl ConflictKind {
    /// Short label for the UI severity badge.
    pub fn label(&self) -> &'static str {
        match self {
            ConflictKind::DirectConflict { .. } => "Direct conflict",
            ConflictKind::PartialOverlap { .. } => "Partial overlap",
        }
    }

    pub fn table(&self) -> &str {
        match self {
            ConflictKind::DirectConflict { table, .. } => table,
            ConflictKind::PartialOverlap { table, .. } => table,
        }
    }

    pub fn entry_key(&self) -> u64 {
        match self {
            ConflictKind::DirectConflict { entry_key, .. } => *entry_key,
            ConflictKind::PartialOverlap { entry_key, .. } => *entry_key,
        }
    }
}

/// Result of running [`analyze`] on a list of [`LoadedMod`]s.
pub struct ConflictReport {
    /// Snapshot of the mods that produced this report. Stored by value so the
    /// UI can render labels without holding back the live `loaded_mods` list.
    pub mods: Vec<LoadedMod>,
    /// Pairwise conflicts. Each tuple is `(mod_a_idx, mod_b_idx, kind)` with
    /// `mod_a_idx < mod_b_idx`, indexing into [`Self::mods`].
    pub conflicts: Vec<(usize, usize, ConflictKind)>,
}

impl ConflictReport {
    /// Count of `DirectConflict` entries — the ones the UI renders red.
    pub fn direct_count(&self) -> usize {
        self.conflicts
            .iter()
            .filter(|(_, _, k)| matches!(k, ConflictKind::DirectConflict { .. }))
            .count()
    }

    /// Count of `PartialOverlap` entries — yellow.
    pub fn partial_count(&self) -> usize {
        self.conflicts
            .iter()
            .filter(|(_, _, k)| matches!(k, ConflictKind::PartialOverlap { .. }))
            .count()
    }
}

/// Read a mod file from disk and normalize it into a [`LoadedMod`].
///
/// Errors:
/// - `io::Error` for read failures.
/// - `InvalidData` for parse failures or unsupported formats — wrapped so
///   the UI can show one error type without juggling a custom enum.
pub fn load_mod(path: &Path) -> std::io::Result<LoadedMod> {
    let raw = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("JSON parse error: {}", e),
        )
    })?;

    // Default human-friendly name from the file stem so the UI never shows
    // a blank row even when the mod has no `_meta`.
    let default_name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    let (name, author, version) = extract_meta(&root, &default_name);
    let changes = build_changes(&root)?;

    Ok(LoadedMod {
        path: path.to_path_buf(),
        name,
        author,
        version,
        changes,
    })
}

/// Pairwise conflict analysis. See module docs for semantics.
pub fn analyze(mods: Vec<LoadedMod>) -> ConflictReport {
    let mut conflicts: Vec<(usize, usize, ConflictKind)> = Vec::new();

    for i in 0..mods.len() {
        for j in (i + 1)..mods.len() {
            let a = &mods[i];
            let b = &mods[j];

            for ((table, key), a_fields) in &a.changes {
                let Some(b_fields) = b.changes.get(&(table.clone(), *key)) else {
                    continue;
                };

                // First pass: walk a_fields, classify each into:
                //   * DirectConflict if b_fields has same path with different value
                //   * (silently composable) if b doesn't have the path
                // We collect direct hits separately so PartialOverlap can be
                // emitted only when zero direct conflicts touched this entry.
                let mut direct_hits: Vec<ConflictKind> = Vec::new();
                let mut overlap_a: Vec<String> = Vec::new();
                let mut overlap_b_seen: std::collections::HashSet<String> =
                    std::collections::HashSet::new();

                for (field_path, a_val) in a_fields {
                    if let Some(b_val) = b_fields.get(field_path) {
                        if a_val != b_val {
                            direct_hits.push(ConflictKind::DirectConflict {
                                table: table.clone(),
                                entry_key: *key,
                                field_path: field_path.clone(),
                                mod_a_value: a_val.clone(),
                                mod_b_value: b_val.clone(),
                            });
                        }
                        // Same value at same path = silent agreement, no
                        // conflict to report. Record so PartialOverlap doesn't
                        // double-list it.
                        overlap_b_seen.insert(field_path.clone());
                    }
                    overlap_a.push(field_path.clone());
                }

                // If we got any direct conflicts, prefer surfacing those —
                // PartialOverlap is the "no real collision" signal and would
                // be misleading next to a red row on the same entry.
                if !direct_hits.is_empty() {
                    for kind in direct_hits {
                        conflicts.push((i, j, kind));
                    }
                    continue;
                }

                // No direct conflicts: this entry is touched by both mods on
                // disjoint paths. Emit one PartialOverlap row listing the
                // field sets so the user can verify the edits compose.
                let only_a: Vec<String> = a_fields
                    .keys()
                    .filter(|k| !b_fields.contains_key(*k))
                    .cloned()
                    .collect();
                let only_b: Vec<String> = b_fields
                    .keys()
                    .filter(|k| !a_fields.contains_key(*k))
                    .cloned()
                    .collect();

                // If both lists are empty we either had nothing in common or
                // every shared path matched values — either way there's
                // nothing actionable to show.
                if only_a.is_empty() && only_b.is_empty() {
                    continue;
                }
                let _ = overlap_a;
                let _ = overlap_b_seen;

                conflicts.push((
                    i,
                    j,
                    ConflictKind::PartialOverlap {
                        table: table.clone(),
                        entry_key: *key,
                        a_fields: only_a,
                        b_fields: only_b,
                    },
                ));
            }
        }
    }

    ConflictReport { mods, conflicts }
}

// ── Format-specific normalizers ────────────────────────────────────────────

/// Extract `(name, author, version)` from the file's metadata block,
/// falling back to `default_name` so the UI never renders an empty cell.
///
/// Two shapes are accepted:
/// - `_meta` with `name/author/version` — workbench-native v3 exports.
/// - `modinfo` with `title/author/version` — DMM 1.3.3+ exports (our own
///   new DMM v3 output uses this shape).
fn extract_meta(root: &Value, default_name: &str) -> (String, Option<String>, Option<String>) {
    // Prefer `modinfo` (DMM-style) when present, fall back to `_meta`
    // (workbench-native). DMM uses `title` for the display name.
    if let Some(modinfo) = root.get("modinfo").and_then(|v| v.as_object()) {
        let name = modinfo
            .get("title")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| default_name.to_string());
        let author = modinfo
            .get("author")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let version = modinfo
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        return (name, author, version);
    }

    let meta = root.get("_meta").and_then(|v| v.as_object());
    let name = meta
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| default_name.to_string());
    let author = meta
        .and_then(|m| m.get("author"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let version = meta
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);
    (name, author, version)
}

/// Convert any supported format into the unified
/// `(table, key) -> {field_path -> value}` map.
///
/// Detection order:
/// 1. `format == "crimson_field_json_v3"` (string) — workbench's own export.
/// 2. `format == 3` (number) — DMM v3 intents (single- or multi-target).
/// 3. Anything else returns InvalidData.
fn build_changes(
    root: &Value,
) -> std::io::Result<HashMap<(String, u64), HashMap<String, Value>>> {
    // workbench-native (string format tag)
    if root
        .get("format")
        .and_then(|v| v.as_str())
        .map(|s| s == "crimson_field_json_v3")
        .unwrap_or(false)
    {
        return Ok(parse_workbench_v3(root));
    }

    // DMM v3 (numeric format tag)
    if root.get("format").and_then(|v| v.as_u64()) == Some(3) {
        return Ok(parse_dmm_v3(root));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "Unsupported mod format: {:?}",
            root.get("format").cloned().unwrap_or(Value::Null)
        ),
    ))
}

/// Workbench-native format: `{ table, entries: [{ key, fields: {...} }] }`.
///
/// Field names are taken verbatim — they're already the dispatch's top-level
/// field names from the parser.
fn parse_workbench_v3(root: &Value) -> HashMap<(String, u64), HashMap<String, Value>> {
    let mut out: HashMap<(String, u64), HashMap<String, Value>> = HashMap::new();
    let table = root
        .get("table")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let entries = match root.get("entries").and_then(|v| v.as_array()) {
        Some(e) => e,
        None => return out,
    };
    for entry in entries {
        let Some(key) = entry.get("key").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(fields) = entry.get("fields").and_then(|v| v.as_object()) else {
            continue;
        };
        let bucket = out.entry((table.clone(), key)).or_default();
        for (k, v) in fields {
            bucket.insert(k.clone(), v.clone());
        }
    }
    out
}

/// DMM v3 intent format. Handles both single-target (`target` + `intents`)
/// and multi-target (`targets[]`) shapes.
///
/// Intents without a numeric `key` are skipped — we'd need a name->key map
/// (which lives in the live game data, not the mod file) to know what
/// `(table, key)` they hit. The conflict viewer surfaces this via the
/// difference between intent count and resolved change count if the user
/// inspects the file.
fn parse_dmm_v3(root: &Value) -> HashMap<(String, u64), HashMap<String, Value>> {
    let mut out: HashMap<(String, u64), HashMap<String, Value>> = HashMap::new();

    // Multi-target wins when present and non-empty (mirrors dmm-beta logic).
    if let Some(targets) = root.get("targets").and_then(|v| v.as_array()) {
        if !targets.is_empty() {
            for tg in targets {
                let file = tg
                    .get("file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let table = pabgb_to_table(&file);
                if let Some(intents) = tg.get("intents").and_then(|v| v.as_array()) {
                    apply_intents(&mut out, &table, intents);
                }
            }
            return out;
        }
    }

    // Single-target fallback.
    let target = root
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("iteminfo.pabgb");
    let table = pabgb_to_table(target);
    if let Some(intents) = root.get("intents").and_then(|v| v.as_array()) {
        apply_intents(&mut out, &table, intents);
    }
    out
}

/// Strip the `.pabgb` / `.pabgh` suffix from a target filename so the table
/// name matches the dispatch name used elsewhere in the workbench. Falls
/// back to the input unchanged for empty or already-bare names.
fn pabgb_to_table(file: &str) -> String {
    if let Some(stem) = file.strip_suffix(".pabgb") {
        return stem.to_string();
    }
    if let Some(stem) = file.strip_suffix(".pabgh") {
        return stem.to_string();
    }
    file.to_string()
}

fn apply_intents(
    out: &mut HashMap<(String, u64), HashMap<String, Value>>,
    table: &str,
    intents: &[Value],
) {
    for intent in intents {
        // Only the `set` op produces a deterministic field write. `add_entry`
        // creates a brand-new entry which can't conflict with a `set` on a
        // different key, and other op codes are reserved.
        let op = intent
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("set");
        if op != "set" {
            continue;
        }

        // `key` may be unsigned (workbench-style) or signed (i64). Accept
        // both and only surface positive values — negative keys never appear
        // in the parser output and would alias a different unsigned bucket.
        let key = intent
            .get("key")
            .and_then(|v| v.as_u64().or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok())));
        let Some(key) = key else {
            continue;
        };

        let Some(field_path) = intent.get("field").and_then(|v| v.as_str()) else {
            continue;
        };
        let new_value = intent.get("new").cloned().unwrap_or(Value::Null);

        let bucket = out.entry((table.to_string(), key)).or_default();
        bucket.insert(field_path.to_string(), new_value);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn loaded_from(name: &str, raw: Value) -> LoadedMod {
        let changes = build_changes(&raw).expect("build_changes");
        LoadedMod {
            path: PathBuf::from(name),
            name: name.to_string(),
            author: None,
            version: None,
            changes,
        }
    }

    #[test]
    fn parse_workbench_v3_format() {
        let root = json!({
            "format": "crimson_field_json_v3",
            "table": "iteminfo",
            "entries": [
                { "key": 1, "fields": { "hp": 100, "name": "foo" } },
                { "key": 2, "fields": { "hp": 50 } },
            ]
        });
        let m = loaded_from("a.json", root);
        assert_eq!(m.entry_count(), 2);
        assert_eq!(m.change_count(), 3);
        let bucket = m.changes.get(&("iteminfo".to_string(), 1)).unwrap();
        assert_eq!(bucket.get("hp"), Some(&json!(100)));
        assert_eq!(bucket.get("name"), Some(&json!("foo")));
    }

    #[test]
    fn parse_dmm_v3_single_target() {
        let root = json!({
            "format": 3,
            "target": "iteminfo.pabgb",
            "intents": [
                { "entry": "Item_A", "key": 1, "field": "cooltime",
                  "op": "set", "new": 5 },
                // No key -> dropped.
                { "entry": "Item_B", "field": "x", "op": "set", "new": 1 },
                // Non-set op -> dropped.
                { "entry": "Item_C", "key": 3, "field": "y",
                  "op": "add_entry", "new": 0 },
            ]
        });
        let m = loaded_from("dmm.json", root);
        assert_eq!(m.entry_count(), 1);
        assert_eq!(m.change_count(), 1);
        let bucket = m.changes.get(&("iteminfo".to_string(), 1)).unwrap();
        assert_eq!(bucket.get("cooltime"), Some(&json!(5)));
    }

    #[test]
    fn parse_dmm_v3_multi_target() {
        let root = json!({
            "format": 3,
            "targets": [
                {
                    "file": "iteminfo.pabgb",
                    "intents": [
                        { "key": 1, "field": "hp", "op": "set", "new": 99 }
                    ]
                },
                {
                    "file": "skill.pabgb",
                    "intents": [
                        { "key": 7, "field": "cd", "op": "set", "new": 0.5 }
                    ]
                },
            ]
        });
        let m = loaded_from("multi.json", root);
        assert_eq!(m.entry_count(), 2);
        assert!(m.changes.contains_key(&("iteminfo".to_string(), 1)));
        assert!(m.changes.contains_key(&("skill".to_string(), 7)));
    }

    #[test]
    fn analyze_direct_conflict() {
        let a = loaded_from(
            "a.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let b = loaded_from(
            "b.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 200 } }]
            }),
        );
        let report = analyze(vec![a, b]);
        assert_eq!(report.direct_count(), 1);
        assert_eq!(report.partial_count(), 0);
        let (i, j, kind) = &report.conflicts[0];
        assert_eq!((*i, *j), (0, 1));
        match kind {
            ConflictKind::DirectConflict {
                field_path,
                mod_a_value,
                mod_b_value,
                ..
            } => {
                assert_eq!(field_path, "hp");
                assert_eq!(mod_a_value, &json!(100));
                assert_eq!(mod_b_value, &json!(200));
            }
            _ => panic!("expected DirectConflict"),
        }
    }

    #[test]
    fn analyze_partial_overlap() {
        let a = loaded_from(
            "a.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let b = loaded_from(
            "b.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "mp": 50 } }]
            }),
        );
        let report = analyze(vec![a, b]);
        assert_eq!(report.direct_count(), 0);
        assert_eq!(report.partial_count(), 1);
        match &report.conflicts[0].2 {
            ConflictKind::PartialOverlap {
                a_fields, b_fields, ..
            } => {
                assert_eq!(a_fields, &vec!["hp".to_string()]);
                assert_eq!(b_fields, &vec!["mp".to_string()]);
            }
            _ => panic!("expected PartialOverlap"),
        }
    }

    #[test]
    fn analyze_silent_agreement_skipped() {
        // Same path, same value -> no conflict reported (mods agree).
        let a = loaded_from(
            "a.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let b = loaded_from(
            "b.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let report = analyze(vec![a, b]);
        assert_eq!(report.conflicts.len(), 0);
    }

    #[test]
    fn analyze_different_tables_no_conflict() {
        let a = loaded_from(
            "a.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "iteminfo",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let b = loaded_from(
            "b.json",
            json!({
                "format": "crimson_field_json_v3",
                "table": "skill",
                "entries": [{ "key": 1, "fields": { "hp": 100 } }]
            }),
        );
        let report = analyze(vec![a, b]);
        assert_eq!(report.conflicts.len(), 0);
    }

    #[test]
    fn meta_extraction() {
        let root = json!({
            "format": "crimson_field_json_v3",
            "table": "iteminfo",
            "entries": [],
            "_meta": {
                "name": "Cool Mod",
                "author": "Someone",
                "version": "1.2.3"
            }
        });
        let (name, author, version) = extract_meta(&root, "fallback");
        assert_eq!(name, "Cool Mod");
        assert_eq!(author.as_deref(), Some("Someone"));
        assert_eq!(version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn meta_falls_back_to_filename() {
        let root = json!({ "format": "crimson_field_json_v3", "table": "x", "entries": [] });
        let (name, author, version) = extract_meta(&root, "my_file");
        assert_eq!(name, "my_file");
        assert!(author.is_none());
        assert!(version.is_none());
    }
}
