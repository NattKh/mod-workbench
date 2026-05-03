use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::notes::NoteStore;
use crate::state::ChangeTracker;

/// User-supplied metadata describing a mod.
///
/// Embedded into v3 field JSON exports under the `_meta` key so consumers
/// (the workbench's own conflict viewer, DMM, Nexus authors, etc.) can read
/// human-friendly attribution + version info without parsing the binary
/// payload.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct ModMetadata {
    pub name: String,
    pub author: String,
    pub version: String,
    pub description: String,
    pub nexus_url: String,
    /// Names of other mods this one depends on. Soft hint — the workbench
    /// doesn't enforce ordering today, but the field is reserved so future
    /// load-order tooling can read it.
    #[serde(default)]
    pub dependencies: Vec<String>,
}

impl ModMetadata {
    /// True when no field has been filled in. Used by the export pipeline
    /// to decide whether to embed `_meta` at all — empty metadata is just
    /// noise in the resulting JSON.
    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
            && self.author.is_empty()
            && self.version.is_empty()
            && self.description.is_empty()
            && self.nexus_url.is_empty()
            && self.dependencies.is_empty()
    }

    /// Read a metadata block from a parsed mod JSON. Returns `None` when
    /// the document has no `_meta` key (older exports / hand-written mods).
    /// Missing fields default to empty strings — we never error here, just
    /// fall back to whatever the user later types into the dialog.
    pub fn from_json(root: &Value) -> Option<Self> {
        let meta = root.get("_meta")?.as_object()?;
        let s = |k: &str| -> String {
            meta.get(k)
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default()
        };
        let dependencies = meta
            .get("dependencies")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some(ModMetadata {
            name: s("name"),
            author: s("author"),
            version: s("version"),
            description: s("description"),
            nexus_url: s("nexus_url"),
            dependencies,
        })
    }
}

/// Export only the changed fields as a v3 field JSON mod, optionally
/// embedding metadata under `_meta`.
///
/// For each entry that the ChangeTracker marks as modified, diffs against
/// the vanilla snapshot and includes only the fields that actually differ.
pub fn export_changes(
    table_name: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
) -> Value {
    export_changes_with_meta(table_name, entries, vanilla, changes, None)
}

/// Variant of [`export_changes`] that embeds the supplied [`ModMetadata`]
/// (when non-empty) under `_meta` in the output JSON. Pass `None` to skip
/// the meta block entirely.
pub fn export_changes_with_meta(
    table_name: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    metadata: Option<&ModMetadata>,
) -> Value {
    export_changes_full(table_name, entries, vanilla, changes, metadata, None)
}

/// Full-power exporter — adds an optional [`NoteStore`] payload alongside
/// the existing metadata block.
///
/// Notes for entries that the [`ChangeTracker`] doesn't list as modified
/// are intentionally still exported — modders sometimes leave annotations
/// on vanilla entries (e.g. "considered changing this, decided not to")
/// and lose-on-export would be silently destructive. The exported map only
/// covers `table_name`, so notes from other tables stay private to that
/// session's [`NoteStore`].
pub fn export_changes_full(
    table_name: &str,
    entries: &[Value],
    vanilla: &[Value],
    changes: &ChangeTracker,
    metadata: Option<&ModMetadata>,
    notes: Option<&NoteStore>,
) -> Value {
    let mut mod_entries = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        let key = extract_entry_key(entry);
        if !changes.is_entry_modified(key) {
            continue;
        }

        let vanilla_entry = vanilla.get(i);
        let changed_fields = diff_entry(entry, vanilla_entry);
        if changed_fields.is_empty() {
            continue;
        }

        mod_entries.push(json!({
            "key": key,
            "fields": Value::Object(changed_fields),
        }));
    }

    let mut root = serde_json::Map::new();
    root.insert(
        "format".into(),
        Value::String("crimson_field_json_v3".into()),
    );
    if let Some(meta) = metadata {
        if !meta.is_empty() {
            // Use serde to serialize so any future field added to ModMetadata
            // is automatically reflected in the on-disk shape.
            if let Ok(meta_value) = serde_json::to_value(meta) {
                root.insert("_meta".into(), meta_value);
            }
        }
    }
    if let Some(store) = notes {
        // Walk the store filtered to this table only — we don't want to
        // leak unrelated notes from other open tabs into a single-table
        // mod export. Stored as a flat `{ "<key>": "<note>" }` map so
        // hand-editing the JSON is trivial.
        let mut table_notes = serde_json::Map::new();
        for (entry_key, note) in store.iter_table(table_name) {
            table_notes.insert(entry_key.to_string(), Value::String(note.to_string()));
        }
        if !table_notes.is_empty() {
            root.insert("_notes".into(), Value::Object(table_notes));
        }
    }
    root.insert("table".into(), Value::String(table_name.to_string()));
    root.insert("entries".into(), Value::Array(mod_entries));

    Value::Object(root)
}

/// Read embedded notes back out of a mod JSON, scoped to `table_name`.
///
/// The `_notes` map uses string keys for the entry id (because JSON object
/// keys are strings); we parse them back to `u64` here. Keys we can't
/// parse are dropped — those would be data shipped from a future workbench
/// version that we don't recognise yet, and silently importing junk would
/// be worse than ignoring it.
pub fn import_notes(mod_json: &Value, table_name: &str, store: &mut NoteStore) -> usize {
    let Some(notes_obj) = mod_json.get("_notes").and_then(|v| v.as_object()) else {
        return 0;
    };
    let mut imported = 0;
    for (key_str, note_value) in notes_obj {
        let Ok(entry_key) = key_str.parse::<u64>() else {
            continue;
        };
        let Some(note) = note_value.as_str() else {
            continue;
        };
        store.set(table_name, entry_key, note.to_string());
        imported += 1;
    }
    imported
}

/// Import a v3 field JSON mod, applying field overrides onto the live entries.
///
/// Returns the number of entries that were matched and patched. Use
/// [`ModMetadata::from_json`] on the same `mod_json` to also read the
/// embedded metadata if any.
pub fn import_mod(mod_json: &Value, entries: &mut [Value]) -> Result<usize, String> {
    let format = mod_json
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if format != "crimson_field_json_v3" {
        return Err(format!("Unsupported format: '{}'", format));
    }

    let mod_entries = mod_json
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid 'entries' array".to_string())?;

    let mut patched = 0;

    for mod_entry in mod_entries {
        let target_key = mod_entry
            .get("key")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "Mod entry missing 'key'".to_string())?;

        let fields = mod_entry
            .get("fields")
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("Mod entry key={} missing 'fields' object", target_key))?;

        // Find the matching entry by key
        if let Some(live_entry) = entries.iter_mut().find(|e| extract_entry_key(e) == target_key) {
            if let Some(obj) = live_entry.as_object_mut() {
                for (field_name, field_value) in fields {
                    obj.insert(field_name.clone(), field_value.clone());
                }
                patched += 1;
            }
        }
    }

    Ok(patched)
}

/// Extract the numeric key from an entry JSON object.
///
/// Looks for "key" first, then "_key", then "unk_key". Falls back to 0.
pub fn extract_entry_key(entry: &Value) -> u64 {
    entry
        .get("key")
        .or_else(|| entry.get("_key"))
        .or_else(|| entry.get("unk_key"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Diff a single entry against its vanilla counterpart.
/// Returns only the top-level fields that differ.
fn diff_entry(current: &Value, vanilla: Option<&Value>) -> Map<String, Value> {
    let mut changed = Map::new();

    let current_obj = match current.as_object() {
        Some(obj) => obj,
        None => return changed,
    };

    let vanilla_obj = vanilla.and_then(|v| v.as_object());

    for (field_name, current_value) in current_obj {
        let differs = match vanilla_obj {
            Some(vo) => vo.get(field_name) != Some(current_value),
            None => true,
        };
        if differs {
            changed.insert(field_name.clone(), current_value.clone());
        }
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_entry_key() {
        assert_eq!(extract_entry_key(&json!({"key": 42})), 42);
        assert_eq!(extract_entry_key(&json!({"_key": 99})), 99);
        assert_eq!(extract_entry_key(&json!({"unk_key": 7})), 7);
        assert_eq!(extract_entry_key(&json!({"other": 1})), 0);
    }

    #[test]
    fn test_diff_entry() {
        let current = json!({"key": 1, "hp": 100, "name": "foo"});
        let vanilla = json!({"key": 1, "hp": 50, "name": "foo"});
        let diff = diff_entry(&current, Some(&vanilla));
        assert_eq!(diff.len(), 1);
        assert_eq!(diff.get("hp"), Some(&json!(100)));
    }

    #[test]
    fn test_import_mod_roundtrip() {
        let mut entries = vec![
            json!({"key": 1, "hp": 50, "name": "foo"}),
            json!({"key": 2, "hp": 80, "name": "bar"}),
        ];
        let mod_json = json!({
            "format": "crimson_field_json_v3",
            "table": "test",
            "entries": [
                {"key": 1, "fields": {"hp": 999}},
            ]
        });
        let count = import_mod(&mod_json, &mut entries).unwrap();
        assert_eq!(count, 1);
        assert_eq!(entries[0]["hp"], 999);
        assert_eq!(entries[1]["hp"], 80); // untouched
    }

    #[test]
    fn test_metadata_is_empty() {
        let m = ModMetadata::default();
        assert!(m.is_empty());
        let m2 = ModMetadata {
            name: "Foo".into(),
            ..Default::default()
        };
        assert!(!m2.is_empty());
    }

    #[test]
    fn test_export_changes_with_meta_embeds_meta() {
        let entries = vec![json!({"key": 1, "hp": 999})];
        let vanilla = vec![json!({"key": 1, "hp": 50})];
        let mut changes = ChangeTracker::new();
        changes.record_change(1, "hp".to_string());
        let meta = ModMetadata {
            name: "Cool Mod".into(),
            author: "Me".into(),
            version: "1.0".into(),
            description: "desc".into(),
            nexus_url: "https://nexus".into(),
            dependencies: vec!["dep_a".into()],
        };
        let value = export_changes_with_meta("test", &entries, &vanilla, &changes, Some(&meta));
        assert_eq!(value["format"], json!("crimson_field_json_v3"));
        assert_eq!(value["_meta"]["name"], json!("Cool Mod"));
        assert_eq!(value["_meta"]["author"], json!("Me"));
        assert_eq!(value["_meta"]["dependencies"][0], json!("dep_a"));
    }

    #[test]
    fn test_export_changes_with_meta_skips_empty_meta() {
        let entries = vec![json!({"key": 1, "hp": 999})];
        let vanilla = vec![json!({"key": 1, "hp": 50})];
        let mut changes = ChangeTracker::new();
        changes.record_change(1, "hp".to_string());
        let meta = ModMetadata::default();
        let value = export_changes_with_meta("test", &entries, &vanilla, &changes, Some(&meta));
        assert!(value.get("_meta").is_none());
    }

    #[test]
    fn test_metadata_from_json_roundtrip() {
        let entries: Vec<Value> = vec![];
        let vanilla: Vec<Value> = vec![];
        let changes = ChangeTracker::new();
        let meta_in = ModMetadata {
            name: "X".into(),
            author: "Y".into(),
            version: "0.1".into(),
            description: "d".into(),
            nexus_url: "u".into(),
            dependencies: vec!["a".into(), "b".into()],
        };
        let value = export_changes_with_meta("t", &entries, &vanilla, &changes, Some(&meta_in));
        let meta_out = ModMetadata::from_json(&value).expect("meta present");
        assert_eq!(meta_out.name, "X");
        assert_eq!(meta_out.author, "Y");
        assert_eq!(meta_out.version, "0.1");
        assert_eq!(meta_out.description, "d");
        assert_eq!(meta_out.nexus_url, "u");
        assert_eq!(meta_out.dependencies, vec!["a", "b"]);
    }

    #[test]
    fn test_metadata_from_json_missing_returns_none() {
        let value = json!({"format": "crimson_field_json_v3", "table": "t", "entries": []});
        assert!(ModMetadata::from_json(&value).is_none());
    }

    #[test]
    fn notes_round_trip_through_export_and_import() {
        let entries = vec![json!({"key": 1, "hp": 999})];
        let vanilla = vec![json!({"key": 1, "hp": 50})];
        let mut changes = ChangeTracker::new();
        changes.record_change(1, "hp".to_string());
        let mut notes = NoteStore::default();
        notes.set("test", 1, "Tweaked HP for boss balance".into());
        notes.set("test", 7, "Ignored — vanilla is fine".into());
        // Notes from another table shouldn't leak.
        notes.set("other", 1, "should not appear".into());

        let value = export_changes_full(
            "test",
            &entries,
            &vanilla,
            &changes,
            None,
            Some(&notes),
        );

        // Embedded under `_notes` keyed by stringified entry id.
        assert_eq!(value["_notes"]["1"], json!("Tweaked HP for boss balance"));
        assert_eq!(value["_notes"]["7"], json!("Ignored — vanilla is fine"));
        assert!(value["_notes"].get("other").is_none());

        // Import side: drop into a fresh store and we should get back the
        // same two entries.
        let mut roundtrip = NoteStore::default();
        let count = import_notes(&value, "test", &mut roundtrip);
        assert_eq!(count, 2);
        assert_eq!(roundtrip.get("test", 1), Some("Tweaked HP for boss balance"));
        assert_eq!(roundtrip.get("test", 7), Some("Ignored — vanilla is fine"));
    }

    #[test]
    fn notes_export_skips_block_when_empty_for_table() {
        let entries = vec![json!({"key": 1, "hp": 999})];
        let vanilla = vec![json!({"key": 1, "hp": 50})];
        let mut changes = ChangeTracker::new();
        changes.record_change(1, "hp".to_string());
        let mut notes = NoteStore::default();
        notes.set("other", 1, "different table".into());
        let value = export_changes_full(
            "test",
            &entries,
            &vanilla,
            &changes,
            None,
            Some(&notes),
        );
        assert!(value.get("_notes").is_none());
    }
}
