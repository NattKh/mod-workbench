//! Template library — named patterns of edits applicable to one or more
//! entries in a PABGB table.
//!
//! A [`Template`] bundles a target table name with a list of
//! [`TemplateField`] changes (path + JSON value, optionally multiplicative).
//! Built-in templates are produced by [`builtin_templates`]; user-saved
//! templates persist as JSON files under
//! `%APPDATA%\Crimson\ModWorkbench\templates\` and are loaded via
//! [`load_user_templates`].
//!
//! Apply semantics ([`apply_template`]):
//!
//! - **Replace mode** (`multiplicative = false`): the value at `path` is
//!   set verbatim to `value`. Missing intermediate objects/arrays are not
//!   created — paths must already exist on the entry.
//! - **Multiplicative mode** (`multiplicative = true`): only meaningful for
//!   numeric leaf values. The current value is multiplied by `value` (which
//!   must itself be numeric). Non-numeric current values are left untouched
//!   and an error is returned for the offending field.
//!
//! Templates apply to one entry at a time. Multi-select handling lives in
//! the templates panel — it just calls `apply_template` in a loop.
//!
//! ## Why JSON on disk
//!
//! User templates are small and infrequently mutated, so we don't want a
//! database. One file per template (`<sanitized_name>.json`) makes them
//! trivial to share, diff, and back up. The on-disk schema is a 1:1 serde
//! round-trip of [`Template`] — no version tag yet, but the field set is
//! `#[serde(default)]`-friendly so future additions stay backward
//! compatible.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::edit_history::{get_at_path, set_at_path};

/// A reusable pattern of field edits for a particular table.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Template {
    pub name: String,
    pub description: String,
    /// Dispatch name of the target table (e.g. `"item_info"`,
    /// `"store_info"`). Templates are filterable by this in the UI so the
    /// user only sees patterns that make sense for the active tab.
    pub table: String,
    /// Field paths and the values to set.
    pub field_changes: Vec<TemplateField>,
    /// Whether this template was loaded from the user's own library on
    /// disk (vs. shipped as a built-in). Skipped during serialization so
    /// it never lands in user files; computed on load.
    #[serde(default, skip)]
    pub user_defined: bool,
}

/// One field change in a [`Template`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TemplateField {
    /// Dot/bracket path from the entry root, e.g. `max_stack_count` or
    /// `_buff_list[0].buff_key`. Same notation that the field panel
    /// produces.
    pub path: String,
    /// Value to set (replace mode) or multiply by (when
    /// `multiplicative` is true).
    pub value: Value,
    /// If true, multiply the existing numeric value by `value` instead of
    /// replacing it.
    #[serde(default)]
    pub multiplicative: bool,
}

/// Built-in template library.
///
/// Each entry is intentionally conservative — we only ship templates whose
/// field paths are known good, since a typo here ships to every workbench
/// install. Add new templates here as fields get documented.
pub fn builtin_templates() -> Vec<Template> {
    vec![
        // ── iteminfo ──────────────────────────────────────────────────
        Template {
            name: "Infinite Stack".to_string(),
            description: "Set max_stack_count to 9999 so the item stacks \
                          past vanilla limits."
                .to_string(),
            table: "item_info".to_string(),
            field_changes: vec![TemplateField {
                path: "max_stack_count".to_string(),
                value: Value::from(9999u32),
                multiplicative: false,
            }],
            user_defined: false,
        },
        Template {
            name: "Stackable (x99)".to_string(),
            description: "Multiplies the item's existing max_stack_count \
                          by 99 — keeps relative scale between item types."
                .to_string(),
            table: "item_info".to_string(),
            field_changes: vec![TemplateField {
                path: "max_stack_count".to_string(),
                value: Value::from(99u32),
                multiplicative: true,
            }],
            user_defined: false,
        },
        // ── store_info ────────────────────────────────────────────────
        Template {
            name: "Free Items (Store)".to_string(),
            description: "Sets _buyPrice on every store-sold item to 0. \
                          TODO: store schema details — this is a starter \
                          placeholder until store fields are mapped."
                .to_string(),
            table: "store_info".to_string(),
            field_changes: vec![TemplateField {
                // Final path will likely need adjusting once the store
                // editor is wired in. Documented as TODO above.
                path: "_buyPrice".to_string(),
                value: Value::from(0u32),
                multiplicative: false,
            }],
            user_defined: false,
        },
        Template {
            name: "Always In Stock".to_string(),
            description: "Sets _stockCount / _maxStockCount to a high value \
                          so the vendor never runs out. TODO: confirm field \
                          paths once store_info schema is mapped."
                .to_string(),
            table: "store_info".to_string(),
            field_changes: vec![
                TemplateField {
                    path: "_stockCount".to_string(),
                    value: Value::from(9999u32),
                    multiplicative: false,
                },
                TemplateField {
                    path: "_maxStockCount".to_string(),
                    value: Value::from(9999u32),
                    multiplicative: false,
                },
            ],
            user_defined: false,
        },
        // ── drop_set_info ─────────────────────────────────────────────
        Template {
            name: "100% Drop Rate".to_string(),
            description: "Sets the drop chance fields to max. TODO: confirm \
                          drop_set_info field paths once schema is mapped."
                .to_string(),
            table: "drop_set_info".to_string(),
            field_changes: vec![TemplateField {
                // Placeholder path — drop tables expose `_dropRate` in some
                // schemas. Will need adjustment after auditing live data.
                path: "_dropRate".to_string(),
                value: Value::from(100u32),
                multiplicative: false,
            }],
            user_defined: false,
        },
        // ── equip_info ────────────────────────────────────────────────
        Template {
            name: "God Stats (Equip)".to_string(),
            description: "Sets DPV/DDD-style attack and defense fields to a \
                          high value. TODO: equip_info stat paths are still \
                          being mapped — values here are placeholders."
                .to_string(),
            table: "equip_info".to_string(),
            field_changes: vec![
                TemplateField {
                    path: "_attack".to_string(),
                    value: Value::from(99999u32),
                    multiplicative: false,
                },
                TemplateField {
                    path: "_defense".to_string(),
                    value: Value::from(99999u32),
                    multiplicative: false,
                },
            ],
            user_defined: false,
        },
    ]
}

/// Resolve the directory under which user-defined templates are stored.
///
/// Returns `None` only when no project directory can be derived (very
/// uncommon — typically only on stripped-down headless setups where we
/// don't expect the workbench to run anyway).
pub fn user_templates_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
    Some(dirs.config_dir().join("templates"))
}

/// Path to a single user template file given its (already-sanitized) name.
pub fn user_templates_path() -> Option<PathBuf> {
    user_templates_dir()
}

/// Read every `.json` file in the user templates directory and return them
/// as parsed [`Template`] values.
///
/// Missing directory is not an error — returns an empty vec. Per-file parse
/// errors are logged via `eprintln!` and the offending file is skipped so
/// one corrupt template doesn't blank the whole library.
pub fn load_user_templates() -> std::io::Result<Vec<Template>> {
    let Some(dir) = user_templates_dir() else {
        return Ok(Vec::new());
    };
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "templates: read {} failed: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        match serde_json::from_str::<Template>(&data) {
            Ok(mut tpl) => {
                tpl.user_defined = true;
                out.push(tpl);
            }
            Err(e) => {
                eprintln!(
                    "templates: parse {} failed: {}",
                    path.display(),
                    e
                );
            }
        }
    }
    // Stable order so the panel is deterministic even after add/remove.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Persist a single user template under
/// `<user_templates_dir>/<sanitized_name>.json`.
///
/// The on-disk filename is derived from `template.name` via
/// [`sanitize_filename`]; collisions with existing templates *overwrite*
/// the prior file (the UI surfaces this as "saving the template" so users
/// can iteratively tweak).
pub fn save_user_template(template: &Template) -> std::io::Result<()> {
    let Some(dir) = user_templates_dir() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no project dir available",
        ));
    };
    std::fs::create_dir_all(&dir)?;

    let filename = format!("{}.json", sanitize_filename(&template.name));
    let path = dir.join(filename);
    let pretty = serde_json::to_string_pretty(template).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    std::fs::write(&path, pretty)?;
    Ok(())
}

/// Remove the on-disk file for a user template by name. No-op when the
/// file isn't present.
pub fn delete_user_template(name: &str) -> std::io::Result<()> {
    let Some(dir) = user_templates_dir() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no project dir available",
        ));
    };
    let filename = format!("{}.json", sanitize_filename(name));
    let path = dir.join(filename);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Apply every field change in `template` to a single target entry.
///
/// Returns `Ok(())` only when *all* changes applied cleanly. On the first
/// failure (missing path, multiplicative on non-numeric, etc.) the entry is
/// left in a partially mutated state — callers that need atomic apply must
/// snapshot the entry before calling and roll back on `Err`.
///
/// Errors are formatted as human-readable strings so the UI can show them
/// directly in a toast.
pub fn apply_template(
    template: &Template,
    target_entry: &mut Value,
) -> Result<(), String> {
    for change in &template.field_changes {
        if change.multiplicative {
            apply_multiplicative(target_entry, &change.path, &change.value)?;
        } else {
            // Replace mode: write the value verbatim.
            if !set_at_path(target_entry, &change.path, change.value.clone()) {
                return Err(format!(
                    "field path '{}' not found on entry",
                    change.path
                ));
            }
        }
    }
    Ok(())
}

/// Multiply the numeric value at `path` by `factor`. Both `factor` and the
/// existing value must be JSON numbers; integer × integer stays integer,
/// anything else falls back to f64.
fn apply_multiplicative(
    entry: &mut Value,
    path: &str,
    factor: &Value,
) -> Result<(), String> {
    let factor_f = factor.as_f64().ok_or_else(|| {
        format!(
            "multiplicative template field '{}' requires a numeric value, got {}",
            path, factor
        )
    })?;
    let current = get_at_path(entry, path)
        .ok_or_else(|| format!("field path '{}' not found on entry", path))?
        .clone();

    let new_value = match (current.as_i64(), current.as_u64(), current.as_f64()) {
        (Some(i), _, _) if factor.is_i64() || factor.is_u64() => {
            // Pure-integer math when both sides are integral.
            let factor_i = factor.as_i64().unwrap_or(0);
            let prod = i.saturating_mul(factor_i);
            Value::from(prod)
        }
        (_, Some(u), _) if factor.is_u64() => {
            let factor_u = factor.as_u64().unwrap_or(0);
            let prod = u.saturating_mul(factor_u);
            Value::from(prod)
        }
        (_, _, Some(f)) => {
            // Float fallback for non-integer current or non-integer factor.
            Value::from(f * factor_f)
        }
        _ => {
            return Err(format!(
                "field at '{}' is not numeric; cannot multiply",
                path
            ));
        }
    };

    if !set_at_path(entry, path, new_value) {
        return Err(format!(
            "failed to write multiplicative result at '{}'",
            path
        ));
    }
    Ok(())
}

/// Replace any character that's awkward in a filename with an underscore so
/// `template.name` round-trips safely to disk. Conservative: only ASCII
/// alphanumerics, dash, underscore and dot survive; the rest become `_`.
fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("template");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn apply_replace_writes_value() {
        let mut entry = json!({"max_stack_count": 1});
        let tpl = Template {
            name: "x".into(),
            description: String::new(),
            table: "item_info".into(),
            field_changes: vec![TemplateField {
                path: "max_stack_count".into(),
                value: json!(9999),
                multiplicative: false,
            }],
            user_defined: false,
        };
        assert!(apply_template(&tpl, &mut entry).is_ok());
        assert_eq!(entry["max_stack_count"], json!(9999));
    }

    #[test]
    fn apply_multiplicative_int_int() {
        let mut entry = json!({"max_stack_count": 10});
        let tpl = Template {
            name: "x".into(),
            description: String::new(),
            table: "item_info".into(),
            field_changes: vec![TemplateField {
                path: "max_stack_count".into(),
                value: json!(5),
                multiplicative: true,
            }],
            user_defined: false,
        };
        assert!(apply_template(&tpl, &mut entry).is_ok());
        assert_eq!(entry["max_stack_count"], json!(50));
    }

    #[test]
    fn apply_multiplicative_float() {
        let mut entry = json!({"rate": 0.5});
        let tpl = Template {
            name: "x".into(),
            description: String::new(),
            table: "item_info".into(),
            field_changes: vec![TemplateField {
                path: "rate".into(),
                value: json!(2.0),
                multiplicative: true,
            }],
            user_defined: false,
        };
        assert!(apply_template(&tpl, &mut entry).is_ok());
        // 0.5 * 2.0 == 1.0
        assert!((entry["rate"].as_f64().unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn apply_missing_path_errors() {
        let mut entry = json!({"foo": 1});
        let tpl = Template {
            name: "x".into(),
            description: String::new(),
            table: "item_info".into(),
            field_changes: vec![TemplateField {
                path: "bar".into(),
                value: json!(2),
                multiplicative: true,
            }],
            user_defined: false,
        };
        let err = apply_template(&tpl, &mut entry).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn apply_replace_creates_top_level_field() {
        // `set_at_path` allows top-level inserts even when the key is new
        // (matches edit_history's existing semantics). Templates that need
        // to add a brand-new top-level field rely on this.
        let mut entry = json!({});
        let tpl = Template {
            name: "x".into(),
            description: String::new(),
            table: "item_info".into(),
            field_changes: vec![TemplateField {
                path: "new_field".into(),
                value: json!(42),
                multiplicative: false,
            }],
            user_defined: false,
        };
        assert!(apply_template(&tpl, &mut entry).is_ok());
        assert_eq!(entry["new_field"], json!(42));
    }

    #[test]
    fn sanitize_filename_strips_unsafe_chars() {
        assert_eq!(sanitize_filename("Hello World"), "Hello_World");
        assert_eq!(sanitize_filename("foo/bar:baz"), "foo_bar_baz");
        assert_eq!(sanitize_filename("ok.name-1_2"), "ok.name-1_2");
        assert_eq!(sanitize_filename(""), "template");
    }

    #[test]
    fn builtin_templates_are_well_formed() {
        for tpl in builtin_templates() {
            assert!(!tpl.name.is_empty());
            assert!(!tpl.table.is_empty());
            assert!(!tpl.field_changes.is_empty());
            assert!(!tpl.user_defined, "builtins must not be user_defined");
        }
    }
}
