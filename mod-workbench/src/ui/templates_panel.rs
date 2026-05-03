//! Templates library panel — central panel when [`MainView::Templates`]
//! is active.
//!
//! Layout (top -> bottom):
//!
//! 1. Toolbar: refresh + "New Template from Current Edits" + "Cancel".
//! 2. Two-column body:
//!    - Left: scrollable list of templates (built-in then user). Filtered
//!      by an optional table-match toggle so the active tab's templates
//!      surface first.
//!    - Right: details for the selected template — name, table, description,
//!      every `field_changes` entry, and apply / delete buttons.
//!
//! ## Why deferred actions
//!
//! Like the conflict panel, this panel iterates over `state.user_templates`
//! while rendering and can't mutate the list mid-iteration. Apply, delete,
//! and reload are queued into `Action` values and applied once the render
//! pass returns.

use serde_json::Value;

use crate::edit_history::{get_at_path, set_at_path, EditOp};
use crate::mod_io::extract_entry_key;
use crate::state::AppState;
use crate::templates::{
    apply_template, builtin_templates, delete_user_template, load_user_templates, save_user_template,
    Template,
};

/// Per-frame intent collected while rendering. Applied after the closure
/// returns to avoid taking a second mutable borrow on `state`.
enum Action {
    Reload,
    Apply { idx: TemplateIdx },
    Delete { idx: usize },
    SaveCurrentAsTemplate,
}

/// Where in the merged list the selected template lives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TemplateIdx {
    Builtin(usize),
    User(usize),
}

/// Per-panel UI state. Lives on [`AppState::templates_panel`].
#[derive(Default)]
pub struct TemplatesPanelState {
    pub selected: Option<TemplateIdx>,
    /// When true, only show templates whose `table` matches the active tab.
    pub filter_by_active_table: bool,
    /// Lazily populated text input for "save as new template".
    pub new_template_name: String,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Templates");
    ui.label(
        egui::RichText::new(
            "Apply preset field changes to the active entry, or save your \
             current edits as a reusable template.",
        )
        .weak(),
    );
    ui.separator();

    let mut pending: Option<Action> = None;

    // ── Toolbar ──────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        if ui
            .button("Reload User Templates")
            .on_hover_text("Re-read the user templates directory from disk.")
            .clicked()
        {
            pending = Some(Action::Reload);
        }
        if ui
            .button("New Template from Current Edits")
            .on_hover_text(
                "Save every changed top-level field on the currently selected \
                 entry as a brand-new user template.",
            )
            .clicked()
        {
            pending = Some(Action::SaveCurrentAsTemplate);
        }
        ui.checkbox(
            &mut state.templates_panel.filter_by_active_table,
            "Filter by active table",
        );
    });
    ui.separator();

    // ── Body: list on left, details on right ─────────────────────────────
    let active_table = state
        .active_table()
        .map(|t| t.dispatch_name.clone())
        .unwrap_or_default();

    let builtins = builtin_templates();

    egui::SidePanel::left("templates_list_panel")
        .resizable(true)
        .default_width(280.0)
        .show_inside(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(egui::RichText::new("Built-in").strong());
                for (i, tpl) in builtins.iter().enumerate() {
                    if state.templates_panel.filter_by_active_table
                        && !active_table.is_empty()
                        && tpl.table != active_table
                    {
                        continue;
                    }
                    let selected =
                        state.templates_panel.selected == Some(TemplateIdx::Builtin(i));
                    let label = format!("{}  [{}]", tpl.name, tpl.table);
                    if ui.selectable_label(selected, label).clicked() {
                        state.templates_panel.selected = Some(TemplateIdx::Builtin(i));
                    }
                }

                ui.add_space(8.0);
                ui.label(egui::RichText::new("User").strong());
                if state.user_templates.is_empty() {
                    ui.label(
                        egui::RichText::new("(no user templates saved yet)")
                            .weak(),
                    );
                }
                for (i, tpl) in state.user_templates.iter().enumerate() {
                    if state.templates_panel.filter_by_active_table
                        && !active_table.is_empty()
                        && tpl.table != active_table
                    {
                        continue;
                    }
                    let selected =
                        state.templates_panel.selected == Some(TemplateIdx::User(i));
                    let label = format!("{}  [{}]", tpl.name, tpl.table);
                    if ui.selectable_label(selected, label).clicked() {
                        state.templates_panel.selected = Some(TemplateIdx::User(i));
                    }
                }
            });
        });

    // Right side: details for the selected template.
    let chosen: Option<Template> = match state.templates_panel.selected {
        Some(TemplateIdx::Builtin(i)) => builtins.get(i).cloned(),
        Some(TemplateIdx::User(i)) => state.user_templates.get(i).cloned(),
        None => None,
    };

    egui::CentralPanel::default().show_inside(ui, |ui| {
        let Some(tpl) = chosen.as_ref() else {
            ui.centered_and_justified(|ui| {
                ui.label("Select a template from the list");
            });
            return;
        };

        ui.heading(&tpl.name);
        ui.label(format!("Target table: {}", tpl.table));
        ui.label(format!(
            "Origin: {}",
            if tpl.user_defined { "User" } else { "Built-in" }
        ));
        ui.separator();
        ui.label(&tpl.description);
        ui.separator();

        ui.label(egui::RichText::new("Field changes").strong());
        if tpl.field_changes.is_empty() {
            ui.label(egui::RichText::new("(none)").weak());
        } else {
            egui::Grid::new("templates_field_changes")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Path").strong());
                    ui.label(egui::RichText::new("Value").strong());
                    ui.label(egui::RichText::new("Mode").strong());
                    ui.end_row();
                    for fc in &tpl.field_changes {
                        ui.label(&fc.path);
                        ui.label(format_value(&fc.value));
                        ui.label(if fc.multiplicative { "× multiply" } else { "= replace" });
                        ui.end_row();
                    }
                });
        }

        ui.add_space(8.0);

        // Action row.
        ui.horizontal(|ui| {
            // Apply
            let apply_enabled = state
                .active_table()
                .and_then(|t| t.selected_entry_idx)
                .is_some();
            let mismatch = !active_table.is_empty() && tpl.table != active_table;
            let apply_btn = ui.add_enabled(
                apply_enabled,
                egui::Button::new("Apply to Selected Entry"),
            );
            let apply_btn = if mismatch {
                apply_btn.on_hover_text(format!(
                    "Template targets '{}' but '{}' is the active tab — \
                     applying will look for the field paths on this entry \
                     anyway, which may fail.",
                    tpl.table, active_table
                ))
            } else {
                apply_btn
            };
            if apply_btn.clicked() {
                if let Some(idx) = state.templates_panel.selected {
                    pending = Some(Action::Apply { idx });
                }
            }

            // Delete (user-defined only).
            if tpl.user_defined {
                if ui
                    .button(
                        egui::RichText::new("Delete")
                            .color(egui::Color32::from_rgb(230, 80, 80)),
                    )
                    .clicked()
                {
                    if let Some(TemplateIdx::User(i)) = state.templates_panel.selected {
                        pending = Some(Action::Delete { idx: i });
                    }
                }
            }
        });
    });

    // Apply deferred action.
    if let Some(action) = pending {
        match action {
            Action::Reload => match load_user_templates() {
                Ok(list) => {
                    let n = list.len();
                    state.user_templates = list;
                    state.toasts.info(format!(
                        "Reloaded {} user template{}",
                        n,
                        if n == 1 { "" } else { "s" }
                    ));
                }
                Err(e) => {
                    state.toasts.error_with_details(
                        "Failed to reload user templates",
                        e.to_string(),
                    );
                }
            },
            Action::Apply { idx } => {
                let tpl = match idx {
                    TemplateIdx::Builtin(i) => builtins.get(i).cloned(),
                    TemplateIdx::User(i) => state.user_templates.get(i).cloned(),
                };
                if let Some(tpl) = tpl {
                    apply_to_active_entry(state, &tpl);
                }
            }
            Action::Delete { idx } => {
                if let Some(tpl) = state.user_templates.get(idx).cloned() {
                    match delete_user_template(&tpl.name) {
                        Ok(()) => {
                            state.user_templates.remove(idx);
                            // Selection may now point past the end — clear it.
                            state.templates_panel.selected = None;
                            state
                                .toasts
                                .info(format!("Deleted template '{}'", tpl.name));
                        }
                        Err(e) => {
                            state.toasts.error_with_details(
                                "Failed to delete template",
                                e.to_string(),
                            );
                        }
                    }
                }
            }
            Action::SaveCurrentAsTemplate => {
                save_current_as_template(state);
            }
        }
    }
}

/// Apply `tpl` to the active tab's currently selected entry, recording one
/// `EditOp` per field so each change is undoable.
fn apply_to_active_entry(state: &mut AppState, tpl: &Template) {
    let Some(active) = state.active_table_mut() else {
        state.toasts.warn("No table loaded");
        return;
    };
    let Some(entry_idx) = active.selected_entry_idx else {
        state.toasts.warn("Select an entry first");
        return;
    };
    let Some(entry) = active.entries.get(entry_idx).cloned() else {
        state.toasts.warn("Selected entry no longer exists");
        return;
    };
    let entry_key = extract_entry_key(&entry);
    let table_name = active.dispatch_name.clone();

    // Snapshot current field values *before* the apply so we can build
    // EditOp records for undo. We also keep a clone of the entry to roll
    // back to on partial failure.
    let mut prior_values: Vec<(String, Option<Value>)> = Vec::new();
    for fc in &tpl.field_changes {
        let prior = get_at_path(&entry, &fc.path).cloned();
        prior_values.push((fc.path.clone(), prior));
    }

    let mut working = entry.clone();
    if let Err(e) = apply_template(tpl, &mut working) {
        state.toasts.error_with_details("Apply Template failed", e);
        return;
    }

    // Commit the new entry into the live tab.
    active.entries[entry_idx] = working.clone();

    // Record an EditOp per field so the user can Ctrl+Z each one. Also
    // sync the change tracker so the export pipeline knows about them.
    let mut applied = 0usize;
    for (path, old_opt) in prior_values {
        let new_value = match get_at_path(&working, &path) {
            Some(v) => v.clone(),
            None => continue,
        };
        let old_value = old_opt.unwrap_or(Value::Null);
        if old_value == new_value {
            continue;
        }
        let vanilla_match = active
            .vanilla
            .get(entry_idx)
            .and_then(|v| get_at_path(v, &path))
            .map(|vv| vv == &new_value)
            .unwrap_or(false);
        if vanilla_match {
            active.changes.unrecord_field(entry_key, &path);
        } else {
            active.changes.record_change(entry_key, path.clone());
        }
        active.history.record(EditOp {
            table: table_name.clone(),
            entry_key,
            field_path: path,
            old_value,
            new_value,
            timestamp: std::time::Instant::now(),
        });
        applied += 1;
    }

    state.toasts.info(format!(
        "Applied template '{}' ({} field change{})",
        tpl.name,
        applied,
        if applied == 1 { "" } else { "s" }
    ));
    // Make sure the user immediately sees that "_" entry-modified style if
    // the underlying entry data changed but no fields were strictly
    // different from vanilla.
    let _ = set_at_path; // silence unused-import warning if path above is empty.
}

/// Save every changed top-level field on the active tab's *selected* entry
/// as a fresh user template. Prompts for a name via a quick rfd save dialog
/// so the user can pick a meaningful filename.
fn save_current_as_template(state: &mut AppState) {
    let Some(active) = state.active_table() else {
        state.toasts.warn("No table loaded");
        return;
    };
    let Some(entry_idx) = active.selected_entry_idx else {
        state.toasts.warn("Select an entry first");
        return;
    };
    let entry = match active.entries.get(entry_idx) {
        Some(e) => e.clone(),
        None => {
            state.toasts.warn("Selected entry no longer exists");
            return;
        }
    };
    let entry_key = extract_entry_key(&entry);
    let table_name = active.dispatch_name.clone();

    // Pull every changed top-level field for this entry.
    let Some(fields) = active.changes.modified.get(&entry_key) else {
        state
            .toasts
            .warn("Selected entry has no recorded changes — edit it first.");
        return;
    };
    if fields.is_empty() {
        state.toasts.warn("Selected entry has no recorded changes.");
        return;
    }
    let mut field_changes = Vec::new();
    for fp in fields {
        if let Some(v) = get_at_path(&entry, fp) {
            field_changes.push(crate::templates::TemplateField {
                path: fp.clone(),
                value: v.clone(),
                multiplicative: false,
            });
        }
    }
    if field_changes.is_empty() {
        state.toasts.warn("Couldn't snapshot any changed fields.");
        return;
    }

    // Cheap prompt: use rfd's save dialog purely as a name picker. We don't
    // actually use the chosen path — `save_user_template` always writes to
    // the project dir.
    let default_name = format!("{}_{}.json", table_name, entry_key);
    let chosen = rfd::FileDialog::new()
        .set_title("Name Your Template")
        .add_filter("Template name", &["json"])
        .set_file_name(default_name)
        .save_file();
    let Some(chosen_path) = chosen else { return };
    let stem = chosen_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("template")
        .to_string();

    let template = Template {
        name: stem.clone(),
        description: format!(
            "Saved from {} entry {} via mod-workbench",
            table_name, entry_key
        ),
        table: table_name,
        field_changes,
        user_defined: true,
    };

    match save_user_template(&template) {
        Ok(()) => {
            // Reload library so the new entry shows in the list.
            if let Ok(list) = load_user_templates() {
                state.user_templates = list;
            }
            state.toasts.info(format!("Saved template '{}'", stem));
        }
        Err(e) => {
            state
                .toasts
                .error_with_details("Failed to save template", e.to_string());
        }
    }
}

fn format_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Array(_) | Value::Object(_) => {
            // Compact for the table view; full detail is one click away in
            // the JSON file on disk.
            serde_json::to_string(v).unwrap_or_else(|_| "<complex>".to_string())
        }
    }
}
