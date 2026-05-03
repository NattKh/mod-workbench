//! Step-by-step guided flows ("wizards") that compose existing primitives
//! (templates, field edits, paseq swaps) into one-button user tasks.
//!
//! Each wizard is its own struct implementing the [`Wizard`] trait. The
//! wizards panel keeps an `Option<Box<dyn Wizard>>` on [`AppState`] and
//! drives it via [`Wizard::show`] every frame until the wizard returns
//! [`WizardResult::Completed`] or [`WizardResult::Cancelled`].
//!
//! ## Why a trait + boxed dyn
//!
//! Wizards have wildly different state (some pick a single item, others a
//! whole table list) but the panel only needs a uniform "render and tell me
//! what happened" interface. Boxing keeps the per-frame UI shim small and
//! lets us add new wizards without touching the panel.
//!
//! ## What v1 ships
//!
//! Two proof-of-concept wizards live in this module:
//!
//! - [`StatBoostWizard`]: pick the active table's selected entry, pick a
//!   field to multiply, set the multiplier, apply.
//! - [`BlankTemplateWizard`]: name a fresh template, fill in a description,
//!   save it to the user library so further entries can be authored from
//!   the templates panel.
//!
//! Two more wizards (`NpcSwapWizard`, `BulkPriceWizard`) are stubbed out as
//! TODO: their underlying primitives already exist (`paseq_editor::swap_npcs`
//! and the templates pipeline), so wrapping them is mostly UI plumbing.

use serde_json::Value;

use crate::edit_history::{get_at_path, set_at_path, EditOp};
use crate::mod_io::{extract_entry_key, ModMetadata};
use crate::state::AppState;
use crate::templates::{save_user_template, Template, TemplateField};

/// Trait implemented by every wizard. The panel only ever sees this
/// abstraction.
pub trait Wizard {
    /// Display name shown in the wizards picker and the live dialog title.
    fn name(&self) -> &str;
    /// One-line description shown next to the picker entry.
    fn description(&self) -> &str;
    /// Render one frame of the wizard's UI. The wizard owns its own state
    /// and tells the host what to do via the returned [`WizardResult`].
    fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) -> WizardResult;
}

/// Result of one wizard `show` call. Maps directly onto host-side actions:
///
/// - `InProgress`: keep the dialog open.
/// - `Cancelled`: drop the wizard from `state.active_wizard`.
/// - `Completed`: drop the wizard, surface a toast, optionally chain into
///   the export-mod flow.
pub enum WizardResult {
    InProgress,
    Cancelled,
    Completed {
        /// Optional metadata describing the mod the wizard produced. The
        /// host may use this to pre-fill the export dialog. None when the
        /// wizard didn't produce a fresh mod (e.g. saved a template).
        mod_metadata: Option<ModMetadata>,
        /// Number of entries / templates / files the wizard modified.
        /// Surfaced verbatim in the completion toast.
        changes_applied: usize,
        /// Short human-readable summary line for the toast.
        summary: String,
    },
}

// ── Catalog of available wizards ────────────────────────────────────────────

/// Construct one wizard per supported flow. The wizards panel calls this
/// once per frame while the picker is open — wizards are cheap to build, so
/// re-instantiating each frame keeps state simple.
pub fn available_wizards() -> Vec<Box<dyn Wizard>> {
    vec![
        Box::new(StatBoostWizard::default()),
        Box::new(BlankTemplateWizard::default()),
    ]
}

// ── StatBoostWizard ─────────────────────────────────────────────────────────

/// Pick a numeric field on the currently selected entry, then multiply it
/// by a chosen factor. Records the result through the active tab's edit
/// history so Ctrl+Z still works.
pub struct StatBoostWizard {
    /// 0 = pick field, 1 = pick multiplier, 2 = confirm.
    step: u8,
    /// Path of the field selected in step 0.
    chosen_field: Option<String>,
    /// Multiplier text the user is typing.
    multiplier_input: String,
    /// Last validated multiplier, set when the user advances from step 1.
    multiplier: f64,
}

impl Default for StatBoostWizard {
    fn default() -> Self {
        Self {
            step: 0,
            chosen_field: None,
            multiplier_input: "2.0".to_string(),
            multiplier: 2.0,
        }
    }
}

impl StatBoostWizard {
    /// Walk the active entry once and return the dot-path of every numeric
    /// leaf, plus its current value as f64. Skips arrays/objects so the
    /// picker only offers things the wizard knows how to multiply.
    fn collect_numeric_fields(&self, entry: &Value) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        collect_numeric_inner(entry, String::new(), &mut out);
        // Stable order helps users find fields again across runs.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

fn collect_numeric_inner(value: &Value, path: String, out: &mut Vec<(String, f64)>) {
    match value {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                out.push((path, f));
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let next = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", path, k)
                };
                collect_numeric_inner(v, next, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let next = format!("{}[{}]", path, i);
                collect_numeric_inner(v, next, out);
            }
        }
        _ => {}
    }
}

impl Wizard for StatBoostWizard {
    fn name(&self) -> &str {
        "Stat Boost"
    }
    fn description(&self) -> &str {
        "Pick a numeric field on the selected entry and multiply it by a chosen factor."
    }

    fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) -> WizardResult {
        // Need a selected entry for any of this to make sense.
        let Some(active) = state.active_table() else {
            ui.label("Open a PABGB table tab and select an entry, then re-run the wizard.");
            ui.add_space(6.0);
            if ui.button("Cancel").clicked() {
                return WizardResult::Cancelled;
            }
            return WizardResult::InProgress;
        };
        let Some(entry_idx) = active.selected_entry_idx else {
            ui.label("No entry selected on the active tab. Click an entry first.");
            ui.add_space(6.0);
            if ui.button("Cancel").clicked() {
                return WizardResult::Cancelled;
            }
            return WizardResult::InProgress;
        };
        let table_name = active.dispatch_name.clone();
        let entry = match active.entries.get(entry_idx) {
            Some(e) => e.clone(),
            None => {
                ui.label("Selected entry no longer exists.");
                if ui.button("Cancel").clicked() {
                    return WizardResult::Cancelled;
                }
                return WizardResult::InProgress;
            }
        };
        let entry_key = extract_entry_key(&entry);

        ui.label(format!("Table: {}", table_name));
        ui.label(format!("Entry key: {}", entry_key));
        ui.separator();

        match self.step {
            0 => {
                ui.heading("Step 1 / 3 — Pick a numeric field");
                let fields = self.collect_numeric_fields(&entry);
                if fields.is_empty() {
                    ui.label("No numeric leaves found on this entry.");
                    if ui.button("Cancel").clicked() {
                        return WizardResult::Cancelled;
                    }
                    return WizardResult::InProgress;
                }
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for (path, val) in &fields {
                            let selected = self.chosen_field.as_deref() == Some(path.as_str());
                            let label = format!("{} = {}", path, val);
                            if ui.selectable_label(selected, label).clicked() {
                                self.chosen_field = Some(path.clone());
                            }
                        }
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        return WizardResult::Cancelled;
                    }
                    let next_enabled = self.chosen_field.is_some();
                    if ui
                        .add_enabled(next_enabled, egui::Button::new("Next"))
                        .clicked()
                    {
                        self.step = 1;
                    }
                    WizardResult::InProgress
                })
                .inner
            }
            1 => {
                ui.heading("Step 2 / 3 — Choose multiplier");
                ui.label(format!(
                    "Field: {}",
                    self.chosen_field.as_deref().unwrap_or("?")
                ));
                ui.horizontal(|ui| {
                    ui.label("Multiplier:");
                    ui.text_edit_singleline(&mut self.multiplier_input);
                });
                let parsed: Option<f64> = self.multiplier_input.trim().parse().ok();
                if parsed.is_none() {
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 190, 60),
                        "Enter a number (e.g. 2 or 0.5).",
                    );
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Back").clicked() {
                        self.step = 0;
                    }
                    if ui.button("Cancel").clicked() {
                        return WizardResult::Cancelled;
                    }
                    let next = ui.add_enabled(
                        parsed.is_some(),
                        egui::Button::new("Next"),
                    );
                    if next.clicked() {
                        if let Some(p) = parsed {
                            self.multiplier = p;
                            self.step = 2;
                        }
                    }
                    WizardResult::InProgress
                })
                .inner
            }
            _ => {
                // Step 2: confirm + apply.
                ui.heading("Step 3 / 3 — Confirm");
                let path = self.chosen_field.clone().unwrap_or_default();
                let current = get_at_path(&entry, &path)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let new_val = current * self.multiplier;
                ui.label(format!(
                    "Apply: {} = {} × {} = {}",
                    path, current, self.multiplier, new_val
                ));
                ui.add_space(6.0);
                let mut result = WizardResult::InProgress;
                ui.horizontal(|ui| {
                    if ui.button("Back").clicked() {
                        self.step = 1;
                    }
                    if ui.button("Cancel").clicked() {
                        result = WizardResult::Cancelled;
                        return;
                    }
                    if ui.button("Apply").clicked() {
                        match apply_stat_boost(state, &table_name, entry_key, &path, self.multiplier) {
                            Ok(()) => {
                                result = WizardResult::Completed {
                                    mod_metadata: None,
                                    changes_applied: 1,
                                    summary: format!(
                                        "Multiplied '{}' by {}",
                                        path, self.multiplier
                                    ),
                                };
                            }
                            Err(e) => {
                                state.toasts.error_with_details(
                                    "Stat Boost failed",
                                    e,
                                );
                            }
                        }
                    }
                });
                result
            }
        }
    }
}

/// Apply the multiplier to the live entry on the named table tab and
/// record an EditOp so the change is undoable.
fn apply_stat_boost(
    state: &mut AppState,
    table_name: &str,
    entry_key: u64,
    path: &str,
    multiplier: f64,
) -> Result<(), String> {
    // Find the tab by dispatch name (the user could have switched away
    // between picking and confirming).
    let tab_idx = state
        .open_tabs
        .iter()
        .position(|t| t.dispatch_name == table_name)
        .ok_or_else(|| format!("table '{}' is no longer open", table_name))?;
    let tab = &mut state.open_tabs[tab_idx];

    let entry_idx = tab
        .entries
        .iter()
        .position(|e| extract_entry_key(e) == entry_key)
        .ok_or_else(|| format!("entry key {} no longer exists", entry_key))?;

    let old_value = get_at_path(&tab.entries[entry_idx], path)
        .ok_or_else(|| format!("path '{}' missing on entry", path))?
        .clone();
    let current_f = old_value
        .as_f64()
        .ok_or_else(|| format!("field at '{}' is not numeric", path))?;
    let new_f = current_f * multiplier;

    // Preserve integer-ness when both sides are whole.
    let new_value = if old_value.is_i64() && multiplier.fract() == 0.0 {
        Value::from(new_f as i64)
    } else if old_value.is_u64() && multiplier.fract() == 0.0 && new_f >= 0.0 {
        Value::from(new_f as u64)
    } else {
        Value::from(new_f)
    };

    if !set_at_path(&mut tab.entries[entry_idx], path, new_value.clone()) {
        return Err(format!("failed to write new value at '{}'", path));
    }

    // Update change tracker (matches vanilla check, like field_panel).
    let vanilla_match = tab
        .vanilla
        .get(entry_idx)
        .and_then(|v| get_at_path(v, path))
        .map(|vv| vv == &new_value)
        .unwrap_or(false);
    if vanilla_match {
        tab.changes.unrecord_field(entry_key, path);
    } else {
        tab.changes.record_change(entry_key, path.to_string());
    }

    // Record op for undo/redo.
    tab.history.record(EditOp {
        table: table_name.to_string(),
        entry_key,
        field_path: path.to_string(),
        old_value,
        new_value,
        timestamp: std::time::Instant::now(),
    });
    Ok(())
}

// ── BlankTemplateWizard ─────────────────────────────────────────────────────

/// Author a brand-new user template by name + description, optionally
/// seeded with field changes derived from the active tab's diff.
pub struct BlankTemplateWizard {
    name_input: String,
    description_input: String,
    /// Whether to seed the new template with the active tab's currently
    /// changed fields. Off by default — most authors start blank.
    seed_from_changes: bool,
    last_error: Option<String>,
}

impl Default for BlankTemplateWizard {
    fn default() -> Self {
        Self {
            name_input: String::new(),
            description_input: String::new(),
            seed_from_changes: false,
            last_error: None,
        }
    }
}

impl Wizard for BlankTemplateWizard {
    fn name(&self) -> &str {
        "New User Template"
    }
    fn description(&self) -> &str {
        "Save the current table edits as a reusable template, or start blank."
    }

    fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) -> WizardResult {
        let table_name = state
            .active_table()
            .map(|t| t.dispatch_name.clone())
            .unwrap_or_default();
        ui.label(format!(
            "Target table: {}",
            if table_name.is_empty() {
                "(none — open a table first)"
            } else {
                table_name.as_str()
            }
        ));
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Name:");
            ui.text_edit_singleline(&mut self.name_input);
        });
        ui.label("Description:");
        ui.add(
            egui::TextEdit::multiline(&mut self.description_input)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        ui.checkbox(
            &mut self.seed_from_changes,
            "Seed with this tab's currently changed fields",
        );

        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::from_rgb(230, 80, 80), err);
        }

        ui.add_space(6.0);
        let mut result = WizardResult::InProgress;
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                result = WizardResult::Cancelled;
                return;
            }
            let can_save = !self.name_input.trim().is_empty() && !table_name.is_empty();
            if ui
                .add_enabled(can_save, egui::Button::new("Save Template"))
                .clicked()
            {
                let template = build_template(
                    state,
                    &table_name,
                    self.name_input.trim(),
                    self.description_input.trim(),
                    self.seed_from_changes,
                );
                match save_user_template(&template) {
                    Ok(()) => {
                        // Reload the on-disk library so the panel sees the
                        // new entry without needing a restart.
                        if let Ok(list) = crate::templates::load_user_templates() {
                            state.user_templates = list;
                        }
                        let n = template.field_changes.len();
                        result = WizardResult::Completed {
                            mod_metadata: None,
                            changes_applied: n,
                            summary: format!(
                                "Saved template '{}' ({} field change{})",
                                template.name,
                                n,
                                if n == 1 { "" } else { "s" },
                            ),
                        };
                    }
                    Err(e) => {
                        self.last_error = Some(format!("Save failed: {}", e));
                    }
                }
            }
        });
        result
    }
}

/// Build a [`Template`] from the active tab's state. When
/// `seed_from_changes` is true we walk the change tracker and snapshot the
/// current value of each modified top-level field.
fn build_template(
    state: &AppState,
    table_name: &str,
    name: &str,
    description: &str,
    seed_from_changes: bool,
) -> Template {
    let mut field_changes = Vec::new();
    if seed_from_changes {
        if let Some(tab) = state.active_table() {
            for (entry_key, fields) in &tab.changes.modified {
                // Find the live entry so we can read the *current* values.
                let Some(entry) = tab
                    .entries
                    .iter()
                    .find(|e| extract_entry_key(e) == *entry_key)
                else {
                    continue;
                };
                for fp in fields {
                    if let Some(v) = get_at_path(entry, fp) {
                        field_changes.push(TemplateField {
                            path: fp.clone(),
                            value: v.clone(),
                            multiplicative: false,
                        });
                    }
                }
                // First entry is enough — templates are entry-agnostic.
                break;
            }
        }
    }
    Template {
        name: name.to_string(),
        description: description.to_string(),
        table: table_name.to_string(),
        field_changes,
        user_defined: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collect_numeric_walks_nested() {
        let v = json!({
            "a": 1,
            "b": {"c": 2.0, "d": "skip"},
            "e": [10, 20]
        });
        let wiz = StatBoostWizard::default();
        let fields = wiz.collect_numeric_fields(&v);
        let paths: Vec<&str> = fields.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"a"));
        assert!(paths.contains(&"b.c"));
        assert!(paths.contains(&"e[0]"));
        assert!(paths.contains(&"e[1]"));
        // Strings are skipped.
        assert!(!paths.contains(&"b.d"));
    }

    #[test]
    fn available_wizards_includes_known_flows() {
        let names: Vec<String> = available_wizards()
            .iter()
            .map(|w| w.name().to_string())
            .collect();
        assert!(names.contains(&"Stat Boost".to_string()));
        assert!(names.contains(&"New User Template".to_string()));
    }
}
