//! Validation / lint panel.
//!
//! Renders [`AppState::lint_findings`] as a grouped, severity-sorted list of
//! issues with one-click "Apply Fix" buttons for findings that ship an
//! [`AutoFix`]. Fixes flow through the same `EditOp` history pipeline used
//! by the field panel so the user can Ctrl+Z them.
//!
//! Layout (top -> bottom):
//!
//! 1. Header: heading + Close button (returns to PABGB editor).
//! 2. Toolbar: "Run Lint Check" button, summary counts, "Clear" button.
//! 3. Scrollable list: findings grouped by rule, severity-coloured rows,
//!    each with a long-form message and (when available) Apply Fix.
//!
//! ## Why findings live on AppState
//!
//! Findings can outlive the table they came from — for example, the user
//! runs lint on iteminfo, switches to a buffinfo tab, and looks at the
//! panel again. Storing the vec on `AppState` (and tagging each finding
//! with its source `table` + `entry_key`) means the panel can still render
//! and "Apply Fix" looks up the right tab.
//!
//! ## Apply Fix details
//!
//! `AutoFix::SetField` and `AutoFix::RemoveField` resolve the target tab by
//! `dispatch_name` (matching the finding's `table` field) and target entry
//! by `entry_key`. If either is missing (tab closed, key removed), the
//! action is a no-op with a warn toast. `AutoFix::Custom` renders a label
//! with the manual-fix description and exposes no button.

use std::time::Instant;

use serde_json::Value;

use crate::edit_history::{get_at_path, set_at_path, EditOp};
use crate::state::{AppState, MainView};
use crate::validation::{AutoFix, LintFinding, LintRunner, Severity};

/// Outcome of one frame's interaction with the lint panel.
///
/// Returned to `app.rs` so the caller can run a lint, apply a fix, or clear
/// findings without taking a second mutable borrow on state from inside the
/// panel.
pub enum LintAction {
    /// User clicked "Run Lint Check" — re-run lints against the active tab.
    Run,
    /// User clicked "Clear" — drop all stored findings.
    Clear,
    /// User clicked "Apply Fix" on the finding at this index in
    /// `state.lint_findings`.
    ApplyFix(usize),
}

/// Render the lint panel into `ui`. Mutations are gated behind the
/// returned [`LintAction`] so caller-side code applies them with a clean
/// `&mut state` borrow.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<LintAction> {
    let mut action: Option<LintAction> = None;

    // Header row: heading on the left, Close button on the right.
    ui.horizontal(|ui| {
        ui.heading("Lint Findings");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Close").clicked() {
                state.main_view = MainView::PabgbTables;
            }
        });
    });
    ui.separator();

    // Active-tab summary so the user always knows what a Run will check.
    let active_table = state
        .active_table()
        .map(|t| (t.dispatch_name.clone(), t.entries.len()));
    match &active_table {
        Some((name, count)) => {
            ui.label(
                egui::RichText::new(format!(
                    "Active tab: {} ({} entries)",
                    name, count
                ))
                .weak(),
            );
        }
        None => {
            ui.label(
                egui::RichText::new("No active tab — load a table to enable lint runs.")
                    .weak(),
            );
        }
    }

    // Toolbar: Run / Clear / count summary.
    ui.horizontal(|ui| {
        if ui
            .add_enabled(active_table.is_some(), egui::Button::new("Run Lint Check"))
            .on_hover_text(
                "Run all built-in lint rules against the entries in the active tab.",
            )
            .clicked()
        {
            action = Some(LintAction::Run);
        }
        if ui
            .add_enabled(
                !state.lint_findings.is_empty(),
                egui::Button::new("Clear"),
            )
            .on_hover_text("Drop all stored findings.")
            .clicked()
        {
            action = Some(LintAction::Clear);
        }
        ui.separator();
        let (errors, warns, infos) = LintRunner::count_by_severity(&state.lint_findings);
        ui.label(
            egui::RichText::new(format!(
                "Errors: {}  Warnings: {}  Info: {}",
                errors, warns, infos
            ))
            .weak(),
        );
    });
    ui.separator();

    if state.lint_findings.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label("No findings. Click \"Run Lint Check\" to validate the active tab.");
        });
        return action;
    }

    // Scrollable list grouped by rule. Findings already arrive sorted by
    // severity (Error > Warn > Info) then by rule, so we just render in
    // order, breaking out a CollapsingHeader on each rule transition.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("lint_findings_scroll")
        .show(ui, |ui| {
            let mut current_rule: Option<&str> = None;
            // Buffer the indices that belong to the current rule group so
            // we can render them inside one CollapsingHeader.
            let mut group_indices: Vec<usize> = Vec::new();

            for (idx, finding) in state.lint_findings.iter().enumerate() {
                match current_rule {
                    Some(name) if name == finding.rule_name.as_str() => {
                        group_indices.push(idx);
                    }
                    _ => {
                        if !group_indices.is_empty() {
                            if let Some(a) =
                                render_group(ui, &state.lint_findings, &group_indices)
                            {
                                action = Some(a);
                            }
                            group_indices.clear();
                        }
                        current_rule = Some(finding.rule_name.as_str());
                        group_indices.push(idx);
                    }
                }
            }
            // Flush the final group.
            if !group_indices.is_empty() {
                if let Some(a) = render_group(ui, &state.lint_findings, &group_indices) {
                    action = Some(a);
                }
            }
        });

    action
}

/// Render a single rule's group of findings inside a CollapsingHeader.
fn render_group(
    ui: &mut egui::Ui,
    all_findings: &[LintFinding],
    indices: &[usize],
) -> Option<LintAction> {
    let mut action: Option<LintAction> = None;

    // Group label uses the worst severity colour so the user can scan the
    // panel by eye and spot the Error groups first.
    let worst_severity = indices
        .iter()
        .filter_map(|i| all_findings.get(*i))
        .map(|f| f.severity)
        .min_by_key(|s| s.rank())
        .unwrap_or(Severity::Info);
    let rule_name = all_findings
        .get(indices[0])
        .map(|f| f.rule_name.clone())
        .unwrap_or_default();

    let header_text = egui::RichText::new(format!(
        "{} {} ({} finding{})",
        severity_glyph(worst_severity),
        rule_name,
        indices.len(),
        if indices.len() == 1 { "" } else { "s" },
    ))
    .color(severity_color(worst_severity))
    .strong();

    egui::CollapsingHeader::new(header_text)
        .id_salt(format!("lint_group_{}", rule_name))
        .default_open(worst_severity == Severity::Error)
        .show(ui, |ui| {
            for &i in indices {
                let Some(finding) = all_findings.get(i) else {
                    continue;
                };
                if let Some(a) = render_finding(ui, i, finding) {
                    action = Some(a);
                }
                ui.separator();
            }
        });

    action
}

/// Render one finding row. Returns Some(ApplyFix) when the user clicked the
/// Apply Fix button.
fn render_finding(
    ui: &mut egui::Ui,
    index: usize,
    finding: &LintFinding,
) -> Option<LintAction> {
    let mut action: Option<LintAction> = None;

    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(
            1.0,
            severity_color(finding.severity),
        ))
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            // Top line: severity badge, table:key, optional name.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(severity_label(finding.severity))
                        .color(severity_color(finding.severity))
                        .strong(),
                );
                ui.separator();
                let target = match &finding.entry_name {
                    Some(name) => {
                        format!("{} : {} (key={})", finding.table, name, finding.entry_key)
                    }
                    None => format!("{} : key={}", finding.table, finding.entry_key),
                };
                ui.label(egui::RichText::new(target).strong());
            });

            // Body: the message itself. Wrap so long messages stay readable.
            ui.label(&finding.message);

            // Footer: Apply Fix button (when automatable) or manual-fix hint.
            match &finding.fix_suggestion {
                Some(AutoFix::SetField {
                    field_path,
                    new_value,
                }) => {
                    ui.horizontal(|ui| {
                        let summary = format!(
                            "Set '{}' = {}",
                            field_path,
                            short_value(new_value)
                        );
                        ui.label(egui::RichText::new(summary).weak().small());
                        if ui
                            .button("Apply Fix")
                            .on_hover_text(
                                "Apply the suggested change as a recorded edit (undoable via Ctrl+Z).",
                            )
                            .clicked()
                        {
                            action = Some(LintAction::ApplyFix(index));
                        }
                    });
                }
                Some(AutoFix::RemoveField { field_path }) => {
                    ui.horizontal(|ui| {
                        let summary = format!("Remove '{}'", field_path);
                        ui.label(egui::RichText::new(summary).weak().small());
                        if ui
                            .button("Apply Fix")
                            .on_hover_text(
                                "Apply the suggested removal as a recorded edit (undoable via Ctrl+Z).",
                            )
                            .clicked()
                        {
                            action = Some(LintAction::ApplyFix(index));
                        }
                    });
                }
                Some(AutoFix::Custom(desc)) => {
                    ui.label(
                        egui::RichText::new(format!("Manual fix: {}", desc))
                            .weak()
                            .italics(),
                    );
                }
                None => {
                    ui.label(
                        egui::RichText::new("No automatic fix available.")
                            .weak()
                            .italics(),
                    );
                }
            }
        });

    action
}

/// One-character severity glyph for the group header.
fn severity_glyph(s: Severity) -> &'static str {
    match s {
        Severity::Error => "[E]",
        Severity::Warn => "[W]",
        Severity::Info => "[i]",
    }
}

/// Long-form severity label used inside each finding card.
fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Error => "ERROR",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

/// Severity colour palette. Picked to read on the dark theme.
fn severity_color(s: Severity) -> egui::Color32 {
    match s {
        Severity::Error => egui::Color32::from_rgb(230, 80, 80),
        Severity::Warn => egui::Color32::from_rgb(240, 190, 60),
        Severity::Info => egui::Color32::from_rgb(100, 170, 255),
    }
}

/// Compact one-line preview of a JSON value, used in the "Set field" hint.
fn short_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{}\"", s),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Apply Fix plumbing
// ---------------------------------------------------------------------------

/// Apply a single fix to the right tab + entry, recording an EditOp on that
/// tab's history so undo restores the prior value.
///
/// Resolved as:
/// 1. Find the open tab whose `dispatch_name` matches `finding.table`. If
///    no tab is open the fix can't apply — return Err and let the caller
///    surface a toast.
/// 2. Find the entry in that tab whose key matches `finding.entry_key`.
///    Same deal: missing entry -> Err.
/// 3. Apply the fix based on the AutoFix variant and record the edit.
///
/// Returns `Ok(())` on success or `Err(message)` describing why the fix
/// couldn't apply. The message is suitable for direct toast display.
pub fn apply_fix(state: &mut AppState, finding: &LintFinding) -> Result<(), String> {
    let Some(fix) = &finding.fix_suggestion else {
        return Err("Finding has no automatic fix.".to_string());
    };

    // Locate the matching tab. We don't auto-load tables — the user might
    // legitimately have closed the tab the lint ran against, and reopening
    // it would race with the in-flight worker.
    let tab_idx = state
        .open_tabs
        .iter()
        .position(|t| t.dispatch_name == finding.table)
        .ok_or_else(|| {
            format!(
                "Tab '{}' is not open. Open it first, then re-run lint.",
                finding.table
            )
        })?;

    let tab = state
        .open_tabs
        .get_mut(tab_idx)
        .expect("tab_idx came from position()");

    // Locate the matching entry by key.
    let entry_idx = tab
        .entries
        .iter()
        .position(|e| crate::mod_io::extract_entry_key(e) == finding.entry_key)
        .ok_or_else(|| {
            format!(
                "Entry with key={} no longer exists in '{}'.",
                finding.entry_key, finding.table
            )
        })?;

    let table_name = tab.dispatch_name.clone();

    match fix {
        AutoFix::SetField {
            field_path,
            new_value,
        } => {
            // Snapshot the old value before mutating so undo can restore it.
            let old_value = get_at_path(&tab.entries[entry_idx], field_path)
                .cloned()
                .unwrap_or(Value::Null);
            let applied = set_at_path(
                &mut tab.entries[entry_idx],
                field_path,
                new_value.clone(),
            );
            if !applied {
                return Err(format!(
                    "Failed to set field '{}' on entry {}.",
                    field_path, finding.entry_key
                ));
            }
            tab.changes
                .record_change(finding.entry_key, field_path.clone());
            tab.history.record(EditOp {
                table: table_name,
                entry_key: finding.entry_key,
                field_path: field_path.clone(),
                old_value,
                new_value: new_value.clone(),
                timestamp: Instant::now(),
            });
            Ok(())
        }
        AutoFix::RemoveField { field_path } => {
            // Removal is currently only supported for top-level fields —
            // nested removal would need a tree-aware mutator we haven't
            // built yet. The validation rules don't emit RemoveField for
            // nested paths, so this is fine for now.
            if field_path.contains('.') || field_path.contains('[') {
                return Err(format!(
                    "Removing nested field '{}' is not supported yet.",
                    field_path
                ));
            }
            let Some(obj) = tab.entries[entry_idx].as_object_mut() else {
                return Err(format!(
                    "Entry {} is not an object — can't remove a field.",
                    finding.entry_key
                ));
            };
            let old_value = obj.remove(field_path).unwrap_or(Value::Null);
            tab.changes
                .record_change(finding.entry_key, field_path.clone());
            tab.history.record(EditOp {
                table: table_name,
                entry_key: finding.entry_key,
                field_path: field_path.clone(),
                old_value,
                new_value: Value::Null,
                timestamp: Instant::now(),
            });
            Ok(())
        }
        AutoFix::Custom(desc) => Err(format!(
            "Manual fix required: {}",
            desc
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_glyph_and_color_round_trip() {
        // Smoke tests: just exercise the helpers so we catch a refactor
        // that drops a variant.
        for s in [Severity::Error, Severity::Warn, Severity::Info] {
            assert!(!severity_glyph(s).is_empty());
            assert!(!severity_label(s).is_empty());
            let _ = severity_color(s);
        }
    }

    #[test]
    fn short_value_handles_null_and_string() {
        assert_eq!(short_value(&Value::Null), "null");
        assert_eq!(short_value(&Value::String("hi".into())), "\"hi\"");
        assert_eq!(short_value(&serde_json::json!(42)), "42");
    }
}
