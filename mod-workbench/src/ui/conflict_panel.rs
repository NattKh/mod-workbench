//! Mod conflict viewer.
//!
//! Renders the central panel when [`MainView::Conflicts`] is active. The
//! panel is split top-to-bottom into three regions:
//!
//! 1. **Toolbar** — `Load Mod...` (multi-select) and `Analyze` buttons.
//! 2. **Loaded mods list** — one row per [`LoadedMod`] with name, author,
//!    version, change count, and a per-row remove button.
//! 3. **Results** — color-coded list of conflicts. Each conflict is a
//!    [`egui::CollapsingHeader`] that expands to show field-level detail.
//!
//! For a v1 viewer there is intentionally no merging logic — the
//! "Pick A" / "Pick B" buttons on direct conflicts are placeholders and
//! display a toast saying so.
//!
//! All file-system calls (`load_mod`) are synchronous since each mod file
//! is a few KB at most. If we ever start loading hundreds of mods we'll
//! want to push this onto the worker, but it isn't worth the complexity
//! today.
//!
//! ## Why deferred actions
//!
//! Like the tab bar, this panel iterates over `state.loaded_mods` while
//! rendering and can't mutate the list mid-iteration. Removals and other
//! mutations are queued into `Action` values and applied once the render
//! pass returns.

use crate::conflict::{self, ConflictKind};
use crate::state::AppState;

/// Deferred mutation collected while rendering. Applied after the render
/// pass so we never mutate `state.loaded_mods` mid-iteration.
enum Action {
    LoadMods(Vec<std::path::PathBuf>),
    RemoveMod(usize),
    Analyze,
    PickPlaceholder, // "Pick A" / "Pick B" — viewer-only stub for v1.
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Mod Conflict Detection");
    ui.label(
        egui::RichText::new(
            "Load multiple mod files (v3 field JSON) to see what each one \
             changes and where they conflict. Viewer only — no merging in v1.",
        )
        .weak(),
    );
    ui.separator();

    let mut pending: Option<Action> = None;

    // ── Toolbar ────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        if ui.button("Load Mod...").clicked() {
            if let Some(paths) = rfd::FileDialog::new()
                .set_title("Load Mod Files")
                .add_filter("Field JSON / Mod JSON", &["json"])
                .pick_files()
            {
                pending = Some(Action::LoadMods(paths));
            }
        }
        let analyze_enabled = state.loaded_mods.len() >= 2;
        if ui
            .add_enabled(analyze_enabled, egui::Button::new("Analyze"))
            .on_hover_text(if analyze_enabled {
                "Compare every pair of loaded mods"
            } else {
                "Load two or more mods first"
            })
            .clicked()
        {
            pending = Some(Action::Analyze);
        }
        ui.label(format!("{} loaded", state.loaded_mods.len()));
    });

    ui.separator();

    // ── Loaded mods list ───────────────────────────────────────────────────
    egui::CollapsingHeader::new(format!("Loaded Mods ({})", state.loaded_mods.len()))
        .id_salt("conflict_loaded_mods")
        .default_open(true)
        .show(ui, |ui| {
            if state.loaded_mods.is_empty() {
                ui.label("(none)");
                return;
            }
            // The mod list is short (manual user load), so a plain vertical
            // layout is fine — no virtualized scroll needed.
            egui::Grid::new("conflict_mods_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Name").strong());
                    ui.label(egui::RichText::new("Author").strong());
                    ui.label(egui::RichText::new("Version").strong());
                    ui.label(egui::RichText::new("Changes").strong());
                    ui.label("");
                    ui.end_row();

                    for (i, m) in state.loaded_mods.iter().enumerate() {
                        ui.label(&m.name)
                            .on_hover_text(m.path.display().to_string());
                        ui.label(m.author.as_deref().unwrap_or("—"));
                        ui.label(m.version.as_deref().unwrap_or("—"));
                        ui.label(format!("{} ({} entries)", m.change_count(), m.entry_count()));
                        if ui.small_button("Remove").clicked() {
                            pending = Some(Action::RemoveMod(i));
                        }
                        ui.end_row();
                    }
                });
        });

    ui.separator();

    // ── Results ────────────────────────────────────────────────────────────
    let report_summary = state.conflict_report.as_ref().map(|r| {
        (
            r.conflicts.len(),
            r.direct_count(),
            r.partial_count(),
            r.mods.len(),
        )
    });

    let header_label = match report_summary {
        Some((total, direct, partial, mods)) => format!(
            "Results: {} conflicts ({} direct, {} partial) across {} mods",
            total, direct, partial, mods
        ),
        None => "Results: (run Analyze)".to_string(),
    };

    egui::CollapsingHeader::new(header_label)
        .id_salt("conflict_results")
        .default_open(true)
        .show(ui, |ui| {
            let report = match &state.conflict_report {
                Some(r) => r,
                None => {
                    ui.label("Click Analyze to compare loaded mods.");
                    return;
                }
            };
            if report.conflicts.is_empty() {
                ui.label(
                    egui::RichText::new("No conflicts detected.")
                        .color(egui::Color32::from_rgb(120, 200, 120)),
                );
                return;
            }
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .id_salt("conflict_results_scroll")
                .show(ui, |ui| {
                    for (idx, (a_idx, b_idx, kind)) in report.conflicts.iter().enumerate() {
                        let mod_a_name = report
                            .mods
                            .get(*a_idx)
                            .map(|m| m.name.as_str())
                            .unwrap_or("?");
                        let mod_b_name = report
                            .mods
                            .get(*b_idx)
                            .map(|m| m.name.as_str())
                            .unwrap_or("?");
                        if render_conflict_row(ui, idx, kind, mod_a_name, mod_b_name) {
                            pending = Some(Action::PickPlaceholder);
                        }
                    }
                });
        });

    // ── Apply queued actions outside the render borrow ─────────────────────
    if let Some(action) = pending {
        apply_action(state, action);
    }
}

/// Render one conflict as a colored, expandable row.
///
/// Returns `true` if the user clicked one of the (placeholder) Pick buttons,
/// in which case the caller queues an `Action::PickPlaceholder` to surface a
/// toast.
fn render_conflict_row(
    ui: &mut egui::Ui,
    idx: usize,
    kind: &ConflictKind,
    mod_a_name: &str,
    mod_b_name: &str,
) -> bool {
    let (color, summary) = match kind {
        ConflictKind::DirectConflict {
            table,
            entry_key,
            field_path,
            ..
        } => (
            egui::Color32::from_rgb(230, 80, 80),
            format!(
                "[Direct] {} {}: {} ({} ↔ {})",
                table, entry_key, field_path, mod_a_name, mod_b_name
            ),
        ),
        ConflictKind::PartialOverlap {
            table, entry_key, ..
        } => (
            egui::Color32::from_rgb(240, 190, 60),
            format!(
                "[Overlap] {} {}: {} & {} touch the same entry",
                table, entry_key, mod_a_name, mod_b_name
            ),
        ),
    };

    let mut clicked_pick = false;

    // Per-row CollapsingHeader: collapsed shows just the colored summary;
    // expanded reveals field-level detail and the (stub) pick buttons.
    egui::CollapsingHeader::new(egui::RichText::new(&summary).color(color))
        .id_salt(("conflict_row", idx))
        .default_open(false)
        .show(ui, |ui| {
            match kind {
                ConflictKind::DirectConflict {
                    table,
                    entry_key,
                    field_path,
                    mod_a_value,
                    mod_b_value,
                } => {
                    egui::Grid::new(("conflict_detail", idx))
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Table");
                            ui.label(table);
                            ui.end_row();
                            ui.label("Entry key");
                            ui.label(entry_key.to_string());
                            ui.end_row();
                            ui.label("Field path");
                            ui.label(field_path);
                            ui.end_row();
                            ui.label(format!("{} value", mod_a_name));
                            ui.label(format_value(mod_a_value));
                            ui.end_row();
                            ui.label(format!("{} value", mod_b_name));
                            ui.label(format_value(mod_b_value));
                            ui.end_row();
                        });
                    ui.horizontal(|ui| {
                        // Both buttons are stubs in v1 — the action queue
                        // surfaces a toast explaining merging isn't wired yet.
                        if ui
                            .button(format!("Pick A ({})", mod_a_name))
                            .on_hover_text("Merging is not implemented yet (v1 is viewer-only)")
                            .clicked()
                        {
                            clicked_pick = true;
                        }
                        if ui
                            .button(format!("Pick B ({})", mod_b_name))
                            .on_hover_text("Merging is not implemented yet (v1 is viewer-only)")
                            .clicked()
                        {
                            clicked_pick = true;
                        }
                    });
                }
                ConflictKind::PartialOverlap {
                    table,
                    entry_key,
                    a_fields,
                    b_fields,
                } => {
                    ui.label(format!(
                        "Both mods touch {} key {} but on disjoint fields — \
                         the changes will compose without overwriting.",
                        table, entry_key
                    ));
                    ui.add_space(4.0);
                    egui::Grid::new(("overlap_detail", idx))
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label(format!("{} fields", mod_a_name));
                            ui.label(if a_fields.is_empty() {
                                "(none)".to_string()
                            } else {
                                a_fields.join(", ")
                            });
                            ui.end_row();
                            ui.label(format!("{} fields", mod_b_name));
                            ui.label(if b_fields.is_empty() {
                                "(none)".to_string()
                            } else {
                                b_fields.join(", ")
                            });
                            ui.end_row();
                        });
                }
            }
        });

    clicked_pick
}

/// Render a `serde_json::Value` as a one-line label, falling back to the
/// debug form for compound values that don't have a clean Display impl.
fn format_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        // For arrays and objects, compact JSON keeps the field grid tidy.
        // Fall back to debug if serialization somehow fails (shouldn't, but
        // we never want to panic the UI).
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v))
        }
    }
}

/// Drain a queued [`Action`] into `state`. Runs *after* the render pass.
fn apply_action(state: &mut AppState, action: Action) {
    match action {
        Action::LoadMods(paths) => {
            let mut loaded = 0usize;
            for p in paths {
                match conflict::load_mod(&p) {
                    Ok(m) => {
                        state.loaded_mods.push(m);
                        loaded += 1;
                    }
                    Err(e) => {
                        state.toasts.error_with_details(
                            format!("Failed to load mod {}", p.display()),
                            e.to_string(),
                        );
                    }
                }
            }
            if loaded > 0 {
                // Any prior report is now stale — drop it so the user has to
                // re-Analyze and can't read out-of-date conflicts.
                state.conflict_report = None;
                state
                    .toasts
                    .info(format!("Loaded {} mod(s)", loaded));
            }
        }
        Action::RemoveMod(idx) => {
            if idx < state.loaded_mods.len() {
                let removed = state.loaded_mods.remove(idx);
                state.conflict_report = None;
                state
                    .toasts
                    .info(format!("Removed {}", removed.name));
            }
        }
        Action::Analyze => {
            let mods = state.loaded_mods.clone();
            let report = conflict::analyze(mods);
            let summary = format!(
                "Analyzed {} mods: {} conflicts ({} direct, {} partial)",
                report.mods.len(),
                report.conflicts.len(),
                report.direct_count(),
                report.partial_count(),
            );
            state.conflict_report = Some(report);
            state.toasts.info(summary);
        }
        Action::PickPlaceholder => {
            state
                .toasts
                .warn("Merging is not implemented yet (v1 is viewer-only)");
        }
    }
}
