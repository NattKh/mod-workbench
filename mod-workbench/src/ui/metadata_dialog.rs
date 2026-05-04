//! Mod metadata input dialog.
//!
//! Modal `egui::Window` shown before any of the three export flows
//! (`SaveJson` / `SaveModpkg` / `SaveDmm`) so the user has one chance to
//! attach attribution and version info to the resulting artifact. The
//! dialog persists its state across showings so users can refine values
//! between exports without retyping.
//!
//! ## Why state lives on [`AppState`]
//!
//! egui windows are immediate-mode — there's no `dialog.show_modal()` that
//! parks the call stack until the user hits OK. To preserve typed values
//! between frames we keep the in-progress [`ModMetadata`] on
//! [`AppState::metadata_dialog`] and let the caller (`app.rs`) read the
//! returned [`MetadataDialogOutcome`] each frame.
//!
//! When the user hits Export the outcome is `Confirm(action)` exactly once
//! — `open` is flipped to false on the same frame so subsequent frames
//! return `None` until the dialog is opened again.

use crate::mod_io::ModMetadata;

/// Which export pipeline to invoke after the dialog confirms.
///
/// Each variant maps 1:1 to a function in `crate::mod_package`. The two
/// DMM-compatible flows (`SaveDmmModFolder` and `SaveDmm`) sit alongside
/// the legacy `SaveJson` (workbench-native v3) and `SaveModpkg` (deprecated
/// zip bundle) — keeping both DMM flavours in the menu lets users pick the
/// shape their downstream tool expects without trial-and-error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportAction {
    /// Single `.json` file via [`crate::mod_package::export_v3_json`].
    /// Workbench-native — only useful for re-importing into mod-workbench.
    SaveJson,
    /// `.modpkg` zip via [`crate::mod_package::export_modpkg`].
    /// Deprecated — kept for backwards compatibility with older releases.
    SaveModpkg,
    /// DMM v3 intent JSON file via [`crate::mod_package::export_dmm_v3_json`].
    /// Single self-contained .json with `modinfo` + `format: 3` + `targets[]`,
    /// the shape DMM 1.3.3+ ingests.
    SaveDmm,
    /// PAZ overlay folder mod via [`crate::mod_package::export_paz_mod_folder`].
    /// What DMM/Stacker actually want for "folder mods" — recommended.
    SaveDmmModFolder,
}

impl ExportAction {
    /// Window-title suffix (e.g. "Export as JSON") so the dialog tells the
    /// user which flow they're on.
    pub fn label(&self) -> &'static str {
        match self {
            ExportAction::SaveJson => "Export as Workbench JSON",
            ExportAction::SaveModpkg => "Export as .modpkg",
            ExportAction::SaveDmm => "Export as DMM v3 Intent JSON",
            ExportAction::SaveDmmModFolder => "Export as DMM Mod Folder",
        }
    }
}

/// Persistent dialog state owned by [`crate::state::AppState`].
pub struct MetadataDialog {
    /// True while the modal is rendered. Flipped to false on Cancel,
    /// Export, or close.
    pub open: bool,
    /// Scratchpad metadata bound to the dialog's text fields. Survives
    /// dialog dismissal so re-opening shows the last typed values.
    pub metadata: ModMetadata,
    /// Which export to fire when the user hits the Export button.
    pub action_after: ExportAction,
    /// Editable buffer for the comma-separated dependencies field. We
    /// keep a string here (rather than mutating `metadata.dependencies`
    /// directly) because the user types commas as separators and we don't
    /// want to re-tokenize on every keystroke.
    pub dependencies_input: String,
}

impl Default for MetadataDialog {
    fn default() -> Self {
        Self {
            open: false,
            metadata: ModMetadata::default(),
            action_after: ExportAction::SaveJson,
            dependencies_input: String::new(),
        }
    }
}

impl MetadataDialog {
    /// Open the dialog targeting `action`. Preserves any previously typed
    /// metadata so users don't have to retype between successive exports.
    pub fn open_for(&mut self, action: ExportAction) {
        self.open = true;
        self.action_after = action;
    }

    /// Sync the comma-separated dependencies input back into
    /// `metadata.dependencies`. Called right before we hand the metadata
    /// off to the export pipeline.
    pub fn commit_dependencies(&mut self) {
        self.metadata.dependencies = self
            .dependencies_input
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
    }
}

/// Outcome returned to the caller for the current frame.
pub enum MetadataDialogOutcome {
    /// User clicked Export — caller should run the matching exporter.
    Confirm(ExportAction),
    /// User clicked Cancel or closed the window.
    Cancel,
}

/// Render the dialog. Returns `Some(outcome)` exactly on the frame the
/// user resolves the modal (Confirm or Cancel); `None` otherwise.
///
/// Caller is expected to gate the call on `dialog.open` so we never
/// re-render after dismissal.
pub fn show(ctx: &egui::Context, dialog: &mut MetadataDialog) -> Option<MetadataDialogOutcome> {
    let mut outcome: Option<MetadataDialogOutcome> = None;

    // We track the `open` flag locally because `egui::Window::open` takes
    // a `&mut bool` and would race with the Cancel/Export buttons below
    // if we shared the same field.
    let mut window_open = dialog.open;

    egui::Window::new(dialog.action_after.label())
        .open(&mut window_open)
        .collapsible(false)
        .resizable(true)
        .default_width(440.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new(
                    "Fill in attribution + version info for this mod. All fields \
                     are optional, but Nexus uploads usually want at least name, \
                     author, and version.",
                )
                .weak(),
            );
            ui.add_space(6.0);

            egui::Grid::new("metadata_dialog_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.metadata.name)
                            .desired_width(f32::INFINITY)
                            .hint_text("e.g. Cool Item Buffs"),
                    );
                    ui.end_row();

                    ui.label("Author");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.metadata.author)
                            .desired_width(f32::INFINITY)
                            .hint_text("Your handle"),
                    );
                    ui.end_row();

                    ui.label("Version");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.metadata.version)
                            .desired_width(f32::INFINITY)
                            .hint_text("e.g. 1.0.0"),
                    );
                    ui.end_row();

                    ui.label("Nexus URL");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.metadata.nexus_url)
                            .desired_width(f32::INFINITY)
                            .hint_text("https://www.nexusmods.com/..."),
                    );
                    ui.end_row();

                    ui.label("Dependencies");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.dependencies_input)
                            .desired_width(f32::INFINITY)
                            .hint_text("Comma-separated mod names"),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.label("Description");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.metadata.description)
                    .desired_width(f32::INFINITY)
                    .desired_rows(4)
                    .hint_text("Short description shown in the README + DMM sidecar"),
            );

            ui.add_space(8.0);
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    outcome = Some(MetadataDialogOutcome::Cancel);
                }
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        let export_label = match dialog.action_after {
                            ExportAction::SaveJson => "Export JSON...",
                            ExportAction::SaveModpkg => "Export .modpkg...",
                            ExportAction::SaveDmm => "Export DMM Intent JSON...",
                            ExportAction::SaveDmmModFolder => "Export Mod Folder...",
                        };
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new(export_label).strong(),
                            ))
                            .clicked()
                        {
                            dialog.commit_dependencies();
                            outcome = Some(MetadataDialogOutcome::Confirm(dialog.action_after));
                        }
                    },
                );
            });
        });

    // Window's titlebar X was clicked.
    if !window_open && outcome.is_none() {
        outcome = Some(MetadataDialogOutcome::Cancel);
    }

    // Snap the persisted flag to whatever happened this frame.
    if matches!(outcome, Some(_)) {
        dialog.open = false;
    } else {
        dialog.open = window_open;
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_dependencies_splits_and_trims() {
        let mut d = MetadataDialog::default();
        d.dependencies_input = " a,  b , ,c ".to_string();
        d.commit_dependencies();
        assert_eq!(d.metadata.dependencies, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_commit_dependencies_empty_input_clears_vec() {
        let mut d = MetadataDialog::default();
        d.metadata.dependencies = vec!["existing".into()];
        d.dependencies_input = "".to_string();
        d.commit_dependencies();
        assert!(d.metadata.dependencies.is_empty());
    }

    #[test]
    fn test_open_for_sets_action_and_open() {
        let mut d = MetadataDialog::default();
        assert!(!d.open);
        d.open_for(ExportAction::SaveModpkg);
        assert!(d.open);
        assert_eq!(d.action_after, ExportAction::SaveModpkg);
    }

    #[test]
    fn test_export_action_label() {
        assert_eq!(ExportAction::SaveJson.label(), "Export as Workbench JSON");
        assert_eq!(ExportAction::SaveModpkg.label(), "Export as .modpkg");
        assert_eq!(ExportAction::SaveDmm.label(), "Export as DMM v3 Intent JSON");
        assert_eq!(
            ExportAction::SaveDmmModFolder.label(),
            "Export as DMM Mod Folder"
        );
    }
}
