//! PAATT projectile-attribute editor panel.
//!
//! One mode for now (`Editor`); the structure mirrors the XML panel so a
//! future second mode (e.g. raw-byte hex view) can be added without a
//! restructure.
//!
//! Workflow:
//!   1. "Browse PAZ for `.paatt` files" walks every numeric overlay
//!      group and lists every `.paatt` it finds (typically the
//!      projectile-attribute file in `0010/actionchart/`).
//!   2. The user picks one from the dropdown; we extract its bytes via
//!      [`crate::paatt_editor::read_paatt_from_paz`] and parse with
//!      [`dmm_parser_rust_only::tables::paatt::PaattFile`].
//!   3. We detect physics-projectile entries via the
//!      `projectileRadius` / `endEffectLifeTime` 0.01f-pair anchor
//!      pattern (matching the Python `paatt_patch.py`). Each anchor is
//!      one entry in the left list.
//!   4. Selecting an entry on the left exposes editable float fields on
//!      the right via `egui::DragValue`. Edits land directly on the
//!      parsed `PaattFile.body`; "Apply to Game" deploys the modified
//!      bytes via [`crate::paatt_editor::deploy_paatt_overlay`].
//!   5. "Restore Vanilla" wipes the overlay group and removes the PAPGT
//!      entry. Same pattern as the XML editor's restore button.
//!
//! Session state lives on [`AppState::paatt`] so view switches don't
//! lose the user's edits.

use dmm_parser_rust_only::tables::paatt::info::{FIELD_OFFSETS, PaattFile};

use crate::paatt_editor::{self, PaattPazEntry};
use crate::state::{AppState, PendingNav};

/// Top-level mode toggle for the panel. Stored on [`PaattSession`].
/// Only one mode for now — the toggle is plumbed in so the panel can
/// grow a second mode (e.g. byte-level raw editor) later without a
/// state restructure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PaattMode {
    /// Field-level editor for each detected physics entry.
    Editor,
}

impl Default for PaattMode {
    fn default() -> Self {
        PaattMode::Editor
    }
}

/// Persistent state for the PAATT panel. Owned by [`AppState`].
pub struct PaattSession {
    pub mode: PaattMode,

    /// PAZ enumeration cache — every `.paatt` file the workbench can
    /// find across all PAZ groups under the configured Game Directory.
    /// `None` means we haven't scanned yet; an empty Vec means we
    /// scanned and found nothing (or the Game Directory isn't set).
    pub paz_files: Option<Vec<PaattPazEntry>>,
    /// Substring filter applied to `paz_files` for the picker dropdown.
    pub paz_filter: String,
    /// The currently-loaded entry, if any.
    pub current_entry: Option<PaattPazEntry>,
    /// The parsed file, mutable so DragValue edits apply in place.
    pub file: Option<PaattFile>,
    /// Vanilla bytes of the currently-loaded entry — kept so a future
    /// "diff vs vanilla" feature can work without re-extracting.
    pub vanilla_bytes: Option<Vec<u8>>,
    /// Detected projectile entries, identified by their
    /// `projectileRadius` body offset. Recomputed when a file is
    /// loaded and after the user explicitly hits "Rescan entries".
    pub entry_offsets: Vec<usize>,
    /// Currently selected entry index into `entry_offsets`.
    pub selected_entry_idx: Option<usize>,
    /// Overlay group used by Apply to Game / Restore. Default `0066`
    /// matches the Python `paatt_deploy.py`. Distinct from the XML
    /// editor's `0070` so multiple workbench overlays can coexist.
    pub overlay_group: String,
}

impl Default for PaattSession {
    fn default() -> Self {
        Self {
            mode: PaattMode::default(),
            paz_files: None,
            paz_filter: String::new(),
            current_entry: None,
            file: None,
            vanilla_bytes: None,
            entry_offsets: Vec::new(),
            selected_entry_idx: None,
            overlay_group: "0066".to_string(),
        }
    }
}

/// Render the PAATT panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    consume_pending_nav(state);
    ui.horizontal(|ui| {
        ui.heading("PAATT Editor (Projectile Attributes)");
        ui.separator();
        ui.selectable_value(&mut state.paatt.mode, PaattMode::Editor, "Editor");
    });
    ui.label(
        "Field-level editor for projectileinfo .paatt files — radius, \
         shape, sound refs. Detects physics entries via the \
         projectileRadius/endEffectLifeTime anchor pair.",
    );
    ui.separator();

    file_picker(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.paatt.file.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a `.paatt` file from the dropdown above (or use \
                 'Load file from disk') to start editing.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    // Two-column layout: entry list on the left, fields on the right.
    egui::SidePanel::left("paatt_entries_left")
        .resizable(true)
        .default_width(260.0)
        .min_width(180.0)
        .show_inside(ui, |ui| {
            ui.heading("Entries");
            ui.label(
                egui::RichText::new(format!(
                    "{} physics entries detected",
                    state.paatt.entry_offsets.len()
                ))
                .small()
                .weak(),
            );
            if ui.button("Rescan").on_hover_text(
                "Re-detect physics entries via the 0.01f-pair anchor pattern.\nUseful after a manual edit changes the byte layout.",
            ).clicked() {
                if let Some(file) = state.paatt.file.as_ref() {
                    state.paatt.entry_offsets = file.physics_radius_offsets();
                    state.paatt.selected_entry_idx = None;
                }
            }
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("paatt_entries_scroll")
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    let entries = state.paatt.entry_offsets.clone();
                    for (i, &body_off) in entries.iter().enumerate() {
                        let selected =
                            state.paatt.selected_entry_idx == Some(i);
                        let label = format!(
                            "Entry #{:<4} @ +0x{:06X}",
                            i, body_off + 8
                        );
                        if ui.selectable_label(selected, label).clicked() {
                            state.paatt.selected_entry_idx = Some(i);
                        }
                    }
                });
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.heading("Entry detail");
        entry_detail_panel(ui, state);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);
        deploy_section(ui, state);
    });
}

fn file_picker(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for .paatt files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match paatt_editor::enumerate_paatt_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.paatt.paz_files = Some(files);
                        state
                            .toasts
                            .info(format!("Found {} .paatt file(s) in PAZ.", count));
                    }
                    Err(e) => state.toasts.error_with_details(
                        "PAZ scan failed",
                        format!("{}", e),
                    ),
                },
                None => state
                    .toasts
                    .warn("Set the Game Directory first (Settings)."),
            }
        }
        if ui.button("Load file from disk...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Pick .paatt file")
                .add_filter("PAATT", &["paatt"])
                .pick_file()
            {
                load_paatt_from_path(state, &path);
            }
        }
    });

    if let Some(files) = state.paatt.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.paatt.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.paatt.paz_filter.to_lowercase();
        let filtered: Vec<&PaattPazEntry> = files
            .iter()
            .filter(|e| {
                if filter.is_empty() {
                    true
                } else {
                    e.filename.to_lowercase().contains(&filter)
                        || e.dir_path.to_lowercase().contains(&filter)
                }
            })
            .collect();

        let current_label = state
            .paatt
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<PaattPazEntry> = None;
        egui::ComboBox::from_id_salt("paatt_paz_file_picker")
            .selected_text(current_label)
            .width(640.0)
            .show_ui(ui, |ui| {
                for e in filtered.iter().take(500) {
                    if ui.selectable_label(false, e.display()).clicked() {
                        to_open = Some((*e).clone());
                    }
                }
                if filtered.len() > 500 {
                    ui.label(
                        egui::RichText::new(format!(
                            "... {} more (use the filter)",
                            filtered.len() - 500
                        ))
                        .weak(),
                    );
                }
            });
        if let Some(entry) = to_open {
            load_paatt_from_paz(state, &entry);
        }
    }

    if let Some(entry) = &state.paatt.current_entry {
        ui.label(
            egui::RichText::new(format!(
                "Loaded: [{}] {}/{}",
                entry.group, entry.dir_path, entry.filename
            ))
            .color(egui::Color32::from_rgb(140, 200, 140)),
        );
    }
}

/// Drain a pending [`PendingNav::Paatt`] request and load the matching
/// file. Byte-offset positioning is not supported here (the panel
/// surfaces detected physics entries, not raw offsets) — the partial
/// jump just opens the file.
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::Paatt {
        paz_group,
        dir_path,
        filename,
    }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    state.pending_global_nav = None;

    if let Some(cur) = state.paatt.current_entry.as_ref() {
        if cur.group == paz_group && cur.dir_path == dir_path && cur.filename == filename {
            return;
        }
    }
    let entry = PaattPazEntry {
        group: paz_group,
        dir_path,
        filename,
    };
    load_paatt_from_paz(state, &entry);
}

fn load_paatt_from_paz(state: &mut AppState, entry: &PaattPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match paatt_editor::read_paatt_from_paz(&game_dir, entry) {
        Ok(bytes) => match PaattFile::parse(&bytes) {
            Ok(file) => {
                let offsets = file.physics_radius_offsets();
                state.paatt.entry_offsets = offsets;
                state.paatt.file = Some(file);
                state.paatt.current_entry = Some(entry.clone());
                state.paatt.vanilla_bytes = Some(bytes);
                state.paatt.selected_entry_idx = None;
                state
                    .toasts
                    .info(format!("Loaded {} from PAZ", entry.filename));
            }
            Err(e) => state.toasts.error_with_details(
                "PAATT parse failed",
                format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAATT read failed",
            format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
        ),
    }
}

fn load_paatt_from_path(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => match PaattFile::parse(&bytes) {
            Ok(file) => {
                let offsets = file.physics_radius_offsets();
                state.paatt.entry_offsets = offsets;
                state.paatt.file = Some(file);
                state.paatt.current_entry = None;
                state.paatt.vanilla_bytes = Some(bytes);
                state.paatt.selected_entry_idx = None;
                state
                    .toasts
                    .info(format!("Loaded {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "PAATT parse failed",
                format!("{}\nFile: {}", e, path.display()),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAATT read failed",
            format!("{}\nFile: {}", e, path.display()),
        ),
    }
}

fn entry_detail_panel(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(idx) = state.paatt.selected_entry_idx else {
        ui.label(
            egui::RichText::new(
                "No entry selected. Click an entry in the left list.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    };
    let Some(file) = state.paatt.file.as_mut() else {
        return;
    };
    let Some(&body_off) = state.paatt.entry_offsets.get(idx) else {
        ui.label(
            egui::RichText::new("Selected entry index is stale; pick again.")
                .color(egui::Color32::from_rgb(230, 80, 80)),
        );
        return;
    };

    ui.label(
        egui::RichText::new(format!(
            "Entry #{} — body offset 0x{:X} (file offset 0x{:X})",
            idx,
            body_off,
            body_off + 8,
        ))
        .strong(),
    );
    ui.add_space(4.0);

    egui::Grid::new("paatt_entry_fields")
        .num_columns(3)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("Field").strong());
            ui.label(egui::RichText::new("Value").strong());
            ui.label(egui::RichText::new("Offset").strong());
            ui.end_row();

            for &(rel, name) in FIELD_OFFSETS {
                ui.label(name);
                if name.starts_with("spawnItemKey") {
                    // u32 key — show as hex / unsigned int.
                    if let Some(v) = file.read_field_u32(body_off, rel) {
                        let mut value = v;
                        let resp = ui.add(
                            egui::DragValue::new(&mut value)
                                .speed(1.0),
                        );
                        if resp.changed() {
                            file.write_field_u32(body_off, rel, value);
                        }
                    } else {
                        ui.label(
                            egui::RichText::new("(out of range)")
                                .color(egui::Color32::from_gray(140)),
                        );
                    }
                } else if let Some(v) = file.read_field_f32(body_off, rel) {
                    // float — DragValue with a sensible step.
                    let mut value = v;
                    let resp = ui.add(
                        egui::DragValue::new(&mut value)
                            .speed(0.01)
                            .range(-1.0e6..=1.0e6),
                    );
                    if resp.changed() {
                        file.write_field_f32(body_off, rel, value);
                    }
                } else {
                    ui.label(
                        egui::RichText::new("(out of range)")
                            .color(egui::Color32::from_gray(140)),
                    );
                }
                let signed_rel = rel;
                ui.label(
                    egui::RichText::new(format!(
                        "+0x{:X}",
                        body_off as i64 + signed_rel,
                    ))
                    .small()
                    .weak(),
                );
                ui.end_row();
            }
        });
}

fn deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paatt.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.paatt.file.is_some()
            && state.paatt.current_entry.is_some()
            && state.game_dir.is_some();
        let deploy_btn = ui.add_enabled(
            can_deploy,
            egui::Button::new(
                egui::RichText::new("⬆ Apply to Game")
                    .color(egui::Color32::from_rgb(140, 200, 240))
                    .strong(),
            ),
        );
        if deploy_btn.clicked() {
            apply_to_game(state);
        }

        let restore_btn = ui.add_enabled(
            state.game_dir.is_some(),
            egui::Button::new(
                egui::RichText::new("✖ Restore Vanilla")
                    .color(egui::Color32::from_rgb(230, 120, 120)),
            ),
        );
        if restore_btn.clicked() {
            restore_overlay(state);
        }

        if ui.button("Save .paatt to disk...").clicked() {
            save_paatt_to_disk(state);
        }
    });

    if !can_apply(state) {
        ui.label(
            egui::RichText::new(
                "Apply to Game needs: a file loaded from PAZ + Game Directory set.",
            )
            .color(egui::Color32::from_gray(160))
            .small(),
        );
    }
}

fn can_apply(state: &AppState) -> bool {
    state.paatt.file.is_some()
        && state.paatt.current_entry.is_some()
        && state.game_dir.is_some()
}

fn apply_to_game(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(entry) = state.paatt.current_entry.clone() else {
        return;
    };
    let Some(file) = state.paatt.file.as_ref() else {
        return;
    };
    let bytes = file.to_bytes();
    let group = state.paatt.overlay_group.clone();
    match paatt_editor::deploy_paatt_overlay(
        &game_dir,
        &entry.dir_path,
        &entry.filename,
        &bytes,
        &group,
    ) {
        Ok(()) => state.toasts.info(format!(
            "Deployed {} as overlay group {}",
            entry.filename, group
        )),
        Err(e) => state.toasts.error_with_details(
            "PAATT deploy failed",
            format!("{}\nGroup: {}\nFile: {}", e, group, entry.filename),
        ),
    }
}

fn restore_overlay(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let group = state.paatt.overlay_group.clone();
    match paatt_editor::restore_paatt_overlay(&game_dir, &group) {
        Ok(()) => state
            .toasts
            .info(format!("Removed PAATT overlay group {}", group)),
        Err(e) => state.toasts.error_with_details(
            "Restore failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn save_paatt_to_disk(state: &mut AppState) {
    let Some(file) = state.paatt.file.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save .paatt")
        .add_filter("PAATT", &["paatt"])
        .save_file()
    else {
        return;
    };
    let bytes = file.to_bytes();
    match std::fs::write(&path, &bytes) {
        Ok(()) => state
            .toasts
            .info(format!("Wrote {}", path.display())),
        Err(e) => state.toasts.error_with_details(
            "Write failed",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}
