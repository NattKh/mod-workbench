//! PAPPT part-prefab table editor panel.
//!
//! Format definition lives at
//! `tools/mod-workbench/PAPPT_FORMAT_RESEARCH.md`. The parser is
//! [`dmm_parser_rust_only::tables::pappt::PapptFile`] and round-trips
//! byte-for-byte against vanilla, so structural edits land cleanly
//! on disk.
//!
//! Workflow:
//!   1. "Browse PAZ for `.pappt` files" walks every numeric overlay
//!      group and lists every `.pappt` it finds (typically just
//!      `character/bin__/partprefabtable.pappt` in retail).
//!   2. The user picks one from the dropdown; we extract its bytes via
//!      [`crate::pappt_editor::read_pappt_from_paz`] and parse with
//!      [`dmm_parser_rust_only::tables::pappt::PapptFile`].
//!   3. The left side has two sub-tabs — Primary entries and
//!      Secondary entries. Selecting a primary row populates the right
//!      side detail panel with editable fields for `key_a`, `key_b`,
//!      `key_c`, `asset_id`, `flag`, and the children list.
//!   4. Secondary entries are edited inline in their table.
//!   5. "Apply to Game" deploys the modified bytes via
//!      [`crate::pappt_editor::deploy_pappt_overlay`]. "Restore Vanilla"
//!      wipes the overlay group and removes the PAPGT entry.
//!
//! Session state lives on [`AppState::pappt`] so view switches don't
//! lose the user's edits. Default overlay group is `"0071"` — one
//! above the XML editor's `"0070"`.

use dmm_parser_rust_only::tables::pappt::{PapptFile, PrimaryChild, SecondaryEntry};
use egui_extras::{Column, TableBuilder};

use crate::pappt_editor::{self, PapptPazEntry};
use crate::state::{AppState, PendingNav};

/// Sub-tab on the left side of the editor — primary entry list vs
/// secondary alias-pair list. Stored on [`PapptSession`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PapptTab {
    Primary,
    Secondary,
}

impl Default for PapptTab {
    fn default() -> Self {
        PapptTab::Primary
    }
}

/// Persistent state for the PAPPT panel. Owned by [`AppState`].
pub struct PapptSession {
    pub tab: PapptTab,

    /// PAZ enumeration cache — every `.pappt` file the workbench can
    /// find across all PAZ groups under the configured Game Directory.
    /// `None` means we haven't scanned yet; an empty Vec means we
    /// scanned and found nothing (or the Game Directory isn't set).
    pub paz_files: Option<Vec<PapptPazEntry>>,
    /// Substring filter applied to `paz_files` for the picker dropdown.
    pub paz_filter: String,
    /// The currently-loaded entry, if any.
    pub current_entry: Option<PapptPazEntry>,
    /// The parsed file, mutable so edits apply in place.
    pub file: Option<PapptFile>,
    /// Vanilla bytes of the currently-loaded entry — kept so a future
    /// "diff vs vanilla" feature can work without re-extracting.
    pub vanilla_bytes: Option<Vec<u8>>,

    /// Substring filter applied to the primary list table.
    pub primary_filter: String,
    /// Substring filter applied to the secondary list table.
    pub secondary_filter: String,
    /// Currently selected primary entry index, drives the right-side
    /// detail panel.
    pub selected_primary_idx: Option<usize>,

    /// Overlay group used by Apply to Game / Restore. Default `"0071"`
    /// — one above the XML editor's `"0070"`.
    pub overlay_group: String,
}

impl Default for PapptSession {
    fn default() -> Self {
        Self {
            tab: PapptTab::default(),
            paz_files: None,
            paz_filter: String::new(),
            current_entry: None,
            file: None,
            vanilla_bytes: None,
            primary_filter: String::new(),
            secondary_filter: String::new(),
            selected_primary_idx: None,
            overlay_group: "0071".to_string(),
        }
    }
}

/// Render the PAPPT panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    consume_pending_nav(state);
    ui.horizontal(|ui| {
        ui.heading("PAPPT Editor (Part-Prefab Table)");
        ui.separator();
        ui.label(
            egui::RichText::new(
                "Single global registry mapping short part-prefab names \
                 + per-character variants to interned string IDs.",
            )
            .small()
            .weak(),
        );
    });
    ui.separator();

    file_picker(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.pappt.file.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a `.pappt` file from the dropdown above (or use \
                 'Load file from disk') to start editing.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    header_strip(ui, state);
    ui.add_space(4.0);
    ui.separator();

    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.pappt.tab, PapptTab::Primary, "Primary entries");
        ui.selectable_value(
            &mut state.pappt.tab,
            PapptTab::Secondary,
            "Secondary entries",
        );
    });
    ui.separator();

    match state.pappt.tab {
        PapptTab::Primary => primary_view(ui, state),
        PapptTab::Secondary => secondary_view(ui, state),
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    deploy_section(ui, state);
}

// ── Header strip ─────────────────────────────────────────────────────

fn header_strip(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(file) = state.pappt.file.as_ref() else {
        return;
    };
    // Recompute the serialized size from the current edited file so
    // the header reflects in-progress edits, not just the vanilla
    // size at load time. write() runs in a few ms even on large
    // pappt files, well under the per-frame budget.
    let serialized_len = file.write().len();
    ui.horizontal(|ui| {
        ui.label(format!("Primary: {}", file.primary.len()));
        ui.separator();
        ui.label(format!("Secondary: {}", file.secondary.len()));
        ui.separator();
        ui.label(format!("File size: {} bytes", serialized_len));
        if let Some(entry) = &state.pappt.current_entry {
            ui.separator();
            ui.label(
                egui::RichText::new(format!(
                    "[{}] {}/{}",
                    entry.group, entry.dir_path, entry.filename
                ))
                .color(egui::Color32::from_rgb(140, 200, 140)),
            );
        }
    });
}

// ── File picker ──────────────────────────────────────────────────────

fn file_picker(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for .pappt files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match pappt_editor::enumerate_pappt_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.pappt.paz_files = Some(files);
                        state
                            .toasts
                            .info(format!("Found {} .pappt file(s) in PAZ.", count));
                    }
                    Err(e) => state
                        .toasts
                        .error_with_details("PAZ scan failed", format!("{}", e)),
                },
                None => state
                    .toasts
                    .warn("Set the Game Directory first (Settings)."),
            }
        }
        if ui.button("Load file from disk...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Pick .pappt file")
                .add_filter("PAPPT", &["pappt"])
                .pick_file()
            {
                load_pappt_from_path(state, &path);
            }
        }
    });

    if let Some(files) = state.pappt.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.pappt.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.pappt.paz_filter.to_lowercase();
        let filtered: Vec<&PapptPazEntry> = files
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
            .pappt
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<PapptPazEntry> = None;
        egui::ComboBox::from_id_salt("pappt_paz_file_picker")
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
            load_pappt_from_paz(state, &entry);
        }
    }
}

/// Drain a pending [`PendingNav::Pappt`] request and load the matching
/// file. Byte-offset positioning is not applied — pappt edits go
/// through structured Primary / Secondary tables, not raw offsets.
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::Pappt {
        paz_group,
        dir_path,
        filename,
    }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    state.pending_global_nav = None;

    if let Some(cur) = state.pappt.current_entry.as_ref() {
        if cur.group == paz_group && cur.dir_path == dir_path && cur.filename == filename {
            return;
        }
    }
    let entry = PapptPazEntry {
        group: paz_group,
        dir_path,
        filename,
    };
    load_pappt_from_paz(state, &entry);
}

fn load_pappt_from_paz(state: &mut AppState, entry: &PapptPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match pappt_editor::read_pappt_from_paz(&game_dir, entry) {
        Ok(bytes) => match PapptFile::parse(&bytes) {
            Ok(file) => {
                state.pappt.file = Some(file);
                state.pappt.current_entry = Some(entry.clone());
                state.pappt.vanilla_bytes = Some(bytes);
                state.pappt.selected_primary_idx = None;
                state
                    .toasts
                    .info(format!("Loaded {} from PAZ", entry.filename));
            }
            Err(e) => state.toasts.error_with_details(
                "PAPPT parse failed",
                format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAPPT read failed",
            format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
        ),
    }
}

fn load_pappt_from_path(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => match PapptFile::parse(&bytes) {
            Ok(file) => {
                state.pappt.file = Some(file);
                state.pappt.current_entry = None;
                state.pappt.vanilla_bytes = Some(bytes);
                state.pappt.selected_primary_idx = None;
                state.toasts.info(format!("Loaded {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "PAPPT parse failed",
                format!("{}\nFile: {}", e, path.display()),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAPPT read failed",
            format!("{}\nFile: {}", e, path.display()),
        ),
    }
}

// ── Primary tab ──────────────────────────────────────────────────────

fn primary_view(ui: &mut egui::Ui, state: &mut AppState) {
    egui::SidePanel::left("pappt_primary_left")
        .resizable(true)
        .default_width(440.0)
        .min_width(280.0)
        .show_inside(ui, |ui| primary_list(ui, state));

    egui::CentralPanel::default().show_inside(ui, |ui| primary_detail(ui, state));
}

fn primary_list(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.pappt.primary_filter)
                .desired_width(220.0)
                .hint_text("substring (matches key_a, key_b, asset_id)"),
        );
        if ui.button("+ New").on_hover_text("Append a blank primary entry.").clicked() {
            if let Some(file) = state.pappt.file.as_mut() {
                file.primary.push(Default::default());
                state.pappt.selected_primary_idx = Some(file.primary.len() - 1);
            }
        }
    });
    ui.add_space(4.0);

    let Some(file) = state.pappt.file.as_ref() else {
        return;
    };
    let filter = state.pappt.primary_filter.to_lowercase();
    let visible: Vec<usize> = file
        .primary
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if filter.is_empty()
                || e.key_a.to_lowercase().contains(&filter)
                || e.key_b.to_lowercase().contains(&filter)
                || e.asset_id.to_lowercase().contains(&filter)
            {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    let mut to_select: Option<usize> = None;
    let selected_idx = state.pappt.selected_primary_idx;

    TableBuilder::new(ui)
        .id_salt("pappt_primary_table")
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(50.0)) // #
        .column(Column::auto().at_least(90.0)) // key_a
        .column(Column::auto().at_least(90.0)) // key_b
        .column(Column::remainder().at_least(140.0)) // asset_id
        .column(Column::auto().at_least(50.0)) // flag
        .column(Column::auto().at_least(60.0)) // children
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("#");
            });
            header.col(|ui| {
                ui.strong("key_a");
            });
            header.col(|ui| {
                ui.strong("key_b");
            });
            header.col(|ui| {
                ui.strong("asset_id");
            });
            header.col(|ui| {
                ui.strong("flag");
            });
            header.col(|ui| {
                ui.strong("children");
            });
        })
        .body(|body| {
            body.rows(22.0, visible.len(), |mut row| {
                let row_idx = row.index();
                let entry_idx = visible[row_idx];
                let entry = &file.primary[entry_idx];
                let is_selected = selected_idx == Some(entry_idx);

                row.col(|ui| {
                    let label = if is_selected {
                        egui::RichText::new(format!("{}", entry_idx))
                            .color(egui::Color32::from_rgb(140, 200, 240))
                            .strong()
                    } else {
                        egui::RichText::new(format!("{}", entry_idx))
                    };
                    if ui.selectable_label(is_selected, label).clicked() {
                        to_select = Some(entry_idx);
                    }
                });
                row.col(|ui| {
                    if ui.selectable_label(is_selected, &entry.key_a).clicked() {
                        to_select = Some(entry_idx);
                    }
                });
                row.col(|ui| {
                    if ui.selectable_label(is_selected, &entry.key_b).clicked() {
                        to_select = Some(entry_idx);
                    }
                });
                row.col(|ui| {
                    if ui
                        .selectable_label(is_selected, &entry.asset_id)
                        .clicked()
                    {
                        to_select = Some(entry_idx);
                    }
                });
                row.col(|ui| {
                    ui.label(format!("{:#04x}", entry.flag));
                });
                row.col(|ui| {
                    ui.label(format!("{}", entry.children.len()));
                });
            });
        });

    if let Some(idx) = to_select {
        state.pappt.selected_primary_idx = Some(idx);
    }
}

fn primary_detail(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(idx) = state.pappt.selected_primary_idx else {
        ui.label(
            egui::RichText::new("Select a primary entry on the left to edit it.")
                .color(egui::Color32::from_gray(160)),
        );
        return;
    };
    let Some(file) = state.pappt.file.as_mut() else {
        return;
    };
    if idx >= file.primary.len() {
        ui.label(
            egui::RichText::new("Stale selection — pick another row.")
                .color(egui::Color32::from_rgb(230, 90, 90)),
        );
        return;
    }

    // Action holder for the Delete button — applied after the borrow
    // of the entry ends so we don't double-borrow `file.primary`.
    let mut delete_requested = false;

    ui.horizontal(|ui| {
        ui.heading(format!("Primary entry #{}", idx));
        ui.separator();
        if ui
            .button("Delete entry")
            .on_hover_text("Remove this primary entry from the file.")
            .clicked()
        {
            delete_requested = true;
        }
    });
    ui.add_space(4.0);

    if delete_requested {
        file.primary.remove(idx);
        state.pappt.selected_primary_idx = None;
        return;
    }

    let entry = &mut file.primary[idx];

    egui::Grid::new("pappt_primary_fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("key_a").strong());
            pstr_edit(ui, &mut entry.key_a, "pappt_key_a");
            ui.end_row();

            ui.label(egui::RichText::new("key_b").strong());
            pstr_edit(ui, &mut entry.key_b, "pappt_key_b");
            ui.end_row();

            ui.label(egui::RichText::new("key_c").strong());
            pstr_edit(ui, &mut entry.key_c, "pappt_key_c");
            ui.end_row();

            ui.label(egui::RichText::new("asset_id").strong());
            pstr_edit(ui, &mut entry.asset_id, "pappt_asset_id");
            ui.end_row();

            ui.label(egui::RichText::new("flag").strong());
            ui.add(egui::DragValue::new(&mut entry.flag).range(0..=255));
            ui.end_row();
        });

    ui.add_space(8.0);
    ui.separator();
    ui.label(egui::RichText::new("Children").strong());
    ui.label(
        egui::RichText::new(
            "Variant entries hashed into the same global string-intern \
             table as `_partPrefabKey`. Up to 255 children per primary entry.",
        )
        .small()
        .weak(),
    );
    ui.add_space(4.0);

    children_table(ui, &mut entry.children);
}

fn children_table(ui: &mut egui::Ui, children: &mut Vec<PrimaryChild>) {
    let mut to_remove: Option<usize> = None;
    let can_add = children.len() < 255;

    ui.horizontal(|ui| {
        let add_btn = ui.add_enabled(can_add, egui::Button::new("+ Add Child"));
        if add_btn.clicked() {
            children.push(PrimaryChild::default());
        }
        if !can_add {
            ui.label(
                egui::RichText::new("(255 child cap reached)")
                    .small()
                    .weak(),
            );
        }
    });

    if children.is_empty() {
        ui.label(
            egui::RichText::new("(no children)")
                .small()
                .weak()
                .italics(),
        );
        return;
    }

    TableBuilder::new(ui)
        .id_salt("pappt_children_table")
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(40.0)) // #
        .column(Column::remainder().at_least(220.0)) // sub_key
        .column(Column::auto().at_least(80.0)) // sub_flag
        .column(Column::auto().at_least(80.0)) // remove
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("#");
            });
            header.col(|ui| {
                ui.strong("sub_key");
            });
            header.col(|ui| {
                ui.strong("sub_flag");
            });
            header.col(|ui| {
                ui.strong("");
            });
        })
        .body(|body| {
            body.rows(22.0, children.len(), |mut row| {
                let i = row.index();
                let child = &mut children[i];
                row.col(|ui| {
                    ui.label(format!("{}", i));
                });
                row.col(|ui| {
                    pstr_edit(ui, &mut child.sub_key, &format!("pappt_child_key_{}", i));
                });
                row.col(|ui| {
                    ui.add(egui::DragValue::new(&mut child.sub_flag).range(0..=255));
                });
                row.col(|ui| {
                    if ui.button("Remove").clicked() {
                        to_remove = Some(i);
                    }
                });
            });
        });

    if let Some(i) = to_remove {
        children.remove(i);
    }
}

// ── Secondary tab ────────────────────────────────────────────────────

fn secondary_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.pappt.secondary_filter)
                .desired_width(280.0)
                .hint_text("substring (matches alias_a or alias_b)"),
        );
        if ui
            .button("+ New alias pair")
            .on_hover_text("Append a blank secondary alias entry.")
            .clicked()
        {
            if let Some(file) = state.pappt.file.as_mut() {
                file.secondary.push(SecondaryEntry::default());
            }
        }
    });
    ui.add_space(4.0);

    let Some(file) = state.pappt.file.as_mut() else {
        return;
    };

    let filter = state.pappt.secondary_filter.to_lowercase();
    // Pre-compute visible indices so we can edit through them inside
    // the table body without re-scanning each frame.
    let visible: Vec<usize> = file
        .secondary
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if filter.is_empty()
                || e.alias_a.to_lowercase().contains(&filter)
                || e.alias_b.to_lowercase().contains(&filter)
            {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    let mut to_remove: Option<usize> = None;

    TableBuilder::new(ui)
        .id_salt("pappt_secondary_table")
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(50.0)) // #
        .column(Column::remainder().at_least(180.0)) // alias_a
        .column(Column::remainder().at_least(180.0)) // alias_b
        .column(Column::auto().at_least(80.0)) // remove
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("#");
            });
            header.col(|ui| {
                ui.strong("alias_a");
            });
            header.col(|ui| {
                ui.strong("alias_b");
            });
            header.col(|ui| {
                ui.strong("");
            });
        })
        .body(|body| {
            body.rows(22.0, visible.len(), |mut row| {
                let row_idx = row.index();
                let entry_idx = visible[row_idx];
                let entry = &mut file.secondary[entry_idx];

                row.col(|ui| {
                    ui.label(format!("{}", entry_idx));
                });
                row.col(|ui| {
                    pstr_edit(
                        ui,
                        &mut entry.alias_a,
                        &format!("pappt_alias_a_{}", entry_idx),
                    );
                });
                row.col(|ui| {
                    pstr_edit(
                        ui,
                        &mut entry.alias_b,
                        &format!("pappt_alias_b_{}", entry_idx),
                    );
                });
                row.col(|ui| {
                    if ui.button("Remove").clicked() {
                        to_remove = Some(entry_idx);
                    }
                });
            });
        });

    if let Some(i) = to_remove {
        file.secondary.remove(i);
    }
}

// ── Deploy ───────────────────────────────────────────────────────────

fn deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.pappt.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.pappt.file.is_some()
            && state.pappt.current_entry.is_some()
            && state.game_dir.is_some();
        let deploy_btn = ui.add_enabled(
            can_deploy,
            egui::Button::new(
                egui::RichText::new("Apply to Game")
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
                egui::RichText::new("Restore Vanilla")
                    .color(egui::Color32::from_rgb(230, 120, 120)),
            ),
        );
        if restore_btn.clicked() {
            restore_overlay(state);
        }

        if ui.button("Save .pappt to disk...").clicked() {
            save_pappt_to_disk(state);
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
    state.pappt.file.is_some()
        && state.pappt.current_entry.is_some()
        && state.game_dir.is_some()
}

fn apply_to_game(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(entry) = state.pappt.current_entry.clone() else {
        return;
    };
    let Some(file) = state.pappt.file.as_ref() else {
        return;
    };
    let bytes = file.write();
    let group = state.pappt.overlay_group.clone();
    match pappt_editor::deploy_pappt_overlay(&game_dir, &entry, &bytes, &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed {} as overlay group {}",
            entry.filename, group
        )),
        Err(e) => state.toasts.error_with_details(
            "PAPPT deploy failed",
            format!("{}\nGroup: {}\nFile: {}", e, group, entry.filename),
        ),
    }
}

fn restore_overlay(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let group = state.pappt.overlay_group.clone();
    match pappt_editor::restore_pappt_overlay(&game_dir, &group) {
        Ok(()) => state
            .toasts
            .info(format!("Removed PAPPT overlay group {}", group)),
        Err(e) => state.toasts.error_with_details(
            "Restore failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn save_pappt_to_disk(state: &mut AppState) {
    let Some(file) = state.pappt.file.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save .pappt")
        .add_filter("PAPPT", &["pappt"])
        .save_file()
    else {
        return;
    };
    let bytes = file.write();
    match std::fs::write(&path, &bytes) {
        Ok(()) => state.toasts.info(format!("Wrote {}", path.display())),
        Err(e) => state.toasts.error_with_details(
            "Write failed",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Length-capped text edit for a `pstr` field. The wire format limits
/// each pstr to 255 bytes; we surface a 255-character cap on the
/// editor (counted as bytes via `as_bytes().len()` so multibyte UTF-8
/// can't blow the limit even with valid keystrokes).
fn pstr_edit(ui: &mut egui::Ui, value: &mut String, id_salt: &str) {
    // egui's TextEdit doesn't expose a byte cap directly, so we
    // post-trim if a paste exceeds the limit. This keeps the cap
    // enforced without rejecting individual keypresses.
    let resp = ui.add(
        egui::TextEdit::singleline(value)
            .id_salt(id_salt)
            .desired_width(f32::INFINITY),
    );
    if resp.changed() && value.as_bytes().len() > 255 {
        // Truncate at the last byte boundary that fits.
        while value.as_bytes().len() > 255 {
            value.pop();
        }
    }
}
