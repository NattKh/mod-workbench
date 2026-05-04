//! PAMHC model-property header collection editor panel.
//!
//! Format definition lives in the `pamhc` section of
//! `tools/mod-workbench/PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md`. The
//! parser is [`dmm_parser_rust_only::tables::pamhc::PamhcFile`] and
//! round-trips byte-for-byte against vanilla, so structural edits
//! land cleanly on disk.
//!
//! Workflow:
//!   1. "Browse PAZ for `.pamhc` files" walks every numeric overlay
//!      group and lists every `.pamhc` it finds (typically just
//!      `miscellaneous/modelpropertyheadercollection.pamhc` in retail).
//!   2. The user picks one from the dropdown; we extract its bytes via
//!      [`crate::pamhc_editor::read_pamhc_from_paz`] and parse with
//!      [`dmm_parser_rust_only::tables::pamhc::PamhcFile`].
//!   3. Five sub-tabs span the five sections:
//!      - Section A — `u32` array, fully editable via DragValue.
//!      - Sections B / C / D / E — opaque byte ranges, shown read-only
//!        via the shared paged hex view ([`crate::ui::hex_view::show`]).
//!        For byte-level edits on B-E, the user can use the Binary
//!        Inspector view, which has find/replace machinery built for
//!        opaque payloads.
//!   4. "Apply to Game" deploys the modified bytes via
//!      [`crate::pamhc_editor::deploy_pamhc_overlay`]. "Restore Vanilla"
//!      wipes the overlay group and removes the PAPGT entry.
//!
//! Session state lives on [`AppState::pamhc`] so view switches don't
//! lose the user's edits. Default overlay group is `"0072"` — one
//! above the pappt editor's `"0071"`.

use dmm_parser_rust_only::tables::pamhc::PamhcFile;
use egui_extras::{Column, TableBuilder};

use crate::pamhc_editor::{self, PamhcPazEntry};
use crate::state::{AppState, PendingNav};
use crate::ui::hex_view::HexViewState;

/// Sub-tab on the editor — one per section. Section A is u32-typed
/// (entry editor); the rest are opaque (hex view).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PamhcTab {
    SectionA,
    SectionB,
    SectionC,
    SectionD,
    SectionE,
}

impl Default for PamhcTab {
    fn default() -> Self {
        PamhcTab::SectionA
    }
}

/// Persistent state for the PAMHC panel. Owned by [`AppState`].
pub struct PamhcSession {
    pub tab: PamhcTab,

    /// PAZ enumeration cache — every `.pamhc` file the workbench can
    /// find across all PAZ groups under the configured Game Directory.
    /// `None` means we haven't scanned yet; an empty Vec means we
    /// scanned and found nothing (or the Game Directory isn't set).
    pub paz_files: Option<Vec<PamhcPazEntry>>,
    /// Substring filter applied to `paz_files` for the picker dropdown.
    pub paz_filter: String,
    /// The currently-loaded entry, if any.
    pub current_entry: Option<PamhcPazEntry>,
    /// The parsed file, mutable so edits apply in place.
    pub file: Option<PamhcFile>,
    /// Vanilla bytes of the currently-loaded entry — kept so a future
    /// "diff vs vanilla" feature can work without re-extracting.
    pub vanilla_bytes: Option<Vec<u8>>,

    /// Whether section A's `u32` cells should render in hex (default)
    /// or decimal. Toggled via a checkbox in the section A toolbar.
    pub section_a_hex: bool,

    /// Persistent hex view state, one per opaque section. Lives on
    /// the session so switching sub-tabs preserves the user's page /
    /// selection.
    pub hex_b: HexViewState,
    pub hex_c: HexViewState,
    pub hex_d: HexViewState,
    pub hex_e: HexViewState,

    /// Overlay group used by Apply to Game / Restore. Default `"0072"`
    /// — one above the pappt editor's `"0071"`.
    pub overlay_group: String,
}

impl Default for PamhcSession {
    fn default() -> Self {
        Self {
            tab: PamhcTab::default(),
            paz_files: None,
            paz_filter: String::new(),
            current_entry: None,
            file: None,
            vanilla_bytes: None,
            section_a_hex: true,
            hex_b: HexViewState::default(),
            hex_c: HexViewState::default(),
            hex_d: HexViewState::default(),
            hex_e: HexViewState::default(),
            overlay_group: "0072".to_string(),
        }
    }
}

/// Render the PAMHC panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    consume_pending_nav(state);
    ui.horizontal(|ui| {
        ui.heading("PAMHC Editor (Model Property Header Collection)");
        ui.separator();
        ui.label(
            egui::RichText::new(
                "Single per-build registry — opaque header + 5 typed/byte sections \
                 (`miscellaneous/modelpropertyheadercollection.pamhc`).",
            )
            .small()
            .weak(),
        );
    });
    ui.separator();

    file_picker(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.pamhc.file.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a `.pamhc` file from the dropdown above (or use \
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
        ui.selectable_value(&mut state.pamhc.tab, PamhcTab::SectionA, "Section A (u32)");
        ui.selectable_value(&mut state.pamhc.tab, PamhcTab::SectionB, "Section B (bytes)");
        ui.selectable_value(&mut state.pamhc.tab, PamhcTab::SectionC, "Section C (bytes)");
        ui.selectable_value(&mut state.pamhc.tab, PamhcTab::SectionD, "Section D (bytes)");
        ui.selectable_value(&mut state.pamhc.tab, PamhcTab::SectionE, "Section E (bytes)");
    });
    ui.separator();

    match state.pamhc.tab {
        PamhcTab::SectionA => section_a_view(ui, state),
        PamhcTab::SectionB => section_b_view(ui, state),
        PamhcTab::SectionC => section_c_view(ui, state),
        PamhcTab::SectionD => section_d_view(ui, state),
        PamhcTab::SectionE => section_e_view(ui, state),
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    deploy_section(ui, state);
}

// ── Header strip ─────────────────────────────────────────────────────

fn header_strip(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(file) = state.pamhc.file.as_ref() else {
        return;
    };
    // Recompute the serialized size from the current edited file so
    // the header reflects in-progress edits, not just the vanilla
    // size at load time. write() is a few extends + memcpy even on
    // multi-MB files, well under the per-frame budget.
    let serialized_len = file.write().len();
    let size_a = file.section_a_u32.len() * 4;
    let size_b = file.section_b.len();
    let size_c = file.section_c.len();
    let size_d = file.section_d.len();
    let size_e = file.section_e.len();

    ui.horizontal(|ui| {
        ui.label(format!("Total: {} bytes", serialized_len));
        ui.separator();
        ui.label(format!(
            "A: {} ({} entries)",
            size_a,
            file.section_a_u32.len()
        ));
        ui.separator();
        ui.label(format!("B: {}", size_b));
        ui.separator();
        ui.label(format!("C: {}", size_c));
        ui.separator();
        ui.label(format!("D: {}", size_d));
        ui.separator();
        ui.label(format!("E: {}", size_e));
        if let Some(entry) = &state.pamhc.current_entry {
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
        if ui.button("Browse PAZ for .pamhc files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match pamhc_editor::enumerate_pamhc_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.pamhc.paz_files = Some(files);
                        state
                            .toasts
                            .info(format!("Found {} .pamhc file(s) in PAZ.", count));
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
                .set_title("Pick .pamhc file")
                .add_filter("PAMHC", &["pamhc"])
                .pick_file()
            {
                load_pamhc_from_path(state, &path);
            }
        }
    });

    if let Some(files) = state.pamhc.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.pamhc.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.pamhc.paz_filter.to_lowercase();
        let filtered: Vec<&PamhcPazEntry> = files
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
            .pamhc
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<PamhcPazEntry> = None;
        egui::ComboBox::from_id_salt("pamhc_paz_file_picker")
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
            load_pamhc_from_paz(state, &entry);
        }
    }
}

/// Drain a pending [`PendingNav::Pamhc`] request and load the matching
/// file. Byte-offset positioning is not applied — pamhc edits go
/// through structured per-section tables and hex sub-views, not a
/// single global offset.
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::Pamhc {
        paz_group,
        dir_path,
        filename,
    }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    state.pending_global_nav = None;

    if let Some(cur) = state.pamhc.current_entry.as_ref() {
        if cur.group == paz_group && cur.dir_path == dir_path && cur.filename == filename {
            return;
        }
    }
    let entry = PamhcPazEntry {
        group: paz_group,
        dir_path,
        filename,
    };
    load_pamhc_from_paz(state, &entry);
}

fn load_pamhc_from_paz(state: &mut AppState, entry: &PamhcPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match pamhc_editor::read_pamhc_from_paz(&game_dir, entry) {
        Ok(bytes) => match PamhcFile::parse(&bytes) {
            Ok(file) => {
                state.pamhc.file = Some(file);
                state.pamhc.current_entry = Some(entry.clone());
                state.pamhc.vanilla_bytes = Some(bytes);
                // Reset hex page positions so a freshly loaded file
                // starts at page 0 in every byte sub-tab.
                state.pamhc.hex_b = HexViewState::default();
                state.pamhc.hex_c = HexViewState::default();
                state.pamhc.hex_d = HexViewState::default();
                state.pamhc.hex_e = HexViewState::default();
                state
                    .toasts
                    .info(format!("Loaded {} from PAZ", entry.filename));
            }
            Err(e) => state.toasts.error_with_details(
                "PAMHC parse failed",
                format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAMHC read failed",
            format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
        ),
    }
}

fn load_pamhc_from_path(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => match PamhcFile::parse(&bytes) {
            Ok(file) => {
                state.pamhc.file = Some(file);
                state.pamhc.current_entry = None;
                state.pamhc.vanilla_bytes = Some(bytes);
                state.pamhc.hex_b = HexViewState::default();
                state.pamhc.hex_c = HexViewState::default();
                state.pamhc.hex_d = HexViewState::default();
                state.pamhc.hex_e = HexViewState::default();
                state.toasts.info(format!("Loaded {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "PAMHC parse failed",
                format!("{}\nFile: {}", e, path.display()),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "PAMHC read failed",
            format!("{}\nFile: {}", e, path.display()),
        ),
    }
}

// ── Section A (u32 entries) ──────────────────────────────────────────

fn section_a_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.pamhc.section_a_hex, "Show values as hex");
        ui.separator();
        if ui
            .button("+ Append entry")
            .on_hover_text("Append a 0 u32 to section A.")
            .clicked()
        {
            if let Some(file) = state.pamhc.file.as_mut() {
                file.section_a_u32.push(0);
            }
        }
    });
    ui.add_space(4.0);

    let Some(file) = state.pamhc.file.as_mut() else {
        return;
    };

    if file.section_a_u32.is_empty() {
        ui.label(
            egui::RichText::new("(section A is empty)")
                .small()
                .weak()
                .italics(),
        );
        return;
    }

    let hex = state.pamhc.section_a_hex;
    let mut to_remove: Option<usize> = None;
    let count = file.section_a_u32.len();

    TableBuilder::new(ui)
        .id_salt("pamhc_section_a_table")
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(60.0)) // #
        .column(Column::remainder().at_least(180.0)) // value
        .column(Column::auto().at_least(80.0)) // remove
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("#");
            });
            header.col(|ui| {
                ui.strong(if hex { "value (hex)" } else { "value (u32)" });
            });
            header.col(|ui| {
                ui.strong("");
            });
        })
        .body(|body| {
            body.rows(22.0, count, |mut row| {
                let i = row.index();
                let value = &mut file.section_a_u32[i];
                row.col(|ui| {
                    ui.label(format!("{}", i));
                });
                row.col(|ui| {
                    if hex {
                        // Render as hex via a side text input. egui's
                        // DragValue doesn't have a hex display mode;
                        // we use a TextEdit + parser so the value
                        // stays editable in either base.
                        let mut text = format!("{:#010x}", *value);
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut text)
                                .id_salt(format!("pamhc_a_hex_{}", i))
                                .desired_width(160.0),
                        );
                        if resp.changed() {
                            // Strip optional 0x prefix and parse as
                            // hex. Bad input is silently ignored —
                            // the value stays at its previous good
                            // state until the user types a parseable
                            // hex literal, mirroring DragValue's
                            // "no-op on invalid" behaviour.
                            let trimmed = text.trim().trim_start_matches("0x").trim_start_matches("0X");
                            if let Ok(parsed) = u32::from_str_radix(trimmed, 16) {
                                *value = parsed;
                            }
                        }
                    } else {
                        ui.add(egui::DragValue::new(value).speed(1.0));
                    }
                });
                row.col(|ui| {
                    if ui.button("Remove").clicked() {
                        to_remove = Some(i);
                    }
                });
            });
        });

    if let Some(i) = to_remove {
        file.section_a_u32.remove(i);
    }
}

// ── Sections B / C / D / E (opaque byte hex views) ───────────────────

fn section_b_view(ui: &mut egui::Ui, state: &mut AppState) {
    opaque_section_view(ui, "Section B", "B", &mut state.pamhc.hex_b, |file| {
        &file.section_b
    }, state.pamhc.file.as_ref());
}

fn section_c_view(ui: &mut egui::Ui, state: &mut AppState) {
    opaque_section_view(ui, "Section C", "C", &mut state.pamhc.hex_c, |file| {
        &file.section_c
    }, state.pamhc.file.as_ref());
}

fn section_d_view(ui: &mut egui::Ui, state: &mut AppState) {
    opaque_section_view(ui, "Section D", "D", &mut state.pamhc.hex_d, |file| {
        &file.section_d
    }, state.pamhc.file.as_ref());
}

fn section_e_view(ui: &mut egui::Ui, state: &mut AppState) {
    opaque_section_view(ui, "Section E", "E", &mut state.pamhc.hex_e, |file| {
        &file.section_e
    }, state.pamhc.file.as_ref());
}

/// Shared body for sections B/C/D/E. Each is an opaque byte range
/// rendered through the standard paged hex view; element schema
/// hasn't been decoded so editing happens at byte level via the
/// Binary Inspector view if needed.
fn opaque_section_view(
    ui: &mut egui::Ui,
    title: &str,
    short: &str,
    hex_state: &mut HexViewState,
    accessor: impl Fn(&PamhcFile) -> &Vec<u8>,
    file: Option<&PamhcFile>,
) {
    let Some(file) = file else {
        return;
    };
    let bytes = accessor(file);

    ui.horizontal(|ui| {
        ui.heading(title);
        ui.separator();
        ui.label(
            egui::RichText::new(format!(
                "{} bytes — element schema not decoded; shown read-only.",
                bytes.len()
            ))
            .small()
            .weak(),
        );
    });
    ui.label(
        egui::RichText::new(format!(
            "For byte-level edits to section {}, switch to the Binary \
             Inspector view (find/replace patches against the whole \
             .pamhc file). The pamhc panel preserves these bytes \
             verbatim on Apply.",
            short
        ))
        .small()
        .weak(),
    );
    ui.add_space(4.0);

    crate::ui::hex_view::show(ui, bytes, hex_state);
}

// ── Deploy ───────────────────────────────────────────────────────────

fn deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.pamhc.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.pamhc.file.is_some()
            && state.pamhc.current_entry.is_some()
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

        if ui.button("Save .pamhc to disk...").clicked() {
            save_pamhc_to_disk(state);
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
    state.pamhc.file.is_some()
        && state.pamhc.current_entry.is_some()
        && state.game_dir.is_some()
}

fn apply_to_game(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(entry) = state.pamhc.current_entry.clone() else {
        return;
    };
    let Some(file) = state.pamhc.file.as_ref() else {
        return;
    };
    let bytes = file.write();
    let group = state.pamhc.overlay_group.clone();
    match pamhc_editor::deploy_pamhc_overlay(&game_dir, &entry, &bytes, &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed {} as overlay group {}",
            entry.filename, group
        )),
        Err(e) => state.toasts.error_with_details(
            "PAMHC deploy failed",
            format!("{}\nGroup: {}\nFile: {}", e, group, entry.filename),
        ),
    }
}

fn restore_overlay(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let group = state.pamhc.overlay_group.clone();
    match pamhc_editor::restore_pamhc_overlay(&game_dir, &group) {
        Ok(()) => state
            .toasts
            .info(format!("Removed PAMHC overlay group {}", group)),
        Err(e) => state.toasts.error_with_details(
            "Restore failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn save_pamhc_to_disk(state: &mut AppState) {
    let Some(file) = state.pamhc.file.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save .pamhc")
        .add_filter("PAMHC", &["pamhc"])
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
