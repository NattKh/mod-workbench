//! Central-panel content for the PALOC editor view.
//!
//! Layout:
//! - Top toolbar: language dropdown + Load + Save Overlay
//! - Search box (filters key OR value, case-insensitive)
//! - Scrollable virtualized table with editable `string_value` cells
//!
//! State lives on `AppState::paloc_session` (`Option<PalocSession>`). When
//! `None` we just show the toolbar and a hint to click Load.

use egui_extras::{Column, TableBuilder};

use crate::paloc_editor::{self, LANGUAGES};
use crate::state::AppState;

/// Internal-storage overlay group name used for paloc deployment.
///
/// We keep this distinct from 0058 (iteminfo) and 0059 (equipslot) so a
/// PALOC overlay never collides with a pabgb mod from the same session.
const PALOC_OVERLAY_GROUP: &str = "0064";

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("PALOC Editor");
    ui.separator();

    // ---- Toolbar: language / Load / Save ----------------------------------
    let mut do_load = false;
    let mut do_save = false;
    ui.horizontal(|ui| {
        ui.label("Language:");
        let current = state.paloc_language.clone();
        egui::ComboBox::from_id_salt("paloc_lang_combo")
            .selected_text(current.to_uppercase())
            .show_ui(ui, |ui| {
                for (lang, group) in LANGUAGES {
                    let label = format!("{} ({})", lang.to_uppercase(), group);
                    ui.selectable_value(&mut state.paloc_language, (*lang).to_string(), label);
                }
            });

        if ui.button("Load").clicked() {
            do_load = true;
        }

        let has_session = state.paloc_session.is_some();
        let save_btn = ui.add_enabled(has_session, egui::Button::new("Save Overlay"));
        if save_btn.clicked() {
            do_save = true;
        }

        // Per-session change count, surfaced inline so the user has feedback
        // before clicking Save.
        if let Some(session) = &state.paloc_session {
            let n = session.change_count();
            let txt = if n == 0 {
                "no changes".to_string()
            } else {
                format!("{} changes", n)
            };
            ui.separator();
            ui.label(
                egui::RichText::new(txt)
                    .color(if n > 0 {
                        egui::Color32::from_rgb(255, 180, 50)
                    } else {
                        egui::Color32::GRAY
                    }),
            );
        }
    });

    ui.separator();

    if do_load {
        load_paloc(state);
    }
    if do_save {
        save_paloc(state);
    }

    let session = match state.paloc_session.as_mut() {
        Some(s) => s,
        None => {
            ui.centered_and_justified(|ui| {
                ui.label("Select a language and click Load");
            });
            return;
        }
    };

    // ---- Search ----------------------------------------------------------
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.add(
            egui::TextEdit::singleline(&mut session.filter)
                .desired_width(260.0)
                .hint_text("substring of key or value..."),
        );
        if !session.filter.is_empty() && ui.small_button("X").clicked() {
            session.filter.clear();
        }

        // Visible vs total count, computed live (cheap relative to the table render).
        let total = session.entries.len();
        let visible: usize = session
            .entries
            .iter()
            .filter(|e| session.matches_filter(e))
            .count();
        if session.filter.is_empty() {
            ui.label(format!("{} entries", total));
        } else {
            ui.label(format!("{} of {} entries", visible, total));
        }
    });
    ui.separator();

    // ---- Editable table --------------------------------------------------
    //
    // Recompute the visible-index list every frame. The egui virtualized
    // table walks `body.rows(...)`, so an O(N) pass on each frame is fine;
    // we don't need a debounced cache like the pabgb tab does.
    let visible_indices: Vec<usize> = session
        .entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| if session.matches_filter(e) { Some(i) } else { None })
        .collect();

    let row_height = 24.0;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(80.0).at_most(120.0).clip(true)) // unk_id
        .column(Column::initial(280.0).at_least(120.0).clip(true)) // key
        .column(Column::remainder().at_least(200.0)) // value (editable)
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong("ID"); });
            header.col(|ui| { ui.strong("string_key"); });
            header.col(|ui| { ui.strong("string_value"); });
        })
        .body(|body| {
            body.rows(row_height, visible_indices.len(), |mut row| {
                let row_idx = row.index();
                let entry_idx = visible_indices[row_idx];
                let vanilla_value = session
                    .vanilla
                    .get(entry_idx)
                    .map(|v| v.string_value.clone());
                let entry = &mut session.entries[entry_idx];

                row.col(|ui| {
                    ui.label(format!("{}", entry.unk_id));
                });
                row.col(|ui| {
                    // string_key is read-only by design — editing the lookup
                    // key would silently break code paths that resolve strings
                    // by hash. Keep it visible but unselectable for now.
                    ui.label(&entry.string_key);
                });
                row.col(|ui| {
                    // Multiline edit for long entries. Single-line works too,
                    // but localization values frequently include `\n`-style
                    // breaks and quest descriptions span paragraphs.
                    let changed = vanilla_value
                        .as_ref()
                        .map(|v| v != &entry.string_value)
                        .unwrap_or(false);
                    let text_edit = egui::TextEdit::multiline(&mut entry.string_value)
                        .desired_rows(1)
                        .desired_width(f32::INFINITY);
                    let resp = ui.add(text_edit);
                    if changed {
                        // Faint orange underline to mirror the pabgb tab's
                        // "modified" affordance without re-coloring the body
                        // text (which would also recolor the user's caret).
                        let rect = resp.rect;
                        ui.painter().line_segment(
                            [rect.left_bottom(), rect.right_bottom()],
                            egui::Stroke::new(1.5, egui::Color32::from_rgb(255, 180, 50)),
                        );
                    }
                });
            });
        });
}

fn load_paloc(state: &mut AppState) {
    let game_dir = match &state.game_dir {
        Some(p) => p.clone(),
        None => {
            state.status = "Set game dir first (File -> Set Game Dir)".to_string();
            state.toasts.warn("Set game dir first");
            return;
        }
    };
    let lang = state.paloc_language.clone();
    match paloc_editor::load_paloc(&game_dir, &lang) {
        Ok(session) => {
            let n = session.entries.len();
            state.status = format!("Loaded paloc {}: {} entries", lang, n);
            state.toasts.info(format!("Loaded paloc {} ({} entries)", lang, n));
            state.paloc_session = Some(session);
        }
        Err(e) => {
            state.status = format!("Paloc load error: {}", e);
            state
                .toasts
                .error_with_details(format!("Failed to load paloc {}", lang), e.to_string());
        }
    }
}

fn save_paloc(state: &mut AppState) {
    let game_dir = match &state.game_dir {
        Some(p) => p.clone(),
        None => {
            state.status = "Set game dir first".to_string();
            state.toasts.warn("Set game dir first");
            return;
        }
    };
    let session = match &state.paloc_session {
        Some(s) => s,
        None => {
            state.status = "No paloc loaded".to_string();
            state.toasts.warn("No paloc loaded");
            return;
        }
    };
    match paloc_editor::save_paloc_overlay(session, &game_dir, PALOC_OVERLAY_GROUP) {
        Ok(()) => {
            let msg = format!(
                "Saved paloc {} overlay to {}/{}",
                session.language,
                game_dir.display(),
                PALOC_OVERLAY_GROUP,
            );
            state.status = msg.clone();
            state.toasts.info(msg);
        }
        Err(e) => {
            state.status = format!("Paloc save error: {}", e);
            state
                .toasts
                .error_with_details("Paloc save failed", e.to_string());
        }
    }
}
