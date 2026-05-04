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
use crate::state::{AppState, PendingNav};

/// Internal-storage overlay group name used for paloc deployment.
///
/// We keep this distinct from 0058 (iteminfo) and 0059 (equipslot) so a
/// PALOC overlay never collides with a pabgb mod from the same session.
const PALOC_OVERLAY_GROUP: &str = "0064";

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("PALOC Editor");
    ui.separator();

    // Drain any pending global-search nav before rendering — keeps the
    // dispatch in this single edge so the rest of the panel doesn't have
    // to know about it. `take()` so a stale request can't fire twice.
    consume_pending_nav(state);

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
    // Translate the entry-index scroll target into a filtered-row index.
    // When the user opened this panel via global-search nav we cleared
    // `session.filter` to keep the target visible, so the entry index
    // and filtered index typically coincide; we still resolve it through
    // `visible_indices` so a manually applied filter doesn't mis-scroll.
    let pending_scroll = session.pending_scroll_row.take();
    let scroll_to_row_target =
        pending_scroll.and_then(|entry_idx| visible_indices.iter().position(|&i| i == entry_idx));

    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(80.0).at_most(120.0).clip(true)) // unk_id
        .column(Column::initial(280.0).at_least(120.0).clip(true)) // key
        .column(Column::remainder().at_least(200.0)); // value (editable)
    if let Some(row) = scroll_to_row_target {
        builder = builder.scroll_to_row(row, Some(egui::Align::Center));
    }
    builder
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

/// Consume a pending [`PendingNav::Paloc`] request, if one is queued.
///
/// Sets [`AppState::paloc_language`] to the requested language, triggers
/// a load when no session is open or the session is on a different
/// language, and writes [`PalocSession::pending_scroll_row`] so the
/// editor's table scrolls to the matching row on its next render.
///
/// Other [`PendingNav`] variants are left untouched so the right editor
/// can pick them up on its own draw.
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::Paloc { lang, hash_id }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    // We're handling it — drop it from the queue regardless of outcome.
    state.pending_global_nav = None;

    state.paloc_language = lang.clone();

    let needs_load = match state.paloc_session.as_ref() {
        Some(s) => s.language != lang,
        None => true,
    };
    if needs_load {
        // Synchronous load — small file, runs in a few ms.
        load_paloc(state);
    }

    // Resolve the row (in the unfiltered list); store on the session so
    // the table renderer can scroll on the next draw. We deliberately
    // clear the search filter so the row is guaranteed to be visible
    // when we hand it to `scroll_to_row` — otherwise a stale filter
    // could hide it.
    if let Some(session) = state.paloc_session.as_mut() {
        session.filter.clear();
        if let Some(idx) = session.entries.iter().position(|e| e.unk_id == hash_id) {
            session.pending_scroll_row = Some(idx);
        } else {
            state.toasts.warn(format!(
                "PALOC[{}]: id {} not found after load.",
                lang, hash_id
            ));
        }
    }
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
