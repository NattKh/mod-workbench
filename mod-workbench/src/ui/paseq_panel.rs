//! PASEQ / PASTAGE editor panel.
//!
//! Two stacked sections:
//!
//! 1. **Sleep Mod** — single-button "Apply Sleep Mod" that wires through to
//!    [`crate::paseq_editor::apply_sleep_mod`].
//!
//! 2. **NPC Sequencer Swap** — source/target NPC dropdowns populated from
//!    [`crate::paseq_editor::list_npcs`] plus a "Swap" button that wires to
//!    [`crate::paseq_editor::swap_npcs`].
//!
//! Errors and successes are surfaced via the toast manager so the user sees
//! feedback even when a long-running scan/extract finishes off-screen.
//!
//! All operations run synchronously on the UI thread today. The largest one
//! (sleep mod) is six file extractions + a PAZ rebuild — fast enough that we
//! haven't moved it onto the worker yet.

use crate::paseq_editor::{self, NpcEntry};
use crate::state::AppState;

/// Default overlay group used by every PASEQ-driven action. 0068 was chosen
/// to sit clear of the pabgb-table overlays (0058–0064) shared with the rest
/// of the workbench.
const DEFAULT_OVERLAY_GROUP: &str = "0068";

/// Per-panel state. Lives on [`AppState::paseq`].
pub struct PaseqSession {
    /// Cached NPC list from the most recent successful scan.
    pub npc_list: Vec<NpcEntry>,
    /// Index into `npc_list` for the source NPC dropdown.
    pub selected_source: Option<usize>,
    /// Index into `npc_list` for the target NPC dropdown.
    pub selected_target: Option<usize>,
}

impl Default for PaseqSession {
    fn default() -> Self {
        Self {
            npc_list: Vec::new(),
            selected_source: None,
            selected_target: None,
        }
    }
}

/// Render the PASEQ editor view. Call once per frame from the central
/// panel when [`crate::state::MainView`] is `Paseq`.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("PASEQ / PASTAGE Editor");
    ui.label(
        "Sequencer-file modding for sleep cooldowns and NPC behavior swaps. \
         Each action writes a fresh overlay PAZ and updates the PAPGT — \
         restart the game to pick up changes.",
    );
    ui.separator();

    sleep_mod_section(ui, state);
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(10.0);
    npc_swap_section(ui, state);
}

fn sleep_mod_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Sleep Mod");
    ui.label(
        "Removes the sleep cooldown by patching the three sleep-related \
         pastage files (`cd_seq_minigame_sleep`, `gimmick_sleep_bed_left`, \
         `gimmick_sleep_bed_right`). Replaces every `False` token with \
         `True ` (same byte length) so the cooldown gate always succeeds.",
    );

    ui.horizontal(|ui| {
        let game_dir_present = state.game_dir.is_some();
        let btn = ui.add_enabled(
            game_dir_present,
            egui::Button::new(egui::RichText::new("Apply Sleep Mod").strong()),
        );
        if btn.clicked() {
            apply_sleep(state);
        }
        if !game_dir_present {
            ui.label(
                egui::RichText::new("Set the game directory first.")
                    .color(egui::Color32::from_rgb(240, 190, 60)),
            );
        }
    });
}

fn npc_swap_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("NPC Sequencer Swap");
    ui.label(
        "Replace a target NPC's sequencer files with another NPC's so the \
         target inherits the source NPC's appearance / behavior. Pastages \
         with hash suffixes are paired alphabetically; extras inherit the \
         source's hash with the stem rewritten to the target.",
    );

    ui.horizontal(|ui| {
        if ui.button("Scan NPCs").clicked() {
            scan_npcs(state);
        }
        let count = state.paseq.npc_list.len();
        if count > 0 {
            ui.label(format!("{} NPCs available", count));
        } else {
            ui.label(
                egui::RichText::new("Scan to populate the dropdowns.")
                    .color(egui::Color32::from_rgb(180, 180, 180)),
            );
        }
    });

    if state.paseq.npc_list.is_empty() {
        return;
    }

    egui::Grid::new("paseq_swap_grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Source NPC:");
            npc_dropdown(ui, "paseq_source", &state.paseq.npc_list, &mut state.paseq.selected_source);
            ui.end_row();

            ui.label("Target NPC:");
            npc_dropdown(ui, "paseq_target", &state.paseq.npc_list, &mut state.paseq.selected_target);
            ui.end_row();
        });

    ui.add_space(6.0);

    // Surface the resolved swap configuration so the user can sanity-check
    // before clicking Swap.
    if let (Some(src), Some(tgt)) = (
        state.paseq.selected_source.and_then(|i| state.paseq.npc_list.get(i)),
        state.paseq.selected_target.and_then(|i| state.paseq.npc_list.get(i)),
    ) {
        ui.label(format!(
            "Will copy `{}` files into `{}`.",
            src.stem, tgt.stem,
        ));
    }

    ui.horizontal(|ui| {
        let game_dir_present = state.game_dir.is_some();
        let pair_picked = state.paseq.selected_source.is_some()
            && state.paseq.selected_target.is_some()
            && state.paseq.selected_source != state.paseq.selected_target;
        let btn = ui.add_enabled(
            game_dir_present && pair_picked,
            egui::Button::new(egui::RichText::new("Swap").strong()),
        );
        if btn.clicked() {
            apply_swap(state);
        }
        if !game_dir_present {
            ui.label(
                egui::RichText::new("Set the game directory first.")
                    .color(egui::Color32::from_rgb(240, 190, 60)),
            );
        } else if !pair_picked {
            ui.label(
                egui::RichText::new("Pick distinct source and target NPCs.")
                    .color(egui::Color32::from_rgb(180, 180, 180)),
            );
        }
    });
}

/// Render a ComboBox tied to an `Option<usize>` index into `npcs`.
fn npc_dropdown(
    ui: &mut egui::Ui,
    id: &str,
    npcs: &[NpcEntry],
    selected: &mut Option<usize>,
) {
    let label = match *selected {
        Some(i) => npcs
            .get(i)
            .map(|e| format!("{}  [{}]", e.display_name, e.stem))
            .unwrap_or_else(|| "<missing>".to_string()),
        None => "<choose>".to_string(),
    };
    egui::ComboBox::from_id_salt(id)
        .width(420.0)
        .selected_text(label)
        .show_ui(ui, |ui| {
            for (i, npc) in npcs.iter().enumerate() {
                let is_selected = *selected == Some(i);
                let label = format!("{}  [{}]", npc.display_name, npc.stem);
                if ui.selectable_label(is_selected, label).clicked() {
                    *selected = Some(i);
                }
            }
        });
}

// ── Action handlers ─────────────────────────────────────────────────────────

fn scan_npcs(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the game directory first.");
        return;
    };
    match paseq_editor::list_npcs(&game_dir) {
        Ok(list) => {
            let count = list.len();
            state.paseq.npc_list = list;
            // Reset selections — old indices may no longer be valid.
            state.paseq.selected_source = None;
            state.paseq.selected_target = None;
            state.status = format!("Scanned {} NPCs", count);
            state.toasts.info(format!("Found {} NPCs", count));
        }
        Err(e) => {
            state.status = format!("NPC scan failed: {}", e);
            state
                .toasts
                .error_with_details("NPC scan failed", e.to_string());
        }
    }
}

fn apply_sleep(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the game directory first.");
        return;
    };
    match paseq_editor::apply_sleep_mod(&game_dir, DEFAULT_OVERLAY_GROUP) {
        Ok(()) => {
            let msg = format!(
                "Sleep mod deployed to {}/. Restart the game.",
                DEFAULT_OVERLAY_GROUP
            );
            state.status = msg.clone();
            state.toasts.info(msg);
        }
        Err(e) => {
            state.status = format!("Sleep mod failed: {}", e);
            state
                .toasts
                .error_with_details("Sleep mod failed", e.to_string());
        }
    }
}

fn apply_swap(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the game directory first.");
        return;
    };
    let (src_idx, tgt_idx) = match (state.paseq.selected_source, state.paseq.selected_target) {
        (Some(s), Some(t)) if s != t => (s, t),
        _ => {
            state.toasts.warn("Pick distinct source and target NPCs.");
            return;
        }
    };
    // Snapshot the entry data so we don't hold a borrow into `state` while
    // mutating `state.toasts`.
    let (source, target) = match (
        state.paseq.npc_list.get(src_idx),
        state.paseq.npc_list.get(tgt_idx),
    ) {
        (Some(s), Some(t)) => (s.clone(), t.clone()),
        _ => {
            state.toasts.warn("Selected NPCs are no longer available — re-scan.");
            return;
        }
    };

    match paseq_editor::swap_npcs(
        &game_dir,
        &source.stem,
        &source.dir_path,
        &target.stem,
        &target.dir_path,
        DEFAULT_OVERLAY_GROUP,
    ) {
        Ok(()) => {
            let msg = format!(
                "Swap deployed: {} -> {} ({}/). Restart the game.",
                source.display_name, target.display_name, DEFAULT_OVERLAY_GROUP,
            );
            state.status = msg.clone();
            state.toasts.info(msg);
        }
        Err(e) => {
            state.status = format!("Swap failed: {}", e);
            state.toasts.error_with_details("Swap failed", e.to_string());
        }
    }
}
