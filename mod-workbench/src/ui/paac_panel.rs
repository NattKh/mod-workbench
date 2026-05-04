//! PAAC action-chart editor panel.
//!
//! Loads a `.paac` file from the game's PAZ archives (or directly from
//! disk), surfaces an inspector with separate views for States,
//! Transitions, Conditions, Strings, and a Float Hunt sweep, and ships
//! edits as a PAZ overlay via [`crate::paac_editor::deploy_paac_overlay`].
//!
//! Editing surface (per the wave-2 plan):
//! - **States** — read-only metadata (format A/B, offset, size,
//!   transition / float counts).
//! - **Transitions** — `threshold`, `target_state`, `sequence` editable
//!   via DragValue. Edits flow through [`patch_transition`] back to the
//!   in-memory bytes so a re-parse picks them up.
//! - **Conditions** — read-only (the Python reference notes the 24-byte
//!   bytecode at +0xE0 is opaque).
//! - **Strings** — filterable identifier list.
//! - **Float Hunt** — runs the Python `find_floats_near_strings`
//!   helper. Each hit's value is editable via DragValue; edits flow
//!   through [`patch_float`].
//!
//! Session state lives on [`AppState::paac`] so view switches don't
//! lose the user's edits.

use dmm_parser_rust_only::tables::paac::info::{
    PaacFile, PaacFormat, find_floats_near_strings, patch_float, patch_transition,
};

use crate::paac_editor::{self, PaacPazEntry};
use crate::state::{AppState, PendingNav};

/// Top-level tab inside the panel — switches the central view.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PaacView {
    States,
    Transitions,
    Conditions,
    Strings,
    FloatHunt,
}

impl Default for PaacView {
    fn default() -> Self {
        PaacView::States
    }
}

/// Persistent state for the PAAC panel. Owned by [`AppState`].
pub struct PaacSession {
    pub view: PaacView,

    /// PAZ enumeration cache — every `.paac` file the workbench can
    /// find across all PAZ groups under the configured Game Directory.
    /// `None` means we haven't scanned yet.
    pub paz_files: Option<Vec<PaacPazEntry>>,
    /// Substring filter applied to `paz_files` for the picker dropdown.
    pub paz_filter: String,
    /// The currently-loaded entry, if any (None when loaded from disk).
    pub current_entry: Option<PaacPazEntry>,
    /// The parsed file, mutable so edits apply in place.
    pub file: Option<PaacFile>,
    /// Vanilla bytes of the currently-loaded entry — kept so a future
    /// "diff vs vanilla" feature can work without re-extracting.
    pub vanilla_bytes: Option<Vec<u8>>,
    /// Currently selected state index (for the States view's right
    /// panel, when we surface one).
    pub selected_state_idx: Option<usize>,
    /// Substring filter applied to the Strings view.
    pub strings_filter: String,
    /// Substring filter applied to the Float Hunt view.
    pub float_hunt_keyword: String,
    /// Cached result of the most recent float hunt sweep so DragValue
    /// changes don't re-run the scan every frame.
    pub float_hunt_hits: Vec<(usize, f32, String)>,
    /// Set true when a Float Hunt is currently in progress (the result
    /// is stable across frames; only the keyword field rebuilds).
    pub float_hunt_dirty: bool,
    /// Overlay group used by Apply to Game / Restore. Default `"0067"`
    /// — distinct from paatt's `0066` so multiple workbench overlays
    /// can coexist.
    pub overlay_group: String,
}

impl Default for PaacSession {
    fn default() -> Self {
        Self {
            view: PaacView::default(),
            paz_files: None,
            paz_filter: String::new(),
            current_entry: None,
            file: None,
            vanilla_bytes: None,
            selected_state_idx: None,
            strings_filter: String::new(),
            float_hunt_keyword: String::new(),
            float_hunt_hits: Vec::new(),
            float_hunt_dirty: true,
            overlay_group: "0067".to_string(),
        }
    }
}

/// Render the PAAC panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    consume_pending_nav(state);
    ui.heading("PAAC Editor (Action Charts)");
    ui.label(
        "Inspect and edit `.paac` action-chart files — character / \
         weapon state machines. Surfaces states, transitions, \
         conditions, identifier strings, and float values found near \
         identifiers. Apply ships changes as a PAZ overlay.",
    );
    ui.separator();

    file_picker(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.paac.file.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a `.paac` file from the dropdown above (or use \
                 'Load file from disk') to start inspecting.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    header_strip(ui, state);
    ui.add_space(4.0);
    ui.separator();

    // Tab strip for the view selector.
    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.paac.view, PaacView::States, "States");
        ui.selectable_value(
            &mut state.paac.view,
            PaacView::Transitions,
            "Transitions",
        );
        ui.selectable_value(
            &mut state.paac.view,
            PaacView::Conditions,
            "Conditions",
        );
        ui.selectable_value(&mut state.paac.view, PaacView::Strings, "Strings");
        ui.selectable_value(
            &mut state.paac.view,
            PaacView::FloatHunt,
            "Float Hunt",
        );
    });
    ui.separator();

    // Two-pane layout: left side has the per-view list/table, right
    // side could host details / actions. For now the central view
    // fills the entire width; we keep the SidePanel structure to make
    // future additions trivial.
    egui::SidePanel::left("paac_view_left")
        .resizable(true)
        .default_width(800.0)
        .min_width(280.0)
        .show_inside(ui, |ui| match state.paac.view {
            PaacView::States => states_view(ui, state),
            PaacView::Transitions => transitions_view(ui, state),
            PaacView::Conditions => conditions_view(ui, state),
            PaacView::Strings => strings_view(ui, state),
            PaacView::FloatHunt => float_hunt_view(ui, state),
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        deploy_section(ui, state);
    });
}

fn file_picker(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for .paac files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match paac_editor::enumerate_paac_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.paac.paz_files = Some(files);
                        state
                            .toasts
                            .info(format!("Found {} .paac file(s) in PAZ.", count));
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
                .set_title("Pick .paac file")
                .add_filter("PAAC", &["paac"])
                .pick_file()
            {
                load_paac_from_path(state, &path);
            }
        }
    });

    if let Some(files) = state.paac.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.paac.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.paac.paz_filter.to_lowercase();
        let filtered: Vec<&PaacPazEntry> = files
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
            .paac
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<PaacPazEntry> = None;
        egui::ComboBox::from_id_salt("paac_paz_file_picker")
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
            load_paac_from_paz(state, &entry);
        }
    }

    if let Some(entry) = &state.paac.current_entry {
        ui.label(
            egui::RichText::new(format!(
                "Loaded: [{}] {}/{}",
                entry.group, entry.dir_path, entry.filename
            ))
            .color(egui::Color32::from_rgb(140, 200, 140)),
        );
    }
}

fn header_strip(ui: &mut egui::Ui, state: &AppState) {
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    ui.horizontal(|ui| {
        let fmt_label = match file.format {
            PaacFormat::InfoTable => "info_table",
            PaacFormat::ActionChartV0 => "action_chart_v0",
            PaacFormat::ActionChartV1 => "action_chart_v1",
            PaacFormat::Unknown => "unknown",
        };
        ui.label(egui::RichText::new("Format:").strong());
        ui.label(fmt_label);
        ui.separator();

        if let Some(h) = file.header.as_ref() {
            ui.label(egui::RichText::new("node_count:").strong());
            ui.label(format!("{}", h.node_count));
            ui.separator();
            ui.label(egui::RichText::new("speed:").strong());
            ui.label(format!("{:.4}", h.speed));
            ui.separator();
        }

        ui.label(egui::RichText::new("size:").strong());
        ui.label(format!("{} B", file.size));
        ui.separator();

        ui.label(format!(
            "states {}  |  transitions {}  |  conditions {}  |  strings {}",
            file.states.len(),
            file.transitions.len(),
            file.condition_records.len(),
            file.strings.len()
        ));
    });
}

fn states_view(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    ui.label(
        egui::RichText::new(format!("{} state records", file.states.len()))
            .small()
            .weak(),
    );
    egui::ScrollArea::vertical()
        .id_salt("paac_states_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            egui::Grid::new("paac_states_grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("#").strong());
                    ui.label(egui::RichText::new("Format").strong());
                    ui.label(egui::RichText::new("Offset").strong());
                    ui.label(egui::RichText::new("Size").strong());
                    ui.label(egui::RichText::new("Transitions").strong());
                    ui.label(egui::RichText::new("Floats").strong());
                    ui.end_row();

                    for (i, s) in file.states.iter().enumerate() {
                        let selected = state.paac.selected_state_idx == Some(i);
                        let label = format!("{}", i);
                        if ui.selectable_label(selected, label).clicked() {
                            state.paac.selected_state_idx = Some(i);
                        }
                        ui.label(format!("{}", s.fmt));
                        ui.label(format!("0x{:X}", s.file_offset));
                        ui.label(format!("{}", s.end - s.record_start));
                        ui.label(format!("{}", s.transitions.len()));
                        ui.label(format!("{}", s.floats.len()));
                        ui.end_row();
                    }
                });
        });
}

fn transitions_view(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(file) = state.paac.file.as_mut() else {
        return;
    };
    ui.label(
        egui::RichText::new(format!(
            "{} inline transitions — edits flush back to the in-memory bytes via patch_transition",
            file.transitions.len()
        ))
        .small()
        .weak(),
    );
    let mut pending: Vec<(usize, f32, u32, u32)> = Vec::new();
    egui::ScrollArea::vertical()
        .id_salt("paac_transitions_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            egui::Grid::new("paac_transitions_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("#").strong());
                    ui.label(egui::RichText::new("State Offset").strong());
                    ui.label(egui::RichText::new("Threshold").strong());
                    ui.label(egui::RichText::new("Target State").strong());
                    ui.label(egui::RichText::new("Sequence").strong());
                    ui.end_row();

                    for (i, t) in file.transitions.iter_mut().enumerate() {
                        ui.label(format!("{}", i));
                        ui.label(format!("0x{:X}", t.file_offset));

                        let mut th = t.threshold;
                        let r = ui.add(
                            egui::DragValue::new(&mut th)
                                .speed(0.01)
                                .range(0.0..=1.0),
                        );
                        if r.changed() {
                            t.threshold = th;
                            pending.push((t.file_offset, t.threshold, t.target_state, t.sequence));
                        }

                        let mut tg = t.target_state;
                        let r = ui.add(egui::DragValue::new(&mut tg).speed(1.0));
                        if r.changed() {
                            t.target_state = tg;
                            pending.push((t.file_offset, t.threshold, t.target_state, t.sequence));
                        }

                        let mut sq = t.sequence;
                        let r = ui.add(egui::DragValue::new(&mut sq).speed(1.0));
                        if r.changed() {
                            t.sequence = sq;
                            pending.push((t.file_offset, t.threshold, t.target_state, t.sequence));
                        }

                        ui.end_row();
                    }
                });
        });

    // Flush DragValue edits into the raw byte buffer so save / deploy
    // see them.
    for (off, threshold, target_state, sequence) in pending {
        let t = dmm_parser_rust_only::tables::paac::info::InlineTransition {
            file_offset: off,
            threshold,
            target_state,
            sequence,
        };
        if let Err(e) = patch_transition(&mut file.raw, &t) {
            state.toasts.error_with_details("patch_transition failed", format!("{}", e));
        }
    }
}

fn conditions_view(ui: &mut egui::Ui, state: &AppState) {
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    ui.label(
        egui::RichText::new(format!(
            "{} condition records — bytecode is opaque per the Python reference, fields below are read-only",
            file.condition_records.len()
        ))
        .small()
        .weak(),
    );
    egui::ScrollArea::vertical()
        .id_salt("paac_conditions_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            egui::Grid::new("paac_conditions_grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("#").strong());
                    ui.label(egui::RichText::new("Offset").strong());
                    ui.label(egui::RichText::new("Target").strong());
                    ui.label(egui::RichText::new("Source State").strong());
                    ui.label(egui::RichText::new("Label Index").strong());
                    ui.label(egui::RichText::new("Opcode").strong());
                    ui.end_row();

                    for (i, c) in file.condition_records.iter().enumerate() {
                        ui.label(format!("{}", i));
                        ui.label(format!("0x{:X}", c.file_offset));
                        ui.label(opt_u32(c.target));
                        ui.label(opt_u32(c.source_state));
                        ui.label(opt_u32(c.label_index));
                        ui.label(opt_u32(c.opcode));
                        ui.end_row();
                    }
                });
        });
}

fn opt_u32(v: Option<u32>) -> String {
    match v {
        Some(x) => format!("{}", x),
        None => "-".to_string(),
    }
}

fn strings_view(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paac.strings_filter)
                .desired_width(280.0)
                .hint_text("substring"),
        );
        ui.label(format!("({} total)", file.strings.len()));
    });

    let filter = state.paac.strings_filter.to_lowercase();
    egui::ScrollArea::vertical()
        .id_salt("paac_strings_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            egui::Grid::new("paac_strings_grid")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Offset").strong());
                    ui.label(egui::RichText::new("Text").strong());
                    ui.end_row();

                    for s in file.strings.iter() {
                        if !filter.is_empty()
                            && !s.text.to_lowercase().contains(&filter)
                        {
                            continue;
                        }
                        ui.label(format!("0x{:X}", s.file_offset));
                        ui.label(&s.text);
                        ui.end_row();
                    }
                });
        });
}

fn float_hunt_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Keyword filter:");
        let r = ui.add(
            egui::TextEdit::singleline(&mut state.paac.float_hunt_keyword)
                .desired_width(280.0)
                .hint_text("substring (e.g. 'charge')"),
        );
        if r.changed() {
            state.paac.float_hunt_dirty = true;
        }
        if ui.button("Run sweep").clicked() {
            state.paac.float_hunt_dirty = true;
        }
    });

    if state.paac.float_hunt_dirty {
        if let Some(file) = state.paac.file.as_ref() {
            let kw = if state.paac.float_hunt_keyword.trim().is_empty() {
                None
            } else {
                Some(state.paac.float_hunt_keyword.trim())
            };
            state.paac.float_hunt_hits =
                find_floats_near_strings(file, kw, 128, 0.001, 10000.0);
            state.paac.float_hunt_dirty = false;
        }
    }

    ui.label(
        egui::RichText::new(format!(
            "{} candidate floats near identifier strings (radius 128 bytes, |v| in [0.001, 10000])",
            state.paac.float_hunt_hits.len()
        ))
        .small()
        .weak(),
    );

    let Some(file) = state.paac.file.as_mut() else {
        return;
    };

    let mut pending_writes: Vec<(usize, f32)> = Vec::new();
    egui::ScrollArea::vertical()
        .id_salt("paac_float_hunt_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            egui::Grid::new("paac_float_hunt_grid")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Offset").strong());
                    ui.label(egui::RichText::new("Value").strong());
                    ui.label(egui::RichText::new("Nearby String").strong());
                    ui.end_row();

                    for (off, _, ctx) in state.paac.float_hunt_hits.iter() {
                        // Always re-read the float from the live raw
                        // bytes so concurrent edits show up.
                        let cur =
                            f32::from_le_bytes(file.raw[*off..*off + 4].try_into().unwrap());
                        let mut value = cur;
                        ui.label(format!("0x{:X}", off));
                        let r = ui.add(
                            egui::DragValue::new(&mut value)
                                .speed(0.01)
                                .range(-1.0e6..=1.0e6),
                        );
                        if r.changed() {
                            pending_writes.push((*off, value));
                        }
                        ui.label(ctx);
                        ui.end_row();
                    }
                });
        });

    for (off, value) in pending_writes {
        if let Err(e) = patch_float(&mut file.raw, off, value) {
            state.toasts.error_with_details("patch_float failed", format!("{}", e));
        }
    }
}

/// Drain a pending [`PendingNav::Paac`] request and load the matching
/// file. The panel views (states / transitions / strings / float-hunt)
/// don't pivot on a byte offset, so byte-level positioning isn't
/// applied — the jump is "partial" (file loaded, no cursor positioning).
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::Paac {
        paz_group,
        dir_path,
        filename,
    }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    state.pending_global_nav = None;

    if let Some(cur) = state.paac.current_entry.as_ref() {
        if cur.group == paz_group && cur.dir_path == dir_path && cur.filename == filename {
            return;
        }
    }
    let entry = PaacPazEntry {
        group: paz_group,
        dir_path,
        filename,
    };
    load_paac_from_paz(state, &entry);
}

fn load_paac_from_paz(state: &mut AppState, entry: &PaacPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match paac_editor::read_paac_from_paz(&game_dir, entry) {
        Ok(bytes) => {
            let file = PaacFile::parse(&bytes);
            state.paac.file = Some(file);
            state.paac.current_entry = Some(entry.clone());
            state.paac.vanilla_bytes = Some(bytes);
            state.paac.selected_state_idx = None;
            state.paac.float_hunt_dirty = true;
            state.paac.float_hunt_hits.clear();
            state
                .toasts
                .info(format!("Loaded {} from PAZ", entry.filename));
        }
        Err(e) => state.toasts.error_with_details(
            "PAAC read failed",
            format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
        ),
    }
}

fn load_paac_from_path(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => {
            let file = PaacFile::parse(&bytes);
            state.paac.file = Some(file);
            state.paac.current_entry = None;
            state.paac.vanilla_bytes = Some(bytes);
            state.paac.selected_state_idx = None;
            state.paac.float_hunt_dirty = true;
            state.paac.float_hunt_hits.clear();
            state.toasts.info(format!("Loaded {}", path.display()));
        }
        Err(e) => state.toasts.error_with_details(
            "PAAC read failed",
            format!("{}\nFile: {}", e, path.display()),
        ),
    }
}

fn deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Deploy");
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paac.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.paac.file.is_some()
            && state.paac.current_entry.is_some()
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

        if ui.button("Save .paac to disk...").clicked() {
            save_paac_to_disk(state);
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
    state.paac.file.is_some()
        && state.paac.current_entry.is_some()
        && state.game_dir.is_some()
}

fn apply_to_game(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(entry) = state.paac.current_entry.clone() else {
        return;
    };
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    let bytes = file.raw.clone();
    let group = state.paac.overlay_group.clone();
    match paac_editor::deploy_paac_overlay(&game_dir, &entry, &bytes, &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed {} as overlay group {}",
            entry.filename, group
        )),
        Err(e) => state.toasts.error_with_details(
            "PAAC deploy failed",
            format!("{}\nGroup: {}\nFile: {}", e, group, entry.filename),
        ),
    }
}

fn restore_overlay(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let group = state.paac.overlay_group.clone();
    match paac_editor::restore_paac_overlay(&game_dir, &group) {
        Ok(()) => state
            .toasts
            .info(format!("Removed PAAC overlay group {}", group)),
        Err(e) => state.toasts.error_with_details(
            "Restore failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn save_paac_to_disk(state: &mut AppState) {
    let Some(file) = state.paac.file.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save .paac")
        .add_filter("PAAC", &["paac"])
        .save_file()
    else {
        return;
    };
    match std::fs::write(&path, &file.raw) {
        Ok(()) => state.toasts.info(format!("Wrote {}", path.display())),
        Err(e) => state.toasts.error_with_details(
            "Write failed",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}
