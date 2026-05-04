//! PASEQ / PASTAGE editor panel.
//!
//! Three modes selectable via a top-row toggle:
//!
//! 1. **Editor** (default) — generic byte-patch authoring. Browse PAZ
//!    group 0014 for `.paseq` / `.paseqc` / `.pastage` files, open one
//!    in the paged hex viewer, build a list of find/replace byte patches
//!    against it, and deploy as a PAZ overlay. Patches save / load as
//!    JSON for sharing. Length-changing replacements are opt-in (most
//!    PASEQ patches need to preserve byte length so file-internal offsets
//!    stay valid).
//!
//! 2. **Sleep Mod (preset)** — the original one-button "False → True "
//!    recipe. Wires through to [`crate::paseq_editor::apply_sleep_mod`].
//!
//! 3. **NPC Swap (preset)** — the original NPC sequencer swap. Wires to
//!    [`crate::paseq_editor::swap_npcs`].
//!
//! All three deploy to overlay group 0068 by default — keep them in sync
//! with [`DEFAULT_OVERLAY_GROUP`] if you change one.
//!
//! Session state lives on [`AppState::paseq`].

use std::path::PathBuf;

use crate::paseq_editor::{
    self, BytePatch, BytePatchDoc, NpcEntry, PaseqPazEntry,
};
use crate::state::AppState;
use crate::ui::hex_view::HexViewState;

/// Default overlay group used by every PASEQ-driven action. 0068 was
/// chosen to sit clear of the pabgb-table overlays (0058–0064) shared
/// with the rest of the workbench.
const DEFAULT_OVERLAY_GROUP: &str = "0068";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PaseqMode {
    Editor,
    SleepMod,
    NpcSwap,
}

impl Default for PaseqMode {
    fn default() -> Self {
        PaseqMode::Editor
    }
}

/// Per-panel state. Lives on [`AppState::paseq`].
pub struct PaseqSession {
    pub mode: PaseqMode,

    // ── Editor (byte patcher) ──────────────────────────────────────────────
    /// PAZ enumeration cache for group 0014.
    pub paz_files: Option<Vec<PaseqPazEntry>>,
    /// Substring filter for the picker dropdown.
    pub paz_filter: String,
    /// Currently-loaded file's vanilla bytes.
    pub file_bytes: Option<Vec<u8>>,
    /// Currently-loaded entry.
    pub current_entry: Option<PaseqPazEntry>,
    /// In-progress patch document for the currently-loaded file.
    pub patch_doc: Option<BytePatchDoc>,
    /// Hex view paging / selection state.
    pub hex_state: HexViewState,
    /// Draft fields for the "add patch" form. Find/replace are typed as
    /// either ASCII strings (default) or hex pairs (toggle below). The
    /// editor parses both forms before storing in `patch_doc`.
    pub draft_name: String,
    pub draft_find: String,
    pub draft_replace: String,
    /// When true, draft_find / draft_replace are interpreted as hex
    /// strings (whitespace/comma separated). When false, as ASCII.
    pub draft_hex_mode: bool,
    /// When true, the new patch will allow find/replace to differ in
    /// length. Defaults to false because most PASEQ binary patches
    /// must preserve byte length (file-internal offsets).
    pub draft_allow_resize: bool,
    pub draft_comment: String,
    /// Last patch JSON path on disk — used to default the Save dialog.
    pub last_patch_path: Option<PathBuf>,
    /// Overlay group for editor deploys. Configurable.
    pub overlay_group: String,

    // ── Presets (NPC list cache + selections) ──────────────────────────────
    pub npc_list: Vec<NpcEntry>,
    pub selected_source: Option<usize>,
    pub selected_target: Option<usize>,
}

impl Default for PaseqSession {
    fn default() -> Self {
        Self {
            mode: PaseqMode::default(),
            paz_files: None,
            paz_filter: String::new(),
            file_bytes: None,
            current_entry: None,
            patch_doc: None,
            hex_state: HexViewState::default(),
            draft_name: String::new(),
            draft_find: String::new(),
            draft_replace: String::new(),
            draft_hex_mode: false,
            draft_allow_resize: false,
            draft_comment: String::new(),
            last_patch_path: None,
            overlay_group: DEFAULT_OVERLAY_GROUP.to_string(),
            npc_list: Vec::new(),
            selected_source: None,
            selected_target: None,
        }
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("PASEQ / PASTAGE Editor");
        ui.separator();
        ui.selectable_value(&mut state.paseq.mode, PaseqMode::Editor, "Editor");
        ui.selectable_value(&mut state.paseq.mode, PaseqMode::SleepMod, "Sleep Mod (preset)");
        ui.selectable_value(&mut state.paseq.mode, PaseqMode::NpcSwap, "NPC Swap (preset)");
    });
    ui.label(match state.paseq.mode {
        PaseqMode::Editor => "Byte-level editor for sequencer files. Browse PAZ, build find/replace patches, deploy as overlay. Load/save patch JSON for sharing.",
        PaseqMode::SleepMod => "Apply the well-known sleep cooldown removal preset (False → True ).",
        PaseqMode::NpcSwap => "Swap one NPC's sequencer files into another NPC's filenames.",
    });
    ui.separator();

    match state.paseq.mode {
        PaseqMode::Editor => render_editor(ui, state),
        PaseqMode::SleepMod => render_sleep_preset(ui, state),
        PaseqMode::NpcSwap => render_npc_swap_preset(ui, state),
    }
}

// ── Editor (byte patcher) ───────────────────────────────────────────────────

fn render_editor(ui: &mut egui::Ui, state: &mut AppState) {
    file_picker_section(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.paseq.file_bytes.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a .paseq / .paseqc / .pastage file from the dropdown above to start editing.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    egui::SidePanel::left("paseq_left")
        .resizable(true)
        .default_width(420.0)
        .min_width(300.0)
        .show_inside(ui, |ui| {
            ui.heading("Hex view");
            if let Some(bytes) = state.paseq.file_bytes.as_ref() {
                crate::ui::hex_view::show(ui, bytes, &mut state.paseq.hex_state);
            }
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        patches_section(ui, state);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);
        editor_deploy_section(ui, state);
    });
}

fn file_picker_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for sequencer files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match paseq_editor::enumerate_paseq_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.paseq.paz_files = Some(files);
                        state
                            .toasts
                            .info(format!("Found {} sequencer file(s).", count));
                    }
                    Err(e) => state
                        .toasts
                        .error_with_details("PAZ scan failed", e.to_string()),
                },
                None => state.toasts.warn("Set the Game Directory first."),
            }
        }
        if ui.button("Load patch JSON...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Load PASEQ byte-patch JSON")
                .add_filter("JSON", &["json"])
                .pick_file()
            {
                load_patch_doc(state, &path);
            }
        }
        let has_doc = state.paseq.patch_doc.is_some();
        if ui
            .add_enabled(has_doc, egui::Button::new("Save patch JSON..."))
            .clicked()
        {
            save_patch_doc(state);
        }
    });

    if let Some(files) = state.paseq.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.paseq.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.paseq.paz_filter.to_lowercase();
        let filtered: Vec<&PaseqPazEntry> = files
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
            .paseq
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<PaseqPazEntry> = None;
        egui::ComboBox::from_id_salt("paseq_paz_picker")
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
            load_paseq_from_paz(state, &entry);
        }
    }

    if let Some(entry) = &state.paseq.current_entry {
        ui.label(
            egui::RichText::new(format!(
                "Loaded: {} ({})  [.{}]",
                entry.filename,
                entry.dir_path,
                entry.extension(),
            ))
            .color(egui::Color32::from_rgb(140, 200, 140)),
        );
    }
}

fn load_paseq_from_paz(state: &mut AppState, entry: &PaseqPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match paseq_editor::read_paseq_from_paz(&game_dir, entry) {
        Ok(bytes) => {
            let len = bytes.len();
            state.paseq.file_bytes = Some(bytes);
            state.paseq.current_entry = Some(entry.clone());
            state.paseq.hex_state = HexViewState::default();
            state.paseq.patch_doc =
                Some(BytePatchDoc::new(entry.dir_path.clone(), entry.filename.clone()));
            state
                .toasts
                .info(format!("Loaded {} ({} bytes)", entry.filename, len));
        }
        Err(e) => state.toasts.error_with_details(
            "PASEQ read failed",
            format!("{}\nFile: {}", e, entry.filename),
        ),
    }
}

fn patches_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(doc) = state.paseq.patch_doc.as_mut() else {
        ui.label(
            egui::RichText::new("(no patch document — load a file first)")
                .color(egui::Color32::from_gray(160)),
        );
        return;
    };

    ui.heading(format!("Patches ({})", doc.patches.len()));
    ui.horizontal(|ui| {
        ui.label("Description:");
        ui.add(
            egui::TextEdit::singleline(&mut doc.description)
                .desired_width(420.0)
                .hint_text("optional human-readable note"),
        );
    });

    let mut to_remove: Option<usize> = None;
    egui::ScrollArea::vertical()
        .id_salt("paseq_patch_list")
        .max_height(180.0)
        .show(ui, |ui| {
            for (i, p) in doc.patches.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("#{i}"));
                    ui.label(format_patch_summary(p));
                    if ui.small_button("✖").on_hover_text("Remove").clicked() {
                        to_remove = Some(i);
                    }
                });
                if !p.comment.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("  // {}", p.comment))
                            .small()
                            .weak(),
                    );
                }
            }
            if doc.patches.is_empty() {
                ui.label(
                    egui::RichText::new("No patches yet — add one below.")
                        .color(egui::Color32::from_gray(160)),
                );
            }
        });
    if let Some(idx) = to_remove {
        doc.patches.remove(idx);
    }

    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);
    add_patch_form(ui, state);
}

fn format_patch_summary(p: &BytePatch) -> String {
    let find_preview = preview_bytes(&p.find, 24);
    let replace_preview = preview_bytes(&p.replace, 24);
    let resize_tag = if p.allow_resize { " (resize)" } else { "" };
    format!(
        "'{}' :: {}B {} -> {}B {}{}",
        p.name,
        p.find.len(),
        find_preview,
        p.replace.len(),
        replace_preview,
        resize_tag,
    )
}

fn preview_bytes(b: &[u8], max: usize) -> String {
    let truncated = b.len() > max;
    let slice = &b[..b.len().min(max)];
    // Render printable ASCII as-is, others as `.<hex>`. Keeps the tooltip
    // readable while still showing the actual byte content.
    let mut s = String::new();
    s.push('"');
    for &byte in slice {
        if (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\' {
            s.push(byte as char);
        } else {
            s.push_str(&format!("\\x{:02x}", byte));
        }
    }
    s.push('"');
    if truncated {
        s.push_str("...");
    }
    s
}

fn add_patch_form(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(egui::RichText::new("Add patch").strong());
    ui.horizontal(|ui| {
        ui.label("Name:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paseq.draft_name)
                .desired_width(280.0)
                .hint_text("e.g. 'Skip cooldown gate'"),
        );
        ui.checkbox(&mut state.paseq.draft_hex_mode, "Hex input");
        ui.checkbox(&mut state.paseq.draft_allow_resize, "Allow length change");
    });

    let hint = if state.paseq.draft_hex_mode {
        "hex bytes: 46 61 6c 73 65"
    } else {
        "ASCII: False"
    };

    ui.horizontal(|ui| {
        ui.label("Find:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paseq.draft_find)
                .desired_width(420.0)
                .hint_text(hint),
        );
    });
    ui.horizontal(|ui| {
        ui.label("Replace:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paseq.draft_replace)
                .desired_width(420.0)
                .hint_text(hint),
        );
    });
    ui.horizontal(|ui| {
        ui.label("Comment:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paseq.draft_comment)
                .desired_width(420.0)
                .hint_text("optional reason / source"),
        );
    });

    ui.horizontal(|ui| {
        if ui.button("+ Add patch").clicked() {
            add_patch_from_draft(state);
        }
        if ui.button("Clear draft").clicked() {
            state.paseq.draft_name.clear();
            state.paseq.draft_find.clear();
            state.paseq.draft_replace.clear();
            state.paseq.draft_comment.clear();
        }
    });
}

fn add_patch_from_draft(state: &mut AppState) {
    let name = state.paseq.draft_name.trim().to_string();
    if name.is_empty() {
        state.toasts.warn("Patch name is required.");
        return;
    }
    let find = match parse_byte_input(&state.paseq.draft_find, state.paseq.draft_hex_mode) {
        Ok(b) => b,
        Err(e) => {
            state.toasts.error_with_details("Find parse failed", e);
            return;
        }
    };
    let replace = match parse_byte_input(&state.paseq.draft_replace, state.paseq.draft_hex_mode) {
        Ok(b) => b,
        Err(e) => {
            state.toasts.error_with_details("Replace parse failed", e);
            return;
        }
    };
    if find.is_empty() {
        state.toasts.warn("Find pattern can't be empty.");
        return;
    }
    if find.len() != replace.len() && !state.paseq.draft_allow_resize {
        state.toasts.warn(
            "Find and replace differ in length — tick 'Allow length change' if intentional.",
        );
        return;
    }

    let patch = BytePatch {
        name,
        find,
        replace,
        comment: state.paseq.draft_comment.clone(),
        allow_resize: state.paseq.draft_allow_resize,
    };

    if let Some(doc) = state.paseq.patch_doc.as_mut() {
        doc.patches.push(patch);
    }
    // Keep allow_resize sticky — most authoring sessions repeat the same
    // mode — but clear the find/replace/name so the next patch starts
    // fresh.
    state.paseq.draft_name.clear();
    state.paseq.draft_find.clear();
    state.paseq.draft_replace.clear();
    state.paseq.draft_comment.clear();
}

/// Parse a draft input as bytes. When `hex_mode` is true, treats the
/// input as a sequence of hex pairs (whitespace / commas optional).
/// Otherwise, takes the input as ASCII and emits its bytes verbatim.
fn parse_byte_input(input: &str, hex_mode: bool) -> Result<Vec<u8>, String> {
    if !hex_mode {
        return Ok(input.as_bytes().to_vec());
    }
    let mut buf = String::new();
    let mut out = Vec::new();
    for ch in input.chars() {
        if ch.is_ascii_whitespace() || ch == ',' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return Err(format!("invalid hex character '{}'", ch));
        }
        buf.push(ch);
        if buf.len() == 2 {
            let byte = u8::from_str_radix(&buf, 16).map_err(|e| e.to_string())?;
            out.push(byte);
            buf.clear();
        }
    }
    if !buf.is_empty() {
        return Err("hex string has odd nibble count".to_string());
    }
    Ok(out)
}

fn editor_deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.paseq.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.paseq.patch_doc.is_some()
            && state
                .paseq
                .patch_doc
                .as_ref()
                .map_or(false, |d| !d.patches.is_empty())
            && state.game_dir.is_some();
        let btn = ui.add_enabled(
            can_deploy,
            egui::Button::new(
                egui::RichText::new("⬆ Apply to Game")
                    .color(egui::Color32::from_rgb(140, 200, 240))
                    .strong(),
            ),
        );
        if btn.clicked() {
            apply_editor_patches(state);
        }
        if ui.button("Preview output (toast)").clicked() {
            preview_patches(state);
        }
    });
}

fn apply_editor_patches(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(doc) = state.paseq.patch_doc.clone() else {
        return;
    };
    let group = state.paseq.overlay_group.clone();
    match paseq_editor::deploy_byte_patches(&game_dir, &[doc], &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed PASEQ overlay to group {}. Restart the game.",
            group
        )),
        Err(e) => state.toasts.error_with_details(
            "PASEQ deploy failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn preview_patches(state: &mut AppState) {
    let Some(bytes) = state.paseq.file_bytes.as_ref() else {
        return;
    };
    let Some(doc) = state.paseq.patch_doc.as_ref() else {
        return;
    };
    match paseq_editor::apply_byte_patches(bytes, &doc.patches) {
        Ok(out) => {
            let diff = changed_byte_count(bytes, &out);
            state.toasts.info(format!(
                "{} patches dry-applied — {} byte(s) changed.",
                doc.patches.len(),
                diff,
            ));
        }
        Err(e) => state
            .toasts
            .error_with_details("Preview failed", e.to_string()),
    }
}

fn changed_byte_count(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut diff = 0;
    for i in 0..n {
        if a[i] != b[i] {
            diff += 1;
        }
    }
    diff + a.len().abs_diff(b.len())
}

fn save_patch_doc(state: &mut AppState) {
    let Some(doc) = state.paseq.patch_doc.as_ref() else {
        return;
    };
    let mut dialog = rfd::FileDialog::new()
        .set_title("Save PASEQ byte-patch JSON")
        .add_filter("JSON", &["json"]);
    if let Some(prev) = state.paseq.last_patch_path.as_ref() {
        if let Some(parent) = prev.parent() {
            dialog = dialog.set_directory(parent);
        }
        if let Some(name) = prev.file_name() {
            dialog = dialog.set_file_name(name.to_string_lossy());
        }
    }
    let Some(path) = dialog.save_file() else {
        return;
    };
    match serde_json::to_vec_pretty(doc) {
        Ok(bytes) => match std::fs::write(&path, &bytes) {
            Ok(()) => {
                state.paseq.last_patch_path = Some(path.clone());
                state
                    .toasts
                    .info(format!("Saved patch to {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "Write failed",
                format!("{}\nPath: {}", e, path.display()),
            ),
        },
        Err(e) => state
            .toasts
            .error_with_details("Serialize failed", e.to_string()),
    }
}

fn load_patch_doc(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<BytePatchDoc>(&bytes) {
            Ok(doc) => {
                state.paseq.patch_doc = Some(doc);
                state.paseq.last_patch_path = Some(path.to_path_buf());
                state
                    .toasts
                    .info(format!("Loaded patch JSON: {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "Patch JSON parse failed",
                format!("{}\nPath: {}", e, path.display()),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "Read failed",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}

// ── Sleep mod preset (existing) ─────────────────────────────────────────────

fn render_sleep_preset(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Sleep Mod (preset)");
    ui.label(
        "Removes the sleep cooldown by patching the three sleep-related \
         pastage files. Replaces every `False` token with `True ` (same \
         byte length) so the cooldown gate always succeeds.",
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

// ── NPC swap preset (existing) ──────────────────────────────────────────────

fn render_npc_swap_preset(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("NPC Sequencer Swap (preset)");
    ui.label(
        "Replace a target NPC's sequencer files with another NPC's so the \
         target inherits the source NPC's appearance / behavior.",
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
            npc_dropdown(
                ui,
                "paseq_source",
                &state.paseq.npc_list,
                &mut state.paseq.selected_source,
            );
            ui.end_row();

            ui.label("Target NPC:");
            npc_dropdown(
                ui,
                "paseq_target",
                &state.paseq.npc_list,
                &mut state.paseq.selected_target,
            );
            ui.end_row();
        });

    ui.add_space(6.0);

    if let (Some(src), Some(tgt)) = (
        state
            .paseq
            .selected_source
            .and_then(|i| state.paseq.npc_list.get(i)),
        state
            .paseq
            .selected_target
            .and_then(|i| state.paseq.npc_list.get(i)),
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
    });
}

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

fn scan_npcs(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the game directory first.");
        return;
    };
    match paseq_editor::list_npcs(&game_dir) {
        Ok(list) => {
            let count = list.len();
            state.paseq.npc_list = list;
            state.paseq.selected_source = None;
            state.paseq.selected_target = None;
            state.toasts.info(format!("Found {} NPCs", count));
        }
        Err(e) => state
            .toasts
            .error_with_details("NPC scan failed", e.to_string()),
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
    let (source, target) = match (
        state.paseq.npc_list.get(src_idx),
        state.paseq.npc_list.get(tgt_idx),
    ) {
        (Some(s), Some(t)) => (s.clone(), t.clone()),
        _ => {
            state
                .toasts
                .warn("Selected NPCs are no longer available — re-scan.");
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
        Ok(()) => state.toasts.info(format!(
            "Swap deployed: {} -> {} ({}/). Restart the game.",
            source.display_name, target.display_name, DEFAULT_OVERLAY_GROUP,
        )),
        Err(e) => state
            .toasts
            .error_with_details("Swap failed", e.to_string()),
    }
}
