//! Binary Inspector panel — generic byte-level editor for game files
//! whose schemas haven't been decoded yet (`.paschedule`,
//! `.paschedulepath`, `.paschedulectx`, `.paseqh`, `.uianiminit`).
//!
//! UI mirrors the [`crate::ui::paseq_panel`] Editor mode exactly — pick
//! a file from PAZ, hex view side panel, find/replace patch list, deploy
//! as PAZ overlay, save/load patch JSON. The only differences:
//!
//! - File picker scans every numeric PAZ group (not just 0014) so files
//!   from any group are reachable.
//! - A small extension-toggle row above the dropdown lets the user
//!   filter by which of the five supported extensions they want to see
//!   in the dropdown without retyping a substring.
//! - Overlay group default is `"0069"` (kept distinct from paseq `0068`,
//!   paatt `0066`, paac `0067`, xml `0070`).
//!
//! Reuses [`crate::paseq_editor::BytePatch`] /
//! [`crate::paseq_editor::BytePatchDoc`] verbatim — patches authored
//! here load in the PASEQ editor and vice versa, so users can flip
//! between panels without translation.
//!
//! Session state lives on [`crate::state::AppState::binary_inspector`].

use std::collections::HashMap;
use std::path::PathBuf;

use crate::binary_inspector::{self, BinaryFileEntry};
use crate::paseq_editor::{self, BytePatch, BytePatchDoc};
use crate::state::{AppState, PendingNav};
use crate::ui::hex_view::HexViewState;

/// Default overlay group used by the binary inspector. Distinct from
/// every other workbench tool's default so multiple overlays can stack
/// without colliding.
const DEFAULT_OVERLAY_GROUP: &str = "0069";

/// The five extensions surfaced by the inspector. Hard-coded per
/// [`crate::binary_inspector`]'s contract — see
/// `PASCHEDULE_FORMAT_RESEARCH.md` for the rationale.
pub const ALLOWED_EXTENSIONS: &[&str] = &[
    // Schedule / sequencer-adjacent (Wave 4 research target).
    "paschedule",
    "paschedulepath",
    "paschedulectx",
    "paseqh",
    "uianiminit",
    // AI behaviour data — `aichart.pai`, `PathFindTable.pai`. Big class
    // hierarchy (AIPackage_*, AIBranch_*, AIState_*, AIFunction_*),
    // structural decode pending.
    "pai",
    // Character part-prefab table (`partprefabtable.pappt`). Single
    // per-build file, gameplay-relevant for character mod authoring.
    "pappt",
    // Tag data (`tag.patag`). Small declarative file used by the level
    // / content pipeline.
    "patag",
    // Dock data (`.padock`). Likely NPC interaction docking points.
    "padock",
    // Unknown but observed in the binary's loader strings.
    // Byte-level editing only — schemas not decoded.
    "pabc",
    "paccd",
    "pasg",
    "parg",
    "pati",
    // Effect emitter data (`*.paem`). Borderline 3D — particle systems
    // — but modders sometimes tweak emitter timings/colors at the
    // byte level so we surface it as opt-in.
    "paem",
    // Build version metadata (`%#/meta/0.paver`). Mostly read-only
    // inspection target — useful for verifying which game build a
    // PAZ overlay matches.
    "paver",
    // Compiled-script header (`%#/objectList.pacpph`). Script
    // bytecode tends to be brittle to edit, but the byte-level
    // inspector + hex view let users at least inspect it and patch
    // known offsets when a recipe is shared.
    "pacpph",
    // Level streaming / region data (`LevelData/%s/%s.palevel`).
    // Gameplay-relevant: region definitions, spawn lists, sub-level
    // refs. Structural decode pending; byte-level patches let users
    // apply known recipes immediately.
    "palevel",
    // Model property header collection
    // (`miscellaneous/modelpropertyheadercollection.pamhc`).
    // Per-mesh property table with scalar tweaks (e.g. break
    // thresholds, LOD distances). Structural decode pending.
    "pamhc",
    // Skeletal volume (`*.pab`). 3D-adjacent, but modders sometimes
    // tweak collision volume sizes via byte patches — opt-in here so
    // recipe-style mods can ship without a full rigging pipeline.
    "pab",
];

/// Per-panel state. Lives on [`AppState::binary_inspector`].
pub struct BinaryInspectorSession {
    /// Hard-coded list of extensions this inspector handles. Stored on
    /// the session (rather than referenced via the const) so a future
    /// expansion can swap the list at runtime without changing the
    /// signature of every helper.
    pub allowed_extensions: Vec<&'static str>,
    /// Per-extension visibility map. Defaults to all-enabled. Toggling
    /// this hides matching entries from the dropdown without re-running
    /// the PAZ scan.
    pub extension_filters: HashMap<String, bool>,
    /// Cached PAZ scan output. None until the user clicks Browse.
    pub paz_files: Option<Vec<BinaryFileEntry>>,
    /// Free-text substring filter applied on top of `extension_filters`.
    pub paz_filter: String,
    /// Currently-loaded file's vanilla bytes.
    pub file_bytes: Option<Vec<u8>>,
    /// Currently-loaded entry.
    pub current_entry: Option<BinaryFileEntry>,
    /// In-progress patch document for the currently-loaded file.
    pub patch_doc: Option<BytePatchDoc>,
    /// Hex view paging / selection state.
    pub hex_state: HexViewState,
    /// Draft fields for the "add patch" form. Mirrors the paseq panel's
    /// draft shape so users can keep the same muscle memory.
    pub draft_name: String,
    pub draft_find: String,
    pub draft_replace: String,
    pub draft_hex_mode: bool,
    pub draft_allow_resize: bool,
    pub draft_comment: String,
    /// Last patch JSON path on disk — used to default the Save dialog.
    pub last_patch_path: Option<PathBuf>,
    /// Overlay group for editor deploys. Configurable.
    pub overlay_group: String,
}

impl Default for BinaryInspectorSession {
    fn default() -> Self {
        let allowed = ALLOWED_EXTENSIONS.to_vec();
        let extension_filters = allowed
            .iter()
            .map(|e| ((*e).to_string(), true))
            .collect();
        Self {
            allowed_extensions: allowed,
            extension_filters,
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
        }
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    consume_pending_nav(state);
    ui.horizontal(|ui| {
        ui.heading("Binary Inspector");
    });
    ui.label(
        "Byte-level editor for sequencer schedule, header, and UI \
         animation init files (`.paschedule`, `.paschedulepath`, \
         `.paschedulectx`, `.paseqh`, `.uianiminit`). Browse PAZ, build \
         find/replace patches, deploy as overlay. Length-changing \
         replacements are opt-in — most binary patches must preserve \
         byte length so file-internal offsets stay valid. Patch JSON is \
         interchangeable with the PASEQ editor.",
    );
    ui.separator();

    file_picker_section(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.binary_inspector.file_bytes.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick a file from the dropdown above to start editing.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    egui::SidePanel::left("binary_inspector_left")
        .resizable(true)
        .default_width(420.0)
        .min_width(300.0)
        .show_inside(ui, |ui| {
            ui.heading("Hex view");
            if let Some(bytes) = state.binary_inspector.file_bytes.as_ref() {
                crate::ui::hex_view::show(ui, bytes, &mut state.binary_inspector.hex_state);
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

// ── File picker ─────────────────────────────────────────────────────────────

fn file_picker_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for binary files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => {
                    let allowed = state.binary_inspector.allowed_extensions.clone();
                    match binary_inspector::enumerate_files(&dir, &allowed) {
                        Ok(files) => {
                            let count = files.len();
                            state.binary_inspector.paz_files = Some(files);
                            state
                                .toasts
                                .info(format!("Found {} binary file(s).", count));
                        }
                        Err(e) => state
                            .toasts
                            .error_with_details("PAZ scan failed", e.to_string()),
                    }
                }
                None => state.toasts.warn("Set the Game Directory first."),
            }
        }
        if ui.button("Load patch JSON...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Load binary byte-patch JSON")
                .add_filter("JSON", &["json"])
                .pick_file()
            {
                load_patch_doc(state, &path);
            }
        }
        let has_doc = state.binary_inspector.patch_doc.is_some();
        if ui
            .add_enabled(has_doc, egui::Button::new("Save patch JSON..."))
            .clicked()
        {
            save_patch_doc(state);
        }
    });

    // Per-extension toggle row. Sits above the dropdown so users can
    // narrow the picker to one extension family at a time without
    // typing into the substring filter.
    ui.horizontal(|ui| {
        ui.label("Show:");
        // Snapshot the extension list so we can mutate the filter map
        // without holding a borrow across iteration.
        let exts: Vec<String> = state
            .binary_inspector
            .allowed_extensions
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for ext in &exts {
            let mut enabled = *state
                .binary_inspector
                .extension_filters
                .get(ext)
                .unwrap_or(&true);
            if ui.checkbox(&mut enabled, ext).changed() {
                state
                    .binary_inspector
                    .extension_filters
                    .insert(ext.clone(), enabled);
            }
        }
    });

    if let Some(files) = state.binary_inspector.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.binary_inspector.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files total)", files.len()));
        });

        let filter = state.binary_inspector.paz_filter.to_lowercase();
        let filtered: Vec<&BinaryFileEntry> = files
            .iter()
            .filter(|e| {
                let ext_enabled = state
                    .binary_inspector
                    .extension_filters
                    .get(&e.extension)
                    .copied()
                    .unwrap_or(true);
                if !ext_enabled {
                    return false;
                }
                if filter.is_empty() {
                    true
                } else {
                    e.filename.to_lowercase().contains(&filter)
                        || e.dir_path.to_lowercase().contains(&filter)
                        || e.group.to_lowercase().contains(&filter)
                }
            })
            .collect();

        let current_label = state
            .binary_inspector
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<BinaryFileEntry> = None;
        egui::ComboBox::from_id_salt("binary_inspector_paz_picker")
            .selected_text(current_label)
            .width(720.0)
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
            load_file_from_paz(state, &entry);
        }
    }

    if let Some(entry) = &state.binary_inspector.current_entry {
        ui.label(
            egui::RichText::new(format!(
                "Loaded: [{}] {} ({})  [.{}]",
                entry.group, entry.filename, entry.dir_path, entry.extension,
            ))
            .color(egui::Color32::from_rgb(140, 200, 140)),
        );
    }
}

fn load_file_from_paz(state: &mut AppState, entry: &BinaryFileEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match binary_inspector::read_file_from_paz(&game_dir, entry) {
        Ok(bytes) => {
            let len = bytes.len();
            state.binary_inspector.file_bytes = Some(bytes);
            state.binary_inspector.current_entry = Some(entry.clone());
            state.binary_inspector.hex_state = HexViewState::default();
            state.binary_inspector.patch_doc = Some(BytePatchDoc::new(
                entry.dir_path.clone(),
                entry.filename.clone(),
            ));
            state
                .toasts
                .info(format!("Loaded {} ({} bytes)", entry.filename, len));
        }
        Err(e) => state.toasts.error_with_details(
            "Binary file read failed",
            format!("{}\nFile: {}", e, entry.filename),
        ),
    }
}

/// Drain a pending [`PendingNav::BinaryInspector`] request, load the
/// matching file, and (when supplied) scroll the hex view to the
/// requested byte offset.
///
/// Used for raw-byte hits, Jenkins-hash hits, and hex-pattern hits —
/// all three resolve to this single editor + variant. The extension
/// filter for the requested extension is force-enabled so a stale
/// "hide .pacpph" preference can't make the loaded file invisible
/// in the picker after the jump.
fn consume_pending_nav(state: &mut AppState) {
    let Some(PendingNav::BinaryInspector {
        ext,
        paz_group,
        dir_path,
        filename,
        byte_offset,
    }) = state.pending_global_nav.as_ref().cloned()
    else {
        return;
    };
    state.pending_global_nav = None;

    // Make sure the picker shows files with this extension. Default
    // map ships every known extension on, but a user could have
    // toggled it off and we don't want to fight them — only force on
    // for the one ext we're navigating to.
    state
        .binary_inspector
        .extension_filters
        .insert(ext.clone(), true);

    let already_loaded = state
        .binary_inspector
        .current_entry
        .as_ref()
        .map(|c| c.group == paz_group && c.dir_path == dir_path && c.filename == filename)
        .unwrap_or(false);

    if !already_loaded {
        let entry = BinaryFileEntry {
            group: paz_group,
            dir_path,
            filename,
            extension: ext,
        };
        load_file_from_paz(state, &entry);
    }

    // After the (synchronous) load, position the hex view if an offset
    // was supplied. Reading `file_bytes` lets us clamp the offset to the
    // actual file length so a stale hit doesn't jump past EOF.
    if let Some(off) = byte_offset {
        if let Some(bytes) = state.binary_inspector.file_bytes.as_ref() {
            let clamped = off.min(bytes.len().saturating_sub(1));
            let hex = &mut state.binary_inspector.hex_state;
            hex.selected_offset = Some(clamped);
            if hex.bytes_per_page > 0 {
                hex.page = clamped / hex.bytes_per_page;
            }
        }
    }
}

// ── Patch list + draft form ────────────────────────────────────────────────

fn patches_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(doc) = state.binary_inspector.patch_doc.as_mut() else {
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
        .id_salt("binary_inspector_patch_list")
        .max_height(180.0)
        .show(ui, |ui| {
            for (i, p) in doc.patches.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("#{i}"));
                    ui.label(format_patch_summary(p));
                    if ui.small_button("X").on_hover_text("Remove").clicked() {
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
            egui::TextEdit::singleline(&mut state.binary_inspector.draft_name)
                .desired_width(280.0)
                .hint_text("e.g. 'Bump schedule id'"),
        );
        ui.checkbox(&mut state.binary_inspector.draft_hex_mode, "Hex input");
        ui.checkbox(
            &mut state.binary_inspector.draft_allow_resize,
            "Allow length change",
        );
    });

    let hint = if state.binary_inspector.draft_hex_mode {
        "hex bytes: 46 61 6c 73 65"
    } else {
        "ASCII: False"
    };

    ui.horizontal(|ui| {
        ui.label("Find:");
        ui.add(
            egui::TextEdit::singleline(&mut state.binary_inspector.draft_find)
                .desired_width(420.0)
                .hint_text(hint),
        );
    });
    ui.horizontal(|ui| {
        ui.label("Replace:");
        ui.add(
            egui::TextEdit::singleline(&mut state.binary_inspector.draft_replace)
                .desired_width(420.0)
                .hint_text(hint),
        );
    });
    ui.horizontal(|ui| {
        ui.label("Comment:");
        ui.add(
            egui::TextEdit::singleline(&mut state.binary_inspector.draft_comment)
                .desired_width(420.0)
                .hint_text("optional reason / source"),
        );
    });

    ui.horizontal(|ui| {
        if ui.button("+ Add patch").clicked() {
            add_patch_from_draft(state);
        }
        if ui.button("Clear draft").clicked() {
            state.binary_inspector.draft_name.clear();
            state.binary_inspector.draft_find.clear();
            state.binary_inspector.draft_replace.clear();
            state.binary_inspector.draft_comment.clear();
        }
    });
}

fn add_patch_from_draft(state: &mut AppState) {
    let name = state.binary_inspector.draft_name.trim().to_string();
    if name.is_empty() {
        state.toasts.warn("Patch name is required.");
        return;
    }
    let find = match parse_byte_input(
        &state.binary_inspector.draft_find,
        state.binary_inspector.draft_hex_mode,
    ) {
        Ok(b) => b,
        Err(e) => {
            state.toasts.error_with_details("Find parse failed", e);
            return;
        }
    };
    let replace = match parse_byte_input(
        &state.binary_inspector.draft_replace,
        state.binary_inspector.draft_hex_mode,
    ) {
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
    if find.len() != replace.len() && !state.binary_inspector.draft_allow_resize {
        state.toasts.warn(
            "Find and replace differ in length — tick 'Allow length change' if intentional.",
        );
        return;
    }

    let patch = BytePatch {
        name,
        find,
        replace,
        comment: state.binary_inspector.draft_comment.clone(),
        allow_resize: state.binary_inspector.draft_allow_resize,
    };

    if let Some(doc) = state.binary_inspector.patch_doc.as_mut() {
        doc.patches.push(patch);
    }
    // Keep allow_resize sticky — most authoring sessions repeat the same
    // mode — but clear name/find/replace/comment so the next patch
    // starts fresh.
    state.binary_inspector.draft_name.clear();
    state.binary_inspector.draft_find.clear();
    state.binary_inspector.draft_replace.clear();
    state.binary_inspector.draft_comment.clear();
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

// ── Deploy / preview / save / load ─────────────────────────────────────────

fn editor_deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.binary_inspector.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.binary_inspector.patch_doc.is_some()
            && state
                .binary_inspector
                .patch_doc
                .as_ref()
                .map_or(false, |d| !d.patches.is_empty())
            && state.game_dir.is_some();
        let btn = ui.add_enabled(
            can_deploy,
            egui::Button::new(
                egui::RichText::new("Apply to Game")
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
    let Some(doc) = state.binary_inspector.patch_doc.clone() else {
        return;
    };
    let group = state.binary_inspector.overlay_group.clone();
    match binary_inspector::deploy_binary_patches(&game_dir, &[doc], &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed binary inspector overlay to group {}. Restart the game.",
            group
        )),
        Err(e) => state.toasts.error_with_details(
            "Binary inspector deploy failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn preview_patches(state: &mut AppState) {
    let Some(bytes) = state.binary_inspector.file_bytes.as_ref() else {
        return;
    };
    let Some(doc) = state.binary_inspector.patch_doc.as_ref() else {
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
    let Some(doc) = state.binary_inspector.patch_doc.as_ref() else {
        return;
    };
    let mut dialog = rfd::FileDialog::new()
        .set_title("Save binary byte-patch JSON")
        .add_filter("JSON", &["json"]);
    if let Some(prev) = state.binary_inspector.last_patch_path.as_ref() {
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
                state.binary_inspector.last_patch_path = Some(path.clone());
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
                state.binary_inspector.patch_doc = Some(doc);
                state.binary_inspector.last_patch_path = Some(path.to_path_buf());
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
