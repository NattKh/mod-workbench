//! XML editor panel.
//!
//! Two modes selected by a top-row toggle:
//!
//! - **Tree Editor** (default) — full structural editor. Browse XML files
//!   in the game's PAZ archives, parse into a tree, click any node to
//!   rename / edit text / set or remove attributes / add or remove
//!   children. "Apply to Game" deploys the modified XML as a PAZ overlay
//!   that wins lookup at runtime; "Save XML to disk" writes the bytes to
//!   a chosen path.
//!
//! - **Patch Builder** — the previous path-based op authoring UI, kept
//!   for users who want shareable JSON patches. Same op set as before
//!   (set_text / set_attr / append_child) and the same JSON shape, so
//!   patches authored before this update still load.
//!
//! Session state lives on [`AppState::xml`] so view switches don't lose
//! the user's edits.

use std::path::PathBuf;

use crate::state::AppState;
use crate::xml_editor::{self, XmlPazEntry};
use crate::xml_patcher::{self, XmlNode, XmlOp, XmlPatch, XmlTree};

/// Top-level mode toggle for the panel. Stored on [`XmlSession`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum XmlMode {
    /// Direct structural edit of an XML file. Default.
    TreeEditor,
    /// Path-op patch authoring (the original v1 surface).
    PatchBuilder,
}

impl Default for XmlMode {
    fn default() -> Self {
        XmlMode::TreeEditor
    }
}

/// Persistent state for the XML panel. Owned by [`AppState`].
pub struct XmlSession {
    pub mode: XmlMode,

    // ── Tree editor ────────────────────────────────────────────────────────
    /// PAZ enumeration cache — every `.xml` file the workbench can find
    /// across all PAZ groups under the configured Game Directory. None
    /// means we haven't scanned yet; an empty Vec means we scanned and
    /// found nothing (or the Game Directory isn't set).
    pub paz_files: Option<Vec<XmlPazEntry>>,
    /// Substring filter applied to `paz_files` for the picker dropdown.
    pub paz_filter: String,
    /// The currently-loaded entry, if any.
    pub current_entry: Option<XmlPazEntry>,
    /// The mutable XML tree. None when no file is loaded.
    pub tree: Option<XmlTree>,
    /// Currently-selected node, identified by index path from root
    /// (e.g. `[0, 2, 1]` = root.children[0].children[2].children[1]).
    /// Empty Vec means the root is selected. None means no selection.
    pub selected_path: Option<Vec<usize>>,
    /// Buffer for the new-attribute name when editing the selected node.
    pub draft_attr_name: String,
    /// Buffer for the new-attribute value (paired with `draft_attr_name`).
    pub draft_attr_value: String,
    /// Buffer for the new-child element name when adding under selection.
    pub draft_child_name: String,
    /// Overlay group used by Apply to Game / Restore. Configurable so
    /// users with multiple workbench overlays can keep them separate.
    pub overlay_group: String,

    // ── Patch builder (legacy) ─────────────────────────────────────────────
    pub patch: Option<XmlPatch>,
    pub vanilla_bytes: Option<Vec<u8>>,
    pub preview_output: Option<Result<String, String>>,
    pub draft: OpDraft,
    pub last_patch_path: Option<PathBuf>,
}

impl Default for XmlSession {
    fn default() -> Self {
        Self {
            mode: XmlMode::default(),
            paz_files: None,
            paz_filter: String::new(),
            current_entry: None,
            tree: None,
            selected_path: None,
            draft_attr_name: String::new(),
            draft_attr_value: String::new(),
            draft_child_name: String::new(),
            overlay_group: "0070".to_string(),
            patch: None,
            vanilla_bytes: None,
            preview_output: None,
            draft: OpDraft::default(),
            last_patch_path: None,
        }
    }
}

/// Draft op for the patch-builder mode (kept verbatim from the v1 UI).
#[derive(Default)]
pub struct OpDraft {
    pub kind: OpKind,
    pub path: String,
    pub value: String,
    pub attr: String,
    pub fragment: String,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    #[default]
    SetText,
    SetAttr,
    AppendChild,
}

impl OpKind {
    fn label(self) -> &'static str {
        match self {
            OpKind::SetText => "set_text",
            OpKind::SetAttr => "set_attr",
            OpKind::AppendChild => "append_child",
        }
    }
}

/// Render the XML panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("XML Editor");
        ui.separator();
        ui.selectable_value(&mut state.xml.mode, XmlMode::TreeEditor, "Tree Editor");
        ui.selectable_value(&mut state.xml.mode, XmlMode::PatchBuilder, "Patch Builder");
    });
    ui.label(
        match state.xml.mode {
            XmlMode::TreeEditor => "Full structural editor for game XML — browse PAZ, edit nodes, deploy as overlay.",
            XmlMode::PatchBuilder => "Author shareable JSON patches with path-based ops (legacy).",
        },
    );
    ui.separator();

    match state.xml.mode {
        XmlMode::TreeEditor => render_tree_editor(ui, state),
        XmlMode::PatchBuilder => render_patch_builder(ui, state),
    }
}

// ── Tree editor ─────────────────────────────────────────────────────────────

fn render_tree_editor(ui: &mut egui::Ui, state: &mut AppState) {
    file_picker(ui, state);
    ui.add_space(6.0);
    ui.separator();

    if state.xml.tree.is_none() {
        ui.label(
            egui::RichText::new(
                "Pick an XML file from the dropdown above (or use 'Load XML from \
                 disk') to start editing.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    // Two-column layout: tree on the left, node detail on the right.
    egui::SidePanel::left("xml_tree_left")
        .resizable(true)
        .default_width(360.0)
        .min_width(220.0)
        .show_inside(ui, |ui| {
            ui.heading("Tree");
            egui::ScrollArea::vertical()
                .id_salt("xml_tree_scroll")
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    let tree_clone = state.xml.tree.as_ref().cloned();
                    if let Some(tree) = tree_clone {
                        let mut pending_select: Option<Vec<usize>> = None;
                        render_node_tree(
                            ui,
                            &tree.root,
                            &mut Vec::new(),
                            &state.xml.selected_path,
                            &mut pending_select,
                        );
                        if let Some(path) = pending_select {
                            state.xml.selected_path = Some(path);
                        }
                    }
                });
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.heading("Node detail");
        node_detail_panel(ui, state);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);
        deploy_section(ui, state);
    });
}

/// Recursively render the tree as collapsible headers. Each node clicks
/// to select; children render under a CollapsingHeader so the user can
/// drill in. The selected node gets a coloured outline.
fn render_node_tree(
    ui: &mut egui::Ui,
    node: &XmlNode,
    path: &mut Vec<usize>,
    selected: &Option<Vec<usize>>,
    pending: &mut Option<Vec<usize>>,
) {
    let is_selected = selected.as_ref().map_or(false, |p| p == path);
    let summary = format_node_summary(node);
    let label = if is_selected {
        egui::RichText::new(summary).color(egui::Color32::from_rgb(140, 200, 240)).strong()
    } else {
        egui::RichText::new(summary)
    };

    if node.children.is_empty() {
        // Leaf — render as a button so the click toggles selection.
        if ui
            .add(egui::SelectableLabel::new(is_selected, label))
            .clicked()
        {
            *pending = Some(path.clone());
        }
    } else {
        let id = ui.make_persistent_id(("xml_tree_node", path.clone()));
        let header = egui::CollapsingHeader::new(label)
            .id_salt(id)
            .default_open(path.is_empty());
        header.show(ui, |ui| {
            // The header label itself can also select. Provide a small
            // "select" button on the row so clicks on the label expand
            // rather than fight with selection.
            ui.horizontal(|ui| {
                if ui
                    .small_button(if is_selected { "✓ selected" } else { "select" })
                    .clicked()
                {
                    *pending = Some(path.clone());
                }
            });
            for (i, child) in node.children.iter().enumerate() {
                path.push(i);
                render_node_tree(ui, child, path, selected, pending);
                path.pop();
            }
        });
    }
}

fn format_node_summary(node: &XmlNode) -> String {
    let attr_count = node.attrs.len();
    let child_count = node.children.len();
    let text_len = node.text.trim().len();
    let mut bits: Vec<String> = Vec::new();
    if attr_count > 0 {
        bits.push(format!("{} attr", attr_count));
    }
    if child_count > 0 {
        bits.push(format!("{} children", child_count));
    }
    if text_len > 0 {
        bits.push(format!("{}B text", text_len));
    }
    if bits.is_empty() {
        node.name.clone()
    } else {
        format!("<{}>  ({})", node.name, bits.join(", "))
    }
}

fn node_detail_panel(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(path) = state.xml.selected_path.clone() else {
        ui.label(
            egui::RichText::new("No node selected. Click a node in the tree.")
                .color(egui::Color32::from_gray(160)),
        );
        return;
    };
    let Some(tree) = state.xml.tree.as_mut() else {
        return;
    };

    // Walk to the selected node mutably.
    let node = match resolve_path_mut(&mut tree.root, &path) {
        Some(n) => n,
        None => {
            ui.label(
                egui::RichText::new("Selected path no longer exists. Click a node.")
                    .color(egui::Color32::from_rgb(230, 80, 80)),
            );
            return;
        }
    };

    ui.horizontal(|ui| {
        ui.label("Tag:");
        ui.add(
            egui::TextEdit::singleline(&mut node.name)
                .desired_width(280.0),
        );
    });

    ui.add_space(4.0);
    ui.label("Text content:");
    ui.add(
        egui::TextEdit::multiline(&mut node.text)
            .desired_width(f32::INFINITY)
            .desired_rows(3),
    );

    ui.add_space(6.0);
    ui.separator();
    ui.label(egui::RichText::new("Attributes").strong());

    let mut attr_to_remove: Option<usize> = None;
    for (i, (k, v)) in node.attrs.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(k)
                    .desired_width(180.0),
            );
            ui.add(
                egui::TextEdit::singleline(v)
                    .desired_width(280.0),
            );
            if ui.small_button("✖").on_hover_text("Remove attribute").clicked() {
                attr_to_remove = Some(i);
            }
        });
    }
    if let Some(i) = attr_to_remove {
        node.attrs.remove(i);
    }

    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.xml.draft_attr_name)
                .desired_width(180.0)
                .hint_text("name"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.xml.draft_attr_value)
                .desired_width(280.0)
                .hint_text("value"),
        );
        if ui.button("+ Add attr").clicked() {
            let name = state.xml.draft_attr_name.trim().to_string();
            if !name.is_empty() {
                if let Some(tree) = state.xml.tree.as_mut() {
                    if let Some(node) = resolve_path_mut(&mut tree.root, &path) {
                        node.attrs
                            .push((name, state.xml.draft_attr_value.clone()));
                    }
                }
                state.xml.draft_attr_name.clear();
                state.xml.draft_attr_value.clear();
            }
        }
    });

    ui.add_space(6.0);
    ui.separator();
    ui.label(egui::RichText::new("Children").strong());

    // Re-resolve since we may have just mutated above.
    let Some(tree) = state.xml.tree.as_mut() else {
        return;
    };
    let Some(node) = resolve_path_mut(&mut tree.root, &path) else {
        return;
    };

    let child_count = node.children.len();
    ui.label(format!("{} child node(s)", child_count));

    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.xml.draft_child_name)
                .desired_width(220.0)
                .hint_text("new child tag name"),
        );
        if ui.button("+ Add child").clicked() {
            let name = state.xml.draft_child_name.trim().to_string();
            if !name.is_empty() {
                node.children.push(XmlNode::new(name));
                state.xml.draft_child_name.clear();
            }
        }
    });

    // "Remove this node" — only available when not at root, since
    // removing the root invalidates the document.
    if !path.is_empty() {
        ui.add_space(4.0);
        if ui
            .button(
                egui::RichText::new("Remove this node")
                    .color(egui::Color32::from_rgb(230, 120, 120)),
            )
            .on_hover_text("Delete the selected node and its subtree from its parent.")
            .clicked()
        {
            // Walk to parent and remove the indexed child.
            let (parent_path, idx) = path.split_at(path.len() - 1);
            let idx = idx[0];
            if let Some(parent) = resolve_path_mut(&mut tree.root, parent_path) {
                if idx < parent.children.len() {
                    parent.children.remove(idx);
                    // Selection now invalid — drop it.
                    state.xml.selected_path = Some(parent_path.to_vec());
                }
            }
        }
    }
}

/// Walk to a node by index path. Returns None if any index is out of
/// bounds (e.g. the user removed an ancestor between selecting and
/// rendering this frame).
fn resolve_path_mut<'a>(root: &'a mut XmlNode, path: &[usize]) -> Option<&'a mut XmlNode> {
    let mut node = root;
    for &i in path {
        if i >= node.children.len() {
            return None;
        }
        node = &mut node.children[i];
    }
    Some(node)
}

fn file_picker(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Browse PAZ for XML files...").clicked() {
            let game_dir = state.game_dir.clone();
            match game_dir {
                Some(dir) => match xml_editor::enumerate_xml_files(&dir) {
                    Ok(files) => {
                        let count = files.len();
                        state.xml.paz_files = Some(files);
                        state.toasts.info(format!("Found {} XML file(s) in PAZ.", count));
                    }
                    Err(e) => state.toasts.error_with_details(
                        "PAZ scan failed",
                        format!("{}", e),
                    ),
                },
                None => state.toasts.warn("Set the Game Directory first (Settings)."),
            }
        }

        if ui.button("Load XML from disk...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Pick XML file")
                .add_filter("XML", &["xml"])
                .pick_file()
            {
                load_xml_from_path(state, &path);
            }
        }
    });

    if let Some(files) = state.xml.paz_files.clone() {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut state.xml.paz_filter)
                    .desired_width(280.0)
                    .hint_text("substring"),
            );
            ui.label(format!("({} files)", files.len()));
        });

        let filter = state.xml.paz_filter.to_lowercase();
        let filtered: Vec<&XmlPazEntry> = files
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
            .xml
            .current_entry
            .as_ref()
            .map(|e| e.display())
            .unwrap_or_else(|| "(pick a file)".to_string());

        let mut to_open: Option<XmlPazEntry> = None;
        egui::ComboBox::from_id_salt("xml_paz_file_picker")
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
            load_xml_from_paz(state, &entry);
        }
    }

    if let Some(entry) = &state.xml.current_entry {
        ui.label(
            egui::RichText::new(format!(
                "Loaded: [{}] {}/{}",
                entry.group, entry.dir_path, entry.filename
            ))
            .color(egui::Color32::from_rgb(140, 200, 140)),
        );
    }
}

fn load_xml_from_paz(state: &mut AppState, entry: &XmlPazEntry) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };
    match xml_editor::read_xml_from_paz(&game_dir, entry) {
        Ok(bytes) => match xml_patcher::parse_to_tree(&bytes) {
            Ok(tree) => {
                state.xml.tree = Some(tree);
                state.xml.current_entry = Some(entry.clone());
                state.xml.selected_path = Some(Vec::new());
                state.xml.vanilla_bytes = Some(bytes);
                state
                    .toasts
                    .info(format!("Loaded {} from PAZ", entry.filename));
            }
            Err(e) => state.toasts.error_with_details(
                "XML parse failed",
                format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "XML read failed",
            format!("{}\nFile: {}/{}", e, entry.dir_path, entry.filename),
        ),
    }
}

fn load_xml_from_path(state: &mut AppState, path: &std::path::Path) {
    match std::fs::read(path) {
        Ok(bytes) => match xml_patcher::parse_to_tree(&bytes) {
            Ok(tree) => {
                state.xml.tree = Some(tree);
                state.xml.current_entry = None;
                state.xml.selected_path = Some(Vec::new());
                state.xml.vanilla_bytes = Some(bytes);
                state.toasts.info(format!("Loaded {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "XML parse failed",
                format!("{}\nFile: {}", e, path.display()),
            ),
        },
        Err(e) => state.toasts.error_with_details(
            "XML read failed",
            format!("{}\nFile: {}", e, path.display()),
        ),
    }
}

fn deploy_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Overlay group:");
        ui.add(
            egui::TextEdit::singleline(&mut state.xml.overlay_group)
                .desired_width(80.0),
        );
        let can_deploy = state.xml.tree.is_some()
            && state.xml.current_entry.is_some()
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

        if ui.button("Save XML to disk...").clicked() {
            save_xml_to_disk(state);
        }
    });

    if !can_apply(state) {
        ui.label(
            egui::RichText::new(
                "Apply to Game needs: a tree loaded from PAZ + Game Directory set.",
            )
            .color(egui::Color32::from_gray(160))
            .small(),
        );
    }
}

fn can_apply(state: &AppState) -> bool {
    state.xml.tree.is_some() && state.xml.current_entry.is_some() && state.game_dir.is_some()
}

fn apply_to_game(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let Some(entry) = state.xml.current_entry.clone() else {
        return;
    };
    let Some(tree) = state.xml.tree.as_ref() else {
        return;
    };
    let bytes = match xml_patcher::serialize_tree(tree) {
        Ok(b) => b,
        Err(e) => {
            state.toasts.error_with_details("XML serialize failed", e.to_string());
            return;
        }
    };
    let group = state.xml.overlay_group.clone();
    match xml_editor::deploy_xml_overlay(&game_dir, &entry.dir_path, &entry.filename, &bytes, &group) {
        Ok(()) => state.toasts.info(format!(
            "Deployed {} as overlay group {}",
            entry.filename, group
        )),
        Err(e) => state.toasts.error_with_details(
            "XML deploy failed",
            format!("{}\nGroup: {}\nFile: {}", e, group, entry.filename),
        ),
    }
}

fn restore_overlay(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        return;
    };
    let group = state.xml.overlay_group.clone();
    match xml_editor::restore_xml_overlay(&game_dir, &group) {
        Ok(()) => state
            .toasts
            .info(format!("Removed XML overlay group {}", group)),
        Err(e) => state.toasts.error_with_details(
            "Restore failed",
            format!("{}\nGroup: {}", e, group),
        ),
    }
}

fn save_xml_to_disk(state: &mut AppState) {
    let Some(tree) = state.xml.tree.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save XML")
        .add_filter("XML", &["xml"])
        .save_file()
    else {
        return;
    };
    let bytes = match xml_patcher::serialize_tree(tree) {
        Ok(b) => b,
        Err(e) => {
            state.toasts.error_with_details("XML serialize failed", e.to_string());
            return;
        }
    };
    match std::fs::write(&path, &bytes) {
        Ok(()) => state.toasts.info(format!("Wrote {}", path.display())),
        Err(e) => state.toasts.error_with_details(
            "Write failed",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}

// ── Patch builder (legacy v1 surface) ───────────────────────────────────────

fn render_patch_builder(ui: &mut egui::Ui, state: &mut AppState) {
    legacy_target_section(ui, state);
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    legacy_ops_section(ui, state);
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    legacy_preview_section(ui, state);
}

fn legacy_target_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Target file");
    ui.horizontal(|ui| {
        if ui.button("New patch from XML...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Pick XML file to patch")
                .add_filter("XML", &["xml"])
                .pick_file()
            {
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let target_str = path.to_string_lossy().into_owned();
                        state.xml.patch = Some(XmlPatch::new(target_str));
                        state.xml.vanilla_bytes = Some(bytes);
                        state.xml.preview_output = None;
                        state.xml.last_patch_path = None;
                    }
                    Err(e) => state.toasts.error_with_details(
                        "Failed to read XML",
                        format!("{}\nPath: {}", e, path.display()),
                    ),
                }
            }
        }
        if ui.button("Load patch JSON...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Load XML patch JSON")
                .add_filter("JSON", &["json"])
                .pick_file()
            {
                match xml_patcher::load_patch(&path) {
                    Ok(patch) => {
                        state.xml.patch = Some(patch);
                        state.xml.vanilla_bytes = None;
                        state.xml.preview_output = None;
                        state.xml.last_patch_path = Some(path);
                    }
                    Err(e) => state.toasts.error_with_details(
                        "Failed to load patch",
                        format!("{}", e),
                    ),
                }
            }
        }
        let has_patch = state.xml.patch.is_some();
        if ui.add_enabled(has_patch, egui::Button::new("Save patch JSON...")).clicked() {
            save_patch(state);
        }
    });

    if let Some(patch) = state.xml.patch.as_mut() {
        ui.horizontal(|ui| {
            ui.label("Target:");
            ui.add(egui::TextEdit::singleline(&mut patch.target).desired_width(420.0));
        });
        ui.horizontal(|ui| {
            ui.label("Description:");
            ui.add(egui::TextEdit::singleline(&mut patch.description).desired_width(420.0));
        });
    }
}

fn legacy_ops_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(patch) = state.xml.patch.as_mut() else {
        ui.label("Operations are available once a patch is loaded.");
        return;
    };
    ui.heading(format!("Operations ({})", patch.ops.len()));

    let mut to_remove: Option<usize> = None;
    egui::ScrollArea::vertical()
        .id_salt("xml_ops_existing")
        .max_height(160.0)
        .show(ui, |ui| {
            for (i, op) in patch.ops.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("#{i}"));
                    ui.label(format_op_summary(op));
                    if ui.small_button("✖").clicked() {
                        to_remove = Some(i);
                    }
                });
            }
        });
    if let Some(idx) = to_remove {
        patch.ops.remove(idx);
    }

    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);
    render_op_form(ui, &mut state.xml.draft, patch);
}

fn render_op_form(ui: &mut egui::Ui, draft: &mut OpDraft, patch: &mut XmlPatch) {
    ui.label(egui::RichText::new("Add operation").strong());
    ui.horizontal(|ui| {
        ui.label("Op:");
        egui::ComboBox::from_id_salt("xml_op_kind")
            .selected_text(draft.kind.label())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut draft.kind, OpKind::SetText, "set_text");
                ui.selectable_value(&mut draft.kind, OpKind::SetAttr, "set_attr");
                ui.selectable_value(&mut draft.kind, OpKind::AppendChild, "append_child");
            });
    });
    ui.horizontal(|ui| {
        ui.label("Path:");
        ui.add(
            egui::TextEdit::singleline(&mut draft.path)
                .desired_width(420.0)
                .hint_text("Root/Item/Name"),
        );
    });
    match draft.kind {
        OpKind::SetText => {
            ui.horizontal(|ui| {
                ui.label("Value:");
                ui.add(egui::TextEdit::singleline(&mut draft.value).desired_width(420.0));
            });
        }
        OpKind::SetAttr => {
            ui.horizontal(|ui| {
                ui.label("Attr:");
                ui.add(egui::TextEdit::singleline(&mut draft.attr).desired_width(160.0));
                ui.label("Value:");
                ui.add(egui::TextEdit::singleline(&mut draft.value).desired_width(260.0));
            });
        }
        OpKind::AppendChild => {
            ui.label("Fragment:");
            ui.add(
                egui::TextEdit::multiline(&mut draft.fragment)
                    .desired_width(640.0)
                    .desired_rows(3),
            );
        }
    }
    if ui.button("Add op").clicked() {
        if let Ok(op) = build_op(draft) {
            patch.ops.push(op);
        }
    }
}

fn build_op(draft: &OpDraft) -> Result<XmlOp, String> {
    if draft.path.trim().is_empty() {
        return Err("path is required".into());
    }
    Ok(match draft.kind {
        OpKind::SetText => XmlOp::SetText {
            path: draft.path.clone(),
            value: draft.value.clone(),
        },
        OpKind::SetAttr => XmlOp::SetAttr {
            path: draft.path.clone(),
            attr: draft.attr.clone(),
            value: draft.value.clone(),
        },
        OpKind::AppendChild => XmlOp::AppendChild {
            path: draft.path.clone(),
            fragment: draft.fragment.clone(),
        },
    })
}

fn format_op_summary(op: &XmlOp) -> String {
    match op {
        XmlOp::SetText { path, value } => format!("set_text {} = \"{}\"", path, truncate(value, 60)),
        XmlOp::SetAttr { path, attr, value } => {
            format!("set_attr {}@{} = \"{}\"", path, attr, truncate(value, 60))
        }
        XmlOp::AppendChild { path, fragment } => {
            format!("append_child {} <- \"{}\"", path, truncate(fragment, 60))
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "..."
    }
}

fn legacy_preview_section(ui: &mut egui::Ui, state: &mut AppState) {
    if state.xml.patch.is_none() {
        return;
    }
    ui.heading("Preview");
    let mut do_refresh = false;
    let has_bytes = state.xml.vanilla_bytes.is_some();
    ui.horizontal(|ui| {
        if ui.add_enabled(has_bytes, egui::Button::new("Refresh preview")).clicked() {
            do_refresh = true;
        }
    });
    if do_refresh {
        if let (Some(patch), Some(bytes)) = (state.xml.patch.as_ref(), state.xml.vanilla_bytes.as_ref()) {
            state.xml.preview_output = Some(
                xml_patcher::apply_patch(bytes, patch)
                    .map(|out| String::from_utf8_lossy(&out).into_owned())
                    .map_err(|e| e.to_string()),
            );
        }
    }
    egui::ScrollArea::both()
        .id_salt("xml_preview")
        .max_height(280.0)
        .show(ui, |ui| match &state.xml.preview_output {
            None => {
                ui.label(egui::RichText::new("(no preview)").weak());
            }
            Some(Ok(text)) => {
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .desired_width(f32::INFINITY)
                        .desired_rows(20)
                        .font(egui::TextStyle::Monospace),
                );
            }
            Some(Err(msg)) => {
                ui.label(
                    egui::RichText::new(format!("Preview error: {}", msg))
                        .color(egui::Color32::from_rgb(230, 80, 80)),
                );
            }
        });
}

fn save_patch(state: &mut AppState) {
    let Some(patch) = state.xml.patch.as_ref() else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save XML patch JSON")
        .add_filter("JSON", &["json"])
        .save_file()
    else {
        return;
    };
    match xml_patcher::save_patch(patch, &path) {
        Ok(()) => {
            state.xml.last_patch_path = Some(path.clone());
            state.toasts.info(format!("Saved patch to {}", path.display()));
        }
        Err(e) => state.toasts.error_with_details(
            "Failed to save patch",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}
