//! XML patcher panel.
//!
//! Tabbed view that picks an XML target inside the game's PAZ archives,
//! lets the user build a list of patch ops (set_text / set_attr /
//! append_child), previews the rewritten XML, and saves the patch as JSON
//! or deploys it as a PAZ overlay.
//!
//! Single-document — only one patch is open at a time. The patch lives on
//! [`AppState::xml`] so navigating away to another view doesn't lose
//! editing state.

use std::path::PathBuf;

use crate::state::AppState;
use crate::xml_patcher::{self, XmlOp, XmlPatch};

/// Persistent state for the XML panel. Owned by [`AppState`] (similar to
/// [`crate::ui::paseq_panel::PaseqSession`]) so view switches don't drop
/// the user's edits.
pub struct XmlSession {
    /// Currently open patch, if any. The `target` field is the
    /// PAZ-relative path of the file the patch will be applied to.
    pub patch: Option<XmlPatch>,
    /// Cached vanilla bytes of the target file. Populated when the user
    /// clicks "Load target". Used as the input to `apply_patch` for the
    /// preview pane and the deploy step.
    pub vanilla_bytes: Option<Vec<u8>>,
    /// Cached preview output of `apply_patch(vanilla_bytes, patch)`. Re-
    /// computed on demand when the user clicks "Refresh preview" — we
    /// don't auto-recompute on every keystroke because patches against
    /// large XMLs can take tens of milliseconds.
    pub preview_output: Option<Result<String, String>>,
    /// Working draft for the new-op form. Bound to the input fields in
    /// [`render_op_form`] so the user can compose without overwriting
    /// existing patch ops.
    pub draft: OpDraft,
    /// Last on-disk path the patch was loaded from / saved to. Drives the
    /// title bar and the default location for "Save".
    pub last_patch_path: Option<PathBuf>,
}

impl Default for XmlSession {
    fn default() -> Self {
        Self {
            patch: None,
            vanilla_bytes: None,
            preview_output: None,
            draft: OpDraft::default(),
            last_patch_path: None,
        }
    }
}

/// Draft for a single op. The user fills in fields and clicks "Add op",
/// which validates + appends to the patch's `ops` list and clears the
/// draft for the next entry.
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

/// Render the XML panel. Call once per frame from the central panel when
/// [`crate::state::MainView`] is `Xml`.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("XML Patcher");
    ui.label(
        "Apply slash-path patches (set_text / set_attr / append_child) to \
         XML game configs. Save patches as JSON for sharing, or apply them \
         in-place to a local file for testing.",
    );
    ui.separator();

    target_section(ui, state);
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    ops_section(ui, state);
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
    preview_section(ui, state);
}

fn target_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Target file");

    // Two ways to pick a target:
    //   1. "Load patch" — JSON patch already on disk; we use its `target`
    //      field as the PAZ-relative path. The user then points at a
    //      local copy of that XML to actually run the patch against.
    //   2. "New patch from XML file" — pick an XML file directly on disk.
    //      The patch's `target` defaults to the absolute path; the user
    //      can edit it later if they want a PAZ-relative target.
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
                        state
                            .toasts
                            .info(format!("Loaded XML target: {}", path.display()));
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
                        state.xml.last_patch_path = Some(path.clone());
                        state.toasts.info(format!("Loaded patch: {}", path.display()));
                    }
                    Err(e) => state.toasts.error_with_details(
                        "Failed to load patch",
                        format!("{}\nPath: {}", e, path.display()),
                    ),
                }
            }
        }

        let has_patch = state.xml.patch.is_some();
        let save_btn = ui.add_enabled(has_patch, egui::Button::new("Save patch JSON..."));
        if save_btn.clicked() {
            save_patch(state);
        }
    });

    if let Some(patch) = state.xml.patch.as_mut() {
        ui.horizontal(|ui| {
            ui.label("Target path:");
            ui.add(
                egui::TextEdit::singleline(&mut patch.target)
                    .desired_width(420.0)
                    .hint_text("gamedata/binary__/client/bin/foo.xml"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Description:");
            ui.add(
                egui::TextEdit::singleline(&mut patch.description)
                    .desired_width(420.0)
                    .hint_text("optional human-readable note"),
            );
        });

        ui.horizontal(|ui| {
            if ui.button("Load XML bytes for preview...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Pick local copy of the target XML")
                    .add_filter("XML", &["xml"])
                    .pick_file()
                {
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            state.xml.vanilla_bytes = Some(bytes);
                            state.xml.preview_output = None;
                            state
                                .toasts
                                .info(format!("Loaded XML for preview: {}", path.display()));
                        }
                        Err(e) => state.toasts.error_with_details(
                            "Failed to read XML",
                            format!("{}\nPath: {}", e, path.display()),
                        ),
                    }
                }
            }
            if state.xml.vanilla_bytes.is_some() {
                ui.label(
                    egui::RichText::new("XML bytes loaded for preview")
                        .color(egui::Color32::from_rgb(120, 200, 120)),
                );
            }
        });

        if let Some(p) = &state.xml.last_patch_path {
            ui.label(
                egui::RichText::new(format!("Patch on disk: {}", p.display())).small(),
            );
        }
    } else {
        ui.label(
            egui::RichText::new("No patch loaded. Use 'New patch from XML' or 'Load patch JSON'.")
                .color(egui::Color32::from_gray(160)),
        );
    }
}

fn ops_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(patch) = state.xml.patch.as_mut() else {
        ui.label("Operations are available once a patch is loaded.");
        return;
    };

    ui.heading(format!("Operations ({})", patch.ops.len()));

    // Existing ops list with Remove buttons. Iterating with an index lets
    // us mutate the vec inside the loop without re-borrowing.
    let mut to_remove: Option<usize> = None;
    egui::ScrollArea::vertical()
        .id_salt("xml_ops_existing")
        .max_height(180.0)
        .show(ui, |ui| {
            for (i, op) in patch.ops.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("#{i}"));
                    ui.label(format_op_summary(op));
                    if ui.small_button("✖").on_hover_text("Remove").clicked() {
                        to_remove = Some(i);
                    }
                });
            }
            if patch.ops.is_empty() {
                ui.label(
                    egui::RichText::new("No operations yet — add one below.")
                        .color(egui::Color32::from_gray(160)),
                );
            }
        });
    if let Some(idx) = to_remove {
        patch.ops.remove(idx);
        state.xml.preview_output = None;
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    render_op_form(ui, &mut state.xml.draft, patch, &mut state.xml.preview_output);
}

fn render_op_form(
    ui: &mut egui::Ui,
    draft: &mut OpDraft,
    patch: &mut XmlPatch,
    preview_output: &mut Option<Result<String, String>>,
) {
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
                ui.add(
                    egui::TextEdit::singleline(&mut draft.value)
                        .desired_width(420.0)
                        .hint_text("new text content"),
                );
            });
        }
        OpKind::SetAttr => {
            ui.horizontal(|ui| {
                ui.label("Attr:");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.attr)
                        .desired_width(160.0)
                        .hint_text("attribute name"),
                );
                ui.label("Value:");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.value)
                        .desired_width(260.0)
                        .hint_text("attribute value"),
                );
            });
        }
        OpKind::AppendChild => {
            ui.label("Fragment (well-formed XML, single root):");
            ui.add(
                egui::TextEdit::multiline(&mut draft.fragment)
                    .desired_width(640.0)
                    .desired_rows(4)
                    .hint_text("<Item id=\"1\"/>"),
            );
        }
    }

    ui.horizontal(|ui| {
        if ui.button("Add op").clicked() {
            match build_op(draft) {
                Ok(op) => {
                    patch.ops.push(op);
                    *preview_output = None;
                    // Clear the draft so the next op starts fresh, but
                    // keep the path — most patches edit several fields
                    // on the same parent so the path is the most reused
                    // input.
                    draft.value.clear();
                    draft.attr.clear();
                    draft.fragment.clear();
                }
                Err(e) => {
                    *preview_output = Some(Err(format!("Invalid op: {}", e)));
                }
            }
        }
        if ui.button("Clear draft").clicked() {
            *draft = OpDraft::default();
        }
    });
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
        OpKind::SetAttr => {
            if draft.attr.trim().is_empty() {
                return Err("attr is required for set_attr".into());
            }
            XmlOp::SetAttr {
                path: draft.path.clone(),
                attr: draft.attr.clone(),
                value: draft.value.clone(),
            }
        }
        OpKind::AppendChild => {
            if draft.fragment.trim().is_empty() {
                return Err("fragment is required for append_child".into());
            }
            XmlOp::AppendChild {
                path: draft.path.clone(),
                fragment: draft.fragment.clone(),
            }
        }
    })
}

fn format_op_summary(op: &XmlOp) -> String {
    match op {
        XmlOp::SetText { path, value } => {
            format!("set_text {} = \"{}\"", path, truncate(value, 60))
        }
        XmlOp::SetAttr { path, attr, value } => format!(
            "set_attr {}@{} = \"{}\"",
            path,
            attr,
            truncate(value, 60)
        ),
        XmlOp::AppendChild { path, fragment } => {
            format!("append_child {} <- \"{}\"", path, truncate(fragment, 60))
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{}...", head)
    }
}

fn preview_section(ui: &mut egui::Ui, state: &mut AppState) {
    if state.xml.patch.is_none() {
        return;
    }

    ui.heading("Preview");

    // Defer button-driven actions until the closure ends so we don't take
    // a second `&mut state` borrow inside the horizontal layout.
    let mut do_refresh = false;
    let mut do_save = false;
    let has_bytes = state.xml.vanilla_bytes.is_some();
    ui.horizontal(|ui| {
        let refresh_btn = ui.add_enabled(has_bytes, egui::Button::new("Refresh preview"));
        if refresh_btn.clicked() {
            do_refresh = true;
        }
        let apply_btn = ui.add_enabled(has_bytes, egui::Button::new("Save patched XML to file..."));
        if apply_btn.clicked() {
            do_save = true;
        }
        if !has_bytes {
            ui.label(
                egui::RichText::new("Load XML bytes (above) to enable preview / save.")
                    .color(egui::Color32::from_rgb(240, 190, 60)),
            );
        }
    });
    if do_refresh {
        run_preview(state);
    }
    if do_save {
        apply_to_file(state);
    }

    egui::ScrollArea::both()
        .id_salt("xml_preview")
        .auto_shrink([false; 2])
        .show(ui, |ui| match &state.xml.preview_output {
            None => {
                ui.label(
                    egui::RichText::new(
                        "(no preview computed yet — click 'Refresh preview')",
                    )
                    .color(egui::Color32::from_gray(160)),
                );
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

fn run_preview(state: &mut AppState) {
    let Some(patch) = state.xml.patch.as_ref() else {
        return;
    };
    let Some(bytes) = state.xml.vanilla_bytes.as_ref() else {
        return;
    };
    state.xml.preview_output = Some(
        xml_patcher::apply_patch(bytes, patch)
            .map(|out| String::from_utf8_lossy(&out).into_owned())
            .map_err(|e| e.to_string()),
    );
}

fn apply_to_file(state: &mut AppState) {
    let Some(patch) = state.xml.patch.clone() else {
        return;
    };
    let Some(bytes) = state.xml.vanilla_bytes.clone() else {
        return;
    };

    let Some(path) = rfd::FileDialog::new()
        .set_title("Save patched XML")
        .add_filter("XML", &["xml"])
        .save_file()
    else {
        return;
    };

    let result = xml_patcher::apply_patch(&bytes, &patch);
    match result {
        Ok(out) => match std::fs::write(&path, &out) {
            Ok(()) => {
                state
                    .toasts
                    .info(format!("Wrote patched XML to {}", path.display()));
            }
            Err(e) => state.toasts.error_with_details(
                "Failed to write XML",
                format!("{}\nPath: {}", e, path.display()),
            ),
        },
        Err(e) => state
            .toasts
            .error_with_details("Patch failed", e.to_string()),
    }
}

fn save_patch(state: &mut AppState) {
    let Some(patch) = state.xml.patch.as_ref() else {
        return;
    };
    let mut dialog = rfd::FileDialog::new()
        .set_title("Save XML patch JSON")
        .add_filter("JSON", &["json"]);
    if let Some(prev) = state.xml.last_patch_path.as_ref() {
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
    match xml_patcher::save_patch(patch, &path) {
        Ok(()) => {
            state.xml.last_patch_path = Some(path.clone());
            state
                .toasts
                .info(format!("Saved patch to {}", path.display()));
        }
        Err(e) => state.toasts.error_with_details(
            "Failed to save patch",
            format!("{}\nPath: {}", e, path.display()),
        ),
    }
}
