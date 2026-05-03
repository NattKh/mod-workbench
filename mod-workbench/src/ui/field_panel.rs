use std::time::Instant;

use serde_json::Value;

use crate::catalog::Catalog;
use crate::edit_history::{get_at_path, set_at_path, EditOp};
use crate::localization::Localization;
use crate::mod_io::extract_entry_key;
use crate::state::AppState;

/// Mapping from field-name suffixes to the dispatch table they reference.
///
/// The matcher walks this list and uses the *first* match where the field
/// name (lower-cased, with any trailing `_list`/`s`/`[N]` stripped) ends with
/// the entry's left-hand side. This lets us match both bare names like
/// `gimmick_info` and dotted/array contexts like `_buff_list[3]`.
///
/// `"STRING"` is a sentinel meaning "resolve via [`Catalog::lookup_string`]"
/// instead of [`Catalog::lookup_name_for_dispatch`].
const FIELD_TARGETS: &[(&str, &str)] = &[
    // Equip / item plumbing
    ("equip_type_info", "equip_type_info"),
    ("equip_slot_info", "equip_slot_info"),
    ("item_use_info", "item_use_info"),
    ("breakable_object_info", "breakable_object_info"),
    ("category_info", "category_info"),
    ("drop_set_info", "drop_set_info"),
    // Gimmick / world
    ("gimmick_info_key", "gimmick_info"),
    ("gimmick_info", "gimmick_info"),
    ("region_info", "region_info"),
    // Strings (PALOC)
    ("local_string_info", "STRING"),
    ("string_key_hash", "STRING"),
    ("string_key", "STRING"),
    ("name_id", "STRING"),
    // Skills / buffs
    ("skill_key", "skill_info"),
    ("skill", "skill_info"),
    ("buff_key", "buff_info"),
    ("buff", "buff_info"),
    // Characters / NPCs
    ("character_info_key", "character_info"),
    ("character_info", "character_info"),
    ("npc_info", "npc_info"),
    // Knowledge / quests / missions
    ("knowledge_info", "knowledge_info"),
    ("quest_info", "quest_info"),
    ("mission_info", "mission_info"),
    // Faction
    ("faction_info", "faction_info"),
    // Misc behavioural tables
    ("condition_info", "condition_info"),
    ("ai_action_attribute_info", "aiaction_attribute_info"),
    ("effect_info", "effect_info"),
    ("status_info", "status_info"),
];

/// Highlight color used for fields whose current value differs from vanilla.
const CHANGED_COLOR: egui::Color32 = egui::Color32::from_rgb(255, 165, 0);

/// One pending edit produced by a widget interaction.
///
/// `path` is dot/bracket notation (e.g. `equip_passive_skill_list[0].skill`).
/// `value` is the new JSON value to set at that path. When `value` is `None`
/// the path is treated as a reset request: the current entry gets the vanilla
/// value reinstated and the change-tracker entry for that path is dropped.
struct PendingEdit {
    path: String,
    value: Option<Value>,
}

/// Right panel: field editor for the selected entry.
///
/// State has moved to a per-tab model: `selected_entry_idx`, `changes`, and
/// `history` all live on [`crate::state::ActiveTable`] now, with the focused
/// tab returned by [`AppState::active_table`] / [`AppState::active_table_mut`].
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Fields");
    ui.separator();

    let active = match state.active_table() {
        Some(t) => t,
        None => {
            ui.label("No table loaded");
            return;
        }
    };

    let entry_idx = match active.selected_entry_idx {
        Some(i) => i,
        None => {
            ui.label("Select an entry from the table");
            return;
        }
    };

    if entry_idx >= active.entries.len() {
        ui.label("Entry index out of range");
        return;
    }

    let entry_key = extract_entry_key(&active.entries[entry_idx]);
    ui.horizontal(|ui| {
        ui.label(format!("Entry key: {}", entry_key));
    });

    // "Reset entire entry to vanilla" affordance — only shown when the entry
    // has changes recorded *and* we still have a vanilla snapshot to fall
    // back to. Sets a flag to apply after we drop the immutable borrow.
    let entry_has_changes = active.changes.is_entry_modified(entry_key);
    let has_vanilla_snapshot = active.vanilla.get(entry_idx).is_some();
    let mut reset_entire_entry = false;
    if entry_has_changes && has_vanilla_snapshot {
        ui.horizontal(|ui| {
            if ui
                .button("\u{21BA} Reset entire entry to vanilla")
                .on_hover_text("Discard all changes for this entry")
                .clicked()
            {
                reset_entire_entry = true;
            }
        });
    }
    ui.separator();

    // Pending widget interactions; applied after the immutable borrow ends.
    let mut edits: Vec<PendingEdit> = Vec::new();
    // Pending note edit. We collect it here while the immutable borrow on
    // `state` is live, then apply once we drop down to the mutable borrow
    // for edit application below. `None` means "don't touch the note this
    // frame".
    let mut note_edit: Option<String> = None;

    let vanilla_entry = active.vanilla.get(entry_idx);
    let catalog: Option<&Catalog> = state.catalog.as_ref();
    let localization: Option<&Localization> = state.localization.as_ref();
    let table_name = active.dispatch_name.clone();
    let existing_note = state
        .notes
        .get(&table_name, entry_key)
        .map(|s| s.to_string())
        .unwrap_or_default();

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            if let Some(obj) = active.entries[entry_idx].as_object() {
                let vanilla_obj = vanilla_entry.and_then(|v| v.as_object());

                for (field_name, value) in obj {
                    let vanilla_value = vanilla_obj.and_then(|vo| vo.get(field_name));

                    render_field(
                        ui,
                        field_name,
                        field_name,
                        value,
                        vanilla_value,
                        catalog,
                        localization,
                        &mut edits,
                    );
                }
            }

            // Notes section — collapsing so the (typically empty) panel
            // doesn't dominate the bottom of the field list, but visible
            // by default once a note exists so authors don't lose track of
            // their reasoning. The text is travel-ready: exports embed it
            // under `_notes` in the v3 field JSON via
            // [`crate::mod_io::export_changes_full`].
            ui.add_space(8.0);
            ui.separator();
            let header = if existing_note.is_empty() {
                "Notes".to_string()
            } else {
                "Notes \u{1F4DD}".to_string() // 📝
            };
            egui::CollapsingHeader::new(header)
                .id_salt(("fp_notes", entry_key))
                .default_open(!existing_note.is_empty())
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(
                            "Free-form annotation attached to this entry. \
                             Travels with the mod export under `_notes`.",
                        )
                        .weak()
                        .small(),
                    );
                    let mut note_buf = existing_note.clone();
                    let resp = ui.add(
                        egui::TextEdit::multiline(&mut note_buf)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .hint_text(
                                "Why did you change this entry? Range hints, links, etc.",
                            ),
                    );
                    if resp.changed() {
                        note_edit = Some(note_buf.clone());
                    }
                    ui.horizontal(|ui| {
                        if !existing_note.is_empty() {
                            if ui.small_button("Clear").clicked() {
                                note_edit = Some(String::new());
                            }
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "{} chars",
                                existing_note.chars().count()
                            ))
                            .weak()
                            .small(),
                        );
                    });
                });
        });

    // Apply any pending note edit before the field-edit pass. Note state
    // lives outside the per-tab `ActiveTable`, so the borrow on `state` we
    // need is independent of the upcoming `active_table_mut()` call.
    if let Some(new_note) = note_edit {
        state.notes.set(&table_name, entry_key, new_note);
    }

    // Apply the "Reset entry" affordance first so subsequent edits (none
    // expected on this frame, but be defensive) don't fight the snapshot.
    //
    // For history we treat a full-entry reset as a *single* op whose path is
    // the empty string and whose old/new values are the entire entry. The
    // history panel doesn't currently surface these specially; undo restores
    // the prior entry verbatim.
    if reset_entire_entry {
        let active = state
            .active_table_mut()
            .expect("active_table_mut must succeed since active_table did");
        if let Some(vanilla) = active.vanilla.get(entry_idx).cloned() {
            let table_name = active.dispatch_name.clone();
            let old_entry = active.entries[entry_idx].clone();
            let new_entry = vanilla.clone();
            active.entries[entry_idx] = vanilla;
            active.changes.unrecord_entry(entry_key);
            active.history.record(EditOp {
                table: table_name,
                entry_key,
                field_path: String::new(), // empty path == whole-entry op
                old_value: old_entry,
                new_value: new_entry,
                timestamp: Instant::now(),
            });
        }
    }

    // Apply per-field edits and reset requests.
    //
    // For each pending edit we capture the prior value at the path *before*
    // mutating, then build an EditOp so undo can put it back. The change
    // tracker continues to run in parallel — exports/diffs read from it, the
    // history powers Ctrl+Z / Ctrl+Y / the History panel.
    if !edits.is_empty() {
        let active = state
            .active_table_mut()
            .expect("active_table_mut must succeed since active_table did");
        let table_name = active.dispatch_name.clone();
        for edit in edits {
            // Snapshot the current value before we mutate it.
            let old_value = get_at_path(&active.entries[entry_idx], &edit.path)
                .cloned()
                .unwrap_or(Value::Null);
            match edit.value {
                Some(new_value) => {
                    if set_at_path(
                        &mut active.entries[entry_idx],
                        &edit.path,
                        new_value.clone(),
                    ) {
                        active.changes.record_change(entry_key, edit.path.clone());
                        active.history.record(EditOp {
                            table: table_name.clone(),
                            entry_key,
                            field_path: edit.path,
                            old_value,
                            new_value,
                            timestamp: Instant::now(),
                        });
                    }
                }
                None => {
                    // Reset request: copy vanilla value at this path back into current.
                    let vanilla_at_path = active
                        .vanilla
                        .get(entry_idx)
                        .and_then(|v| get_at_path(v, &edit.path).cloned());
                    if let Some(v) = vanilla_at_path {
                        if set_at_path(&mut active.entries[entry_idx], &edit.path, v.clone()) {
                            active.changes.unrecord_field(entry_key, &edit.path);
                            // Reset to vanilla is still an EditOp — it changes
                            // the entry's value, and the user may want to undo
                            // it (i.e. restore the modification they reset).
                            active.history.record(EditOp {
                                table: table_name.clone(),
                                entry_key,
                                field_path: edit.path,
                                old_value,
                                new_value: v,
                                timestamp: Instant::now(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Render a single field with appropriate widget based on JSON type.
///
/// `display_name` is what we render in the UI (the leaf name). `path` is the
/// full dot/bracket path used for diffing, edits, and change tracking.
///
/// `localization` is consulted by `annotate_reference` for STRING-targeted
/// fields: if a hash matches an entry in the EN map we show the English
/// string inline; if both EN and KR are present, the Korean variant lands
/// in the hover tooltip.
fn render_field(
    ui: &mut egui::Ui,
    display_name: &str,
    path: &str,
    value: &Value,
    vanilla_value: Option<&Value>,
    catalog: Option<&Catalog>,
    localization: Option<&Localization>,
    edits: &mut Vec<PendingEdit>,
) {
    // For containers (Array/Object) we walk into the children for diff
    // purposes — the parent dot only fires when *any* leaf differs.
    let is_changed = match (value, vanilla_value) {
        (Value::Array(_) | Value::Object(_), Some(vv)) => values_differ_recursive(value, vv),
        (_, Some(vv)) => value != vv,
        // No vanilla snapshot at this path — treat as not-changed so we don't
        // light up the entire entry as orange when vanilla is missing.
        (_, None) => false,
    };

    let label_color = if is_changed {
        CHANGED_COLOR
    } else {
        ui.visuals().text_color()
    };

    // Prefix changed leaves with a bullet so the panel scans easily.
    let prefix = if is_changed { "\u{25CF} " } else { "" };
    let label_text =
        egui::RichText::new(format!("{}{}", prefix, display_name)).color(label_color);

    match value {
        Value::Number(n) => {
            render_number_field(
                ui,
                display_name,
                path,
                n,
                label_text,
                is_changed,
                vanilla_value,
                catalog,
                localization,
                edits,
            );
        }

        Value::String(s) => {
            // Decide rendering style based on the content:
            //   1. If the field name suggests a base64 blob, REPLACE the
            //      blob display with the extracted text runs — the raw
            //      base64 string is unreadable and useless to show by
            //      default. The user can still see the original via a
            //      collapsible "Show raw base64" toggle.
            //   2. Otherwise show the editable string. CJK content uses a
            //      multiline editor so long Korean phrases wrap properly.
            let looks_like_blob = path.ends_with("_blob_b64")
                || path.ends_with("blob_b64")
                || (path.contains("blob") && crate::blob_text::looks_like_blob_base64(s));

            if looks_like_blob {
                // Blob field — show decoded text inline, hide raw base64.
                let runs = crate::blob_text::extract_from_base64(s).unwrap_or_default();
                let interesting: Vec<_> = runs
                    .into_iter()
                    .filter(|r| r.text.chars().count() >= 3)
                    .collect();

                ui.horizontal(|ui| {
                    let label = ui.label(label_text);
                    if is_changed {
                        if let Some(vv) = vanilla_value {
                            label.on_hover_text(format!("Vanilla: {}", vv));
                        }
                    }
                    ui.label(
                        egui::RichText::new(format!(
                            "[blob, {} bytes b64, {} text runs]",
                            s.len(),
                            interesting.len()
                        ))
                        .color(egui::Color32::from_gray(140))
                        .small(),
                    );
                });

                if !interesting.is_empty() {
                    // Show every text run inline in an indented block —
                    // open by default so users actually see them. Korean
                    // and other CJK runs get the 📝 prefix; ASCII runs
                    // (asset paths etc.) display as-is.
                    ui.indent(format!("blob_decoded_{}", path), |ui| {
                        for run in &interesting {
                            let prefix = if run.has_cjk { "📝 " } else { "" };
                            // Use selectable label so users can copy text.
                            ui.add(
                                egui::Label::new(format!(
                                    "{}{}",
                                    prefix, run.text
                                ))
                                .selectable(true)
                                .wrap(),
                            );
                        }
                        // Optional: raw base64 hidden under a collapsible
                        // for advanced users.
                        ui.collapsing("Show raw base64", |ui| {
                            let mut buf = s.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut buf)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false),
                            );
                        });
                    });
                }
            } else {
                // Regular string field.
                ui.horizontal(|ui| {
                    let label = ui.label(label_text);
                    if is_changed {
                        if let Some(vv) = vanilla_value {
                            label.on_hover_text(format!("Vanilla: {}", vv));
                        }
                    }
                    let mut text = s.clone();
                    let has_cjk = text.chars().any(|c| {
                        let cp = c as u32;
                        (0xAC00..=0xD7A3).contains(&cp)
                            || (0x4E00..=0x9FFF).contains(&cp)
                            || (0x3040..=0x309F).contains(&cp)
                            || (0x30A0..=0x30FF).contains(&cp)
                    });
                    let editor_response = if has_cjk {
                        ui.add(
                            egui::TextEdit::multiline(&mut text)
                                .desired_rows(1)
                                .desired_width(f32::INFINITY),
                        )
                    } else {
                        ui.text_edit_singleline(&mut text)
                    };
                    if editor_response.changed() {
                        edits.push(PendingEdit {
                            path: path.to_string(),
                            value: Some(Value::String(text)),
                        });
                    }
                    if is_changed {
                        render_reset_button(ui, path, vanilla_value, edits);
                    }
                });
            }
        }

        Value::Bool(b) => {
            ui.horizontal(|ui| {
                let label = ui.label(label_text);
                if is_changed {
                    if let Some(vv) = vanilla_value {
                        label.on_hover_text(format!("Vanilla: {}", vv));
                    }
                }
                let mut val = *b;
                if ui.checkbox(&mut val, "").changed() {
                    edits.push(PendingEdit {
                        path: path.to_string(),
                        value: Some(Value::Bool(val)),
                    });
                }
                if is_changed {
                    render_reset_button(ui, path, vanilla_value, edits);
                }
            });
        }

        Value::Array(arr) => {
            // Smart editor: if this array looks like an RGB[A] color, render
            // a color picker on a single line instead of recursing into the
            // list view. The picker's edit (if any) is collected as a single
            // replacement at this path.
            if is_color_array(display_name, arr) {
                ui.horizontal(|ui| {
                    let label = ui.label(label_text.clone());
                    if is_changed {
                        if let Some(vv) = vanilla_value {
                            label.on_hover_text(format!("Vanilla: {}", vv));
                        }
                    }
                    if let Some(replacement) = render_color_picker_array(ui, path, arr) {
                        edits.push(PendingEdit {
                            path: path.to_string(),
                            value: Some(replacement),
                        });
                    }
                    if is_changed {
                        render_reset_button(ui, path, vanilla_value, edits);
                    }
                });
                return;
            }

            ui.horizontal(|ui| {
                let header = format!("{}{} [{} items]", prefix, display_name, arr.len());
                let header_text = egui::RichText::new(&header).color(label_color);
                let response = egui::CollapsingHeader::new(header_text)
                    .id_salt(path)
                    .show(ui, |ui| {
                        let vanilla_arr = vanilla_value.and_then(|v| v.as_array());
                        for (i, item) in arr.iter().enumerate() {
                            let child_display = format!("{}[{}]", display_name, i);
                            let child_path = format!("{}[{}]", path, i);
                            let vanilla_child = vanilla_arr.and_then(|va| va.get(i));
                            render_field(
                                ui,
                                &child_display,
                                &child_path,
                                item,
                                vanilla_child,
                                catalog,
                                localization,
                                edits,
                            );
                        }
                    });
                if is_changed {
                    if let Some(vv) = vanilla_value {
                        response.header_response.on_hover_text(pretty_vanilla_summary(vv));
                    }
                    render_reset_button(ui, path, vanilla_value, edits);
                }
            });
        }

        Value::Object(obj) => {
            // Smart editor: if this object looks like an RGB[A] color
            // (`{r, g, b}` / `{r, g, b, a}`), render a color picker.
            if is_color_object(display_name, obj) {
                ui.horizontal(|ui| {
                    let label = ui.label(label_text.clone());
                    if is_changed {
                        if let Some(vv) = vanilla_value {
                            label.on_hover_text(format!("Vanilla: {}", vv));
                        }
                    }
                    if let Some(replacement) = render_color_picker_object(ui, path, obj) {
                        edits.push(PendingEdit {
                            path: path.to_string(),
                            value: Some(replacement),
                        });
                    }
                    if is_changed {
                        render_reset_button(ui, path, vanilla_value, edits);
                    }
                });
                return;
            }

            ui.horizontal(|ui| {
                let header = format!("{}{} {{{} fields}}", prefix, display_name, obj.len());
                let header_text = egui::RichText::new(&header).color(label_color);
                let response = egui::CollapsingHeader::new(header_text)
                    .id_salt(path)
                    .show(ui, |ui| {
                        let vanilla_obj = vanilla_value.and_then(|v| v.as_object());
                        for (child_name, child_value) in obj {
                            let child_path = format!("{}.{}", path, child_name);
                            let vanilla_child = vanilla_obj.and_then(|vo| vo.get(child_name));
                            render_field(
                                ui,
                                child_name,
                                &child_path,
                                child_value,
                                vanilla_child,
                                catalog,
                                localization,
                                edits,
                            );
                        }
                    });
                if is_changed {
                    if let Some(vv) = vanilla_value {
                        response.header_response.on_hover_text(pretty_vanilla_summary(vv));
                    }
                    render_reset_button(ui, path, vanilla_value, edits);
                }
            });
        }

        Value::Null => {
            ui.horizontal(|ui| {
                let label = ui.label(label_text);
                if is_changed {
                    if let Some(vv) = vanilla_value {
                        label.on_hover_text(format!("Vanilla: {}", vv));
                    }
                }
                ui.label("null");
                if is_changed {
                    render_reset_button(ui, path, vanilla_value, edits);
                }
            });
        }
    }
}

/// Render the widget for a `Value::Number` leaf. Split out from `render_field`
/// so the match arm doesn't balloon: numbers have three internal variants
/// (i64 / u64 / f64) plus a reference annotation and reset button alongside.
///
/// This version composes several optional smart-editor decorators on top of the
/// existing DragValue:
///   - **Hex display toggle** for hash-like fields (top bit set, or `_hash` /
///     `_key` suffix).
///   - **Catalog dropdown** for fields with a known dispatch target
///     ([`FIELD_TARGETS`]). The dropdown is a click-to-open searchable popup;
///     the DragValue stays so users can still type a raw key.
///   - **Bitmask grid** for fields named `*flags*`, `*mask*`, `*bits*`. Renders
///     32 checkboxes below the value.
///   - **Percent slider** for fields named `*rate*`, `*percent*`,
///     `*percentage*`. Maps `_rate` (0..=1 unit floats) to a 0..=100 slider for
///     ergonomics.
fn render_number_field(
    ui: &mut egui::Ui,
    display_name: &str,
    path: &str,
    n: &serde_json::Number,
    label_text: egui::RichText,
    is_changed: bool,
    vanilla_value: Option<&Value>,
    catalog: Option<&Catalog>,
    localization: Option<&Localization>,
    edits: &mut Vec<PendingEdit>,
) {
    if let Some(i) = n.as_i64() {
        render_integer_field(
            ui,
            display_name,
            path,
            i,
            false,
            label_text,
            is_changed,
            vanilla_value,
            catalog,
            localization,
            edits,
        );
    } else if let Some(u) = n.as_u64() {
        render_integer_field(
            ui,
            display_name,
            path,
            u as i64,
            true,
            label_text,
            is_changed,
            vanilla_value,
            catalog,
            localization,
            edits,
        );
    } else if let Some(f) = n.as_f64() {
        render_float_field(
            ui,
            display_name,
            path,
            f,
            label_text,
            is_changed,
            vanilla_value,
            edits,
        );
    } else {
        ui.horizontal(|ui| {
            let label = ui.label(label_text);
            if is_changed {
                if let Some(vv) = vanilla_value {
                    label.on_hover_text(format!("Vanilla: {}", vv));
                }
            }
            ui.label(n.to_string());
            if is_changed {
                render_reset_button(ui, path, vanilla_value, edits);
            }
        });
    }
}

/// Render an integer-typed numeric field with the full smart-editor suite.
///
/// `unsigned_origin` records whether the JSON value was a u64 — preserved so
/// large hashes don't roundtrip through i64 negative values when re-emitted.
fn render_integer_field(
    ui: &mut egui::Ui,
    display_name: &str,
    path: &str,
    initial: i64,
    unsigned_origin: bool,
    label_text: egui::RichText,
    is_changed: bool,
    vanilla_value: Option<&Value>,
    catalog: Option<&Catalog>,
    localization: Option<&Localization>,
    edits: &mut Vec<PendingEdit>,
) {
    let dispatch = target_for_field(display_name);
    let is_hashy = looks_like_hash(display_name, initial, unsigned_origin) || dispatch.is_some();
    let bitmask_width = bitmask_kind_for(display_name);
    let pct_kind = percent_kind_for(display_name);

    let mut new_value: Option<i64> = None;

    ui.horizontal(|ui| {
        let label = ui.label(label_text);
        if is_changed {
            if let Some(vv) = vanilla_value {
                label.on_hover_text(format!("Vanilla: {}", vv));
            }
        }

        // Hex display toggle: persist per (path, field) in egui memory.
        let hex_id = ui.make_persistent_id(("fp_hex", path));
        let mut show_hex = ui.memory_mut(|m| {
            *m.data
                .get_temp_mut_or_insert_with(hex_id, || is_hashy)
        });

        if show_hex {
            // Edit as a hex string. Width clamps so 16-digit hashes fit.
            let mut buf = format!("{:#X}", initial as u64);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut buf)
                    .desired_width(140.0)
                    .font(egui::TextStyle::Monospace),
            );
            if resp.lost_focus() && resp.changed() {
                if let Some(parsed) = parse_hex_or_dec(&buf) {
                    new_value = Some(parsed as i64);
                }
            }
        } else if unsigned_origin && initial >= 0 {
            let mut val = initial as u64;
            if ui.add(egui::DragValue::new(&mut val)).changed() {
                new_value = Some(val as i64);
            }
        } else {
            let mut val = initial;
            if ui.add(egui::DragValue::new(&mut val)).changed() {
                new_value = Some(val);
            }
        }

        // "0x" toggle button — only for fields that look hashy.
        if is_hashy {
            let label = if show_hex { "0x" } else { "10" };
            let resp = ui
                .small_button(label)
                .on_hover_text("Toggle hex/decimal display");
            if resp.clicked() {
                show_hex = !show_hex;
                ui.memory_mut(|m| m.data.insert_temp(hex_id, show_hex));
            }
        }

        // Catalog dropdown picker for fields with a known dispatch target.
        if let (Some(dispatch), Some(cat)) = (dispatch, catalog) {
            if let Some(picked) = show_hash_dropdown(ui, cat, dispatch, path, initial) {
                new_value = Some(picked);
            }
        }

        // Resolved-name annotation (existing behaviour, untouched).
        annotate_reference(ui, display_name, initial, catalog, localization);

        if is_changed {
            render_reset_button(ui, path, vanilla_value, edits);
        }
    });

    // Optional bitmask grid below the value.
    if let Some(width) = bitmask_width {
        if let Some(updated) = render_bitmask_grid(ui, path, initial, width) {
            new_value = Some(updated);
        }
    }

    // Optional percent slider below the value (and below the bitmask grid).
    if let Some(kind) = pct_kind {
        if let Some(updated) = render_pct_slider_int(ui, path, initial, kind) {
            new_value = Some(updated);
        }
    }

    if let Some(v) = new_value {
        let serialized = if unsigned_origin && v >= 0 {
            Value::from(v as u64)
        } else {
            Value::from(v)
        };
        edits.push(PendingEdit {
            path: path.to_string(),
            value: Some(serialized),
        });
    }
}

/// Render a float-typed numeric field with the optional percent slider.
///
/// Floats only get the slider companion — hashes are integer-only, and
/// bitmask widgets don't make sense on floats.
fn render_float_field(
    ui: &mut egui::Ui,
    display_name: &str,
    path: &str,
    initial: f64,
    label_text: egui::RichText,
    is_changed: bool,
    vanilla_value: Option<&Value>,
    edits: &mut Vec<PendingEdit>,
) {
    let pct_kind = percent_kind_for(display_name);
    let mut new_value: Option<f64> = None;

    ui.horizontal(|ui| {
        let label = ui.label(label_text);
        if is_changed {
            if let Some(vv) = vanilla_value {
                label.on_hover_text(format!("Vanilla: {}", vv));
            }
        }
        let mut val = initial;
        if ui
            .add(egui::DragValue::new(&mut val).speed(0.01))
            .changed()
        {
            new_value = Some(val);
        }
        if is_changed {
            render_reset_button(ui, path, vanilla_value, edits);
        }
    });

    if let Some(kind) = pct_kind {
        if let Some(updated) = render_pct_slider_float(ui, path, initial, kind) {
            new_value = Some(updated);
        }
    }

    if let Some(v) = new_value {
        let pushed = serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null);
        edits.push(PendingEdit {
            path: path.to_string(),
            value: Some(pushed),
        });
    }
}

/// Append a small "reset this field" button. Only call when the field actually
/// differs from vanilla and a vanilla value is available — otherwise we'd
/// have nothing to reset to.
fn render_reset_button(
    ui: &mut egui::Ui,
    path: &str,
    vanilla_value: Option<&Value>,
    edits: &mut Vec<PendingEdit>,
) {
    if vanilla_value.is_none() {
        return;
    }
    let response = ui
        .small_button("\u{21BA}")
        .on_hover_text("Reset this field to vanilla");
    if response.clicked() {
        edits.push(PendingEdit {
            path: path.to_string(),
            value: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Smart-editor helpers
//
// These power the type-aware decorations on numeric fields (hex toggle, hash
// dropdown, bitmask grid, percent slider) and color pickers on RGB[A] arrays
// and objects. None of them mutate state directly — they all return optional
// replacement values that the caller pushes into the edit queue.
// ---------------------------------------------------------------------------

/// What kind of percentage scale a field uses, if any.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PercentKind {
    /// Field stores `0..=100` directly (e.g. `loot_percentage`).
    Hundred,
    /// Field stores `0..=1` (common for normalized floats like drop rates).
    /// The slider still shows `0..=100` for ergonomics; we multiply by 100 on
    /// display and divide on write.
    Unit,
}

/// Heuristic: which percent style does this field use?
///
/// Returns `Some(Hundred)` for `*percent*` / `*percentage*` fields,
/// `Some(Unit)` for `*rate*` fields (most common in Crimson's drop tables),
/// and `None` otherwise.
fn percent_kind_for(field_name: &str) -> Option<PercentKind> {
    let plain = normalize_field_name(field_name).replace('_', "");
    if plain.contains("percentage") || plain.contains("percent") {
        return Some(PercentKind::Hundred);
    }
    if plain.contains("rate") {
        return Some(PercentKind::Unit);
    }
    None
}

/// Render a `0..=100` slider for an integer percent-style field. Returns the
/// new value when the user dragged it this frame.
///
/// The slider is wrapped in an `ui.push_id` so multiple percent-style fields
/// in the same panel don't collide on the global widget id.
fn render_pct_slider_int(
    ui: &mut egui::Ui,
    path: &str,
    initial: i64,
    _kind: PercentKind,
) -> Option<i64> {
    let mut new_value: Option<i64> = None;
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        let mut v = initial.clamp(0, 100);
        let resp = ui
            .push_id(("fp_pct_slider_i", path), |ui| {
                ui.add(
                    egui::Slider::new(&mut v, 0..=100)
                        .text("%")
                        .clamping(egui::SliderClamping::Never),
                )
            })
            .inner;
        if resp.changed() {
            new_value = Some(v);
        }
    });
    new_value
}

/// Render a `0..=100` slider for a float percent-style field. For the `Unit`
/// variant we display in `0..=100` while the underlying storage stays in
/// `0..=1` (common for rate fields).
fn render_pct_slider_float(
    ui: &mut egui::Ui,
    path: &str,
    initial: f64,
    kind: PercentKind,
) -> Option<f64> {
    let mut new_value: Option<f64> = None;
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        match kind {
            PercentKind::Hundred => {
                let mut v = initial;
                let resp = ui
                    .push_id(("fp_pct_slider_f100", path), |ui| {
                        ui.add(
                            egui::Slider::new(&mut v, 0.0..=100.0)
                                .text("%")
                                .clamping(egui::SliderClamping::Never),
                        )
                    })
                    .inner;
                if resp.changed() {
                    new_value = Some(v);
                }
            }
            PercentKind::Unit => {
                let mut display = initial * 100.0;
                let resp = ui
                    .push_id(("fp_pct_slider_funit", path), |ui| {
                        ui.add(
                            egui::Slider::new(&mut display, 0.0..=100.0)
                                .text("% (x100)")
                                .clamping(egui::SliderClamping::Never),
                        )
                    })
                    .inner;
                if resp.changed() {
                    new_value = Some(display / 100.0);
                }
            }
        }
    });
    new_value
}

/// Heuristic: does `field_name` + `value` look like a hash/key?
///
/// Triggers on:
///   - Field names ending in `_hash` / `_key` (handles `name_hash`,
///     `string_key_hash`, etc.).
///   - Top-bit-set u32 values: `0x80000000`..=`0xFFFFFFFF`. Counters never get
///     this large in practice; Jenkins hashes routinely do.
///   - Any value larger than a u32. Crimson hash inputs are u32-wide but the
///     blob runtime sometimes stores them as u64 — better to display in hex
///     for those rather than as 10+ digit decimals.
fn looks_like_hash(field_name: &str, value: i64, unsigned_origin: bool) -> bool {
    let plain = normalize_field_name(field_name).replace('_', "");
    if plain.ends_with("hash") || plain.ends_with("key") {
        return true;
    }
    if !unsigned_origin {
        return false;
    }
    let u = value as u64;
    if u > 0x7FFF_FFFF && u <= 0xFFFF_FFFF {
        return true;
    }
    if u > 0x0000_0000_FFFF_FFFF {
        return true;
    }
    false
}

/// Parse a string as either hex (`0x...`) or decimal. Returns `None` on
/// unparseable input so callers can leave the field unchanged rather than
/// zero-stomping it.
fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).ok()
    } else {
        lower.parse::<u64>().ok()
    }
}

/// Decide which bit-width grid (currently always 32 when matched) to render.
/// Returns `None` when the field name doesn't look like a bitmask.
///
/// We match on the lowercased raw name (with underscores stripped) rather than
/// `normalize_field_name`'s output because the normalizer drops a trailing
/// `s`, which would turn `flags` into `flag` and miss the obvious case.
fn bitmask_kind_for(field_name: &str) -> Option<u32> {
    // Take the leaf segment so dotted parents (`foo.flags`) still match.
    let last = field_name.rsplit('.').next().unwrap_or(field_name);
    let plain = last
        .trim_start_matches('_')
        .to_ascii_lowercase()
        .replace('_', "");
    if plain.contains("flag")
        || plain.contains("bitmask")
        || plain.contains("bitfield")
        || plain.ends_with("mask")
        || plain.contains("bits")
    {
        // 32-bit grid covers virtually every flag field in the game data.
        // Larger fields can still be edited via DragValue/hex above; the grid
        // just covers the low 32 bits.
        return Some(32);
    }
    None
}

/// Render a row-by-row checkbox grid for the low `width` bits of `value`.
/// Returns the new value when any bit was toggled this frame. Wrapped in a
/// CollapsingHeader so the grid doesn't dominate dense field panels by
/// default.
fn render_bitmask_grid(
    ui: &mut egui::Ui,
    path: &str,
    value: i64,
    width: u32,
) -> Option<i64> {
    let mut current = value as u64;
    let mut changed = false;
    let cols = 8u32;

    let collapse_id = ui.make_persistent_id(("fp_bits", path));
    let header = format!("Bits ({} of {})", current.count_ones(), width);
    egui::CollapsingHeader::new(header)
        .id_salt(collapse_id)
        .show(ui, |ui| {
            egui::Grid::new(("fp_bits_grid", path))
                .num_columns(cols as usize)
                .spacing([4.0, 2.0])
                .show(ui, |ui| {
                    for bit in 0..width {
                        let mask: u64 = 1u64 << bit;
                        let mut on = (current & mask) != 0;
                        let label = format!("B{:02}", bit);
                        if ui.checkbox(&mut on, label).changed() {
                            if on {
                                current |= mask;
                            } else {
                                current &= !mask;
                            }
                            changed = true;
                        }
                        if (bit + 1) % cols == 0 {
                            ui.end_row();
                        }
                    }
                });
        });

    if changed {
        Some(current as i64)
    } else {
        None
    }
}

/// Searchable dropdown picker for hash fields with a known dispatch target.
/// The popup shows up to 500 `(name, key)` rows from the catalog section,
/// filtered by the user's search query. Clicking a row commits its key to
/// the field; the surrounding DragValue/hex input still accepts arbitrary
/// raw values.
fn show_hash_dropdown(
    ui: &mut egui::Ui,
    catalog: &Catalog,
    target_dispatch: &str,
    path: &str,
    current_value: i64,
) -> Option<i64> {
    let popup_id = ui.make_persistent_id(("fp_dropdown", path));
    let response = ui
        .small_button("v")
        .on_hover_text(format!("Pick from {}", target_dispatch));

    if response.clicked() {
        ui.memory_mut(|m| m.toggle_popup(popup_id));
    }

    let mut picked: Option<i64> = None;

    egui::popup::popup_below_widget(
        ui,
        popup_id,
        &response,
        egui::PopupCloseBehavior::CloseOnClickOutside,
        |ui| {
            ui.set_min_width(320.0);
            ui.set_max_height(360.0);

            // The STRING dispatch isn't backed by a single catalog section,
            // so we show a hint instead of an empty list.
            if target_dispatch == "STRING" {
                ui.label(
                    egui::RichText::new("String hashes: type the value directly")
                        .italics(),
                );
                return;
            }

            // Persist the search query per field path.
            let search_id = ui.make_persistent_id(("fp_dropdown_search", path));
            let mut query: String = ui.memory_mut(|m| {
                m.data.get_temp::<String>(search_id).unwrap_or_default()
            });
            let resp = ui.add(
                egui::TextEdit::singleline(&mut query)
                    .desired_width(300.0)
                    .hint_text("Search..."),
            );
            if resp.changed() {
                ui.memory_mut(|m| m.data.insert_temp(search_id, query.clone()));
            }

            ui.label(
                egui::RichText::new(format!("Current: {}", current_value)).weak(),
            );
            ui.separator();

            // Resolve the catalog section for this dispatch.
            let Some(section_name) = catalog.dispatch_to_section.get(target_dispatch) else {
                ui.label("No section mapped for this dispatch.");
                return;
            };
            let Some(entries) = catalog.sections.get(section_name) else {
                ui.label(format!("Section '{}' not loaded.", section_name));
                return;
            };

            let lower_query = query.trim().to_lowercase();
            let mut hits: Vec<(&str, u64, &str)> = entries
                .iter()
                .filter_map(|(key_str, val)| {
                    let key: u64 = key_str.parse().ok()?;
                    let name = val.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if !lower_query.is_empty() {
                        let in_name = name.to_lowercase().contains(&lower_query);
                        let in_key = key_str.contains(&lower_query);
                        if !in_name && !in_key {
                            return None;
                        }
                    }
                    Some((name, key, key_str.as_str()))
                })
                .collect();
            hits.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));

            const ROW_CAP: usize = 500;
            let total_hits = hits.len();
            let truncated = total_hits > ROW_CAP;
            if truncated {
                hits.truncate(ROW_CAP);
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(300.0)
                .show(ui, |ui| {
                    if hits.is_empty() {
                        ui.label("(no matches)");
                        return;
                    }
                    for (name, key, key_str) in &hits {
                        let display = if name.is_empty() {
                            format!("(unnamed) [{}]", key_str)
                        } else {
                            format!("{} [{}]", name, key_str)
                        };
                        let selected = *key as i64 == current_value;
                        if ui.selectable_label(selected, display).clicked() {
                            picked = Some(*key as i64);
                            ui.memory_mut(|m| m.close_popup());
                        }
                    }
                    if truncated {
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!(
                                "{} more, refine search...",
                                total_hits - ROW_CAP
                            ))
                            .weak(),
                        );
                    }
                });
        },
    );

    picked
}

// ---- Color picker -------------------------------------------------------

/// Field-name heuristic: matches `*color*`, `*colour*`, `*tint*`, `*rgb*`,
/// `*rgba*`. Used as a positive signal for color pickers.
fn field_looks_like_color(field_name: &str) -> bool {
    let plain = normalize_field_name(field_name).replace('_', "");
    plain.contains("color")
        || plain.contains("colour")
        || plain.contains("tint")
        || plain.contains("rgba")
        || plain.contains("rgb")
}

/// Decide whether `arr` should render as a color picker. Both the field name
/// and the array shape have to look color-like (3 or 4 finite numeric
/// channels) to avoid accidentally promoting unrelated `[x, y, z]` fields.
fn is_color_array(field_name: &str, arr: &[Value]) -> bool {
    if !field_looks_like_color(field_name) {
        return false;
    }
    if arr.len() != 3 && arr.len() != 4 {
        return false;
    }
    arr.iter().all(|v| v.as_f64().is_some_and(|f| f.is_finite()))
}

/// Same idea as [`is_color_array`] but for objects with `r/g/b[/a]` fields.
fn is_color_object(field_name: &str, obj: &serde_json::Map<String, Value>) -> bool {
    if !field_looks_like_color(field_name) {
        return false;
    }
    let has_rgb = obj
        .iter()
        .filter(|(k, _)| {
            matches!(
                k.as_str(),
                "r" | "g" | "b" | "R" | "G" | "B" | "red" | "green" | "blue"
            )
        })
        .count()
        >= 3;
    has_rgb && obj.values().all(|v| v.as_f64().is_some_and(|f| f.is_finite()))
}

/// Render a color picker for a 3- or 4-element numeric array. Returns the
/// replacement array (preserving int-vs-float and 0-255-vs-0-1 conventions of
/// the input) when the user edited the color.
fn render_color_picker_array(
    ui: &mut egui::Ui,
    _path: &str,
    arr: &[Value],
) -> Option<Value> {
    let nums: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
    if nums.len() != arr.len() {
        return None;
    }
    let (r, g, b, a, was_unit_scale) = decode_color_channels(&nums);

    let mut tmp = if arr.len() == 4 {
        egui::Rgba::from_rgba_unmultiplied(r, g, b, a)
    } else {
        egui::Rgba::from_rgb(r, g, b)
    };

    let alpha = if arr.len() == 4 {
        egui::color_picker::Alpha::OnlyBlend
    } else {
        egui::color_picker::Alpha::Opaque
    };
    let resp = egui::color_picker::color_edit_button_rgba(ui, &mut tmp, alpha);

    if was_unit_scale {
        ui.label(egui::RichText::new("(0..1)").weak());
    } else {
        ui.label(egui::RichText::new("(0..255)").weak());
    }

    if !resp.changed() {
        return None;
    }

    // Re-emit the array in the original scale and number type per channel.
    let channels = [tmp[0], tmp[1], tmp[2], tmp[3]];
    let out: Vec<Value> = arr
        .iter()
        .enumerate()
        .map(|(i, original)| {
            let v = channels[i.min(3)];
            let scaled = if was_unit_scale {
                v as f64
            } else {
                (v * 255.0).round().clamp(0.0, 255.0) as f64
            };
            if original.is_i64() || original.is_u64() {
                Value::from(scaled as i64)
            } else {
                serde_json::Number::from_f64(scaled)
                    .map(Value::Number)
                    .unwrap_or_else(|| original.clone())
            }
        })
        .collect();

    Some(Value::Array(out))
}

/// Render a color picker for an `{r, g, b[, a]}` object. Returns the replacement
/// object when the user edited the color, preserving the int-vs-float and
/// 0-255-vs-0-1 conventions of the source.
fn render_color_picker_object(
    ui: &mut egui::Ui,
    _path: &str,
    obj: &serde_json::Map<String, Value>,
) -> Option<Value> {
    let r_v = pick_channel(obj, &["r", "R", "red"])?;
    let g_v = pick_channel(obj, &["g", "G", "green"])?;
    let b_v = pick_channel(obj, &["b", "B", "blue"])?;
    let a_v = pick_channel(obj, &["a", "A", "alpha"]);
    let mut nums = vec![r_v, g_v, b_v];
    if let Some(a) = a_v {
        nums.push(a);
    }

    let (r, g, b, a, was_unit_scale) = decode_color_channels(&nums);

    let mut tmp = egui::Rgba::from_rgba_unmultiplied(r, g, b, a);
    let alpha = if a_v.is_some() {
        egui::color_picker::Alpha::OnlyBlend
    } else {
        egui::color_picker::Alpha::Opaque
    };
    let resp = egui::color_picker::color_edit_button_rgba(ui, &mut tmp, alpha);
    if was_unit_scale {
        ui.label(egui::RichText::new("(0..1)").weak());
    } else {
        ui.label(egui::RichText::new("(0..255)").weak());
    }

    if !resp.changed() {
        return None;
    }

    let mut out = obj.clone();
    write_channel(&mut out, &["r", "R", "red"], tmp[0], was_unit_scale);
    write_channel(&mut out, &["g", "G", "green"], tmp[1], was_unit_scale);
    write_channel(&mut out, &["b", "B", "blue"], tmp[2], was_unit_scale);
    if a_v.is_some() {
        write_channel(&mut out, &["a", "A", "alpha"], tmp[3], was_unit_scale);
    }
    Some(Value::Object(out))
}

/// Look up the first present channel value across a list of plausible names.
/// Used to support both short (`r`) and long (`red`) color-channel keys
/// without requiring the caller to pre-canonicalize.
fn pick_channel(
    obj: &serde_json::Map<String, Value>,
    names: &[&str],
) -> Option<f64> {
    for n in names {
        if let Some(v) = obj.get(*n).and_then(|v| v.as_f64()) {
            return Some(v);
        }
    }
    None
}

/// Inverse of [`pick_channel`]: write the new channel value back into the
/// first slot whose key appears in `obj`. Preserves int-vs-float and the
/// 0-255-vs-0-1 scale of the original entry.
fn write_channel(
    obj: &mut serde_json::Map<String, Value>,
    names: &[&str],
    new_unit: f32,
    was_unit_scale: bool,
) {
    for n in names {
        if obj.contains_key(*n) {
            let original = obj.get(*n).cloned().unwrap_or(Value::Null);
            let scaled: f64 = if was_unit_scale {
                new_unit as f64
            } else {
                (new_unit * 255.0).round().clamp(0.0, 255.0) as f64
            };
            let next = if original.is_i64() || original.is_u64() {
                Value::from(scaled as i64)
            } else {
                serde_json::Number::from_f64(scaled)
                    .map(Value::Number)
                    .unwrap_or(original)
            };
            obj.insert((*n).to_string(), next);
            return;
        }
    }
}

/// Decode a list of 3 or 4 numeric channels into normalized `(r, g, b, a)`
/// f32 RGBA. Returns `was_unit_scale` so callers can re-emit values in the
/// original convention. The scale is detected by inspecting the max channel:
/// anything `<= 1.0` is treated as unit-normalized, anything larger is treated
/// as `0..=255`.
fn decode_color_channels(nums: &[f64]) -> (f32, f32, f32, f32, bool) {
    let max = nums.iter().fold(0.0f64, |m, v| m.max(*v));
    let was_unit_scale = max <= 1.0;
    let div = if was_unit_scale { 1.0 } else { 255.0 };
    let r = (nums.first().copied().unwrap_or(0.0) / div) as f32;
    let g = (nums.get(1).copied().unwrap_or(0.0) / div) as f32;
    let b = (nums.get(2).copied().unwrap_or(0.0) / div) as f32;
    let a = (nums.get(3).copied().unwrap_or(div) / div) as f32;
    (r, g, b, a, was_unit_scale)
}

/// Recursive value comparison used for highlighting parent containers when
/// any leaf inside differs. `serde_json::Value` already implements `PartialEq`
/// recursively, so this is just `!=` — kept as a named function so the intent
/// at call sites is obvious.
fn values_differ_recursive(a: &Value, b: &Value) -> bool {
    a != b
}

/// Format a vanilla container value compactly for tooltip display.
fn pretty_vanilla_summary(v: &Value) -> String {
    let raw = serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string());
    let mut out = String::from("Vanilla:\n");
    for (i, line) in raw.lines().enumerate() {
        if i >= 12 {
            out.push_str("...");
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// If `field_name`+`value` look like a reference to another table, render the
/// resolved name inline in dim text with a hover preview.
///
/// For STRING-targeted fields we consult `localization` *first* (the
/// freshly-extracted EN+KR maps) and fall back to the catalog's
/// `lookup_string` only when no live entry exists. This means raw saves
/// dragged in from older catalog snapshots still resolve as long as the
/// localization cache covers the hash.
///
/// When `localization` returns both EN and KR for the same hash, the English
/// string is shown inline and Korean lands in the hover tooltip — useful for
/// authors cross-referencing two languages without flipping panels.
fn annotate_reference(
    ui: &mut egui::Ui,
    field_name: &str,
    value: i64,
    catalog: Option<&Catalog>,
    localization: Option<&Localization>,
) {
    let Some(target) = target_for_field(field_name) else { return };

    let resolved: Option<(String, Option<String>)> = match target {
        "STRING" => {
            // Strings use 32-bit hashes in pabgb tables, but the paloc
            // `unk_id` column is u64 — use u32 for the catalog path (which
            // is the legacy code path) and u64 for the localization path
            // (which is the canonical source).
            if value < 0 {
                None
            } else {
                let hash_u64 = value as u64;
                let (eng, kor) = match localization {
                    Some(loc) => loc.lookup_pair(hash_u64),
                    None => (None, None),
                };
                match (eng, kor) {
                    (Some(en), Some(kr)) => Some((
                        en.to_string(),
                        Some(format!("EN: {}\nKR: {}", en, kr)),
                    )),
                    (Some(en), None) => Some((en.to_string(), None)),
                    (None, Some(kr)) => {
                        // English missing but Korean is available — show the
                        // Korean string inline so authors aren't left
                        // staring at a raw hash. Tooltip clarifies which
                        // language it came from.
                        Some((kr.to_string(), Some(format!("KR: {}", kr))))
                    }
                    (None, None) => {
                        // Final fallback: the catalog's PALOC-derived
                        // `lookup_string` — only useful when the catalog was
                        // built with localization joined in, but cheap to
                        // try and harmless when it isn't.
                        if value > u32::MAX as i64 {
                            None
                        } else {
                            catalog.and_then(|c| c.lookup_string(value as u32))
                                .filter(|s| !s.is_empty())
                                .map(|s| (s.to_string(), None))
                        }
                    }
                }
            }
        }
        dispatch => {
            let Some(catalog) = catalog else { return };
            if value < 0 {
                None
            } else {
                let key = value as u64;
                catalog.lookup_name_for_dispatch(dispatch, key).map(|name| {
                    let preview = catalog
                        .dispatch_to_section
                        .get(dispatch)
                        .and_then(|section| catalog.sections.get(section))
                        .and_then(|entries| entries.get(&key.to_string()))
                        .map(|entry| truncate_lines(&serde_json::to_string_pretty(entry)
                            .unwrap_or_default(), 10));
                    (name.to_string(), preview)
                })
            }
        }
    };

    if let Some((name, preview)) = resolved {
        let label = ui.label(
            egui::RichText::new(name).color(egui::Color32::from_gray(140)),
        );
        if let Some(preview_text) = preview {
            label.on_hover_text(preview_text);
        }
    }
}

/// Find the target dispatch table (or "STRING") for a field name.
///
/// The match is suffix-based on a normalized form of the name so it works
/// for plain fields (`gimmick_info`), dotted contexts (`foo.gimmick_info`),
/// list elements (`gimmick_info[3]`), and pluralised list parents
/// (`equip_passive_skill_list`).
fn target_for_field(field_name: &str) -> Option<&'static str> {
    let normalized = normalize_field_name(field_name);
    for (suffix, target) in FIELD_TARGETS {
        if normalized == *suffix || normalized.ends_with(&format!("_{}", suffix))
            || normalized.ends_with(*suffix)
        {
            return Some(*target);
        }
    }
    None
}

/// Strip leading underscores, trailing `[N]` index suffixes, and trailing
/// `_list` / pluralising `s` so list parents resolve to their element table.
fn normalize_field_name(field_name: &str) -> String {
    // Take the part after the last `.` to ignore parent-object prefixes.
    let last = field_name.rsplit('.').next().unwrap_or(field_name);
    let mut name = last.trim_start_matches('_').to_lowercase();
    // Trim trailing array indexer like `[3]`.
    if let Some(open) = name.rfind('[') {
        if name.ends_with(']') {
            name.truncate(open);
        }
    }
    // Drop a trailing `_list` so `_buff_list` matches `buff`.
    if let Some(stripped) = name.strip_suffix("_list") {
        name = stripped.to_string();
    }
    // For lists where each element is a key, the parent is often plural
    // (`skills`, `buffs`). Drop a trailing `s` so list parents like
    // `skills` become `skill` and match a FIELD_TARGETS key. Safe because
    // every FIELD_TARGETS key already ends with `_info` (or is `STRING`),
    // never with `s`.
    if name.ends_with('s') && name.len() > 1 {
        name.pop();
    }
    name
}

/// Truncate a multi-line string to at most `max_lines` lines, appending a
/// trailing ellipsis line when content was dropped.
fn truncate_lines(s: &str, max_lines: usize) -> String {
    let mut out = String::new();
    for (i, line) in s.lines().enumerate() {
        if i >= max_lines {
            out.push_str("...\n");
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_strips_underscores_and_index() {
        assert_eq!(normalize_field_name("_skill"), "skill");
        assert_eq!(normalize_field_name("foo.gimmick_info"), "gimmick_info");
        assert_eq!(normalize_field_name("_buff_list[3]"), "buff");
        assert_eq!(normalize_field_name("skills"), "skill");
    }

    #[test]
    fn target_for_known_fields() {
        assert_eq!(target_for_field("gimmick_info"), Some("gimmick_info"));
        assert_eq!(target_for_field("_skill_key"), Some("skill_info"));
        assert_eq!(target_for_field("name_id"), Some("STRING"));
        assert_eq!(target_for_field("equip_passive_skill_list[2]"), Some("skill_info"));
        assert_eq!(target_for_field("hp"), None);
    }

    #[test]
    fn truncate_lines_keeps_first_n() {
        let s = "a\nb\nc\nd\ne\nf\n";
        let t = truncate_lines(s, 3);
        // First three lines plus the trailing ellipsis line.
        assert!(t.starts_with("a\nb\nc\n"));
        assert!(t.contains("..."));
    }

    #[test]
    fn values_differ_recursive_is_a_real_function() {
        assert!(values_differ_recursive(&json!(1), &json!(2)));
        assert!(values_differ_recursive(
            &json!({"a": [1, 2]}),
            &json!({"a": [1, 3]})
        ));
        assert!(!values_differ_recursive(&json!({"a": 1}), &json!({"a": 1})));
    }

    #[test]
    fn pretty_vanilla_summary_includes_marker_and_truncates() {
        let v = json!({
            "a": 1, "b": 2, "c": 3, "d": 4, "e": 5,
            "f": 6, "g": 7, "h": 8, "i": 9, "j": 10,
            "k": 11, "l": 12, "m": 13, "n": 14, "o": 15,
        });
        let s = pretty_vanilla_summary(&v);
        assert!(s.starts_with("Vanilla:\n"));
        assert!(s.contains("..."));
    }

    // ---- Smart-editor heuristics ----------------------------------------

    #[test]
    fn percent_kind_detects_common_names() {
        assert_eq!(percent_kind_for("drop_rate"), Some(PercentKind::Unit));
        assert_eq!(percent_kind_for("loot_percent"), Some(PercentKind::Hundred));
        assert_eq!(percent_kind_for("percentage"), Some(PercentKind::Hundred));
        assert!(percent_kind_for("hp").is_none());
        assert!(percent_kind_for("price").is_none());
    }

    #[test]
    fn bitmask_kind_detects_flags_mask_bits() {
        assert_eq!(bitmask_kind_for("flags"), Some(32));
        assert_eq!(bitmask_kind_for("equip_mask"), Some(32));
        assert_eq!(bitmask_kind_for("status_bits"), Some(32));
        assert_eq!(bitmask_kind_for("bitmask_extra"), Some(32));
        assert!(bitmask_kind_for("hp").is_none());
        assert!(bitmask_kind_for("name").is_none());
    }

    #[test]
    fn looks_like_hash_triggers_on_suffixes() {
        assert!(looks_like_hash("name_hash", 0, true));
        assert!(looks_like_hash("string_key", 0, true));
        assert!(looks_like_hash("buff_key", 100, true));
        assert!(!looks_like_hash("hp", 100, true));
        assert!(!looks_like_hash("level", -1, false));
    }

    #[test]
    fn looks_like_hash_triggers_on_large_unsigned() {
        assert!(looks_like_hash("foo", 0xC000_0000, true));
        assert!(looks_like_hash("foo", 0x1_0000_0000, true));
        // Negative i64 should not trigger when the source wasn't unsigned.
        assert!(!looks_like_hash("foo", -1, false));
    }

    #[test]
    fn field_looks_like_color_matches() {
        assert!(field_looks_like_color("base_color"));
        assert!(field_looks_like_color("tintColor"));
        assert!(field_looks_like_color("rgba"));
        assert!(!field_looks_like_color("hp"));
        assert!(!field_looks_like_color("price"));
    }

    #[test]
    fn is_color_array_requires_name_and_shape() {
        let three = vec![Value::from(255), Value::from(128), Value::from(0)];
        let four = vec![
            Value::from(0.5),
            Value::from(0.25),
            Value::from(0.0),
            Value::from(1.0),
        ];
        let two = vec![Value::from(1), Value::from(2)];
        // Field name matches color, shape matches.
        assert!(is_color_array("tint_color", &three));
        assert!(is_color_array("tint_color", &four));
        // Shape matches but name doesn't — pure position vectors etc.
        assert!(!is_color_array("position", &three));
        // Name matches but shape doesn't.
        assert!(!is_color_array("color", &two));
    }

    #[test]
    fn is_color_object_recognizes_rgb_and_rgba() {
        let mut rgb = serde_json::Map::new();
        rgb.insert("r".to_string(), Value::from(0));
        rgb.insert("g".to_string(), Value::from(0));
        rgb.insert("b".to_string(), Value::from(0));
        assert!(is_color_object("base_color", &rgb));

        let mut weird = serde_json::Map::new();
        weird.insert("x".to_string(), Value::from(1));
        weird.insert("y".to_string(), Value::from(2));
        weird.insert("z".to_string(), Value::from(3));
        assert!(!is_color_object("tint", &weird));
    }

    #[test]
    fn decode_color_unit_vs_byte_scale() {
        let unit = decode_color_channels(&[0.5, 0.25, 0.0]);
        assert!(unit.4); // was_unit_scale
        assert_eq!(unit.0, 0.5);
        let byte = decode_color_channels(&[255.0, 128.0, 0.0]);
        assert!(!byte.4);
        assert!((byte.0 - 1.0).abs() < 1e-3);
    }

    #[test]
    fn parse_hex_or_dec_basics() {
        assert_eq!(parse_hex_or_dec("0xFF"), Some(0xFF));
        assert_eq!(parse_hex_or_dec("0X10"), Some(16));
        assert_eq!(parse_hex_or_dec("100"), Some(100));
        assert_eq!(parse_hex_or_dec("0xffff_zz"), None);
        assert_eq!(parse_hex_or_dec(""), None);
    }
}
