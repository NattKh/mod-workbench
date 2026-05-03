use std::time::{Duration, Instant};

use egui_extras::{Column, TableBuilder};
use serde_json::Value;

use crate::mod_io::extract_entry_key;
use crate::state::AppState;

/// How long the search input must be idle before we re-run the (potentially
/// expensive) filter pass. With ~50k entries and catalog lookups this matters.
const FILTER_DEBOUNCE: Duration = Duration::from_millis(200);

/// Cap on recursion depth when walking nested entry values for substring
/// matches. Prevents pathological catalog-derived structures from blowing up
/// the filter.
const MAX_RECURSION_DEPTH: u32 = 5;

/// Center panel: scrollable entry table with virtualized rows.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    if state.active_table().is_none() {
        ui.centered_and_justified(|ui| {
            ui.label("Select a table from the left panel");
        });
        return;
    }

    // Loading / error states are rendered before any of the search-bar /
    // table machinery so the user gets a clear "what's happening" view
    // even before entries exist.
    {
        let active = state.active_table().unwrap();
        match &active.load_state {
            crate::state::LoadState::Loading => {
                let name = active.dispatch_name.clone();
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.heading(format!("Loading {}...", name));
                    ui.label("Reading PAZ archive and parsing entries on a worker thread.");
                    ui.label("This tab will fill in automatically when the load completes.");
                    ui.add_space(8.0);
                    ui.spinner();
                });
                ui.ctx().request_repaint_after(Duration::from_millis(150));
                return;
            }
            crate::state::LoadState::Error(msg) => {
                let name = active.dispatch_name.clone();
                let msg = msg.clone();
                let mut want_retry = false;
                let mut want_close = false;
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.heading(
                        egui::RichText::new(format!("Failed to load {}", name))
                            .color(egui::Color32::from_rgb(230, 80, 80)),
                    );
                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.set_max_width(700.0);
                        ui.label(
                            egui::RichText::new("Parser error:")
                                .strong(),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&msg).monospace(),
                            )
                            .wrap()
                            .selectable(true),
                        );
                    });
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(
                            "Most likely cause: the parser was last updated for game v1.0.5 \
                             but this table changed in the 2026-5-1 patch. The fix is in \
                             dmm-parser PR #11 (still open upstream). Other tables that \
                             didn't change in the patch should still load fine.",
                        )
                        .color(egui::Color32::from_gray(160))
                        .small(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔄 Retry").clicked() {
                            want_retry = true;
                        }
                        if ui.button("✖ Close tab").clicked() {
                            want_close = true;
                        }
                    });
                });
                if want_retry {
                    // Resubmit by closing the error tab and calling submit_load.
                    let active_idx = state.active_tab_idx;
                    if let Some(idx) = active_idx {
                        state.close_tab(idx);
                    }
                    let table_idx = state
                        .tables
                        .iter()
                        .position(|m| m.dispatch_name == name);
                    if let Some(t_idx) = table_idx {
                        crate::ui::table_list::submit_load(state, t_idx);
                    }
                }
                if want_close {
                    if let Some(idx) = state.active_tab_idx {
                        state.close_tab(idx);
                    }
                }
                return;
            }
            crate::state::LoadState::Loaded => {
                // fall through to the regular table renderer below
            }
        }
    }

    // ---- Search bar -------------------------------------------------------
    //
    // Splits into an editable text input plus an inline "X" clear button when
    // a filter is active, followed by a result-count summary.
    //
    // The TextEdit carries a stable id_salt ("entry_search") so the keyboard
    // shortcut handler in `app.rs` can call `ui.memory_mut(|m| m.request_focus(id))`
    // and pop focus into the field when the user presses `F`.
    let mut clear_filter = false;
    let search_focus_requested = std::mem::take(&mut state.entry_search_focus_pending);
    ui.horizontal(|ui| {
        ui.label("Search:");
        let search_id = ui.make_persistent_id("entry_search");
        let response = ui.add(
            egui::TextEdit::singleline(&mut state.entry_filter)
                .id(search_id)
                .desired_width(260.0)
                .hint_text("key, name, or any field..."),
        );
        if search_focus_requested {
            response.request_focus();
        }
        if !state.entry_filter.is_empty() {
            // Compact "X" so the clear button doesn't dominate the row.
            if ui
                .small_button("X")
                .on_hover_text("Clear search")
                .clicked()
            {
                clear_filter = true;
            }
        }

        let active_ref = state.active_table().unwrap();
        let total = active_ref.entries.len();
        if state.entry_filter.is_empty() {
            ui.label(format!("{} entries", total));
        } else {
            ui.label(format!(
                "{} of {} entries",
                active_ref.filtered_indices.len(),
                total
            ));
        }
    });
    if clear_filter {
        state.entry_filter.clear();
    }
    ui.separator();

    // ---- Debounced filter recomputation -----------------------------------
    //
    // We track `last_filter` on the ActiveTable. When the live filter differs,
    // bump `last_filter_change` and request a repaint after the debounce so
    // the filter actually fires even if the user stops typing without moving
    // the mouse. The actual recomputation only runs once the input has been
    // idle for `FILTER_DEBOUNCE`.
    let entry_filter_snapshot = state.entry_filter.clone();
    let active = state.active_table_mut().unwrap();
    let now = Instant::now();
    if active.last_filter != entry_filter_snapshot {
        active.last_filter_change = now;
    }

    let filter_dirty = active.last_filter != entry_filter_snapshot;
    let debounce_elapsed = now.duration_since(active.last_filter_change) >= FILTER_DEBOUNCE;
    if filter_dirty && debounce_elapsed {
        recompute_filter(state);
    } else if filter_dirty {
        // Schedule a repaint at the moment the debounce window closes so the
        // filter result lands without the user nudging the UI.
        let active = state.active_table().unwrap();
        let remaining = FILTER_DEBOUNCE
            .checked_sub(now.duration_since(active.last_filter_change))
            .unwrap_or_default();
        ui.ctx().request_repaint_after(remaining);
    }

    // ---- F3: advance to next filtered match -------------------------------
    //
    // The keyboard shortcut handler flips `entry_search_advance_pending` when
    // the user hits F3. We translate that into "move the selection to the
    // next filtered index", wrapping around at the end so repeatedly pressing
    // F3 cycles through every match.
    if std::mem::take(&mut state.entry_search_advance_pending) {
        if let Some(active) = state.active_table_mut() {
            let visible = &active.filtered_indices;
            if !visible.is_empty() {
                // Locate the current selection within the filtered list (if
                // any), then advance by one with wrap-around. Selection
                // outside the filtered set is treated as "before the first
                // match" so the next match is index 0.
                let next_pos = match active.selected_entry_idx {
                    Some(sel) => match visible.iter().position(|&i| i == sel) {
                        Some(p) => (p + 1) % visible.len(),
                        None => 0,
                    },
                    None => 0,
                };
                active.selected_entry_idx = Some(visible[next_pos]);
            }
        }
    }

    // ---- Render the filtered rows -----------------------------------------
    //
    // From here on we only need an immutable borrow of state, so re-bind it.
    let active = state.active_table().unwrap();
    let columns = &active.column_names;
    let visible_indices = &active.filtered_indices;
    let table_name = active.dispatch_name.clone();
    // Borrow the note store up front so the per-row closure can check
    // membership without re-borrowing `state` for every cell.
    let notes = &state.notes;

    let mut clicked_idx: Option<usize> = None;

    let row_height = 20.0;

    let mut table = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));

    // Add columns
    for _col_name in columns {
        table = table.column(Column::auto().at_least(60.0).clip(true));
    }

    table
        .header(22.0, |mut header| {
            for col_name in columns {
                header.col(|ui| {
                    ui.strong(col_name);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, visible_indices.len(), |mut row| {
                let visible_row_idx = row.index();
                let entry_idx = visible_indices[visible_row_idx];
                let entry = &active.entries[entry_idx];
                let entry_key = extract_entry_key(entry);
                let is_selected = active.selected_entry_idx == Some(entry_idx);
                let is_modified = active.changes.is_entry_modified(entry_key);
                // Whether this row has a user-authored note attached.
                // Looked up once per row instead of per cell because the
                // marker only appears in the first column.
                let has_note = notes.get(&table_name, entry_key).is_some();

                for (col_idx, col_name) in columns.iter().enumerate() {
                    row.col(|ui| {
                        // Prefix the first column with a small 📝 when the
                        // row has a note, so users can spot annotated
                        // entries while skimming. Subsequent columns stay
                        // unchanged so the table stays well-aligned.
                        let raw_text = format_cell_value(entry, col_name);
                        let text = if col_idx == 0 && has_note {
                            format!("\u{1F4DD} {}", raw_text)
                        } else {
                            raw_text
                        };

                        let label = if is_modified {
                            egui::RichText::new(&text).color(egui::Color32::from_rgb(255, 180, 50))
                        } else if is_selected {
                            egui::RichText::new(&text).color(egui::Color32::from_rgb(100, 200, 255))
                        } else {
                            egui::RichText::new(&text)
                        };

                        let response = ui.selectable_label(is_selected, label);
                        if has_note && col_idx == 0 {
                            response
                                .clone()
                                .on_hover_text("This entry has a note (open it in the Fields panel)");
                        }
                        if response.clicked() {
                            clicked_idx = Some(entry_idx);
                        }
                    });
                }
            });
        });

    // Handle click outside the table borrow
    if let Some(idx) = clicked_idx {
        if let Some(active) = state.active_table_mut() {
            active.selected_entry_idx = Some(idx);
        }
    }
}

/// Format a cell value for display in the table.
fn format_cell_value(entry: &Value, field_name: &str) -> String {
    match entry.get(field_name) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => {
            // Truncate long strings
            if s.len() > 40 {
                format!("{}...", &s[..37])
            } else {
                s.clone()
            }
        }
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Array(a)) => format!("[{} items]", a.len()),
        Some(Value::Object(o)) => format!("{{{} fields}}", o.len()),
        None => "-".to_string(),
    }
}

/// Recompute the active tab's `filtered_indices` against the current filter text.
///
/// Resolves the catalog section once up front, parses the filter as a number
/// once up front, and lowercases the filter string once. Then walks every
/// entry exactly once. The catalog lookup is a HashMap hit; the recursive
/// string walk is depth-limited.
fn recompute_filter(state: &mut AppState) {
    let filter_lower = state.entry_filter.to_lowercase();
    let entry_filter_snapshot = state.entry_filter.clone();
    let filter_as_number = parse_user_number(filter_lower.trim());

    // Resolve the dispatch name to a catalog section (e.g. "item_info" ->
    // "items"). When the catalog isn't loaded we still want all the other
    // criteria to work.
    let dispatch_name = state
        .active_table()
        .map(|t| t.dispatch_name.clone())
        .unwrap_or_default();
    // Resolve the catalog section now and own the result so the catalog
    // borrow doesn't conflict with the upcoming `active_table_mut()`. We
    // can't carry an `&Catalog` across that mutable borrow either, so we
    // collect the matched name lookups eagerly into a side table keyed by
    // entry key.
    let catalog_section: Option<String> = state.catalog.as_ref().and_then(|cat| {
        cat.dispatch_to_section.get(&dispatch_name).cloned()
    });

    // Snapshot per-entry catalog names so the matcher doesn't need to hold a
    // catalog borrow across the upcoming mutable borrow of the active tab.
    //
    // Skip this entirely when the filter is empty — there's nothing to match
    // against, and for 12K-entry tables this saves 12K HashMap lookups +
    // 12K String allocations every time the user clears the search box.
    let name_lookup: std::collections::HashMap<u64, String> = if filter_lower.is_empty() {
        std::collections::HashMap::new()
    } else {
        match (
            catalog_section.as_deref(),
            state.catalog.as_ref(),
            state.active_table(),
        ) {
            (Some(section), Some(cat), Some(active)) => active
                .entries
                .iter()
                .filter_map(|e| {
                    let k = e.get("key").and_then(|v| v.as_u64())?;
                    cat.lookup_name(section, k).map(|n| (k, n.to_string()))
                })
                .collect(),
            _ => std::collections::HashMap::new(),
        }
    };

    // Compute filtered indices using only immutable borrows of `state` so
    // the matcher can read both the entries and the localization tables
    // without conflicting with the active-tab mut borrow we need below.
    //
    // We split into two phases:
    //   1. Read-only: walk every entry, collect matching indices into a
    //      local `Vec<usize>`, all under immutable borrows.
    //   2. Mutable: re-borrow the active tab and install the result + the
    //      filter snapshot.
    let new_indices: Vec<usize> = if filter_lower.is_empty() {
        let active_ro = match state.active_table() {
            Some(a) => a,
            None => return,
        };
        (0..active_ro.entries.len()).collect()
    } else {
        let active_ro = match state.active_table() {
            Some(a) => a,
            None => return,
        };
        let loc_eng = state.localization.as_ref().map(|l| &l.eng);
        let loc_kor = state.localization.as_ref().map(|l| &l.kor);

        let mut out: Vec<usize> =
            Vec::with_capacity(active_ro.entries.len() / 4 + 16);
        for (i, entry) in active_ro.entries.iter().enumerate() {
            if entry_matches_with_lookup(
                entry,
                &filter_lower,
                filter_as_number,
                &name_lookup,
                loc_eng,
                loc_kor,
            ) {
                out.push(i);
            }
        }
        out
    };

    if let Some(active) = state.active_table_mut() {
        active.filtered_indices = new_indices;
        active.last_filter = entry_filter_snapshot;
    }
}

/// Variant of [`entry_matches`] that uses a precomputed `entry_key -> name`
/// lookup map, avoiding the need to hold a catalog borrow across this call.
///
/// `loc_eng` / `loc_kor` are the EN/KR localization HashMaps (keyed by
/// `unk_id` decimal-string). When supplied, the matcher walks every numeric
/// field on the entry, treats each as a potential string-hash, and checks
/// whether the matched localized string contains the filter — letting users
/// search "Pyeonjeon Arrow" and find any pabgb entry that references the
/// English name even when the entry stores only the raw hash.
fn entry_matches_with_lookup(
    entry: &Value,
    filter_lower: &str,
    filter_as_number: Option<u64>,
    name_lookup: &std::collections::HashMap<u64, String>,
    loc_eng: Option<&std::collections::HashMap<String, String>>,
    loc_kor: Option<&std::collections::HashMap<String, String>>,
) -> bool {
    if let Some(target) = filter_as_number {
        if let Some(k) = entry.get("key").and_then(|v| v.as_u64()) {
            if k == target {
                return true;
            }
        }
    }

    if let Some(sk) = entry.get("string_key").and_then(|v| v.as_str()) {
        if sk.to_lowercase().contains(filter_lower) {
            return true;
        }
    }

    if let Some(k) = entry.get("key").and_then(|v| v.as_u64()) {
        if let Some(name) = name_lookup.get(&k) {
            if name.to_lowercase().contains(filter_lower) {
                return true;
            }
        }
    }

    if loc_eng.is_some() || loc_kor.is_some() {
        if walk_localized_match(entry, filter_lower, loc_eng, loc_kor, 0) {
            return true;
        }
    }

    walk_strings_match(entry, filter_lower, 0)
}

/// Recursively walk `value` and return true if any numeric leaf, when looked
/// up in either localization map, matches `filter_lower`.
///
/// Depth-limited the same way [`walk_strings_match`] is. We accept both
/// languages so users can find an entry by typing the English *or* Korean
/// version of a referenced string.
fn walk_localized_match(
    value: &Value,
    filter_lower: &str,
    loc_eng: Option<&std::collections::HashMap<String, String>>,
    loc_kor: Option<&std::collections::HashMap<String, String>>,
    depth: u32,
) -> bool {
    if depth >= MAX_RECURSION_DEPTH {
        return false;
    }
    match value {
        Value::Number(n) => {
            // Try the value as both u64 (paloc unk_id is u64) and u32
            // (legacy hash storage). A u64 narrows back to the same key
            // string when the number fits in u32 anyway, so the dual-key
            // attempt is just defensive.
            let key_u64 = n.as_u64();
            let key_u32 = n.as_u64().filter(|k| *k <= u32::MAX as u64);
            for key in [key_u64, key_u32].into_iter().flatten() {
                let key_str = key.to_string();
                if let Some(en) = loc_eng.and_then(|m| m.get(&key_str)) {
                    if !en.is_empty() && en.to_lowercase().contains(filter_lower) {
                        return true;
                    }
                }
                if let Some(kr) = loc_kor.and_then(|m| m.get(&key_str)) {
                    if !kr.is_empty() && kr.to_lowercase().contains(filter_lower) {
                        return true;
                    }
                }
            }
            false
        }
        Value::Object(map) => map.values().any(|v| {
            walk_localized_match(v, filter_lower, loc_eng, loc_kor, depth + 1)
        }),
        Value::Array(arr) => arr.iter().any(|v| {
            walk_localized_match(v, filter_lower, loc_eng, loc_kor, depth + 1)
        }),
        _ => false,
    }
}

/// Parse the user's input as a numeric key. Accepts plain decimal and
/// `0x`-prefixed hex. Returns `None` on anything else (so the function's
/// callers know to skip the numeric-key check entirely).
fn parse_user_number(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.is_empty() {
            return None;
        }
        return u64::from_str_radix(rest, 16).ok();
    }
    s.parse::<u64>().ok()
}

/// Return true if `entry` matches the search.
///
/// The match is OR across:
/// 1. Numeric key — if `filter_as_number` is `Some` and equals `entry["key"]`.
/// 2. `string_key` substring (case-insensitive).
/// 3. Resolved catalog name substring (case-insensitive) when the catalog is
///    loaded and the entry has a numeric key.
/// 4. Any nested string field value, recursive up to [`MAX_RECURSION_DEPTH`].
fn entry_matches(
    entry: &Value,
    filter_lower: &str,
    filter_as_number: Option<u64>,
    catalog_section: Option<&str>,
    catalog: Option<&crate::catalog::Catalog>,
) -> bool {
    // 1) Numeric key match.
    if let Some(target) = filter_as_number {
        if let Some(k) = entry.get("key").and_then(|v| v.as_u64()) {
            if k == target {
                return true;
            }
        }
    }

    // 2) string_key substring match.
    if let Some(sk) = entry.get("string_key").and_then(|v| v.as_str()) {
        if sk.to_lowercase().contains(filter_lower) {
            return true;
        }
    }

    // 3) Catalog name substring match (only when both section and catalog are
    //    available and the entry has a numeric key).
    if let (Some(section), Some(cat)) = (catalog_section, catalog) {
        if let Some(k) = entry.get("key").and_then(|v| v.as_u64()) {
            if let Some(name) = cat.lookup_name(section, k) {
                if name.to_lowercase().contains(filter_lower) {
                    return true;
                }
            }
        }
    }

    // 4) Recursive walk of all string field values.
    walk_strings_match(entry, filter_lower, 0)
}

/// Recursively walk `value`, returning true as soon as a string field
/// (lowercased) contains `filter_lower`. Depth-limited to keep pathologically
/// nested entries from blowing up.
fn walk_strings_match(value: &Value, filter_lower: &str, depth: u32) -> bool {
    if depth >= MAX_RECURSION_DEPTH {
        return false;
    }
    match value {
        Value::String(s) => s.to_lowercase().contains(filter_lower),
        Value::Object(map) => map
            .values()
            .any(|v| walk_strings_match(v, filter_lower, depth + 1)),
        Value::Array(arr) => arr
            .iter()
            .any(|v| walk_strings_match(v, filter_lower, depth + 1)),
        // Numbers, booleans, and null contribute nothing here. Numeric keys
        // are matched separately by the numeric-key check above.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry() -> Value {
        json!({
            "key": 2200,
            "string_key": "Pyeonjeon_Arrow",
            "category": "consumable",
            "nested": {
                "label": "Sharp Pointy Stick",
                "deeper": {"more": "even deeper goodness"}
            },
            "tags": ["arrow", "ranged"],
            "rate": 0.5,
        })
    }

    #[test]
    fn parse_user_number_basic() {
        assert_eq!(parse_user_number("42"), Some(42));
        assert_eq!(parse_user_number("0x2A"), Some(42));
        assert_eq!(parse_user_number("0X2a"), Some(42));
        assert_eq!(parse_user_number("0x"), None);
        assert_eq!(parse_user_number(""), None);
        assert_eq!(parse_user_number("not_a_number"), None);
    }

    #[test]
    fn matches_numeric_key() {
        let e = entry();
        assert!(entry_matches(&e, "2200", Some(2200), None, None));
        assert!(!entry_matches(&e, "2201", Some(2201), None, None));
    }

    #[test]
    fn matches_string_key_case_insensitive() {
        let e = entry();
        // Callers (recompute_filter) lowercase the filter before invocation,
        // so we mirror that contract here. The entry's stored values get
        // lowercased inside the matcher.
        assert!(entry_matches(&e, "pyeonjeon", None, None, None));
        assert!(entry_matches(&e, "arrow", None, None, None));
        // Filter that doesn't appear anywhere in the entry should miss.
        assert!(!entry_matches(&e, "longbow", None, None, None));
    }

    #[test]
    fn matches_nested_string_value() {
        let e = entry();
        assert!(entry_matches(&e, "pointy", None, None, None));
        assert!(entry_matches(&e, "even deeper", None, None, None));
        assert!(!entry_matches(&e, "absent", None, None, None));
    }

    #[test]
    fn no_match_on_unrelated_filter() {
        let e = entry();
        assert!(!entry_matches(&e, "totally_unrelated_string", None, None, None));
    }

    #[test]
    fn recursion_depth_caps_out() {
        // Hand-build a value deeper than MAX_RECURSION_DEPTH so the buried
        // string can't be reached.
        let mut deep = json!({"hit": "needle"});
        for _ in 0..(MAX_RECURSION_DEPTH + 2) {
            deep = json!({"down": deep});
        }
        assert!(!walk_strings_match(&deep, "needle", 0));
        // Same string at depth 0 trivially matches.
        assert!(walk_strings_match(&json!("needle"), "needle", 0));
    }
}
