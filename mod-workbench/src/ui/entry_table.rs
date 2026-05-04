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
                let has_raw_bytes = active.raw_pabgb.is_some();
                let already_hex = active.show_hex_view;
                let mut want_retry = false;
                let mut want_close = false;
                let mut want_toggle_hex = false;
                // Pick a hint based on the actual failure mode rather than
                // always blaming a parser version mismatch. The three modes
                // we see in the wild:
                //   1. "File 'X.pabgb' not found in gamedata/binary__/..."
                //      = the file isn't in the PAZ at all (dev-only file or
                //      a name mismatch between dispatch and on-disk).
                //   2. "Cannot read PAMT" / "Directory '...' not found"
                //      = game install path or PAMT itself is wrong.
                //   3. anything else (parse error, EOF, etc.)
                //      = parser couldn't decode the bytes.
                let (header_label, hint) = if msg.contains("not found in gamedata") {
                    (
                        "PAZ lookup failed:",
                        "This table isn't present in your game's 0008 PAZ at the \
                         standard internal path. Common causes: it's a dev-only \
                         table (lives in `bin_dev/`, gated off in retail), or it \
                         was renamed in a patch and the registry is out of date. \
                         Other tables are unaffected — close this tab and try \
                         another one.",
                    )
                } else if msg.contains("Cannot read PAMT") || msg.contains("not found in 0008") {
                    (
                        "Game data lookup failed:",
                        "Couldn't read the PAMT for the 0008 PAZ group. Verify \
                         that the configured Game Directory points at a real \
                         Crimson Desert install (Settings → Game Dir). The PAMT \
                         file is at `<game-dir>/0008/0.pamt`.",
                    )
                } else {
                    (
                        "Parser error:",
                        "The parser couldn't decode this table's bytes. Most \
                         likely cause: the table's binary layout changed in a \
                         recent game patch. Try Show Hex to inspect the raw \
                         pabgb. Other tables that didn't change are unaffected.",
                    )
                };

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
                            egui::RichText::new(header_label)
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
                        egui::RichText::new(hint)
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
                        let hex_label = if already_hex { "Hide Hex" } else { "Show Hex" };
                        let hex_btn = ui.add_enabled(
                            has_raw_bytes,
                            egui::Button::new(hex_label),
                        );
                        if hex_btn.clicked() {
                            want_toggle_hex = true;
                        }
                        if !has_raw_bytes {
                            hex_btn.on_hover_text(
                                "No raw pabgb bytes were captured (PAZ extraction also failed).",
                            );
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
                    return;
                }
                if want_close {
                    if let Some(idx) = state.active_tab_idx {
                        state.close_tab(idx);
                    }
                    return;
                }
                if want_toggle_hex {
                    if let Some(active) = state.active_table_mut() {
                        active.show_hex_view = !active.show_hex_view;
                    }
                }

                // If the user wants the hex view (and we have bytes for it)
                // render it in place of the rest of the error placeholder
                // so byte-level inspection is possible without leaving the
                // tab.
                let active_after = state.active_table().unwrap();
                if active_after.show_hex_view && active_after.raw_pabgb.is_some() {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.heading("Raw bytes (hex view)");
                    // Clone out of the immutable borrow so we can reborrow
                    // `state` mutably below to write back the hex state.
                    let bytes_owned = active_after.raw_pabgb.as_ref().unwrap().clone();
                    let mut hex_state = active_after.hex_view_state.clone();
                    let _ = active_after;
                    crate::ui::hex_view::show(ui, &bytes_owned, &mut hex_state);
                    if let Some(active_mut) = state.active_table_mut() {
                        active_mut.hex_view_state = hex_state;
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
    let mut toggle_hex = false;
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

        // "Search all PABGBs" toggle. Off by default — when on, the search
        // turns into a worker-driven scan across every table in the
        // registry instead of just the active tab. Streamed hits appear
        // below; click any to jump to that entry.
        let prev_global = state.global_search.enabled;
        ui.checkbox(&mut state.global_search.enabled, "Search all PABGBs")
            .on_hover_text(
                "Scan every PABGB in the game's PAZ for matches against this \
                 search box. Off by default because it loads ~120 tables from \
                 disk; expect 30–60 s on a cold run. Streams results as it \
                 finds them.",
            );
        if prev_global && !state.global_search.enabled {
            // User turned it off — drop accumulated hits + invalidate
            // any in-flight reply with a fresh request id.
            state.global_search.hits.clear();
            state.global_search.in_progress = false;
            state.global_search.request_id = state.global_search.request_id.wrapping_add(1);
        }

        let active_ref = state.active_table().unwrap();
        let total = active_ref.entries.len();
        if state.global_search.enabled {
            // When global search is active the per-table count is
            // misleading — surface the global counters instead.
            let hits = state.global_search.hits.len();
            if state.global_search.in_progress {
                ui.label(format!(
                    "scanning {} / {}: {} hits",
                    state.global_search.scanned,
                    state.global_search.total,
                    hits,
                ));
            } else if !state.entry_filter.is_empty() {
                ui.label(format!("{} hit(s) across all PABGBs", hits));
            } else {
                ui.label("type a search to scan all PABGBs");
            }
        } else if state.entry_filter.is_empty() {
            ui.label(format!("{} entries", total));
        } else {
            ui.label(format!(
                "{} of {} entries",
                active_ref.filtered_indices.len(),
                total
            ));
        }

        // "Show Hex" toggle. Shifted to the right so it doesn't crowd the
        // search bar; uses the same state field as the error placeholder
        // so the toggle persists across retries / view switches.
        let has_bytes = active_ref.raw_pabgb.is_some();
        let already_hex = active_ref.show_hex_view;
        let label = if already_hex { "Table" } else { "Hex" };
        let tooltip = if already_hex {
            "Switch back to the entry table view"
        } else if has_bytes {
            "Show raw pabgb bytes in a paged hex view"
        } else {
            "No raw bytes captured for this table — hex view unavailable"
        };
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let btn = ui.add_enabled(has_bytes || already_hex, egui::Button::new(label));
            if btn.on_hover_text(tooltip).clicked() {
                toggle_hex = true;
            }
        });
    });
    if clear_filter {
        state.entry_filter.clear();
    }
    if toggle_hex {
        if let Some(active) = state.active_table_mut() {
            active.show_hex_view = !active.show_hex_view;
        }
    }

    // When the hex toggle is on, swap the entry table for the hex view
    // and bail before the filter / table renderer runs. We clone the
    // bytes into local ownership because the table view's renderer needs
    // an immutable borrow on `state` further down — keeping the hex
    // path self-contained avoids borrow-juggling against that.
    if state
        .active_table()
        .map(|a| a.show_hex_view && a.raw_pabgb.is_some())
        .unwrap_or(false)
    {
        ui.separator();
        let active_ref = state.active_table().unwrap();
        let bytes_owned = active_ref.raw_pabgb.as_ref().unwrap().clone();
        let mut hex_state = active_ref.hex_view_state.clone();
        let _ = active_ref;
        crate::ui::hex_view::show(ui, &bytes_owned, &mut hex_state);
        if let Some(active_mut) = state.active_table_mut() {
            active_mut.hex_view_state = hex_state;
        }
        return;
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

    // Only bump `last_filter_change` when the filter ACTUALLY changed since
    // last frame — i.e. the user just typed or deleted a character. The
    // earlier code compared against `last_filter` (a snapshot from the last
    // recompute), which always differs while typing, so the timer reset
    // every frame and the recompute never fired. See `prev_frame_filter`.
    if active.prev_frame_filter != entry_filter_snapshot {
        active.last_filter_change = now;
        active.prev_frame_filter = entry_filter_snapshot.clone();
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

    // ---- Global search kick-off ------------------------------------------
    //
    // When the "Search all PABGBs" checkbox is on AND the user has finished
    // typing (debounce elapsed) AND the filter differs from the one we last
    // kicked a scan with, fire a fresh worker job. Each kick bumps
    // `request_id` so any in-flight replies from the previous scan are
    // discarded by `app.rs::handle_worker_reply`.
    if state.global_search.enabled
        && !entry_filter_snapshot.is_empty()
        && state.global_search.filter_at_kick != entry_filter_snapshot
        && debounce_elapsed
    {
        kick_global_search(state, entry_filter_snapshot.clone());
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

    // ---- Global search results panel -----------------------------------
    //
    // When the "Search all PABGBs" checkbox is on we replace the per-table
    // entry view with a hits list streamed from the worker. Clicking a hit
    // opens its source table (loading it if necessary) and jumps to the
    // matched entry.
    if state.global_search.enabled {
        render_global_search_panel(ui, state);
        return;
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

// ── Global search ───────────────────────────────────────────────────────────

/// Submit a fresh `Job::SearchAllPabgb` to the worker. Bumps the request
/// id so any in-flight replies from a previous scan are discarded by
/// [`crate::app::WorkbenchApp::handle_worker_reply`]. Snapshots the
/// registry so the worker has a stable list of tables to walk even if
/// the registry mutates while the scan runs.
fn kick_global_search(state: &mut AppState, filter: String) {
    let Some(game_dir) = state.game_dir.clone() else {
        state
            .toasts
            .warn("Set the Game Directory first (Settings panel).");
        state.global_search.enabled = false;
        return;
    };

    state.global_search.filter_at_kick = filter.clone();
    state.global_search.request_id = state.global_search.request_id.wrapping_add(1);
    state.global_search.in_progress = true;
    state.global_search.scanned = 0;
    state.global_search.total = state.tables.len();
    state.global_search.current_table = String::new();
    state.global_search.hits.clear();
    state.global_search.error = None;

    // Worker walks the registry snapshot; we hand it the lowercased filter
    // and a parsed numeric form (so it can match key fields without
    // re-parsing per entry).
    let filter_lower = filter.to_lowercase();
    let filter_as_number = parse_user_number(filter_lower.trim());

    state.worker.submit(crate::worker::Job::SearchAllPabgb {
        request_id: state.global_search.request_id,
        game_dir,
        filter: filter_lower,
        filter_as_number,
        tables: state.tables.clone(),
    });
}

/// Render the global-search results: progress bar (when scanning) plus a
/// scrollable list of hits. Clicking a row opens the source table (loads
/// it if not already open) and selects the matched entry.
fn render_global_search_panel(ui: &mut egui::Ui, state: &mut AppState) {
    if state.global_search.in_progress {
        let frac = if state.global_search.total > 0 {
            state.global_search.scanned as f32 / state.global_search.total as f32
        } else {
            0.0
        };
        ui.add(egui::ProgressBar::new(frac).text(format!(
            "Scanning {} / {}: {}",
            state.global_search.scanned,
            state.global_search.total,
            state.global_search.current_table,
        )));
        ui.label(
            egui::RichText::new(
                "Streaming hits as the worker scans each table — \
                 results may continue to grow until 'complete'.",
            )
            .small()
            .weak(),
        );
        // Repaint so progress + new hits land without the user nudging
        // the UI.
        ui.ctx().request_repaint_after(Duration::from_millis(120));
    }

    if let Some(err) = &state.global_search.error {
        ui.label(
            egui::RichText::new(format!("Partial scan error: {}", err))
                .color(egui::Color32::from_rgb(230, 180, 80))
                .small(),
        );
    }

    if state.global_search.hits.is_empty() && !state.global_search.in_progress {
        ui.label(
            egui::RichText::new(
                "No hits yet. Type a search and untick the 'Search all PABGBs' \
                 box to return to the per-table view.",
            )
            .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    let mut clicked: Option<crate::worker::GlobalSearchHit> = None;

    egui::ScrollArea::vertical()
        .id_salt("global_search_results")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            // Use a TableBuilder so columns line up regardless of label
            // length. Three columns: table name, key + string_key, matched
            // field summary.
            use egui_extras::{Column, TableBuilder};
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .column(Column::auto().at_least(140.0).clip(true))
                .column(Column::auto().at_least(220.0).clip(true))
                .column(Column::remainder().at_least(280.0).clip(true))
                .header(20.0, |mut h| {
                    h.col(|ui| {
                        ui.label(egui::RichText::new("Table").strong());
                    });
                    h.col(|ui| {
                        ui.label(egui::RichText::new("Entry").strong());
                    });
                    h.col(|ui| {
                        ui.label(egui::RichText::new("Match").strong());
                    });
                })
                .body(|body| {
                    let hits = &state.global_search.hits;
                    body.rows(20.0, hits.len(), |mut row| {
                        let i = row.index();
                        let hit = &hits[i];
                        row.col(|ui| {
                            ui.label(&hit.dispatch_name);
                        });
                        row.col(|ui| {
                            let label = if hit.string_key.is_empty() {
                                format!("key={}", hit.entry_key)
                            } else {
                                format!("{} ({})", hit.string_key, hit.entry_key)
                            };
                            if ui.link(label).clicked() {
                                clicked = Some(hit.clone());
                            }
                        });
                        row.col(|ui| {
                            ui.label(&hit.matched);
                        });
                    });
                });
        });

    if let Some(hit) = clicked {
        jump_to_global_hit(state, hit);
    }
}

/// Open the source table of a global-search hit and select the matched
/// entry. If the table is already open as a tab, focuses it; otherwise
/// records a `pending_xref_nav` so the worker reply that loads the table
/// will pre-select the entry on arrival.
fn jump_to_global_hit(state: &mut AppState, hit: crate::worker::GlobalSearchHit) {
    // 1) Already open? Focus it and select the entry inline.
    if let Some(idx) = state
        .open_tabs
        .iter()
        .position(|t| t.dispatch_name == hit.dispatch_name)
    {
        state.active_tab_idx = Some(idx);
        if let Some(tab) = state.open_tabs.get_mut(idx) {
            if hit.entry_idx < tab.entries.len() {
                tab.selected_entry_idx = Some(hit.entry_idx);
            }
        }
        // Also turn off the global-search overlay so the user lands in
        // the per-table view directly. The hits stay in `state.global_
        // search.hits` so the user can re-tick the box and resume.
        state.global_search.enabled = false;
        return;
    }

    // 2) Not open — submit a load and remember which entry to focus.
    let Some(meta) = state
        .tables
        .iter()
        .find(|m| m.dispatch_name == hit.dispatch_name)
        .cloned()
    else {
        state.toasts.warn(format!(
            "Table '{}' isn't in the registry — can't open.",
            hit.dispatch_name
        ));
        return;
    };
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the Game Directory first.");
        return;
    };

    // Push a placeholder tab so the user gets immediate visual feedback.
    let placeholder =
        crate::state::ActiveTable::placeholder_loading(hit.dispatch_name.clone());
    state.open_tabs.push(placeholder);
    state.active_tab_idx = Some(state.open_tabs.len() - 1);

    // Stash the entry idx as an xref-style nav so the load handler
    // selects it on arrival. We re-resolve the entry by key on the UI
    // side because the entries vec rebuilds on each load.
    state.pending_xref_nav = Some((hit.dispatch_name.clone(), hit.entry_key));

    state.worker.submit(crate::worker::Job::LoadTable {
        dispatch_name: meta.dispatch_name.clone(),
        game_dir,
        pabgb_filename: meta.pabgb_filename.clone(),
        pabgh_filename: meta.pabgh_filename.clone(),
    });
    state.global_search.enabled = false;
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
