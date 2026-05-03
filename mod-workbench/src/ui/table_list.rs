use crate::state::AppState;

/// Left panel: searchable list of all 122+ game data tables.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Tables");
    ui.separator();

    // Search filter
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut state.table_filter);
    });

    // Worker activity indicator. Visible while any background job is in
    // flight — typically a `LoadTable` triggered by the user clicking an
    // entry below. Sits above the list so it's not scrolled away when the
    // user is far down the list.
    if state.worker.in_flight > 0 {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new().size(14.0));
            ui.label(egui::RichText::new("Loading...").italics());
        });
    }

    ui.separator();

    let filter_lower = state.table_filter.to_lowercase();

    // Snapshot the active tab and the set of dispatch names that already
    // have an open tab so the per-row label can mark each state distinctly.
    let active_name = state
        .active_table()
        .map(|t| t.dispatch_name.clone());
    let open_tab_names: std::collections::HashSet<String> = state
        .open_tabs
        .iter()
        .map(|t| t.dispatch_name.clone())
        .collect();

    let mut load_request: Option<usize> = None;

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            for (i, meta) in state.tables.iter().enumerate() {
                // Filter
                if !filter_lower.is_empty()
                    && !meta.dispatch_name.to_lowercase().contains(&filter_lower)
                {
                    continue;
                }

                let is_selected = active_name
                    .as_deref()
                    .map(|n| n == meta.dispatch_name.as_str())
                    .unwrap_or(false);
                let is_open = open_tab_names.contains(&meta.dispatch_name);
                let was_loaded = state.loaded_tables.contains(&meta.dispatch_name);

                // Build the display label:
                // - Active tab: "name (count)" — entries currently visible.
                // - Open in another tab: "name *" — already open, click focuses it.
                // - Loaded before but not active: "name ✓"
                // - Never loaded: "name"
                let label = if is_selected {
                    if let Some(active) = state.active_table() {
                        format!("{} ({})", meta.dispatch_name, active.entries.len())
                    } else {
                        meta.dispatch_name.clone()
                    }
                } else if is_open {
                    format!("{} *", meta.dispatch_name)
                } else if was_loaded {
                    format!("{} ✓", meta.dispatch_name)
                } else {
                    meta.dispatch_name.clone()
                };

                if ui.selectable_label(is_selected, &label).clicked() && !is_selected {
                    load_request = Some(i);
                }
            }
        });

    // Handle load request outside the borrow of state.tables.
    if let Some(idx) = load_request {
        submit_load(state, idx);
    }
}

/// Submit a table load to the background worker, or focus an existing tab.
///
/// If the requested table already has an open tab we just switch focus —
/// no need to re-load. Otherwise we kick off a `LoadTable` job and the
/// reply handler in `app.rs` opens a new tab.
///
/// The actual parsing happens off the UI thread so the egui frame stays at
/// 60 fps even on the largest tables (multichanges ≈ 17 k rows, drop_sets
/// ≈ 11 k). The matching `Reply::TableLoaded` is consumed by
/// [`crate::app::WorkbenchApp::handle_worker_reply`], which appends to
/// `state.open_tabs` and inserts the dispatch_name into
/// `state.loaded_tables` for the "✓" affordance.
pub(crate) fn submit_load(state: &mut AppState, table_idx: usize) {
    let dispatch_name = state.tables[table_idx].dispatch_name.clone();

    // Already open? Focus it without re-loading.
    if state.open_or_focus_tab(&dispatch_name).is_some() {
        state.status = format!("Focused {}", dispatch_name);
        return;
    }

    let Some(game_dir) = state.game_dir.clone() else {
        state.status = "Set game dir first (File -> Set Game Dir)".to_string();
        state.toasts.warn("Set game dir first");
        return;
    };

    let meta = &state.tables[table_idx];
    let pabgb_filename = meta.pabgb_filename.clone();
    let pabgh_filename = meta.pabgh_filename.clone();

    // Push a placeholder tab IMMEDIATELY so the user sees something happen
    // when they click. The worker reply will overwrite this in place once
    // the load finishes (success or error). This is the difference between
    // "did my click do anything?" and "I can see it's loading".
    let placeholder = crate::state::ActiveTable::placeholder_loading(dispatch_name.clone());
    state.open_tabs.push(placeholder);
    state.active_tab_idx = Some(state.open_tabs.len() - 1);

    state.status = format!("Loading {} in background...", dispatch_name);
    state.worker.submit(crate::worker::Job::LoadTable {
        dispatch_name,
        game_dir,
        pabgb_filename,
        pabgh_filename,
    });
}

/// Auto-detect up to 6 interesting columns from the first entry.
///
/// Prioritizes: key, string_key, is_blocked, then the first few scalar fields.
pub(crate) fn detect_columns(entries: &[serde_json::Value]) -> Vec<String> {
    let first = match entries.first().and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => return vec!["key".to_string()],
    };

    let priority = ["key", "string_key", "is_blocked", "unk_key", "_key"];
    let mut cols: Vec<String> = Vec::new();

    // Add priority fields that exist
    for &name in &priority {
        if first.contains_key(name) && !cols.contains(&name.to_string()) {
            cols.push(name.to_string());
        }
    }

    // Fill with remaining scalar fields up to 6 total
    for (name, value) in first {
        if cols.len() >= 6 {
            break;
        }
        if cols.contains(name) {
            continue;
        }
        // Only include scalar types (not objects or arrays)
        match value {
            serde_json::Value::Number(_)
            | serde_json::Value::String(_)
            | serde_json::Value::Bool(_) => {
                cols.push(name.clone());
            }
            _ => {}
        }
    }

    if cols.is_empty() {
        cols.push("key".to_string());
    }

    cols
}
