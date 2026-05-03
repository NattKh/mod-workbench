//! Cross-reference panel.
//!
//! Lives in the lower half of the right SidePanel (under `field_panel`).
//! Shows the catalog links — outgoing and incoming — for the currently
//! selected entry, and lets the user click a link to navigate to the
//! referenced entry.
//!
//! ## How navigation works
//!
//! 1. The user clicks a link target (e.g. `[unlocks_skill] skills:
//!    Equip_Passive_LightningWeapon (91101)`).
//! 2. We resolve the target's catalog section (`"skills"`) back to the
//!    dmm-parser-rust-only dispatch name (`"skill_info"`) by reverse-lookup
//!    on `catalog.dispatch_to_section`.
//! 3. If the target dispatch is already the active table, we just find the
//!    matching entry and set `selected_entry_idx` directly.
//! 4. Otherwise we set `state.pending_xref_nav = Some((dispatch, key))`
//!    and submit a `LoadTable` job. The reply handler in `app.rs` notices
//!    the pending nav after the table loads, picks the right entry, and
//!    clears the field.
//!
//! ## Why we only render endpoints whose section we can resolve
//!
//! Some catalog sections don't map back to a loadable dispatch name (e.g.
//! `strings`, or sections produced solely from in-engine data). For those,
//! we still display the link, but click is a no-op. That keeps surprise
//! debug noise out without hiding the relationship from the user.

use crate::mod_io::extract_entry_key;
use crate::state::AppState;

/// Render the cross-reference panel.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Cross References");
    ui.separator();

    // Bail early if we don't have what we need to compute relationships.
    let catalog = match &state.catalog {
        Some(c) => c,
        None => {
            ui.label("Load a catalog and table to see relationships");
            return;
        }
    };
    let active = match state.active_table() {
        Some(t) => t,
        None => {
            ui.label("Load a catalog and table to see relationships");
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

    // Resolve the current entry's catalog section.
    let dispatch_name = active.dispatch_name.as_str();
    let section = match catalog.dispatch_to_section.get(dispatch_name) {
        Some(s) => s.clone(),
        None => {
            ui.label(format!(
                "No catalog section mapped for dispatch '{}'",
                dispatch_name
            ));
            return;
        }
    };

    let entry_key = extract_entry_key(&active.entries[entry_idx]);

    let outgoing = catalog.outgoing_links(&section, entry_key);
    let incoming = catalog.incoming_links(&section, entry_key);
    let total = outgoing.len() + incoming.len();

    // Snapshot the click target so we can mutate state after the immutable
    // borrow on `catalog` ends.
    let mut click_target: Option<(String, u64)> = None;

    egui::CollapsingHeader::new(format!("Related Entries ({})", total))
        .id_salt("xref_root")
        .default_open(true)
        .show(ui, |ui| {
            if total == 0 {
                ui.label("No related entries.");
                return;
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .id_salt("xref_scroll")
                .show(ui, |ui| {
                    egui::CollapsingHeader::new(format!("Outgoing ({})", outgoing.len()))
                        .id_salt("xref_outgoing")
                        .default_open(true)
                        .show(ui, |ui| {
                            if outgoing.is_empty() {
                                ui.label("(none)");
                            } else {
                                for link in &outgoing {
                                    if let Some(target) =
                                        render_link(ui, catalog, &link.link_type, &link.to)
                                    {
                                        click_target = Some(target);
                                    }
                                }
                            }
                        });

                    egui::CollapsingHeader::new(format!("Incoming ({})", incoming.len()))
                        .id_salt("xref_incoming")
                        .default_open(true)
                        .show(ui, |ui| {
                            if incoming.is_empty() {
                                ui.label("(none)");
                            } else {
                                for link in &incoming {
                                    if let Some(target) =
                                        render_link(ui, catalog, &link.link_type, &link.from)
                                    {
                                        click_target = Some(target);
                                    }
                                }
                            }
                        });
                });
        });

    // Apply navigation request after the catalog borrow drops.
    if let Some((dispatch_name, key)) = click_target {
        navigate_to(state, dispatch_name, key);
    }
}

/// Render one link as a clickable line. Returns `Some((dispatch_name, key))`
/// when the user clicked, otherwise `None`.
///
/// Format: `[link_type] target_section: target_name (target_key)`. Falls
/// back to the raw key when the catalog has no `name` for the target.
fn render_link(
    ui: &mut egui::Ui,
    catalog: &crate::catalog::Catalog,
    link_type: &str,
    endpoint: &str,
) -> Option<(String, u64)> {
    // Parse "section:key".
    let (target_section, target_key_str) = match endpoint.split_once(':') {
        Some((s, k)) => (s, k),
        None => {
            ui.label(format!("[{}] (malformed endpoint: {})", link_type, endpoint));
            return None;
        }
    };

    let target_key: Option<u64> = target_key_str.parse().ok();

    // Resolve a human-readable name when possible.
    let name_label = target_key
        .and_then(|k| catalog.lookup_name(target_section, k))
        .map(|s| s.to_string());

    let display = match (&name_label, target_key) {
        (Some(name), Some(k)) => {
            format!("[{}] {}: {} ({})", link_type, target_section, name, k)
        }
        (None, Some(k)) => format!("[{}] {}: {}", link_type, target_section, k),
        (_, None) => format!("[{}] {}: {}", link_type, target_section, target_key_str),
    };

    // Reverse-lookup: catalog section -> dispatch name. We need this to know
    // which table to load on click. If no dispatch maps to this section, the
    // link is informational only (rendered as a plain label).
    let dispatch_for_target = catalog
        .dispatch_to_section
        .iter()
        .find(|(_, sec)| sec.as_str() == target_section)
        .map(|(d, _)| d.clone());

    match (dispatch_for_target, target_key) {
        (Some(dispatch), Some(key)) => {
            // Use a Link widget so it visually reads as clickable. egui's
            // built-in Link styling underlines on hover.
            if ui.link(display).clicked() {
                return Some((dispatch, key));
            }
        }
        _ => {
            // Not navigable — show as a dim label so it's obvious clicking
            // won't do anything.
            ui.label(egui::RichText::new(display).weak());
        }
    }
    None
}

/// Navigate to `(dispatch_name, key)`. If the target table is already open
/// in *any* tab, focus that tab and select the entry directly. Otherwise
/// stash a pending nav request and kick off a worker load — the reply handler
/// in `app.rs` opens a new tab and finishes the navigation when the table
/// arrives.
fn navigate_to(state: &mut AppState, dispatch_name: String, key: u64) {
    // Case 1: target table is already open in some tab. Focus it and pick
    // the entry. This works whether the target tab was already active or
    // sitting in the background.
    if let Some(_idx) = state.open_or_focus_tab(&dispatch_name) {
        let active = state
            .active_table_mut()
            .expect("just focused a tab so active_table_mut must exist");
        if let Some(entry_idx) = active
            .entries
            .iter()
            .position(|e| extract_entry_key(e) == key)
        {
            active.selected_entry_idx = Some(entry_idx);
            state.pending_xref_nav = None;
            state.status = format!("Jumped to {}:{}", dispatch_name, key);
        } else {
            state.status = format!("Entry {} not found in {}", key, dispatch_name);
            state.toasts.warn(format!(
                "Entry {} not found in {}",
                key, dispatch_name
            ));
        }
        return;
    }

    // Case 2: need to load the target table first. Stash the nav request and
    // submit a load job. handle_worker_reply will finish up when it arrives.
    let game_dir = match &state.game_dir {
        Some(d) => d.clone(),
        None => {
            state.status = "Set game dir first (File -> Set Game Dir)".to_string();
            state
                .toasts
                .warn("Set game dir first (File -> Set Game Dir)");
            return;
        }
    };

    let meta = match state
        .tables
        .iter()
        .find(|m| m.dispatch_name == dispatch_name)
        .cloned()
    {
        Some(m) => m,
        None => {
            state.status = format!("No registry entry for dispatch '{}'", dispatch_name);
            state
                .toasts
                .warn(format!("No registry entry for '{}'", dispatch_name));
            return;
        }
    };

    state.pending_xref_nav = Some((dispatch_name.clone(), key));
    state.status = format!("Loading {} for xref jump...", dispatch_name);
    state.worker.submit(crate::worker::Job::LoadTable {
        dispatch_name,
        game_dir,
        pabgb_filename: meta.pabgb_filename,
        pabgh_filename: meta.pabgh_filename,
    });
}
