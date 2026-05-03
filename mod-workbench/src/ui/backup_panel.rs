//! Backup browser view.
//!
//! Renders a table of every snapshot under [`crate::backup::backup_dir`] with
//! per-row Restore / Delete buttons, plus a "Refresh" button to re-scan and a
//! "Clear All" button (with confirmation) for bulk purging.
//!
//! The panel lives at the same z-level as the central table editor — switched
//! to via `state.main_view = MainView::Backups` (set from the File menu). It
//! never claims the side panels because the file menu / status bar still
//! belong to the editor; rendering this view simply replaces the central
//! panel content.
//!
//! ## State coupling
//!
//! The list of snapshots is cached on `AppState::backup_snapshots` so the
//! panel doesn't hit the disk every frame. A user-initiated "Refresh" (or the
//! first time the view is opened with an empty cache) re-reads it. Mutating
//! actions (Restore / Delete / Clear All) all refresh the cache afterwards
//! so the row the user clicked actually disappears.

use crate::backup::{self, Snapshot};
use crate::state::{AppState, MainView};

/// Render the backup browser into `ui`. Returns nothing — side effects
/// (refreshing the cache, restoring/deleting snapshots, surfacing toasts)
/// are applied directly to `state`.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("Backups");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Close").clicked() {
                // Drop back to the historical default view so the user lands
                // somewhere familiar regardless of which view they came from.
                state.main_view = MainView::PabgbTables;
            }
        });
    });
    ui.separator();

    // Top-level info + refresh / clear-all buttons.
    ui.horizontal(|ui| {
        let dir_display = backup::backup_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<no platform data dir>".to_string());
        ui.label(egui::RichText::new(dir_display).weak().small());
    });

    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            refresh(state);
        }

        // "Clear All" gets a two-step confirmation so a single misclick can't
        // blow away every backup. We model the confirmation as a transient
        // boolean on `state` (not persisted) — see `confirm_clear_all`.
        if state.backup_confirm_clear_all {
            ui.colored_label(
                egui::Color32::from_rgb(230, 80, 80),
                "Really clear ALL snapshots?",
            );
            if ui.button("Yes, delete all").clicked() {
                let total = state.backup_snapshots.len();
                let mut deleted = 0usize;
                for s in state.backup_snapshots.clone() {
                    if backup::delete_snapshot(&s.id).is_ok() {
                        deleted += 1;
                    }
                }
                state.backup_confirm_clear_all = false;
                state.toasts.info(format!(
                    "Deleted {} of {} snapshots",
                    deleted, total
                ));
                refresh(state);
            }
            if ui.button("Cancel").clicked() {
                state.backup_confirm_clear_all = false;
            }
        } else if ui.button("Clear All").clicked() {
            state.backup_confirm_clear_all = true;
        }
    });

    ui.separator();

    // Lazy first-load: if we've never populated the cache, read it now so the
    // user sees something on the very first open of this view.
    if !state.backup_loaded_once {
        refresh(state);
    }

    // The list is small (capped at SNAPSHOT_RETAIN_COUNT == 20 by default),
    // but wrap in a scroll area so an oversized history still renders sanely.
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if state.backup_snapshots.is_empty() {
                ui.label(
                    egui::RichText::new(
                        "No snapshots yet. Snapshots are auto-created before each deploy.",
                    )
                    .italics(),
                );
                return;
            }

            // We can't mutate state.backup_snapshots while we're iterating
            // it, so collect any user actions and apply them after the loop.
            let mut to_restore: Option<String> = None;
            let mut to_delete: Option<String> = None;

            // Render header row.
            egui::Grid::new("backup_grid")
                .num_columns(5)
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.strong("Label");
                    ui.strong("Created");
                    ui.strong("Overlay");
                    ui.strong("Sizes");
                    ui.strong("Actions");
                    ui.end_row();

                    for snap in &state.backup_snapshots {
                        ui.label(&snap.label);
                        ui.label(&snap.created_at);
                        ui.label(&snap.overlay_group);
                        ui.label(format_sizes(snap));
                        ui.horizontal(|ui| {
                            if ui.button("Restore").clicked() {
                                to_restore = Some(snap.id.clone());
                            }
                            if ui.button("Delete").clicked() {
                                to_delete = Some(snap.id.clone());
                            }
                        });
                        ui.end_row();
                    }
                });

            if let Some(id) = to_restore {
                handle_restore(state, &id);
            }
            if let Some(id) = to_delete {
                handle_delete(state, &id);
            }
        });
}

/// Re-read the snapshot list from disk into [`AppState::backup_snapshots`].
///
/// Failures are reported via toast so the user knows why the list looks
/// empty — silent failure here would be confusing the first time the data
/// dir doesn't exist yet.
fn refresh(state: &mut AppState) {
    match backup::list_snapshots() {
        Ok(list) => {
            state.backup_snapshots = list;
            state.backup_loaded_once = true;
        }
        Err(e) => {
            state
                .toasts
                .error_with_details("Failed to list snapshots", e.to_string());
        }
    }
}

/// Render a snapshot's two captured sizes as a single human-friendly string.
fn format_sizes(snap: &Snapshot) -> String {
    format!(
        "papgt: {} | overlay: {}",
        format_bytes(snap.papgt_size),
        format_bytes(snap.paz_size)
    )
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if b == 0 {
        return "—".to_string();
    }
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.2} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn handle_restore(state: &mut AppState, snapshot_id: &str) {
    let game_dir = match &state.game_dir {
        Some(d) => d.clone(),
        None => {
            state.toasts.warn("Set game dir first");
            return;
        }
    };
    match backup::restore_snapshot(snapshot_id, &game_dir) {
        Ok(()) => {
            let msg = format!("Restored snapshot {}", snapshot_id);
            state.status = msg.clone();
            state.toasts.info(msg);
        }
        Err(e) => {
            state
                .toasts
                .error_with_details(format!("Restore failed: {}", snapshot_id), e.to_string());
        }
    }
    refresh(state);
}

fn handle_delete(state: &mut AppState, snapshot_id: &str) {
    match backup::delete_snapshot(snapshot_id) {
        Ok(()) => {
            state.toasts.info(format!("Deleted snapshot {}", snapshot_id));
        }
        Err(e) => {
            state
                .toasts
                .error_with_details(format!("Delete failed: {}", snapshot_id), e.to_string());
        }
    }
    refresh(state);
}
