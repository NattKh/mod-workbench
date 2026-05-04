//! PAZ archive inspector panel.
//!
//! Read-only browser over every numeric PAZ group folder under the
//! configured Game Directory, plus two write paths gated behind
//! confirmations:
//!
//! - **Open in Hex**: extract one file's bytes and route them to
//!   [`crate::ui::hex_view::show`].
//! - **Remove Overlay**: delete the group directory + drop its PAPGT entry.
//!
//! View modes inside the panel:
//!
//! - `Groups`: top-level table — one row per numeric group with the PAPGT
//!   registration flag, the two checksum values, file count, total
//!   uncompressed size, and a "Workbench backup" indicator.
//! - `Detail(name)`: drill-in showing every directory in the group's PAMT
//!   and every file with its size + compression / crypto flags.
//! - `Hex(name, dir, file)`: byte-level view of one file extracted via
//!   [`crate::archive_editor::extract_one_file`].
//! - `Diff`: compare the live `meta/0.papgt` against
//!   `meta/0.papgt.workbench_backup` and show added / removed / changed
//!   group entries.
//!
//! The panel does its own (synchronous) PAMT parsing on first open and on
//! manual Refresh — PAMT parsing is fast enough that running it on the UI
//! thread is fine for this view, per the wave-3 plan.

use egui_extras::{Column, TableBuilder};

use crate::archive_editor::{
    self, ArchiveGroup, ArchiveGroupDetail, PapgtDiff,
};
use crate::state::{AppState, MainView};
use crate::ui::hex_view::HexViewState;

/// Persistent state for the archive inspector. Owned by [`AppState`].
pub struct ArchiveSession {
    /// Which sub-view is active (groups list / drill-in / hex / diff).
    pub mode: ArchiveMode,
    /// Cached top-level group list. `None` until populated by
    /// [`refresh_groups`]. Empty vec means "scanned and found nothing".
    pub groups: Option<Vec<ArchiveGroup>>,
    /// First error from the most recent `refresh_groups` call. Surfaced
    /// inline so the user can see why the list is empty.
    pub error: Option<String>,
    /// Cached drill-in detail for the group named in [`ArchiveMode::Detail`].
    pub detail: Option<ArchiveGroupDetail>,
    /// Substring filter applied to the groups table — matches against the
    /// group name. Case-insensitive.
    pub filter: String,
    /// Hex-view state for the currently-open file (when in
    /// [`ArchiveMode::Hex`]). Carries the bytes plus the page state.
    pub hex_bytes: Vec<u8>,
    pub hex_state: HexViewState,
    pub hex_label: String,
    /// Cached PAPGT diff for the [`ArchiveMode::Diff`] view. None until the
    /// user clicks "Compare to Backup" or re-enters the view.
    pub diff: Option<Option<PapgtDiff>>,
    /// Two-step confirmation gate for the per-group Remove Overlay button.
    /// Carries the group name we're about to wipe so we don't blow away
    /// the wrong row if the cache changes mid-confirmation.
    pub remove_confirm_pending: Option<String>,
}

/// Sub-view selector for the archive inspector. Each variant carries the
/// state needed to render its body without round-tripping through the
/// session's caches every frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveMode {
    /// Top-level groups table.
    Groups,
    /// Drill-in for a specific group. The cached [`ArchiveGroupDetail`] on
    /// the session is keyed off this group name.
    Detail(String),
    /// Hex view of one file inside a group.
    Hex {
        group: String,
        dir_path: String,
        file_name: String,
    },
    /// PAPGT diff against the workbench backup.
    Diff,
}

impl Default for ArchiveSession {
    fn default() -> Self {
        Self {
            mode: ArchiveMode::Groups,
            groups: None,
            error: None,
            detail: None,
            filter: String::new(),
            hex_bytes: Vec::new(),
            hex_state: HexViewState::default(),
            hex_label: String::new(),
            diff: None,
            remove_confirm_pending: None,
        }
    }
}

/// Render the archive panel into `ui`. Mirrors the `show()` signature of
/// every other panel module so `app.rs` can route to it the same way.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header_bar(ui, state);
    ui.separator();

    // Lazy first-load: opening this view with no cache triggers a refresh
    // so the user sees data immediately.
    if state.archive.groups.is_none() && state.archive.error.is_none() {
        refresh_groups(state);
    }

    // Drive the body off a clone of `mode` so we can mutate state freely
    // inside the closure without re-borrowing.
    let mode = state.archive.mode.clone();
    match mode {
        ArchiveMode::Groups => render_groups_table(ui, state),
        ArchiveMode::Detail(name) => render_detail(ui, state, &name),
        ArchiveMode::Hex {
            group,
            dir_path,
            file_name,
        } => render_hex(ui, state, &group, &dir_path, &file_name),
        ArchiveMode::Diff => render_diff(ui, state),
    }
}

fn header_bar(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("PAZ Archive Inspector");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Close").clicked() {
                state.main_view = MainView::PabgbTables;
            }
        });
    });

    ui.horizontal(|ui| {
        let game_dir_label = state
            .game_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<no game directory set>".to_string());
        ui.label(
            egui::RichText::new(game_dir_label)
                .weak()
                .small(),
        );
    });

    ui.horizontal(|ui| {
        // Always-visible mode toggles — a row of selectable buttons that
        // mirror the egui pattern in xml_panel.rs.
        let is_groups = matches!(state.archive.mode, ArchiveMode::Groups);
        if ui.selectable_label(is_groups, "Groups").clicked() {
            state.archive.mode = ArchiveMode::Groups;
        }
        let is_diff = matches!(state.archive.mode, ArchiveMode::Diff);
        if ui
            .selectable_label(is_diff, "PAPGT vs Backup")
            .on_hover_text(
                "Compare the live meta/0.papgt against \
                 meta/0.papgt.workbench_backup and list added / removed / \
                 changed group entries.",
            )
            .clicked()
        {
            state.archive.mode = ArchiveMode::Diff;
            // Recompute on entry so a stale cache from earlier in the
            // session doesn't mask a freshly-changed PAPGT.
            state.archive.diff = None;
        }

        ui.separator();
        if ui.button("Refresh").clicked() {
            refresh_groups(state);
            // Drop any cached drill-in so re-clicking the row triggers a
            // fresh PAMT parse. Cheap, and avoids stale data after the
            // user removes an overlay from a different surface.
            state.archive.detail = None;
            state.archive.diff = None;
        }
    });
}

fn render_groups_table(ui: &mut egui::Ui, state: &mut AppState) {
    if let Some(err) = state.archive.error.clone() {
        ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err);
        return;
    }

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.archive.filter)
                .desired_width(200.0)
                .hint_text("e.g. 0058"),
        );
        if !state.archive.filter.is_empty() && ui.button("Clear").clicked() {
            state.archive.filter.clear();
        }
    });

    let groups: Vec<ArchiveGroup> = state
        .archive
        .groups
        .clone()
        .unwrap_or_default();
    if groups.is_empty() {
        ui.label(
            egui::RichText::new(
                "No PAZ groups found. Set the Game Directory in Settings, \
                 then click Refresh.",
            )
            .italics(),
        );
        return;
    }

    let needle = state.archive.filter.trim().to_ascii_lowercase();
    let visible: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter_map(|(i, g)| {
            if needle.is_empty() || g.name.to_ascii_lowercase().contains(&needle) {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    ui.add_space(4.0);

    // Action holders — collected during render, applied after the table
    // closes so we don't re-borrow `state` while the table is iterating.
    let mut to_drill: Option<String> = None;
    let mut to_remove: Option<String> = None;
    let mut to_confirm: Option<String> = None;
    let mut cancel_confirm = false;

    let pending_removal = state.archive.remove_confirm_pending.clone();

    TableBuilder::new(ui)
        .id_salt("archive_groups_table")
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(60.0)) // group name
        .column(Column::auto().at_least(70.0)) // PAPGT registered
        .column(Column::auto().at_least(110.0)) // PAPGT checksum
        .column(Column::auto().at_least(110.0)) // PAMT checksum
        .column(Column::auto().at_least(70.0)) // file count
        .column(Column::auto().at_least(110.0)) // total size
        .column(Column::auto().at_least(80.0)) // backup
        .column(Column::remainder().at_least(180.0)) // actions / error
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong("Group"); });
            header.col(|ui| { ui.strong("In PAPGT"); });
            header.col(|ui| { ui.strong("PAPGT chk"); });
            header.col(|ui| { ui.strong("PAMT chk"); });
            header.col(|ui| { ui.strong("Files"); });
            header.col(|ui| { ui.strong("Size"); });
            header.col(|ui| { ui.strong("Backup"); });
            header.col(|ui| { ui.strong("Actions"); });
        })
        .body(|body| {
            body.rows(24.0, visible.len(), |mut row| {
                let row_idx = row.index();
                let g = &groups[visible[row_idx]];
                let mismatch = g.checksum_mismatch();

                row.col(|ui| {
                    let label = if mismatch {
                        egui::RichText::new(&g.name)
                            .color(egui::Color32::from_rgb(230, 90, 90))
                            .strong()
                    } else {
                        egui::RichText::new(&g.name).strong()
                    };
                    if ui.link(label).clicked() {
                        to_drill = Some(g.name.clone());
                    }
                });
                row.col(|ui| {
                    let (txt, color) = if g.registered_in_papgt {
                        ("yes", egui::Color32::from_rgb(120, 200, 120))
                    } else {
                        ("no", egui::Color32::from_gray(160))
                    };
                    ui.colored_label(color, txt);
                });
                row.col(|ui| {
                    if let Some(c) = g.papgt_checksum {
                        ui.label(format!("{:#010x}", c));
                    } else {
                        ui.weak("—");
                    }
                });
                row.col(|ui| {
                    if let Some(c) = g.pamt_checksum {
                        let txt = format!("{:#010x}", c);
                        if mismatch {
                            ui.colored_label(
                                egui::Color32::from_rgb(230, 90, 90),
                                txt,
                            );
                        } else {
                            ui.label(txt);
                        }
                    } else {
                        ui.weak("—");
                    }
                });
                row.col(|ui| {
                    ui.label(format!("{}", g.file_count));
                });
                row.col(|ui| {
                    ui.label(format_bytes(g.total_uncompressed_size));
                });
                row.col(|ui| {
                    if g.has_workbench_backup {
                        ui.colored_label(
                            egui::Color32::from_rgb(120, 200, 120),
                            "yes",
                        );
                    } else {
                        ui.weak("no");
                    }
                });
                row.col(|ui| {
                    if let Some(err) = &g.error {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 130, 80),
                            format!("error: {}", err),
                        );
                        return;
                    }

                    if pending_removal.as_deref() == Some(g.name.as_str()) {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 90, 90),
                            "Remove?",
                        );
                        if ui.button("Yes").clicked() {
                            to_remove = Some(g.name.clone());
                        }
                        if ui.button("Cancel").clicked() {
                            cancel_confirm = true;
                        }
                    } else {
                        if ui.button("Open").clicked() {
                            to_drill = Some(g.name.clone());
                        }
                        if ui.button("Remove").on_hover_text(
                            "Delete this overlay group's directory and drop its PAPGT \
                             entry. The base game group (e.g. 0008) should NOT be \
                             removed — only mod overlays.",
                        ).clicked() {
                            to_confirm = Some(g.name.clone());
                        }
                    }
                });
            });
        });

    // Apply collected actions outside the table closure.
    if let Some(name) = to_drill {
        enter_detail(state, &name);
    }
    if let Some(name) = to_confirm {
        state.archive.remove_confirm_pending = Some(name);
    }
    if cancel_confirm {
        state.archive.remove_confirm_pending = None;
    }
    if let Some(name) = to_remove {
        handle_remove_overlay(state, &name);
        state.archive.remove_confirm_pending = None;
    }
}

fn render_detail(ui: &mut egui::Ui, state: &mut AppState, name: &str) {
    ui.horizontal(|ui| {
        if ui.button("< Back to groups").clicked() {
            state.archive.mode = ArchiveMode::Groups;
            state.archive.detail = None;
        }
        ui.separator();
        ui.heading(format!("Group {}", name));
    });

    if state.archive.detail.as_ref().map(|d| d.name.as_str()) != Some(name) {
        // Reload detail for this group. Synchronous: PAMT parse is sub-ms.
        let game_dir = match &state.game_dir {
            Some(p) => p.clone(),
            None => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 90, 90),
                    "Game directory is not set.",
                );
                return;
            }
        };
        let group_dir = game_dir.join(name);
        match archive_editor::load_group_detail(&group_dir) {
            Ok(d) => state.archive.detail = Some(d),
            Err(e) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 90, 90),
                    format!("Failed to load detail for {}: {}", name, e),
                );
                return;
            }
        }
    }

    let detail = match &state.archive.detail {
        Some(d) => d.clone(),
        None => {
            ui.weak("Loading…");
            return;
        }
    };

    // Summary line above the directory listing.
    let total_files: usize = detail.directories.iter().map(|d| d.files.len()).sum();
    let total_bytes: u64 = detail
        .directories
        .iter()
        .flat_map(|d| d.files.iter())
        .map(|f| u64::from(f.uncompressed_size))
        .sum();
    ui.label(format!(
        "{} directories, {} files, {} uncompressed",
        detail.directories.len(),
        total_files,
        format_bytes(total_bytes),
    ));

    ui.separator();

    let mut to_open: Option<(String, String)> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for dir in &detail.directories {
                egui::CollapsingHeader::new(format!(
                    "{}  ({} files)",
                    if dir.path.is_empty() { "<root>" } else { dir.path.as_str() },
                    dir.files.len(),
                ))
                .id_salt(format!("archive_dir_{}_{}", name, dir.path))
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .id_salt(format!("archive_files_{}_{}", name, dir.path))
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(280.0).at_least(160.0).clip(true)) // name
                        .column(Column::auto().at_least(110.0)) // size
                        .column(Column::auto().at_least(80.0)) // compression
                        .column(Column::auto().at_least(80.0)) // crypto
                        .column(Column::auto().at_least(60.0)) // chunk id
                        .column(Column::remainder().at_least(120.0)) // actions
                        .header(20.0, |mut header| {
                            header.col(|ui| { ui.strong("Name"); });
                            header.col(|ui| { ui.strong("Size"); });
                            header.col(|ui| { ui.strong("Compression"); });
                            header.col(|ui| { ui.strong("Crypto"); });
                            header.col(|ui| { ui.strong("Chunk"); });
                            header.col(|ui| { ui.strong("Actions"); });
                        })
                        .body(|body| {
                            body.rows(20.0, dir.files.len(), |mut row| {
                                let f = &dir.files[row.index()];
                                row.col(|ui| { ui.label(&f.name); });
                                row.col(|ui| {
                                    ui.label(format_bytes(u64::from(f.uncompressed_size)));
                                });
                                row.col(|ui| { ui.label(f.compression_label()); });
                                row.col(|ui| { ui.label(f.crypto_label()); });
                                row.col(|ui| { ui.label(format!("{}", f.chunk_id)); });
                                row.col(|ui| {
                                    if ui
                                        .button("Open in Hex")
                                        .on_hover_text(
                                            "Extract this file's bytes (decrypt + \
                                             decompress) and show them in the hex viewer.",
                                        )
                                        .clicked()
                                    {
                                        to_open = Some((dir.path.clone(), f.name.clone()));
                                    }
                                });
                            });
                        });
                });
            }
        });

    if let Some((dir_path, file_name)) = to_open {
        open_file_in_hex(state, name, &dir_path, &file_name);
    }
}

fn render_hex(
    ui: &mut egui::Ui,
    state: &mut AppState,
    group: &str,
    dir_path: &str,
    file_name: &str,
) {
    ui.horizontal(|ui| {
        if ui.button("< Back to group").clicked() {
            state.archive.mode = ArchiveMode::Detail(group.to_string());
            state.archive.hex_bytes.clear();
            state.archive.hex_label.clear();
        }
        ui.separator();
        ui.heading(format!(
            "Hex: {} / {} / {}",
            group, dir_path, file_name,
        ));
    });

    if state.archive.hex_bytes.is_empty() {
        ui.label(
            egui::RichText::new("(no bytes — extraction failed earlier)")
                .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    ui.label(&state.archive.hex_label);
    ui.separator();
    crate::ui::hex_view::show(
        ui,
        &state.archive.hex_bytes,
        &mut state.archive.hex_state,
    );
}

fn render_diff(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("PAPGT vs workbench backup");
    ui.label(
        "Compares meta/0.papgt against meta/0.papgt.workbench_backup and \
         lists groups added since the first deploy, removed by mistake, or \
         changed (different checksum / optional flag / language).",
    );
    ui.add_space(4.0);

    if ui.button("Recompute").clicked() {
        state.archive.diff = None;
    }

    if state.archive.diff.is_none() {
        let game_dir = match &state.game_dir {
            Some(p) => p.clone(),
            None => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 90, 90),
                    "Game directory is not set.",
                );
                return;
            }
        };
        match archive_editor::diff_papgt_against_backup(&game_dir) {
            Ok(maybe_diff) => state.archive.diff = Some(maybe_diff),
            Err(e) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 90, 90),
                    format!("Failed to read PAPGT: {}", e),
                );
                return;
            }
        }
    }

    let cached = state.archive.diff.clone();
    let diff = match cached.as_ref().and_then(|x| x.as_ref()) {
        Some(d) => d,
        None => {
            ui.weak(
                "No backup found at meta/0.papgt.workbench_backup. The \
                 backup file is created the first time the workbench \
                 deploys an overlay.",
            );
            return;
        }
    };

    if diff.is_empty() {
        ui.colored_label(
            egui::Color32::from_rgb(120, 200, 120),
            "No differences. Live PAPGT matches the backup.",
        );
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if !diff.added.is_empty() {
                ui.add_space(4.0);
                ui.heading(format!("Added ({})", diff.added.len()));
                for entry in &diff.added {
                    ui.label(format!(
                        "  + {}  chk={:#010x}  optional={}  lang={:#06x}",
                        entry.group_name,
                        entry.pack_meta_checksum,
                        entry.is_optional,
                        entry.language,
                    ));
                }
            }
            if !diff.removed.is_empty() {
                ui.add_space(4.0);
                ui.heading(format!("Removed ({})", diff.removed.len()));
                for entry in &diff.removed {
                    ui.colored_label(
                        egui::Color32::from_rgb(230, 130, 80),
                        format!(
                            "  - {}  chk={:#010x}  optional={}  lang={:#06x}",
                            entry.group_name,
                            entry.pack_meta_checksum,
                            entry.is_optional,
                            entry.language,
                        ),
                    );
                }
            }
            if !diff.changed.is_empty() {
                ui.add_space(4.0);
                ui.heading(format!("Changed ({})", diff.changed.len()));
                for (backup, live) in &diff.changed {
                    ui.label(format!(
                        "  ~ {}",
                        backup.group_name,
                    ));
                    ui.label(format!(
                        "      backup: chk={:#010x}  optional={}  lang={:#06x}",
                        backup.pack_meta_checksum,
                        backup.is_optional,
                        backup.language,
                    ));
                    ui.label(format!(
                        "      live  : chk={:#010x}  optional={}  lang={:#06x}",
                        live.pack_meta_checksum,
                        live.is_optional,
                        live.language,
                    ));
                }
            }
        });
}

// ── State helpers ──────────────────────────────────────────────────────────

fn refresh_groups(state: &mut AppState) {
    let game_dir = match &state.game_dir {
        Some(p) => p.clone(),
        None => {
            state.archive.groups = Some(Vec::new());
            state.archive.error = Some(
                "Game directory is not set. Set it in Settings first.".to_string(),
            );
            return;
        }
    };
    state.archive.error = None;
    match archive_editor::enumerate_groups(&game_dir) {
        Ok(list) => {
            state.archive.groups = Some(list);
        }
        Err(e) => {
            state.archive.groups = Some(Vec::new());
            state.archive.error = Some(format!("Scan failed: {}", e));
        }
    }
}

fn enter_detail(state: &mut AppState, name: &str) {
    state.archive.mode = ArchiveMode::Detail(name.to_string());
    state.archive.detail = None; // force a fresh PAMT parse on next render
}

fn open_file_in_hex(state: &mut AppState, group: &str, dir_path: &str, file_name: &str) {
    let game_dir = match &state.game_dir {
        Some(p) => p.clone(),
        None => {
            state.toasts.warn("Set game dir first");
            return;
        }
    };
    let group_dir = game_dir.join(group);
    match archive_editor::extract_one_file(&group_dir, dir_path, file_name) {
        Ok(bytes) => {
            state.archive.hex_bytes = bytes;
            state.archive.hex_state = HexViewState::default();
            state.archive.hex_label = format!(
                "{} / {} / {}  —  {} bytes uncompressed",
                group,
                dir_path,
                file_name,
                state.archive.hex_bytes.len(),
            );
            state.archive.mode = ArchiveMode::Hex {
                group: group.to_string(),
                dir_path: dir_path.to_string(),
                file_name: file_name.to_string(),
            };
        }
        Err(e) => {
            state.toasts.error_with_details(
                format!("Failed to extract {}/{}", dir_path, file_name),
                e.to_string(),
            );
        }
    }
}

fn handle_remove_overlay(state: &mut AppState, group: &str) {
    let game_dir = match &state.game_dir {
        Some(p) => p.clone(),
        None => {
            state.toasts.warn("Set game dir first");
            return;
        }
    };
    match archive_editor::remove_overlay(&game_dir, group) {
        Ok(()) => {
            state.toasts.info(format!("Removed overlay {}", group));
            // Refresh so the user sees the row disappear.
            refresh_groups(state);
            state.archive.detail = None;
            state.archive.diff = None;
        }
        Err(e) => {
            state.toasts.error_with_details(
                format!("Failed to remove overlay {}", group),
                e.to_string(),
            );
        }
    }
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if b == 0 {
        return "0 B".to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_breakpoints() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.00 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn default_session_starts_in_groups_mode() {
        let s = ArchiveSession::default();
        assert_eq!(s.mode, ArchiveMode::Groups);
        assert!(s.groups.is_none());
        assert!(s.detail.is_none());
        assert!(s.diff.is_none());
        assert!(s.remove_confirm_pending.is_none());
    }
}
