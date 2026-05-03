//! Mod library + profile manager panel.
//!
//! Renders the central panel when [`MainView::Library`] is active. The view
//! has three logical regions stacked top-to-bottom:
//!
//! 1. **Profile selector** — dropdown of saved profiles, "New Profile",
//!    "Delete Profile", "Apply Profile" buttons, and an editable name field
//!    for the active profile.
//! 2. **Two-column mod list** — left side is the on-disk library, right
//!    side is the active profile's ordered mod list. Buttons in the gutter
//!    move mods between the two.
//! 3. **Toolbar** — "Import Mod...", "Open Library Folder...", "Refresh"
//!    buttons sit at the bottom so they're available regardless of scroll
//!    position in the lists.
//!
//! ## Why deferred actions
//!
//! Like the conflict panel, this view iterates the library / profile lists
//! while rendering, so any mutation (re-order, remove, apply) is queued
//! into an [`Action`] enum and applied after the render pass. This avoids
//! taking a second mutable borrow on `state` from inside the closure.
//!
//! ## Persistence
//!
//! Every mutation that touches `state.profile_store` calls
//! [`crate::profile::save_store`] before returning so a crash never loses
//! the user's curation. Profile-store IO failures surface as toasts but
//! don't abort the action — losing the on-disk record is recoverable, but
//! losing the in-memory action would silently betray the user.

use std::path::{Path, PathBuf};

use crate::mod_library::{self, LibraryMod};
use crate::profile;
use crate::state::{AppState, MainView};

/// Deferred mutation collected while rendering. Applied after the render
/// pass returns so we never mutate `state` mid-iteration.
enum Action {
    /// Refresh the library by re-scanning [`crate::mod_library::library_dir`].
    RefreshLibrary,
    /// Trigger the file-picker for `Import Mod...`. The picker itself runs
    /// inline; this action is purely the post-pick "copy + refresh" step.
    ImportMod(Vec<PathBuf>),
    /// Delete a mod from the library at `library` index.
    DeleteFromLibrary(usize),
    /// Open the library directory in the OS file explorer (best effort).
    OpenLibraryFolder,
    /// Create a brand-new profile and switch to it.
    NewProfile,
    /// Remove the named profile.
    DeleteProfile(String),
    /// Switch the active profile to `name`. Re-saves the store on success.
    SwitchActive(String),
    /// Append `library_idx` to the active profile's `active_mods`.
    AddToActive(usize),
    /// Drop the entry at `idx` from the active profile's `active_mods`.
    RemoveFromActive(usize),
    /// Move the active profile's mod at `idx` up (toward index 0 = higher
    /// priority).
    MoveUp(usize),
    /// Move down (toward higher index = lower priority).
    MoveDown(usize),
    /// Rename the active profile.
    RenameActive { old: String, new: String },
    /// Apply the active profile to the game directory.
    ApplyActive,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Mod Library");
    ui.label(
        egui::RichText::new(
            "Browse mods saved to your local library and bundle them into \
             named profiles. Apply a profile to deploy every mod in it as a \
             stack of overlay groups.",
        )
        .weak(),
    );
    ui.separator();

    // Lazy first-load. The library directory is created on first scan if it
    // doesn't exist, so the UI never has to special-case "fresh install".
    if !state.library_loaded {
        refresh_library(state);
    }

    let mut pending: Option<Action> = None;

    // ── Profile selector strip ─────────────────────────────────────────────
    pending = render_profile_strip(ui, state).or(pending);
    ui.separator();

    // ── Two-column mod list ────────────────────────────────────────────────
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .id_salt("library_panel_scroll")
        .show(ui, |ui| {
            ui.columns(2, |cols| {
                if let Some(action) =
                    render_library_column(&mut cols[0], state)
                {
                    pending = Some(action);
                }
                if let Some(action) =
                    render_active_profile_column(&mut cols[1], state)
                {
                    pending = Some(action);
                }
            });
        });

    ui.separator();

    // ── Toolbar at the bottom — universal regardless of scroll ─────────────
    ui.horizontal(|ui| {
        if ui
            .button("Import Mod...")
            .on_hover_text(
                "Pick one or more JSON / .modpkg files; they're copied \
                 into the local library and become available to every \
                 profile.",
            )
            .clicked()
        {
            if let Some(paths) = rfd::FileDialog::new()
                .set_title("Import Mod into Library")
                .add_filter("Mod files", &["json", "modpkg"])
                .pick_files()
            {
                pending = Some(Action::ImportMod(paths));
            }
        }
        if ui.button("Open Library Folder...").clicked() {
            pending = Some(Action::OpenLibraryFolder);
        }
        if ui.button("Refresh").clicked() {
            pending = Some(Action::RefreshLibrary);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(
                    mod_library::library_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<no platform data dir>".to_string()),
                )
                .weak()
                .small(),
            );
        });
    });

    if let Some(action) = pending {
        apply_action(state, action);
    }
}

// ── Section renderers ───────────────────────────────────────────────────────

/// Render the profile selector strip (dropdown + buttons + name field).
fn render_profile_strip(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut pending = None;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Profile:").strong());

        let active_name = state.profile_store.active_profile.clone();
        let display = active_name.clone().unwrap_or_else(|| "(none)".to_string());
        // Snapshot the profile names so we can render the menu without
        // holding a borrow on state.profile_store.
        let names: Vec<String> = state
            .profile_store
            .profiles
            .iter()
            .map(|p| p.name.clone())
            .collect();

        egui::ComboBox::from_id_salt("library_profile_combo")
            .selected_text(display)
            .show_ui(ui, |ui| {
                for name in &names {
                    if ui
                        .selectable_label(active_name.as_deref() == Some(name.as_str()), name)
                        .clicked()
                    {
                        pending = Some(Action::SwitchActive(name.clone()));
                    }
                }
                if names.is_empty() {
                    ui.label("(no profiles)");
                }
            });

        if ui.button("New Profile").clicked() {
            pending = Some(Action::NewProfile);
        }
        if ui
            .add_enabled(active_name.is_some(), egui::Button::new("Delete Profile"))
            .on_hover_text(if active_name.is_some() {
                "Delete the active profile (the mods in your library are kept)."
            } else {
                "No profile selected"
            })
            .clicked()
        {
            if let Some(name) = active_name.clone() {
                pending = Some(Action::DeleteProfile(name));
            }
        }

        let apply_enabled =
            state.game_dir.is_some() && active_name.is_some() && {
                state
                    .profile_store
                    .active()
                    .map(|p| !p.active_mods.is_empty())
                    .unwrap_or(false)
            };
        if ui
            .add_enabled(apply_enabled, egui::Button::new("Apply Profile"))
            .on_hover_text(if state.game_dir.is_none() {
                "Set the game directory in File menu before applying."
            } else if active_name.is_none() {
                "Select a profile first."
            } else if !apply_enabled {
                "Active profile has no mods to apply."
            } else {
                "Restore vanilla, then deploy each mod in the active profile \
                 as a separate overlay group."
            })
            .clicked()
        {
            pending = Some(Action::ApplyActive);
        }
    });

    // Inline rename for the active profile, kept on its own row so a long
    // name doesn't push the buttons around. Editing here updates the in-
    // memory profile only when the user hits Enter or blurs the field —
    // that way every keystroke isn't a separate save.
    if let Some(active_name) = state.profile_store.active_profile.clone() {
        ui.horizontal(|ui| {
            ui.label("Name:");
            // We mutate a temporary buffer because direct in-place editing
            // of profile_store while iterating elsewhere is awkward.
            let mut buf = active_name.clone();
            let resp = ui.add(
                egui::TextEdit::singleline(&mut buf)
                    .desired_width(220.0)
                    .hint_text("profile name"),
            );
            let committed = resp.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));
            // Also commit on focus loss so blurring the field saves the rename.
            let committed = committed || (resp.changed() && resp.lost_focus());
            if committed && buf != active_name {
                pending = Some(Action::RenameActive {
                    old: active_name.clone(),
                    new: buf,
                });
            }
        });
    }

    pending
}

/// Left column: the on-disk library.
fn render_library_column(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut pending = None;
    ui.heading(format!("All Mods ({})", state.library.len()));
    if state.library.is_empty() {
        ui.label(
            egui::RichText::new(
                "No mods in your library yet. Use Import Mod... to add files \
                 (or drop .json files directly into the library folder).",
            )
            .italics(),
        );
        return None;
    }

    let active_paths: std::collections::HashSet<PathBuf> = state
        .profile_store
        .active()
        .map(|p| p.active_mods.iter().cloned().collect())
        .unwrap_or_default();

    for (i, m) in state.library.iter().enumerate() {
        let already_in_profile = active_paths.contains(&m.path);
        ui.group(|ui| {
            render_mod_card(ui, m);
            ui.horizontal(|ui| {
                let add_label = if already_in_profile { "Added" } else { "→ Add" };
                let add_enabled = !already_in_profile
                    && state.profile_store.active_profile.is_some();
                if ui
                    .add_enabled(add_enabled, egui::Button::new(add_label))
                    .on_hover_text(if already_in_profile {
                        "Already in the active profile."
                    } else if state.profile_store.active_profile.is_none() {
                        "No active profile — create one first."
                    } else {
                        "Append this mod to the active profile."
                    })
                    .clicked()
                {
                    pending = Some(Action::AddToActive(i));
                }
                if ui
                    .small_button("Delete")
                    .on_hover_text("Remove the file from the library directory.")
                    .clicked()
                {
                    pending = Some(Action::DeleteFromLibrary(i));
                }
            });
        });
    }
    pending
}

/// Right column: the active profile's ordered mod list.
fn render_active_profile_column(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut pending = None;

    let Some(active) = state.profile_store.active() else {
        ui.heading("Active Mods");
        ui.label(
            egui::RichText::new(
                "No active profile. Click New Profile to create one.",
            )
            .italics(),
        );
        return None;
    };

    ui.heading(format!(
        "Active Mods — {} ({})",
        active.name,
        active.active_mods.len(),
    ));
    if active.active_mods.is_empty() {
        ui.label(
            egui::RichText::new(
                "Profile is empty. Click → Add on a mod in the library to \
                 stack it into this profile.",
            )
            .italics(),
        );
        return None;
    }

    let total = active.active_mods.len();
    for (idx, mod_path) in active.active_mods.iter().enumerate() {
        ui.group(|ui| {
            // Look up the library entry for richer rendering when present.
            // If the path no longer points to a known library mod (file was
            // deleted out from under us), we fall back to a plain row that
            // still lets the user remove the broken reference.
            let library_match = state.library.iter().find(|m| &m.path == mod_path);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("#{}", idx + 1))
                        .small()
                        .weak(),
                );
                match library_match {
                    Some(m) => render_mod_card_inline(ui, m),
                    None => {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 80, 80),
                            format!("[missing] {}", mod_path.display()),
                        );
                    }
                }
            });
            ui.horizontal(|ui| {
                let up_enabled = idx > 0;
                let down_enabled = idx + 1 < total;
                if ui
                    .add_enabled(up_enabled, egui::Button::new("↑"))
                    .on_hover_text("Move up — higher priority on conflict.")
                    .clicked()
                {
                    pending = Some(Action::MoveUp(idx));
                }
                if ui
                    .add_enabled(down_enabled, egui::Button::new("↓"))
                    .on_hover_text("Move down — lower priority on conflict.")
                    .clicked()
                {
                    pending = Some(Action::MoveDown(idx));
                }
                if ui
                    .small_button("← Remove")
                    .on_hover_text("Drop this mod from the active profile.")
                    .clicked()
                {
                    pending = Some(Action::RemoveFromActive(idx));
                }
            });
        });
    }

    pending
}

// ── Mod card renderers ──────────────────────────────────────────────────────

/// Mod card body — name (strong), author + version, change count, and the
/// list of tables touched. Used in the library column where each entry
/// gets a multi-line block.
fn render_mod_card(ui: &mut egui::Ui, m: &LibraryMod) {
    ui.label(
        egui::RichText::new(&m.metadata.name)
            .strong()
            .size(14.0),
    )
    .on_hover_text(m.path.display().to_string());
    let meta_line = match (&m.metadata.author, &m.metadata.version) {
        (Some(a), Some(v)) => format!("by {}  ·  v{}", a, v),
        (Some(a), None) => format!("by {}", a),
        (None, Some(v)) => format!("v{}", v),
        (None, None) => "—".to_string(),
    };
    ui.label(egui::RichText::new(meta_line).weak());
    ui.label(format!("{} field changes", m.change_count));
    let tables = if m.tables_touched.is_empty() {
        "(no tables resolved — open the file to inspect)".to_string()
    } else {
        m.tables_touched.join(", ")
    };
    ui.label(
        egui::RichText::new(format!("Tables: {}", tables))
            .small()
            .weak(),
    );
}

/// Compact one-line card. Used in the active-profile column where each
/// entry needs to coexist with up/down/remove buttons on a single row.
fn render_mod_card_inline(ui: &mut egui::Ui, m: &LibraryMod) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(&m.metadata.name).strong())
            .on_hover_text(m.path.display().to_string());
        ui.label(
            egui::RichText::new(format!(
                "{} change(s)  ·  {}",
                m.change_count,
                if m.tables_touched.is_empty() {
                    "—".to_string()
                } else {
                    m.tables_touched.join(", ")
                },
            ))
            .small()
            .weak(),
        );
    });
}

// ── Action dispatch ─────────────────────────────────────────────────────────

fn apply_action(state: &mut AppState, action: Action) {
    match action {
        Action::RefreshLibrary => refresh_library(state),
        Action::ImportMod(paths) => import_paths(state, paths),
        Action::DeleteFromLibrary(idx) => delete_library_entry(state, idx),
        Action::OpenLibraryFolder => open_library_folder(state),
        Action::NewProfile => new_profile(state),
        Action::DeleteProfile(name) => delete_profile(state, &name),
        Action::SwitchActive(name) => switch_active(state, &name),
        Action::AddToActive(library_idx) => add_to_active(state, library_idx),
        Action::RemoveFromActive(idx) => remove_from_active(state, idx),
        Action::MoveUp(idx) => move_in_active(state, idx, -1),
        Action::MoveDown(idx) => move_in_active(state, idx, 1),
        Action::RenameActive { old, new } => rename_active(state, &old, &new),
        Action::ApplyActive => apply_active(state),
    }
}

fn refresh_library(state: &mut AppState) {
    match mod_library::scan_library() {
        Ok(report) => {
            state.library = report.mods;
            state.library_loaded = true;
            for (path, msg) in report.errors {
                state.toasts.warn(format!(
                    "Skipped {}: {}",
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.display().to_string()),
                    msg
                ));
            }
        }
        Err(e) => {
            state.toasts.error_with_details(
                "Library scan failed",
                e.to_string(),
            );
        }
    }
}

fn import_paths(state: &mut AppState, paths: Vec<PathBuf>) {
    let mut imported = 0usize;
    for p in paths {
        match mod_library::import_to_library(&p) {
            Ok(_dest) => imported += 1,
            Err(e) => {
                state.toasts.error_with_details(
                    format!(
                        "Failed to import {}",
                        p.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| p.display().to_string()),
                    ),
                    e.to_string(),
                );
            }
        }
    }
    if imported > 0 {
        state
            .toasts
            .info(format!("Imported {} mod(s) into the library", imported));
        refresh_library(state);
    }
}

fn delete_library_entry(state: &mut AppState, idx: usize) {
    let Some(m) = state.library.get(idx).cloned() else {
        return;
    };
    match mod_library::delete_from_library(&m.path) {
        Ok(()) => {
            state
                .toasts
                .info(format!("Removed {} from library", m.metadata.name));
            // Also drop the entry from any profile that references it so we
            // don't leave dangling pointers behind.
            let mut profile_dirty = false;
            for p in state.profile_store.profiles.iter_mut() {
                let before = p.active_mods.len();
                p.active_mods.retain(|q| q != &m.path);
                if p.active_mods.len() != before {
                    profile_dirty = true;
                }
            }
            if profile_dirty {
                if let Err(e) = profile::save_store(&state.profile_store) {
                    state.toasts.warn(format!(
                        "Library entry removed but profiles save failed: {}",
                        e
                    ));
                }
            }
            refresh_library(state);
        }
        Err(e) => {
            state
                .toasts
                .error_with_details("Delete failed", e.to_string());
        }
    }
}

fn open_library_folder(state: &mut AppState) {
    let Some(dir) = mod_library::library_dir() else {
        state
            .toasts
            .warn("No platform data directory available — library disabled.");
        return;
    };
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            state
                .toasts
                .error_with_details("Failed to create library dir", e.to_string());
            return;
        }
    }
    if let Err(e) = open_in_explorer(&dir) {
        state
            .toasts
            .error_with_details("Failed to open library folder", e.to_string());
    }
}

/// Best-effort "Reveal in Explorer" — uses `cmd /c start ""` on Windows so
/// the call doesn't block. Other platforms get a similar `xdg-open`/`open`
/// invocation. We stay platform-aware to avoid pulling in an extra dep.
fn open_in_explorer(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("explorer.exe").arg(path).spawn()?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("open").arg(path).spawn()?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::process::Command;
        Command::new("xdg-open").arg(path).spawn()?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no opener for this platform",
    ))
}

fn new_profile(state: &mut AppState) {
    let name = state.profile_store.add_unique("New Profile");
    state.profile_store.active_profile = Some(name.clone());
    if let Err(e) = profile::save_store(&state.profile_store) {
        state
            .toasts
            .error_with_details("Failed to save profile store", e.to_string());
        return;
    }
    state.toasts.info(format!("Created profile '{}'", name));
}

fn delete_profile(state: &mut AppState, name: &str) {
    if state.profile_store.remove(name) {
        // Pick a fallback active profile so the UI doesn't end up in a
        // "no active" state when other profiles still exist.
        if state.profile_store.active_profile.is_none() {
            if let Some(first) = state.profile_store.profiles.first() {
                state.profile_store.active_profile = Some(first.name.clone());
            }
        }
        if let Err(e) = profile::save_store(&state.profile_store) {
            state.toasts.warn(format!(
                "Profile removed but save failed: {}",
                e
            ));
        } else {
            state
                .toasts
                .info(format!("Deleted profile '{}'", name));
        }
    }
}

fn switch_active(state: &mut AppState, name: &str) {
    if state.profile_store.get(name).is_none() {
        return;
    }
    state.profile_store.active_profile = Some(name.to_string());
    if let Err(e) = profile::save_store(&state.profile_store) {
        state
            .toasts
            .warn(format!("Switched profile but save failed: {}", e));
    }
}

fn add_to_active(state: &mut AppState, library_idx: usize) {
    let Some(m) = state.library.get(library_idx).cloned() else {
        return;
    };
    let Some(active) = state.profile_store.active_mut() else {
        state
            .toasts
            .warn("No active profile — create one before adding mods.");
        return;
    };
    if active.active_mods.iter().any(|p| p == &m.path) {
        // Idempotent — adding twice silently does nothing.
        return;
    }
    active.active_mods.push(m.path.clone());
    if let Err(e) = profile::save_store(&state.profile_store) {
        state.toasts.warn(format!(
            "Added '{}' but save failed: {}",
            m.metadata.name, e
        ));
    }
}

fn remove_from_active(state: &mut AppState, idx: usize) {
    let Some(active) = state.profile_store.active_mut() else {
        return;
    };
    if idx >= active.active_mods.len() {
        return;
    }
    active.active_mods.remove(idx);
    if let Err(e) = profile::save_store(&state.profile_store) {
        state
            .toasts
            .warn(format!("Removed but save failed: {}", e));
    }
}

/// Move active_mods[idx] by `delta` slots. `delta == -1` moves toward index 0
/// (higher priority); `delta == 1` moves the other way. Bounds are clamped
/// silently.
fn move_in_active(state: &mut AppState, idx: usize, delta: i32) {
    let Some(active) = state.profile_store.active_mut() else {
        return;
    };
    let len = active.active_mods.len();
    if idx >= len {
        return;
    }
    let target = (idx as i32 + delta).max(0).min(len as i32 - 1) as usize;
    if target == idx {
        return;
    }
    let item = active.active_mods.remove(idx);
    active.active_mods.insert(target, item);
    if let Err(e) = profile::save_store(&state.profile_store) {
        state
            .toasts
            .warn(format!("Reordered but save failed: {}", e));
    }
}

fn rename_active(state: &mut AppState, old: &str, new: &str) {
    let trimmed = new.trim();
    if trimmed.is_empty() {
        state.toasts.warn("Profile name can't be empty.");
        return;
    }
    if !state.profile_store.rename(old, trimmed) {
        state
            .toasts
            .warn(format!("Couldn't rename to '{}': name taken or invalid.", trimmed));
        return;
    }
    if let Err(e) = profile::save_store(&state.profile_store) {
        state
            .toasts
            .warn(format!("Renamed but save failed: {}", e));
    }
}

fn apply_active(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state.toasts.warn("Set the game directory in File menu first.");
        return;
    };
    let Some(active) = state.profile_store.active().cloned() else {
        state.toasts.warn("No active profile.");
        return;
    };

    // Apply is synchronous; on a typical profile (1–10 mods) this completes
    // in a few hundred ms. If profiles grow past ~25 entries we should
    // push this onto the worker, but it isn't worth the complexity today.
    match profile::apply_profile(&active, &game_dir, &state.tables) {
        Ok(report) => {
            let deployed = report.deployed.len();
            let skipped = report.skipped.len();
            if let Some(msg) = report.restore_failed.as_ref() {
                state
                    .toasts
                    .warn(format!("Pre-apply restore had issues: {}", msg));
            }
            if skipped > 0 {
                let detail = report
                    .skipped
                    .iter()
                    .map(|s| {
                        format!(
                            "• {}: {}",
                            s.mod_path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| s.mod_path.display().to_string()),
                            s.reason
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                state.toasts.error_with_details(
                    format!(
                        "Profile '{}': deployed {} / skipped {}",
                        active.name, deployed, skipped,
                    ),
                    detail,
                );
            } else if deployed == 0 {
                state.toasts.info(format!(
                    "Profile '{}' applied — vanilla baseline (no mods).",
                    active.name
                ));
            } else {
                state.toasts.info(format!(
                    "Profile '{}' applied — {} mod(s) deployed.",
                    active.name, deployed,
                ));
            }
        }
        Err(e) => {
            state.toasts.error_with_details(
                format!("Apply '{}' failed", active.name),
                e.to_string(),
            );
        }
    }

    // Switch the user back to the editor view since the apply is done; they
    // probably want to test in-game now.
    state.main_view = MainView::PabgbTables;
}
