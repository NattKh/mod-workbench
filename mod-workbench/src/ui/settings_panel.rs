//! Settings panel.
//!
//! Renders into the central panel when `state.main_view == MainView::Settings`.
//! Exposes the user-tunable preferences that don't already have their own
//! menu item:
//!
//! - Game directory and catalog path (with "Change..." file pickers).
//! - Theme picker (Dark / Light / Crimson).
//! - Deploy snapshot retention count.
//! - Reset-to-defaults button.
//!
//! Mutations are persisted via `state.config.save()` immediately so closing
//! the app doesn't lose the new settings (mirroring the existing File menu
//! pattern). The panel is intentionally simple — there's no scroll area
//! because the field set fits comfortably in the central panel.
//!
//! ## Theme application
//!
//! Picking a new theme here updates `state.config.theme`, persists it, and
//! flips `state.theme_change_pending` so `WorkbenchApp::update` reapplies
//! visuals on the same frame. Doing it in two steps avoids holding a borrow
//! on `state` across `theme::apply_theme(ctx, ...)`.

use crate::state::{AppState, MainView};
use crate::theme::{self, Theme};

/// Default snapshot retention used when the config doesn't override it.
/// Mirrors `deploy::SNAPSHOT_RETAIN_COUNT`. The deploy module owns the real
/// constant; we duplicate the literal here only so the settings panel has
/// a sensible "default" hint without leaking a public constant for one UI.
const DEFAULT_SNAPSHOT_RETENTION: usize = 20;

/// Render the settings panel and apply any user-driven changes immediately.
///
/// Returns nothing — all mutations land directly on `state` (and disk via
/// `config.save()`). Theme changes set `state.theme_change_pending` so the
/// app shell can re-apply visuals on the next frame.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("Settings");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Close").clicked() {
                state.main_view = MainView::PabgbTables;
            }
        });
    });
    ui.separator();

    let mut config_dirty = false;

    // ---- Game directory ---------------------------------------------------
    ui.heading("Paths");
    ui.add_space(4.0);
    egui::Grid::new("settings_paths_grid")
        .num_columns(3)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Game directory:");
            ui.label(
                state
                    .game_dir
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<not set>".to_string()),
            );
            if ui.button("Change...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Select Crimson Desert Game Directory")
                    .pick_folder()
                {
                    if path.join("meta/0.papgt").exists() {
                        state.game_dir = Some(path.clone());
                        state.config.game_dir = Some(path.clone());
                        state
                            .toasts
                            .info(format!("Game dir set: {}", path.display()));
                        config_dirty = true;
                    } else {
                        state
                            .toasts
                            .error("Invalid game dir (meta/0.papgt not found)");
                    }
                }
            }
            ui.end_row();

            ui.label("Catalog path:");
            ui.label(
                state
                    .config
                    .catalog_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<not set>".to_string()),
            );
            if ui.button("Change...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Select Catalog JSON")
                    .add_filter("JSON", &["json"])
                    .pick_file()
                {
                    state.config.catalog_path = Some(path.clone());
                    state.toasts.info(format!(
                        "Catalog path set: {}",
                        path.display()
                    ));
                    config_dirty = true;
                }
            }
            ui.end_row();
        });

    ui.add_space(8.0);

    // ---- Theme ------------------------------------------------------------
    ui.heading("Appearance");
    ui.add_space(4.0);
    let current_theme = state
        .config
        .theme
        .as_deref()
        .map(theme::from_str)
        .unwrap_or_default();
    let mut selected = current_theme;
    ui.horizontal(|ui| {
        ui.label("Theme:");
        egui::ComboBox::from_id_salt("settings_theme_combo")
            .selected_text(theme_label(selected))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut selected, Theme::Dark, theme_label(Theme::Dark));
                ui.selectable_value(&mut selected, Theme::Light, theme_label(Theme::Light));
                ui.selectable_value(
                    &mut selected,
                    Theme::Crimson,
                    theme_label(Theme::Crimson),
                );
            });
    });
    if selected != current_theme {
        state.config.theme = Some(theme::to_str(selected).to_string());
        // Apply right away so the user sees the change without leaving the panel.
        theme::apply_theme(ui.ctx(), selected);
        config_dirty = true;
    }

    ui.add_space(8.0);

    // ---- Backups ----------------------------------------------------------
    ui.heading("Backups");
    ui.add_space(4.0);
    let mut retention =
        state.config.snapshot_retention.unwrap_or(DEFAULT_SNAPSHOT_RETENTION);
    ui.horizontal(|ui| {
        ui.label("Snapshot retention:");
        if ui
            .add(egui::DragValue::new(&mut retention).range(1..=200))
            .on_hover_text(
                "How many deploy snapshots to keep before pruning the oldest. \
                 The deploy action enforces this after each successful run.",
            )
            .changed()
        {
            state.config.snapshot_retention = Some(retention);
            config_dirty = true;
        }
        ui.weak(format!("(default: {})", DEFAULT_SNAPSHOT_RETENTION));
    });

    ui.add_space(12.0);
    ui.separator();

    // ---- Reset ------------------------------------------------------------
    ui.horizontal(|ui| {
        if ui
            .button("Reset to defaults")
            .on_hover_text(
                "Restores the default theme and snapshot retention. \
                 Game dir and catalog path are left as-is so you don't have \
                 to re-pick them.",
            )
            .clicked()
        {
            state.config.theme = Some(theme::to_str(Theme::default()).to_string());
            state.config.snapshot_retention = None;
            theme::apply_theme(ui.ctx(), Theme::default());
            config_dirty = true;
            state.toasts.info("Settings reset to defaults");
        }
    });

    if config_dirty {
        if let Err(e) = state.config.save() {
            state
                .toasts
                .error_with_details("Failed to save settings", e.to_string());
        }
    }
}

/// Human-readable label for a theme — used in the combo box and in toasts.
pub fn theme_label(theme: Theme) -> &'static str {
    match theme {
        Theme::Dark => "Dark",
        Theme::Light => "Light",
        Theme::Crimson => "Crimson",
    }
}
