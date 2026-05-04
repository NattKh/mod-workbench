use crate::state::AppState;

/// Action requested from the bottom bar. The actual handlers live on
/// `WorkbenchApp` (so they can mutate worker, file system, etc.); this enum
/// just gets the click-intent across the borrow boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BottomBarAction {
    Apply,
    Remove,
    StartGame,
}

/// Bottom status bar showing game dir, active table, change count, and
/// quick-action buttons (Apply / Remove Overlay / Start Game).
///
/// Returns the action the user clicked this frame, or `None`. Caller
/// dispatches via `WorkbenchApp::action_*`.
pub fn show(ui: &mut egui::Ui, state: &AppState) -> Option<BottomBarAction> {
    let mut clicked: Option<BottomBarAction> = None;

    ui.horizontal(|ui| {
        // Game directory
        let dir_text = match &state.game_dir {
            Some(path) => path.display().to_string(),
            None => "No game dir set".to_string(),
        };
        ui.label(dir_text);

        ui.separator();

        // Active tab
        if let Some(active) = state.active_table() {
            ui.label(format!(
                "{} ({} entries)",
                active.dispatch_name,
                active.entries.len()
            ));
        } else {
            ui.label("No table loaded");
        }

        ui.separator();

        // Per-tab change count for the focused tab.
        let count = state
            .active_table()
            .map(|t| t.changes.change_count())
            .unwrap_or(0);
        if count > 0 {
            ui.label(
                egui::RichText::new(format!("{} entries modified", count))
                    .color(egui::Color32::from_rgb(255, 180, 50)),
            );
        } else {
            ui.label("No changes");
        }

        // Quick-action buttons (right-aligned). These mirror the File menu
        // entries so users can iterate without opening menus. Color-coded
        // so the destructive (Remove) action stands out from Apply.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Status message stays on the rightmost edge; buttons sit
            // to its left.
            ui.label(&state.status);
            ui.separator();

            // Start Game — green tint; needs a game dir to be useful.
            let can_start = state.game_dir.is_some();
            if ui
                .add_enabled(
                    can_start,
                    egui::Button::new(
                        egui::RichText::new("▶ Start Game")
                            .color(egui::Color32::from_rgb(140, 220, 140)),
                    ),
                )
                .on_hover_text("Launch CrimsonDesert.exe from the configured game directory.")
                .clicked()
            {
                clicked = Some(BottomBarAction::StartGame);
            }

            // Remove Overlay — red tint; restores vanilla in one click.
            let can_remove = state.game_dir.is_some();
            if ui
                .add_enabled(
                    can_remove,
                    egui::Button::new(
                        egui::RichText::new("✖ Remove Overlay")
                            .color(egui::Color32::from_rgb(230, 120, 120)),
                    ),
                )
                .on_hover_text(
                    "Delete the overlay directory from the game and remove its \
                     entry from PAPGT, in one go.",
                )
                .clicked()
            {
                clicked = Some(BottomBarAction::Remove);
            }

            // Apply to Game — primary action; only enabled when there's
            // an active table loaded. The deploy path itself takes a
            // pre-snapshot so this is safe to spam.
            let can_apply = state.game_dir.is_some() && state.active_table().is_some();
            if ui
                .add_enabled(
                    can_apply,
                    egui::Button::new(
                        egui::RichText::new("⬆ Apply to Game")
                            .color(egui::Color32::from_rgb(140, 200, 240))
                            .strong(),
                    ),
                )
                .on_hover_text(
                    "Pack the active table as a PAZ overlay and deploy to the \
                     game directory. Quick-test workflow.",
                )
                .clicked()
            {
                clicked = Some(BottomBarAction::Apply);
            }
        });
    });

    clicked
}
