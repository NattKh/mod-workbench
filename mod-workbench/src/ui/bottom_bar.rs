use crate::state::AppState;

/// Bottom status bar showing game dir, active table, and change count.
pub fn show(ui: &mut egui::Ui, state: &AppState) {
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

        // Status message (right-aligned)
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(&state.status);
        });
    });
}
