//! Wizards panel — central panel when [`MainView::Wizards`] is active.
//!
//! Renders two sections:
//!
//! 1. **Picker**: list of every wizard returned by
//!    [`crate::wizards::available_wizards`]. Clicking a row opens the
//!    wizard in step 2.
//! 2. **Live wizard**: hosted in an [`egui::Window`] anchored to the centre
//!    of the screen. The wizard owns its own multi-step UI; this panel
//!    only inspects [`crate::wizards::WizardResult`] to decide whether to
//!    keep the dialog open.
//!
//! The "active wizard" lives on [`AppState::active_wizard`] so switching
//! views or scrolling doesn't drop the user's mid-flow state.

use crate::state::AppState;
use crate::wizards::{available_wizards, WizardResult};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Wizards");
    ui.label(
        egui::RichText::new(
            "Step-by-step flows for common mod tasks. Each wizard composes \
             existing primitives (templates, field edits, paseq swaps) into \
             one guided sequence.",
        )
        .weak(),
    );
    ui.separator();

    // Picker: list of wizards. We only show this when no wizard is open
    // because mid-flow we don't want the user firing a second wizard on top
    // of the first.
    if state.active_wizard.is_none() {
        let wizards = available_wizards();
        for (i, wiz) in wizards.into_iter().enumerate() {
            let _ = i; // index unused; we identify wizards by name.
            let name = wiz.name().to_string();
            let desc = wiz.description().to_string();
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&name).strong());
                        ui.label(egui::RichText::new(&desc).weak());
                    });
                    if ui.button("Open").clicked() {
                        // Re-instantiate to pick up a fresh wizard with
                        // default state. We can't reuse `wiz` because the
                        // for loop already moved it.
                        if let Some(fresh) = wizard_by_name(&name) {
                            state.active_wizard = Some(fresh);
                        }
                    }
                });
            });
        }
    } else {
        ui.label(
            egui::RichText::new(
                "A wizard is open. Complete or cancel it from the dialog \
                 below before launching a new one.",
            )
            .italics(),
        );
    }

    // Live wizard window. We pull the active wizard out of state for the
    // call so the wizard's `show` can take `&mut state` without aliasing,
    // then put it back afterwards (unless the wizard ended).
    let mut wiz_box = state.active_wizard.take();
    if let Some(mut wiz) = wiz_box.take() {
        let title = wiz.name().to_string();
        let mut still_running = true;
        let mut result_after_render = WizardResult::InProgress;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ui.ctx(), |ui| {
                result_after_render = wiz.show(ui, state);
            });

        match result_after_render {
            WizardResult::InProgress => {
                // Put the wizard back so it lives across frames.
                state.active_wizard = Some(wiz);
            }
            WizardResult::Cancelled => {
                state.toasts.info("Wizard cancelled");
                still_running = false;
            }
            WizardResult::Completed {
                mod_metadata: _,
                changes_applied,
                summary,
            } => {
                state.toasts.info(format!(
                    "{} ({} change{})",
                    summary,
                    changes_applied,
                    if changes_applied == 1 { "" } else { "s" }
                ));
                still_running = false;
            }
        }
        if !still_running {
            state.active_wizard = None;
        }
    }
}

/// Re-instantiate a wizard by display name. Used by the picker so we don't
/// have to keep the listed `Box<dyn Wizard>` alive after the user clicks
/// "Open" (which would conflict with putting it on `AppState`).
fn wizard_by_name(name: &str) -> Option<Box<dyn crate::wizards::Wizard>> {
    available_wizards().into_iter().find(|w| w.name() == name)
}
