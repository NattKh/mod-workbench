//! Horizontal tab bar above the entry table.
//!
//! Renders one tab per entry in [`AppState::open_tabs`]. Each tab shows the
//! table's dispatch name, an entry count, and a `●` indicator when the tab
//! has unsaved changes. The active tab is drawn with the egui selection
//! background; click switches focus, right-click opens a context menu (close /
//! close others / close to right), and a hover-only `x` button closes the
//! single tab.
//!
//! All actions are deferred via local [`Action`] values and applied after the
//! render pass so we never mutate `state.open_tabs` while we're iterating
//! over it.

use crate::state::AppState;

/// One queued action from the tab bar. We collect actions during rendering
/// (when `state` is borrowed for iteration) and apply them after the strip
/// is laid out.
enum Action {
    Focus(usize),
    Close(usize),
    CloseOthers(usize),
    CloseToRight(usize),
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    if state.open_tabs.is_empty() {
        return;
    }

    let active_idx = state.active_tab_idx;
    let mut pending: Option<Action> = None;

    egui::ScrollArea::horizontal()
        .id_salt("tab_bar_scroll")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, tab) in state.open_tabs.iter().enumerate() {
                    let is_active = active_idx == Some(i);
                    let is_modified = tab.changes.change_count() > 0;
                    // Reflect load state in the tab title so users can spot
                    // pending loads / failed loads without clicking through.
                    let label = match &tab.load_state {
                        crate::state::LoadState::Loading => {
                            format!("{} ⏳", tab.dispatch_name)
                        }
                        crate::state::LoadState::Error(_) => {
                            format!("{} ❌", tab.dispatch_name)
                        }
                        crate::state::LoadState::Loaded => {
                            build_tab_label(&tab.dispatch_name, tab.entries.len(), is_modified)
                        }
                    };

                    let response = render_tab(ui, &label, is_active);

                    if response.clicked() {
                        pending = Some(Action::Focus(i));
                    }

                    response.context_menu(|ui| {
                        if ui.button("Close").clicked() {
                            pending = Some(Action::Close(i));
                            ui.close_menu();
                        }
                        let other_count = state.open_tabs.len().saturating_sub(1);
                        if ui
                            .add_enabled(other_count > 0, egui::Button::new("Close Others"))
                            .clicked()
                        {
                            pending = Some(Action::CloseOthers(i));
                            ui.close_menu();
                        }
                        let right_count = state.open_tabs.len().saturating_sub(i + 1);
                        if ui
                            .add_enabled(right_count > 0, egui::Button::new("Close to Right"))
                            .clicked()
                        {
                            pending = Some(Action::CloseToRight(i));
                            ui.close_menu();
                        }
                    });

                    // Hover-only close button. egui doesn't offer a real
                    // hover-anchored child widget, so we approximate by always
                    // rendering a small `x` and only acting on click — visually
                    // dim it when the tab isn't hovered or active.
                    if response.hovered() || is_active {
                        let close_response = ui
                            .add(egui::Button::new(egui::RichText::new("x").small()).frame(false))
                            .on_hover_text("Close tab");
                        if close_response.clicked() {
                            pending = Some(Action::Close(i));
                        }
                    }

                    ui.add_space(4.0);
                }
            });
        });

    if let Some(action) = pending {
        apply_action(state, action);
    }
}

fn render_tab(ui: &mut egui::Ui, label: &str, is_active: bool) -> egui::Response {
    // SelectableLabel handles the active highlight for us — same affordance
    // egui uses for table-list rows, so visual language stays consistent.
    ui.selectable_label(is_active, label)
}

fn build_tab_label(name: &str, count: usize, is_modified: bool) -> String {
    if is_modified {
        // Show both the row count and the modified bullet so the user can
        // see at a glance which tab has pending edits.
        format!("{} ({}) \u{25CF}", name, count)
    } else {
        format!("{} ({})", name, count)
    }
}

fn apply_action(state: &mut AppState, action: Action) {
    match action {
        Action::Focus(idx) => {
            if idx < state.open_tabs.len() {
                state.active_tab_idx = Some(idx);
            }
        }
        Action::Close(idx) => state.close_tab(idx),
        Action::CloseOthers(keep) => {
            // Walk right-to-left so each removal leaves earlier indices stable.
            let total = state.open_tabs.len();
            for i in (0..total).rev() {
                if i != keep {
                    state.close_tab(i);
                }
            }
        }
        Action::CloseToRight(idx) => {
            // Same right-to-left pattern; close every tab whose original
            // index was greater than `idx`.
            for i in (idx + 1..state.open_tabs.len()).rev() {
                state.close_tab(i);
            }
        }
    }
}
