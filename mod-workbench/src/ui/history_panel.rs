//! Edit history panel.
//!
//! Renders a collapsible list of the most recent edits on the active tab,
//! letting the user click an entry to jump back (or forward) to that point in
//! history. Mirrors the cursor exposed by [`crate::edit_history::EditHistory`]:
//!
//! - `current_position()` ops are currently applied (states `[..pos]`).
//! - Anything from `pos` onwards is redoable (states `[pos..]`).
//!
//! The user-visible affordances:
//! - Up to [`MAX_VISIBLE_OPS`] most recent ops are listed; older ones get
//!   summarised under a "older entries" line so the panel never grows
//!   unbounded.
//! - Each row shows index, dispatch table + entry key + field path, the
//!   transition (`old → new` truncated to short strings), and a relative
//!   "Ns ago" timestamp.
//! - A small marker (`▸ here`) indicates the current cursor row so the user
//!   can see where undo/redo will land next.
//! - Clicking a row triggers a "jump-to-history" action handed back to the
//!   caller; the actual mutation lives in `app.rs::action_jump_to_history`.

use std::time::Instant;

use serde_json::Value;

use crate::edit_history::EditOp;
use crate::state::AppState;

/// Cap on visible rows. Older entries are summarised in a single line above
/// the visible window so the panel can't grow unbounded for long sessions.
const MAX_VISIBLE_OPS: usize = 50;

/// Outcome of one frame's interaction with the history panel.
///
/// Returned to the caller so the (mutating) "jump to position" action can be
/// applied from `app.rs` without taking a second mutable borrow on state from
/// inside the panel.
pub enum HistoryAction {
    /// User clicked the row at `target_pos` (history cursor target). The
    /// caller should walk the history forward or backward to land at this
    /// position.
    JumpTo(usize),
    /// User clicked the "Undo last" button.
    Undo,
    /// User clicked the "Redo next" button.
    Redo,
    /// User clicked "Clear history".
    Clear,
}

/// Render the history panel and return any action the user requested.
///
/// Designed to be embedded as a collapsing section (e.g. at the bottom of
/// the field panel) — the caller decides where in the layout it goes.
pub fn show(ui: &mut egui::Ui, state: &AppState) -> Option<HistoryAction> {
    let active = state.active_table()?;
    let ops = active.history.ops();
    let pos = active.history.current_position();

    let header = format!("History ({} ops)", ops.len());
    let mut requested: Option<HistoryAction> = None;

    egui::CollapsingHeader::new(header)
        .id_salt("history_panel")
        .default_open(false)
        .show(ui, |ui| {
            // Top toolbar: undo / redo / clear shortcuts.
            ui.horizontal(|ui| {
                let can_undo = pos > 0;
                let can_redo = pos < ops.len();
                if ui
                    .add_enabled(can_undo, egui::Button::new("\u{21BA} Undo"))
                    .on_hover_text("Ctrl+Z")
                    .clicked()
                {
                    requested = Some(HistoryAction::Undo);
                }
                if ui
                    .add_enabled(can_redo, egui::Button::new("\u{21BB} Redo"))
                    .on_hover_text("Ctrl+Y or Ctrl+Shift+Z")
                    .clicked()
                {
                    requested = Some(HistoryAction::Redo);
                }
                ui.separator();
                if ui
                    .add_enabled(!ops.is_empty(), egui::Button::new("Clear"))
                    .on_hover_text("Drop all history for this tab")
                    .clicked()
                {
                    requested = Some(HistoryAction::Clear);
                }
                ui.separator();
                ui.label(egui::RichText::new(format!("cursor: {} / {}", pos, ops.len())).weak());
            });

            ui.separator();

            if ops.is_empty() {
                ui.label(egui::RichText::new("(no edits yet)").weak());
                return;
            }

            // Decide which slice to render. We always show the *most recent*
            // window so freshly minted edits stay in view; older entries get
            // summarised on a single weak line.
            let total = ops.len();
            let start = total.saturating_sub(MAX_VISIBLE_OPS);
            let now = Instant::now();

            egui::ScrollArea::vertical()
                .max_height(220.0)
                .auto_shrink([false, true])
                .id_salt("history_scroll")
                .show(ui, |ui| {
                    if start > 0 {
                        ui.label(
                            egui::RichText::new(format!(
                                "... {} older entries hidden",
                                start
                            ))
                            .weak()
                            .italics(),
                        );
                    }

                    // Render newest first so the bottom of the list is the
                    // most actionable history (matches the `cursor` display).
                    for (i, op) in ops.iter().enumerate().skip(start).rev() {
                        if render_row(ui, i, pos, op, now) {
                            // Jump target is the *post-state* of clicking
                            // this row: if we click the latest applied op, the
                            // user wants to undo it (i.e. land at i). If we
                            // click a redoable op, the user wants to apply
                            // through it (i.e. land at i+1). The simplest
                            // intuitive contract: clicking an op selects "the
                            // state after this op was applied", i.e. i+1.
                            requested = Some(HistoryAction::JumpTo(i + 1));
                        }
                    }
                });
        });

    requested
}

/// Render a single op row. Returns `true` when the user clicked it.
fn render_row(
    ui: &mut egui::Ui,
    op_index: usize,
    cursor: usize,
    op: &EditOp,
    now: Instant,
) -> bool {
    let is_applied = op_index < cursor;
    let is_cursor = op_index + 1 == cursor;

    // "[N+1] table.field: old → new   (5s ago)"
    let path = if op.field_path.is_empty() {
        "<entire entry>".to_string()
    } else {
        op.field_path.clone()
    };
    let elapsed = now
        .saturating_duration_since(op.timestamp)
        .as_secs();
    let when = format_relative(elapsed);

    let summary = format!(
        "[{}] {}.{} key={}",
        op_index + 1,
        op.table,
        path,
        op.entry_key,
    );
    let transition = format!(
        "{} \u{2192} {}",
        truncate_value(&op.old_value, 20),
        truncate_value(&op.new_value, 20),
    );

    let mut clicked = false;
    ui.horizontal(|ui| {
        // Cursor marker so the user can see where undo/redo will hit next.
        let marker = if is_cursor { "\u{25B8} " } else { "  " };
        ui.label(egui::RichText::new(marker).strong());

        let text_color = if is_applied {
            ui.visuals().text_color()
        } else {
            // Redoable ops drawn weak so they read as "future / not active".
            egui::Color32::from_gray(140)
        };

        let summary_text = egui::RichText::new(summary).color(text_color);
        if ui
            .selectable_label(is_cursor, summary_text)
            .on_hover_text(format!(
                "{}\nClick to jump to the state after this op was applied.",
                transition,
            ))
            .clicked()
        {
            clicked = true;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(when).weak());
        });
    });

    // Inline transition under the summary, dimmer so the eye lands on the
    // path first.
    ui.horizontal(|ui| {
        ui.add_space(20.0);
        ui.label(egui::RichText::new(transition).weak().small());
    });

    clicked
}

/// Format a JSON value as a short single-line string suitable for inlining
/// in a history row. Long strings/arrays/objects get truncated.
fn truncate_value(v: &Value, max_len: usize) -> String {
    let raw = match v {
        Value::String(s) => format!("\"{}\"", s),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    };
    if raw.len() <= max_len {
        raw
    } else {
        let mut out = raw[..max_len.saturating_sub(3)].to_string();
        out.push_str("...");
        out
    }
}

/// "Ns ago" / "Nm ago" / "Nh ago" relative-time formatter.
fn format_relative(secs: u64) -> String {
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 60 * 60 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_value_short_passes_through() {
        let v = Value::String("hi".to_string());
        assert_eq!(truncate_value(&v, 20), "\"hi\"");
    }

    #[test]
    fn truncate_value_long_gets_ellipsis() {
        let v = Value::String("a".repeat(50));
        let out = truncate_value(&v, 10);
        assert_eq!(out.len(), 10);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn truncate_value_handles_null() {
        assert_eq!(truncate_value(&Value::Null, 10), "null");
    }

    #[test]
    fn format_relative_seconds_minutes_hours() {
        assert_eq!(format_relative(0), "0s ago");
        assert_eq!(format_relative(45), "45s ago");
        assert_eq!(format_relative(60), "1m ago");
        assert_eq!(format_relative(125), "2m ago");
        assert_eq!(format_relative(3600), "1h ago");
    }
}
