//! Toast notification system.
//!
//! Stacks messages in the bottom-right corner with severity-based styling and
//! auto-dismiss. Hovering a toast pauses its timeout. Errors can carry an
//! expandable details payload (e.g., a full error stack) shown via "Show
//! details".
//!
//! Toasts are pop-ups; they're a separate concept from the bottom status bar
//! (`AppState::status`) which always reflects the current state.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn default_timeout(self) -> Duration {
        match self {
            Level::Info => Duration::from_secs(3),
            Level::Warn => Duration::from_secs(5),
            Level::Error => Duration::from_secs(10),
        }
    }

    fn border_color(self) -> egui::Color32 {
        match self {
            // Blue / yellow / red, picked to read on the dark theme.
            Level::Info => egui::Color32::from_rgb(80, 150, 255),
            Level::Warn => egui::Color32::from_rgb(240, 190, 60),
            Level::Error => egui::Color32::from_rgb(230, 80, 80),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Level::Info => "Info",
            Level::Warn => "Warn",
            Level::Error => "Error",
        }
    }
}

pub struct Toast {
    pub level: Level,
    pub message: String,
    /// Optional details (full error stack/context). Only meaningful for Error.
    pub details: Option<String>,
    pub created_at: Instant,
    pub timeout: Duration,
    /// Set true if user clicked "Show details".
    pub expanded: bool,
}

impl Toast {
    fn new(level: Level, message: String, details: Option<String>) -> Self {
        Self {
            level,
            message,
            details,
            created_at: Instant::now(),
            timeout: level.default_timeout(),
            expanded: false,
        }
    }
}

#[derive(Default)]
pub struct ToastManager {
    toasts: Vec<Toast>,
}

impl ToastManager {
    pub fn info(&mut self, msg: impl Into<String>) {
        self.toasts.push(Toast::new(Level::Info, msg.into(), None));
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.toasts.push(Toast::new(Level::Warn, msg.into(), None));
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.toasts.push(Toast::new(Level::Error, msg.into(), None));
    }

    pub fn error_with_details(&mut self, msg: impl Into<String>, details: impl Into<String>) {
        self.toasts.push(Toast::new(
            Level::Error,
            msg.into(),
            Some(details.into()),
        ));
    }

    /// Render toasts in the bottom-right corner. Call once per frame from the
    /// top-level update. Removes expired (and not-hovered) toasts.
    pub fn show(&mut self, ctx: &egui::Context) {
        if self.toasts.is_empty() {
            return;
        }

        // Indices to drop after the layout pass.
        let mut to_remove: Vec<usize> = Vec::new();
        // Whether any toast was hovered this frame — drives a repaint request
        // so timeouts continue to advance smoothly when the cursor leaves.
        let mut any_hovered = false;

        egui::Area::new("toasts".into())
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-10.0, -40.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_max_width(360.0);

                // Newest at top: render the vec in reverse order. The vec
                // itself stays oldest-first so "remove expired" indexing is
                // straightforward.
                let count = self.toasts.len();
                for rev_i in 0..count {
                    let i = count - 1 - rev_i;
                    let toast = &mut self.toasts[i];

                    let border = toast.level.border_color();
                    let mut dismiss = false;

                    // Frame: rounded panel with colored left border drawn as a
                    // thick left stroke via inner_margin+rect overlay would be
                    // overkill — egui::Frame doesn't do per-side strokes, so
                    // we instead use a solid stroke with a left "tab" rect.
                    let frame = egui::Frame::group(ui.style())
                        .fill(ui.style().visuals.window_fill)
                        .stroke(egui::Stroke::new(1.0, ui.style().visuals.window_stroke.color))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin {
                            left: 12,
                            right: 8,
                            top: 6,
                            bottom: 6,
                        });

                    let response = frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Colored "level" badge stands in for the left
                            // border so we don't have to hand-paint one.
                            ui.label(
                                egui::RichText::new(toast.level.label())
                                    .strong()
                                    .color(border),
                            );
                            ui.separator();

                            ui.vertical(|ui| {
                                ui.set_max_width(280.0);
                                ui.label(&toast.message);

                                if toast.level == Level::Error && toast.details.is_some() {
                                    let link_label = if toast.expanded {
                                        "Hide details"
                                    } else {
                                        "Show details"
                                    };
                                    if ui.link(link_label).clicked() {
                                        toast.expanded = !toast.expanded;
                                    }
                                    if toast.expanded {
                                        if let Some(details) = &toast.details {
                                            egui::ScrollArea::vertical()
                                                .max_height(160.0)
                                                .show(ui, |ui| {
                                                    ui.monospace(details);
                                                });
                                        }
                                    }
                                }
                            });

                            // Right-aligned dismiss button.
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::TOP),
                                |ui| {
                                    if ui.small_button("x").clicked() {
                                        dismiss = true;
                                    }
                                },
                            );
                        });
                    });

                    let hovered = response.response.hovered();
                    if hovered {
                        any_hovered = true;
                    }

                    // NOTE: click-anywhere-to-dismiss was removed. It was
                    // stealing clicks from the "Show details" link in the
                    // frame, immediately dismissing the toast instead of
                    // letting the user expand it. The X button is the only
                    // dismiss path now.

                    let expired = !hovered && toast.created_at.elapsed() > toast.timeout;

                    if dismiss || expired {
                        to_remove.push(i);
                    }

                    ui.add_space(4.0);
                }
            });

        // Remove from highest index down so earlier indices stay valid.
        to_remove.sort_unstable_by(|a, b| b.cmp(a));
        for i in to_remove {
            self.toasts.remove(i);
        }

        // Keep advancing timeouts even when the UI is otherwise idle.
        ctx.request_repaint_after(Duration::from_millis(250));
        // Suppress unused warning when no toast was hovered.
        let _ = any_hovered;
    }
}
