//! Visual theme support.
//!
//! Three themes are exposed:
//!
//! - [`Theme::Dark`]   — egui's stock dark visuals; the default for users who
//!   never visit the View menu.
//! - [`Theme::Light`]  — egui's stock light visuals.
//! - [`Theme::Crimson`]— dark visuals with a deep crimson accent on
//!   selections, hyperlinks, and a few hover/active states. Reads as
//!   "game-themed" without sacrificing the legibility of the dark base.
//!
//! ## Persistence
//!
//! The chosen theme is stored on `Config::theme` as a string slug
//! (`"dark"` / `"light"` / `"crimson"`). [`from_str`] is forgiving — unknown
//! values fall back to [`Theme::Dark`] so a hand-edited config can't trap the
//! user in an unrenderable state.
//!
//! ## When to apply
//!
//! Themes are global (applied via `egui::Context`) so the typical wiring is:
//! - apply on app startup with the value loaded from config, and
//! - apply again each time the user picks a new option from the View menu.
//!
//! There's no per-frame work in [`apply_theme`] — it just installs visuals on
//! the context, which egui caches internally.

/// The three supported visual themes.
///
/// `Copy` because it's a 1-byte enum and callers (the View menu, settings
/// panel) clone it casually.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
    Crimson,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::Dark
    }
}

/// Parse a slug back into a [`Theme`]. Unknown / missing values fall back to
/// [`Theme::Dark`] so a corrupt config can't render the app unusable.
pub fn from_str(s: &str) -> Theme {
    match s.to_ascii_lowercase().as_str() {
        "light" => Theme::Light,
        "crimson" => Theme::Crimson,
        // Includes the explicit "dark" slug plus anything else.
        _ => Theme::Dark,
    }
}

/// Slug for serializing to config. Round-trips through [`from_str`].
pub fn to_str(theme: Theme) -> &'static str {
    match theme {
        Theme::Dark => "dark",
        Theme::Light => "light",
        Theme::Crimson => "crimson",
    }
}

/// Install the visuals for `theme` onto `ctx`.
///
/// Cheap to call repeatedly: egui caches the visuals struct internally and
/// only invalidates layouts / fonts on actual changes. The intended cadence
/// is "once at startup, then once per user-driven theme change" rather than
/// every frame.
pub fn apply_theme(ctx: &egui::Context, theme: Theme) {
    match theme {
        Theme::Dark => {
            ctx.set_visuals(egui::Visuals::dark());
        }
        Theme::Light => {
            ctx.set_visuals(egui::Visuals::light());
        }
        Theme::Crimson => {
            // Start from the dark base so widgets stay legible, then paint
            // the accent surfaces (selection, active widget edges, hyperlink
            // text) in the deep crimson tone.
            ctx.set_visuals(egui::Visuals::dark());
            ctx.style_mut(|style| {
                let accent = egui::Color32::from_rgb(160, 30, 30);
                let accent_dim = egui::Color32::from_rgb(110, 20, 20);
                let accent_bright = egui::Color32::from_rgb(200, 60, 60);

                // Primary "the user picked this" surface — selected list rows,
                // highlighted entry table rows, focused text inputs.
                style.visuals.selection.bg_fill = accent;
                style.visuals.selection.stroke.color = accent_bright;

                // Hyperlinks pick up the accent so the View menu / settings
                // panel hint colour matches.
                style.visuals.hyperlink_color = accent_bright;

                // Outline the active widget (e.g. focused button, dragged
                // slider) in a brighter accent so focus is obvious without
                // changing the base widget fills (which would hurt contrast
                // on the dark background).
                style.visuals.widgets.active.bg_stroke.color = accent_bright;
                style.visuals.widgets.hovered.bg_stroke.color = accent_dim;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_roundtrip() {
        for t in [Theme::Dark, Theme::Light, Theme::Crimson] {
            assert_eq!(from_str(to_str(t)), t);
        }
    }

    #[test]
    fn unknown_slug_falls_back_to_dark() {
        assert_eq!(from_str(""), Theme::Dark);
        assert_eq!(from_str("nonsense"), Theme::Dark);
        // Case-insensitive
        assert_eq!(from_str("CRIMSON"), Theme::Crimson);
        assert_eq!(from_str("Light"), Theme::Light);
    }
}
