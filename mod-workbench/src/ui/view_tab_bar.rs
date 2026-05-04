//! Top-of-central-panel tab bar for switching [`MainView`].
//!
//! Replaces the View menu as the primary surface for navigating between
//! the workbench's editors / tools / workflow panels. The View menu
//! itself stays wired up untouched so existing muscle memory and the
//! command palette ("Open View: ...") rows keep working.
//!
//! ## Layout
//!
//! One `horizontal_wrapped` row of `selectable_value` buttons grouped by
//! function:
//!
//! 1. **Data** — PABGB Tables, PALOC, XML, PASEQ, PAATT, PAAC, PAPPT, PAMHC.
//!    The format-editor stack — every view that opens a single binary
//!    file or family of binary files for direct editing.
//! 2. **Tools** — Archive, Binary Inspector, Global Search. Cross-cutting
//!    inspectors that aren't tied to one format.
//! 3. **Workflow** — Library, Templates, Wizards, Lint, Conflicts, Backups.
//!    Higher-level surfaces: mod management, presets, validation.
//! 4. **System** — Settings.
//!
//! Vertical separators read the groups as sections without imposing a
//! grid.
//!
//! ## Side-effects on switch
//!
//! A handful of views need cache resets on entry so they don't show
//! stale data from a previous visit. This matches the existing View-
//! menu behaviour:
//!
//! - **Backups**: clear `backup_loaded_once` so the panel refreshes from
//!   disk on first draw.
//! - **Templates**: lazy-load `user_templates` if empty so a missing /
//!   broken templates dir doesn't crash startup.
//! - **Archive**: drop cached groups + detail + diff so the panel
//!   re-scans the game directory.
//! - **Library**: flip `library_loaded` so newly-imported mods between
//!   sessions become visible.
//!
//! All other views are stateless on entry and just need `main_view` set.
//!
//! ## Why a separate module
//!
//! Keeps `app.rs` lean (it's already 2.6K lines) and gives the tab bar
//! its own surface for tooltips + side-effect handling. The View menu
//! over in `app.rs` has the same logic interleaved — pulling the tab
//! bar's version into a module avoids two copies fighting for the same
//! "what runs when the user picks this view?" responsibility.

use crate::state::{AppState, MainView};

/// Tooltip text per view. Kept short — one line of intent each. These
/// mirror the longer hover-texts already present on the View menu so a
/// user toggling between menu and tab bar sees consistent guidance.
fn tooltip_for(view: MainView) -> &'static str {
    match view {
        MainView::PabgbTables => {
            "Tabbed PABGB game-data table editor — the historical default. \
             Open a table from the left panel to begin."
        }
        MainView::Paloc => {
            "Localization editor (PALOC). Edit per-language string maps; \
             changes ship as a PAZ overlay."
        }
        MainView::Paseq => {
            "PASEQ / PASTAGE editor. Sequencer + stage swaps for sleep mods, \
             NPC routines, etc."
        }
        MainView::Xml => {
            "Apply slash-path patches (set_text / set_attr / append_child) \
             to XML game configs. Save patches as JSON for sharing."
        }
        MainView::Paatt => {
            "Edit projectile attribute (.paatt) physics — radius, shape \
             size, lifetime — for every projectile entry in the game."
        }
        MainView::Paac => {
            "Inspect and edit action-chart (.paac) files — character / \
             weapon state machines, transitions, and condition records."
        }
        MainView::Pappt => {
            "Edit the part-prefab table (.pappt) — global registry mapping \
             short part-prefab names plus per-character variants."
        }
        MainView::Pamhc => {
            "Edit the model-property header collection (.pamhc) — typed/byte \
             sections behind an opaque header."
        }
        MainView::Archive => {
            "Browse every PAZ group folder under the game directory: \
             inspect PAMT contents, compare PAPGT checksums, remove overlays."
        }
        MainView::BinaryInspector => {
            "Generic byte-level editor for sequencer schedule, stage \
             header, and UI animation init files. Build find/replace \
             byte patches."
        }
        MainView::GlobalSearch => {
            "Search across every supported format — PABGB / PALOC / XML / \
             paatt / paac / pappt / pamhc plus opt-in byte / Korean scans."
        }
        MainView::Library => {
            "Browse the local mod library and switch between named profiles \
             that batch-deploy a chosen subset of mods."
        }
        MainView::Templates => {
            "Apply preset field changes (built-in and user-saved) to the \
             selected entry."
        }
        MainView::Wizards => {
            "Step-by-step guided flows for common mod tasks (stat boost, \
             NPC swap, etc.)."
        }
        MainView::Lint => {
            "Run validation rules against the active table and review \
             findings (with one-click fixes for known issues)."
        }
        MainView::Conflicts => {
            "Mod conflict viewer — load multiple mod JSONs and report \
             overlapping field changes."
        }
        MainView::Backups => {
            "Snapshot browser — restore a prior deploy state from disk."
        }
        MainView::Settings => {
            "Application settings — game directory, catalog path, theme, \
             snapshot retention."
        }
    }
}

/// Short, human-readable display name per view. Reused from the
/// command-palette labels so the user sees a consistent name across both
/// surfaces.
fn label_for(view: MainView) -> &'static str {
    match view {
        MainView::PabgbTables => "PABGB Tables",
        MainView::Paloc => "PALOC",
        MainView::Paseq => "PASEQ",
        MainView::Xml => "XML",
        MainView::Paatt => "PAATT",
        MainView::Paac => "PAAC",
        MainView::Pappt => "PAPPT",
        MainView::Pamhc => "PAMHC",
        MainView::Archive => "Archive",
        MainView::BinaryInspector => "Binary Inspector",
        MainView::GlobalSearch => "Global Search",
        MainView::Library => "Library",
        MainView::Templates => "Templates",
        MainView::Wizards => "Wizards",
        MainView::Lint => "Lint",
        MainView::Conflicts => "Conflicts",
        MainView::Backups => "Backups",
        MainView::Settings => "Settings",
    }
}

/// Render the top-of-central-panel view-switch tab bar.
///
/// Wraps so the bar stays usable on narrower windows. Returns nothing —
/// the side-effects are applied in-place on `state` (most just flip
/// `state.main_view`; a few flush caches as documented above).
///
/// `id_salt` keeps egui's auto-generated widget ids from colliding with
/// the per-table tab bar (which is rendered just below this one inside
/// the PABGB view).
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    // Group definitions. Order inside each group is deliberate — Data
    // groups by editor family (tabbed-table editor first, then text
    // editors, then small binary-format editors), Workflow groups by
    // user task (browse mods, apply presets, run wizards, validate,
    // resolve conflicts, restore backups).
    let groups: [&[MainView]; 4] = [
        // Data
        &[
            MainView::PabgbTables,
            MainView::Paloc,
            MainView::Xml,
            MainView::Paseq,
            MainView::Paatt,
            MainView::Paac,
            MainView::Pappt,
            MainView::Pamhc,
        ],
        // Tools
        &[
            MainView::Archive,
            MainView::BinaryInspector,
            MainView::GlobalSearch,
        ],
        // Workflow
        &[
            MainView::Library,
            MainView::Templates,
            MainView::Wizards,
            MainView::Lint,
            MainView::Conflicts,
            MainView::Backups,
        ],
        // System
        &[MainView::Settings],
    ];

    // Use horizontal_wrapped so a narrow window pushes overflow into a
    // second line instead of clipping the tail of the bar.
    ui.push_id("view_tab_bar", |ui| {
        ui.horizontal_wrapped(|ui| {
            for (group_idx, group) in groups.iter().enumerate() {
                if group_idx > 0 {
                    ui.separator();
                }
                for view in group.iter().copied() {
                    let label = label_for(view);
                    let tooltip = tooltip_for(view);
                    let is_active = state.main_view == view;
                    // selectable_value gives us the active highlight for
                    // free; same affordance the per-table tab bar and
                    // the command palette use.
                    let resp = ui
                        .selectable_value(&mut state.main_view, view, label)
                        .on_hover_text(tooltip);
                    // Only run side-effects on the click that flips the
                    // active view — selectable_value writes through on
                    // every render when active, so we need the explicit
                    // click + change check to avoid resetting caches on
                    // every frame.
                    if resp.clicked() && !is_active {
                        on_view_switched(state, view);
                    }
                }
            }
        });
    });
}

/// Run the same cache-flush / lazy-load side-effects the View menu
/// applies on entry to a handful of views. Centralised here so both
/// surfaces agree on the post-switch state and adding a new side-effect
/// only requires one edit.
fn on_view_switched(state: &mut AppState, view: MainView) {
    match view {
        MainView::Backups => {
            // Force a fresh backup-list scan on next render so the
            // panel doesn't show data from a previous session that may
            // have been trimmed by retention policy in the meantime.
            state.backup_loaded_once = false;
        }
        MainView::Templates => {
            // Lazy-load user templates the first time the user opens
            // the Templates view this session. Failure surfaces as a
            // toast and leaves the list empty rather than crashing.
            // Clippy wants this `if` collapsed into the outer match
            // via a guard, but that hides the lazy-load intent — keep
            // the explicit form.
            #[allow(clippy::collapsible_match)]
            if state.user_templates.is_empty() {
                match crate::templates::load_user_templates() {
                    Ok(list) => state.user_templates = list,
                    Err(e) => state.toasts.error_with_details(
                        "Failed to load user templates",
                        e.to_string(),
                    ),
                }
            }
        }
        MainView::Archive => {
            // Drop cached archive data so the view rescans from disk.
            // Without this the user can't see overlays that were
            // added or removed by another tool while the workbench
            // was open.
            state.archive.groups = None;
            state.archive.detail = None;
            state.archive.diff = None;
        }
        MainView::Library => {
            // Force a re-scan so newly-imported mods (or files added
            // directly to the library directory between sessions) are
            // visible.
            state.library_loaded = false;
        }
        _ => {
            // Every other view is stateless on entry — no cache to
            // flush, no lazy load to kick. The selectable_value write
            // already updated `main_view`.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: every variant has a label and a tooltip. If a new
    /// `MainView` lands and someone forgets to wire it up here, this
    /// fails — better than the user seeing a blank tab.
    #[test]
    fn label_and_tooltip_cover_every_variant() {
        // The compiler enforces match exhaustiveness in `label_for` /
        // `tooltip_for`, so this test is mostly a smoke check that
        // every variant produces non-empty strings.
        for view in [
            MainView::PabgbTables,
            MainView::Paloc,
            MainView::Paseq,
            MainView::Backups,
            MainView::Conflicts,
            MainView::Lint,
            MainView::Settings,
            MainView::Library,
            MainView::Templates,
            MainView::Wizards,
            MainView::Xml,
            MainView::Archive,
            MainView::Paatt,
            MainView::Paac,
            MainView::Pappt,
            MainView::Pamhc,
            MainView::BinaryInspector,
            MainView::GlobalSearch,
        ] {
            assert!(!label_for(view).is_empty(), "{:?} missing label", view);
            assert!(
                !tooltip_for(view).is_empty(),
                "{:?} missing tooltip",
                view
            );
        }
    }
}
