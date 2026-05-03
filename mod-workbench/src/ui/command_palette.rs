//! VS Code-style command palette.
//!
//! Toggleable modal overlay (Ctrl+P) that lists every available action,
//! every loaded tab, every entry in the active table, and every recently
//! used mod file in a single searchable surface. Up/Down arrows move the
//! highlight, Enter dispatches, Esc dismisses.
//!
//! ## Why this lives in `ui::` and not a panel
//!
//! The palette renders as a centered [`egui::Window`] on top of the entire
//! frame, so it is conceptually closer to the toast overlay than to one of
//! the side panels. It still ships its rendering logic here so the palette
//! state can stay close to the rest of the UI module.
//!
//! ## State ownership
//!
//! The persistent bits — open / closed flag, query string, selected
//! row — live on [`crate::state::AppState::command_palette`]. The
//! per-frame work (filtering, scoring, action dispatch) happens in [`show`]
//! and the helpers below.
//!
//! [`show`] returns a [`PaletteAction`] when the user confirms a row;
//! `app.rs` then routes that into the existing `action_*` handlers
//! (Deploy, Restore, RunLint, view switches, tab focuses, entry jumps,
//! library mod imports). This keeps the palette decoupled from the
//! handlers — adding a new action is one new variant + one match arm in
//! the dispatcher.

use std::path::PathBuf;

use crate::mod_io::extract_entry_key;
use crate::state::{AppState, MainView};

/// Maximum number of matched rows to keep visible. Anything past this gets
/// dropped before render so the popup stays usable. Filter is "narrow your
/// query" — power users won't be hunting through 5,000 rows by eye.
const MAX_VISIBLE_ITEMS: usize = 20;
/// Hard cap on rows pulled from the active table during palette refresh.
/// Even with the visible cap above we still need to score each candidate to
/// pick the best matches; this keeps the scoring loop bounded on the very
/// largest tables (multichanges / drop_sets).
const MAX_ENTRY_CANDIDATES: usize = 200;

/// Persistent state for the command palette.
///
/// Lives on [`AppState::command_palette`]. Reset between sessions —
/// nothing here is worth persisting, but the bookkeeping has to outlive a
/// single render frame so the palette can keep its query and selection
/// while the user navigates the popup.
#[derive(Default)]
pub struct CommandPalette {
    /// Whether the palette window is currently shown. Toggled by Ctrl+P
    /// and cleared by Esc / on action dispatch.
    pub open: bool,
    /// Current search input. Lower-cased and filtered against each
    /// candidate row's `label`. Cleared every time the palette closes so
    /// the next open starts fresh.
    pub query: String,
    /// Index into the *visible* (post-filter) item list of the highlighted
    /// row. Driven by Up/Down arrow input and clamped to the list bounds
    /// each frame so swapping queries can't leave a stale out-of-range
    /// selection.
    pub selected_idx: usize,
    /// Set true on the frame the palette is opened so the input line can
    /// grab keyboard focus immediately. Consumed (cleared) inside [`show`]
    /// once the focus request lands.
    pub focus_input: bool,
}

impl CommandPalette {
    /// Toggle the palette open/closed state. When opening, also resets the
    /// query/selection and arms the focus-input flag. Used by the Ctrl+P
    /// shortcut handler in `app.rs`.
    pub fn toggle(&mut self) {
        if self.open {
            self.close();
        } else {
            self.open = true;
            self.query.clear();
            self.selected_idx = 0;
            self.focus_input = true;
        }
    }

    /// Force-close the palette and reset transient state. Called on Esc or
    /// after an action fires so the next open is fresh.
    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.selected_idx = 0;
        self.focus_input = false;
    }
}

/// Logical category for a palette row. Drives the small grey label rendered
/// next to each candidate so the user can disambiguate two rows that share
/// a name (e.g. "Deploy to Game" the action vs a hypothetical "Deploy"
/// table). Sort tie-breaker also reads this to keep actions ahead of
/// entries when scores are equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteCategory {
    /// Top-level command (Deploy, Restore, Run Lint, view switches, etc.).
    Action,
    /// A previously-selected entry the user can jump to. Reserved for a
    /// future "recents" surface; the current implementation builds these
    /// from the active table's selection history once that lands.
    RecentEntry,
    /// One of the currently-open tabs.
    LoadedTable,
    /// A mod JSON file from `config.recent_mods` the user can re-open.
    LibraryMod,
}

impl PaletteCategory {
    /// Two-character tag rendered to the right of each row. Picked to be
    /// visually obvious without using emoji (which look inconsistent across
    /// Windows font stacks).
    fn short_label(self) -> &'static str {
        match self {
            PaletteCategory::Action => "Action",
            PaletteCategory::RecentEntry => "Entry",
            PaletteCategory::LoadedTable => "Tab",
            PaletteCategory::LibraryMod => "Mod",
        }
    }

    /// Sort key used as a final tie-breaker after the substring score
    /// (lower wins). Actions outrank entries which outrank tabs which
    /// outrank library mods, so a query that matches multiple categories
    /// still surfaces the most-likely-useful match first.
    fn rank(self) -> u8 {
        match self {
            PaletteCategory::Action => 0,
            PaletteCategory::LoadedTable => 1,
            PaletteCategory::RecentEntry => 2,
            PaletteCategory::LibraryMod => 3,
        }
    }
}

/// Concrete action a palette row represents.
///
/// Variants intentionally mirror existing app handlers so the palette
/// dispatcher stays a thin one-line-per-arm match.
#[derive(Clone, Debug)]
pub enum PaletteAction {
    /// Run the same code path as `File -> Deploy to Game`.
    Deploy,
    /// Run the same code path as `File -> Restore`.
    Restore,
    /// Trigger a lint check on the active tab. Equivalent to clicking
    /// "Run Lint Check" in the Lint panel.
    RunLint,
    /// Open the [`File -> Import Mod...`] dialog.
    ImportMod,
    /// Open the [`File -> Export Mod...`] dialog.
    ExportMod,
    /// Switch the central panel to the given [`MainView`].
    OpenView(MainView),
    /// Focus / load the table with the given dispatch name.
    JumpToTable(String),
    /// Focus the table named `table` and select the entry at index
    /// `entry_idx`. Caller is responsible for loading the table first if
    /// it isn't already open.
    JumpToEntry { table: String, entry_idx: usize },
    /// Open a previously-used mod JSON via the conflict viewer.
    /// `app.rs` reuses the conflict panel's mod loader so the mod becomes
    /// available for cross-mod analysis.
    OpenLibraryMod(PathBuf),
}

/// Single candidate row presented to the user.
///
/// Built fresh every frame from [`AppState`]; we don't cache because the
/// candidate set is at most ~250 rows and recomputing keeps the panel
/// reactive to live state changes (e.g. a tab just loaded).
#[derive(Clone)]
pub struct PaletteItem {
    /// Visible label. Substring-matched against the lowercased query.
    pub label: String,
    pub category: PaletteCategory,
    pub action: PaletteAction,
}

/// Render the command palette window if it is currently open. Returns the
/// confirmed [`PaletteAction`] when the user pressed Enter (or clicked a
/// row); the caller is expected to route that through the existing app
/// handlers before the next frame.
///
/// Closing on Esc / clicking outside also resets state on the way out.
pub fn show(ctx: &egui::Context, state: &mut AppState) -> Option<PaletteAction> {
    if !state.command_palette.open {
        return None;
    }

    // Build candidates from current state. Cheap (≤ a few hundred rows) so
    // we rebuild every frame — simpler than dirty-tracking and lets the
    // palette react instantly to a freshly loaded tab.
    let candidates = build_candidates(state);
    let (filtered, _truncated) = filter_and_score(&candidates, &state.command_palette.query);

    // Read input *before* the popup renders so arrow keys / Enter / Esc
    // beat any focus-stealing the TextEdit might do this frame.
    let (move_up, move_down, confirm, cancel) = ctx.input(|i| {
        (
            i.key_pressed(egui::Key::ArrowUp),
            i.key_pressed(egui::Key::ArrowDown),
            i.key_pressed(egui::Key::Enter),
            i.key_pressed(egui::Key::Escape),
        )
    });
    if cancel {
        state.command_palette.close();
        return None;
    }

    // Clamp the selected index against the current visible range. The list
    // can shrink between frames as the user types, so a stale selection
    // from a wider result set has to be reined in or the highlight could
    // sit on a phantom row.
    let visible_count = filtered.len().min(MAX_VISIBLE_ITEMS);
    if visible_count == 0 {
        state.command_palette.selected_idx = 0;
    } else if state.command_palette.selected_idx >= visible_count {
        state.command_palette.selected_idx = visible_count - 1;
    }
    if move_down && visible_count > 0 {
        let next = state.command_palette.selected_idx + 1;
        state.command_palette.selected_idx = if next >= visible_count { 0 } else { next };
    }
    if move_up && visible_count > 0 {
        let cur = state.command_palette.selected_idx;
        state.command_palette.selected_idx = if cur == 0 { visible_count - 1 } else { cur - 1 };
    }

    let mut chosen: Option<PaletteAction> = None;
    let mut want_close = false;

    egui::Window::new("Command Palette")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 60.0))
        .fixed_size(egui::vec2(560.0, 0.0))
        .show(ctx, |ui| {
            // Search input
            let edit = egui::TextEdit::singleline(&mut state.command_palette.query)
                .desired_width(540.0)
                .hint_text("> Type a command, table, entry, or recent mod...");
            let resp = ui.add(edit);
            if state.command_palette.focus_input {
                resp.request_focus();
                state.command_palette.focus_input = false;
            }

            ui.label(
                egui::RichText::new(format!(
                    "{} matches  ·  Up/Down to select  ·  Enter to run  ·  Esc to close",
                    visible_count
                ))
                .weak(),
            );
            ui.separator();

            if visible_count == 0 {
                ui.label(egui::RichText::new("(no matches)").italics());
                return;
            }

            egui::ScrollArea::vertical()
                .max_height(360.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (visible_idx, scored) in filtered.iter().take(MAX_VISIBLE_ITEMS).enumerate() {
                        let item = &scored.item;
                        let is_selected = visible_idx == state.command_palette.selected_idx;

                        let row = ui.horizontal(|ui| {
                            // Highlight strip for the active row. Using
                            // selectable_label gives us hover affordance and
                            // theme-consistent selection tint for free.
                            let main = ui.selectable_label(
                                is_selected,
                                egui::RichText::new(&item.label),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(item.category.short_label())
                                            .color(egui::Color32::from_gray(140))
                                            .small(),
                                    );
                                },
                            );
                            main
                        });

                        let main_resp = row.inner;
                        if main_resp.clicked() {
                            chosen = Some(item.action.clone());
                        }
                    }
                });

            // Confirm via Enter (driven by the key read at the top of
            // `show`). We do this after the list renders so the row used
            // is whatever ended up highlighted this frame.
            if confirm && visible_count > 0 {
                if let Some(scored) = filtered.get(state.command_palette.selected_idx) {
                    chosen = Some(scored.item.action.clone());
                }
            }

            if chosen.is_some() {
                want_close = true;
            }
        });

    if want_close {
        state.command_palette.close();
    }

    chosen
}

/// Internal: candidate row paired with its substring score.
///
/// A lower score sorts earlier; ties break on `category.rank()` so action
/// rows beat tab rows beat entry rows beat library-mod rows when match
/// quality is identical.
struct ScoredItem {
    item: PaletteItem,
    score: u32,
}

/// Build the unfiltered list of palette candidates from current state.
///
/// Order: actions, view switches, loaded tabs, active-table entries,
/// recent mod files. The filter pass scores every candidate against the
/// query — ordering here only matters as a tie-breaker (combined with
/// `PaletteCategory::rank`).
fn build_candidates(state: &AppState) -> Vec<PaletteItem> {
    let mut out: Vec<PaletteItem> = Vec::new();

    // ---- Always-present actions -------------------------------------
    out.push(PaletteItem {
        label: "Deploy to Game".to_string(),
        category: PaletteCategory::Action,
        action: PaletteAction::Deploy,
    });
    out.push(PaletteItem {
        label: "Restore (remove deployed overlay)".to_string(),
        category: PaletteCategory::Action,
        action: PaletteAction::Restore,
    });
    out.push(PaletteItem {
        label: "Run Lint Check".to_string(),
        category: PaletteCategory::Action,
        action: PaletteAction::RunLint,
    });
    out.push(PaletteItem {
        label: "Import Mod...".to_string(),
        category: PaletteCategory::Action,
        action: PaletteAction::ImportMod,
    });
    out.push(PaletteItem {
        label: "Export Mod...".to_string(),
        category: PaletteCategory::Action,
        action: PaletteAction::ExportMod,
    });

    // View switches — every MainView variant gets a row so the palette
    // doubles as the View menu's keyboard surface.
    for (label, view) in [
        ("Open View: PABGB Tables", MainView::PabgbTables),
        ("Open View: PALOC Editor", MainView::Paloc),
        ("Open View: PASEQ Editor", MainView::Paseq),
        ("Open View: Backups", MainView::Backups),
        ("Open View: Mod Conflicts", MainView::Conflicts),
        ("Open View: Lint Panel", MainView::Lint),
        ("Open View: Settings", MainView::Settings),
        ("Open View: Library", MainView::Library),
    ] {
        out.push(PaletteItem {
            label: label.to_string(),
            category: PaletteCategory::Action,
            action: PaletteAction::OpenView(view),
        });
    }

    // ---- Loaded tabs ------------------------------------------------
    for tab in &state.open_tabs {
        out.push(PaletteItem {
            label: format!("Jump to Table: {} ({} entries)", tab.dispatch_name, tab.entries.len()),
            category: PaletteCategory::LoadedTable,
            action: PaletteAction::JumpToTable(tab.dispatch_name.clone()),
        });
    }

    // ---- Entries in the active table -------------------------------
    //
    // Capped to `MAX_ENTRY_CANDIDATES` rows so even a 17K-row table
    // doesn't dominate scoring. The cap is generous enough that any
    // realistic query narrows below it before the user finishes typing.
    if let Some(active) = state.active_table() {
        let table = active.dispatch_name.clone();
        for (idx, entry) in active.entries.iter().take(MAX_ENTRY_CANDIDATES).enumerate() {
            let entry_key = extract_entry_key(entry);
            let name = entry
                .get("string_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let label = if name.is_empty() {
                format!("Entry: key={} in {}", entry_key, table)
            } else {
                format!("Entry: {} (key={}) in {}", name, entry_key, table)
            };
            out.push(PaletteItem {
                label,
                category: PaletteCategory::RecentEntry,
                action: PaletteAction::JumpToEntry {
                    table: table.clone(),
                    entry_idx: idx,
                },
            });
        }
    }

    // ---- Recent mods -----------------------------------------------
    for path in &state.config.recent_mods {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("(unnamed)");
        out.push(PaletteItem {
            label: format!("Open Library Mod: {}", name),
            category: PaletteCategory::LibraryMod,
            action: PaletteAction::OpenLibraryMod(path.clone()),
        });
    }

    out
}

/// Filter and score a candidate set against `query`.
///
/// Returns a vec sorted by relevance (lowest score first) plus a flag
/// indicating whether any rows were dropped because of [`MAX_VISIBLE_ITEMS`].
/// An empty query keeps everything in the original (build) order, scored
/// uniformly so the category-rank tie-breaker still surfaces actions first.
///
/// Scoring rules (lower is better):
/// - Exact match (case-insensitive) -> 0
/// - Prefix match -> 100
/// - Anywhere substring -> 200 + position
/// - No match -> filtered out
fn filter_and_score(items: &[PaletteItem], query: &str) -> (Vec<ScoredItem>, bool) {
    let q = query.trim().to_lowercase();
    let mut scored: Vec<ScoredItem> = Vec::with_capacity(items.len());

    for item in items {
        let label_lower = item.label.to_lowercase();
        let score = if q.is_empty() {
            // Surface everything in build order, with category rank as
            // the only tie-breaker.
            500
        } else if label_lower == q {
            0
        } else if label_lower.starts_with(&q) {
            100
        } else if let Some(pos) = label_lower.find(&q) {
            200 + (pos as u32).min(99)
        } else {
            continue;
        };
        scored.push(ScoredItem {
            item: item.clone(),
            score,
        });
    }

    // Stable sort first by score, then by category rank, then by label so
    // identical-score rows present in a deterministic order (avoids the
    // result list visibly shuffling between frames as scores tie).
    scored.sort_by(|a, b| {
        a.score
            .cmp(&b.score)
            .then(a.item.category.rank().cmp(&b.item.category.rank()))
            .then(a.item.label.cmp(&b.item.label))
    });

    let truncated = scored.len() > MAX_VISIBLE_ITEMS;
    (scored, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(label: &str, cat: PaletteCategory) -> PaletteItem {
        PaletteItem {
            label: label.to_string(),
            category: cat,
            action: PaletteAction::Deploy,
        }
    }

    #[test]
    fn empty_query_keeps_everything() {
        let items = vec![
            item("Deploy", PaletteCategory::Action),
            item("Tab Foo", PaletteCategory::LoadedTable),
        ];
        let (scored, _) = filter_and_score(&items, "");
        assert_eq!(scored.len(), 2);
    }

    #[test]
    fn substring_filter_drops_misses() {
        let items = vec![
            item("Deploy to Game", PaletteCategory::Action),
            item("Lint check", PaletteCategory::Action),
        ];
        let (scored, _) = filter_and_score(&items, "deploy");
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].item.label, "Deploy to Game");
    }

    #[test]
    fn prefix_match_beats_anywhere_match() {
        let items = vec![
            item("undeploy", PaletteCategory::Action),
            item("deploy now", PaletteCategory::Action),
        ];
        let (scored, _) = filter_and_score(&items, "deploy");
        assert_eq!(scored[0].item.label, "deploy now");
        assert_eq!(scored[1].item.label, "undeploy");
    }

    #[test]
    fn category_rank_breaks_ties() {
        // Same score (anywhere match at position 0 -> 200), so category
        // rank takes over. Action (0) should beat LoadedTable (1).
        let items = vec![
            item("foo", PaletteCategory::LoadedTable),
            item("foo", PaletteCategory::Action),
        ];
        let (scored, _) = filter_and_score(&items, "foo");
        assert_eq!(scored[0].item.category, PaletteCategory::Action);
    }

    #[test]
    fn category_short_label_does_not_panic() {
        for cat in [
            PaletteCategory::Action,
            PaletteCategory::RecentEntry,
            PaletteCategory::LoadedTable,
            PaletteCategory::LibraryMod,
        ] {
            let _ = cat.short_label();
            let _ = cat.rank();
        }
    }

    #[test]
    fn toggle_clears_state_when_closing() {
        let mut p = CommandPalette::default();
        p.toggle();
        assert!(p.open);
        p.query = "search".into();
        p.selected_idx = 5;
        p.toggle();
        assert!(!p.open);
        assert!(p.query.is_empty());
        assert_eq!(p.selected_idx, 0);
    }
}
