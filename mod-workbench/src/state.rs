use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::backup::Snapshot;
use crate::catalog::Catalog;
use crate::config::Config;
use crate::conflict::{ConflictReport, LoadedMod};
use crate::edit_history::EditHistory;
use crate::localization::Localization;
use crate::mod_library::LibraryMod;
use crate::notes::NoteStore;
use crate::paloc_editor::PalocSession;
use crate::profile::ProfileStore;
use crate::templates::Template;
use crate::toast;
use crate::ui::command_palette::CommandPalette;
use crate::ui::metadata_dialog::MetadataDialog;
use crate::ui::paseq_panel::PaseqSession;
use crate::ui::templates_panel::TemplatesPanelState;
use crate::ui::xml_panel::XmlSession;
use crate::validation::LintFinding;
use crate::wizards::Wizard;
use crate::worker;

/// Which view occupies the central panel.
///
/// The PABGB editor (`PabgbTables`) is the historical default — tabbed game-data
/// table editing. `Paloc` swaps the central panel for the localization editor,
/// which has its own session state ([`AppState::paloc_session`]) and ignores
/// the open-tabs / catalog-driven sidebar widgets. `Paseq` swaps it for the
/// PASEQ/PASTAGE editor (sleep mod + NPC sequencer swaps) which uses
/// [`AppState::paseq`] instead of the tab list. `Backups` shows the snapshot
/// browser ([`crate::ui::backup_panel`]) for restoring prior deploy states.
/// `Conflicts` shows the mod conflict viewer ([`crate::ui::conflict_panel`])
/// which loads multiple mod JSONs and reports overlapping field changes.
/// `Lint` shows the validation panel ([`crate::ui::lint_panel`]) which runs
/// rule-based checks against the active tab and exposes one-click fixes for
/// findings that ship an [`crate::validation::AutoFix`].
/// `Settings` shows the application settings panel ([`crate::ui::settings_panel`])
/// covering game directory, catalog path, theme, and snapshot retention.
/// `Library` shows the mod library / profile manager
/// ([`crate::ui::library_panel`]) — local browseable mod store plus named
/// profiles that batch-deploy a chosen subset of mods.
/// `Templates` shows the templates library
/// ([`crate::ui::templates_panel`]) which lists built-in + user templates
/// and applies them to the active entry.
/// `Wizards` shows the wizards picker
/// ([`crate::ui::wizards_panel`]) — step-by-step guided flows that compose
/// existing primitives into one-click user tasks.
/// `Xml` shows the XML patcher ([`crate::ui::xml_panel`]) for game configs
/// stored as plain XML inside PAZ archives. Loads a target file, runs a
/// list of slash-path-addressed mutation ops, and previews / saves /
/// deploys the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainView {
    PabgbTables,
    Paloc,
    Paseq,
    Backups,
    Conflicts,
    Lint,
    Settings,
    Library,
    Templates,
    Wizards,
    Xml,
}

pub struct AppState {
    pub game_dir: Option<PathBuf>,
    pub tables: Vec<TableMeta>,
    pub table_filter: String,
    /// All open tables, one per tab. Each tab owns its own entries, vanilla
    /// snapshot, filter state, selected entry, change tracker, and edit
    /// history so users can switch tabs without losing local edits.
    pub open_tabs: Vec<ActiveTable>,
    /// Index into [`Self::open_tabs`] of the currently focused tab. `None`
    /// when no tabs are open.
    pub active_tab_idx: Option<usize>,
    pub entry_filter: String,
    pub status: String,
    pub config: Config,
    pub toasts: toast::ToastManager,
    /// Background worker for slow operations (table loads, deploy, restore).
    /// UI submits jobs via `worker.submit(...)` and drains replies once per
    /// frame via `worker.poll()`.
    pub worker: worker::Worker,
    /// Game data catalog (game_map_complete_v4.json). `None` until loaded
    /// via [`AppState::load_catalog_blocking`] (or the future async loader).
    pub catalog: Option<Catalog>,
    /// Pending cross-reference navigation request.
    ///
    /// Set by `xref_panel` when the user clicks a related entry. Tuple is
    /// `(target_dispatch_name, target_key)`. The worker reply handler in
    /// `app.rs` checks this after a `TableLoaded` reply: if the loaded
    /// table's dispatch_name matches, it finds the entry whose `key` field
    /// equals `target_key`, sets the new tab's `selected_entry_idx`, and
    /// clears this field.
    ///
    /// If the target table is already loaded when the click happens, the
    /// xref panel resolves the selection directly and never sets this.
    pub pending_xref_nav: Option<(String, u64)>,
    /// Dispatch names of tables that have been successfully loaded at least
    /// once during this session. Used purely for UI affordance (checkmark
    /// in the table list) — the actual cached entries live on each tab in
    /// `open_tabs`.
    pub loaded_tables: HashSet<String>,
    /// Which view (PABGB tables vs PALOC editor) the central panel is showing.
    pub main_view: MainView,
    /// Currently selected language code in the PALOC editor (e.g. `"eng"`).
    /// Persists across loads so re-opening the panel keeps your last pick.
    pub paloc_language: String,
    /// Active PALOC editing session, or `None` when nothing has been loaded.
    /// Owned by [`AppState`] (rather than a tab) because the PALOC view is
    /// single-document — only one paloc is loaded at a time.
    pub paloc_session: Option<PalocSession>,
    /// Persistent state for the PASEQ/PASTAGE editor view (NPC list cache +
    /// dropdown selections). Owned by [`AppState`] so switching views
    /// preserves the most recent scan and chosen swap pair.
    pub paseq: PaseqSession,
    /// Cached list of snapshots shown by [`crate::ui::backup_panel`].
    /// Refreshed on demand (first open of the view, manual "Refresh", or
    /// after restore/delete actions) instead of every frame so the disk
    /// scan doesn't run on idle redraws.
    pub backup_snapshots: Vec<Snapshot>,
    /// True once the backup view has populated `backup_snapshots` at least
    /// once. Drives lazy first-load: opening the view with this still false
    /// triggers a refresh, but later frames don't.
    pub backup_loaded_once: bool,
    /// Two-step confirmation flag for the backup view's "Clear All" button.
    /// Reset when the user cancels, confirms, or navigates away from the
    /// view — see `ui::backup_panel`.
    pub backup_confirm_clear_all: bool,
    /// Mods loaded into the conflict viewer. Independent of `open_tabs`
    /// because mods aren't tied to any particular table — one mod can touch
    /// many tables, so the viewer stores them flat.
    pub loaded_mods: Vec<LoadedMod>,
    /// Most recent conflict analysis output. Cleared whenever `loaded_mods`
    /// changes so the user is forced to re-run Analyze and can't read stale
    /// data.
    pub conflict_report: Option<ConflictReport>,
    /// Findings from the most recent lint run. Re-populated each time the
    /// user clicks "Run Lint Check" in the lint panel; pre-deploy gating
    /// also writes here when the deploy action runs lint automatically.
    ///
    /// Findings are sorted Error -> Warn -> Info by [`crate::validation::LintRunner::check_table`]
    /// so the panel can render them straight off the vec.
    pub lint_findings: Vec<LintFinding>,
    /// Set true when `action_deploy` runs lint pre-flight, finds Errors,
    /// and is waiting on the user to confirm "deploy anyway". The deploy
    /// confirmation modal in `app.rs` reads this flag to render itself.
    pub deploy_confirm_pending: bool,
    /// Set true after a successful deploy. Drives the post-deploy follow-up
    /// modal which offers Start Game / Restore Vanilla / OK so the user can
    /// chain test → see → revert without leaving the workbench. Cleared
    /// when the user clicks any of the three buttons (or the X close).
    /// Carries the overlay group that was just deployed so Restore knows
    /// which one to wipe.
    pub deploy_followup_modal: Option<DeployFollowup>,
    /// Two-step confirmation flag for the keyboard-triggered restore action
    /// (Ctrl+R). When true, the app shows a small modal asking the user to
    /// confirm before wiping the overlay group. Cleared when the user
    /// cancels or confirms.
    pub restore_confirm_pending: bool,
    /// Pre-export warning flag for "As Field JSON v3...". When true, the app
    /// shows a red-tinted modal pointing out that mod-manager support for
    /// Field JSON v3 is still rolling out and recommending the Mod Folder
    /// export instead. Cleared when the user picks Continue / Cancel /
    /// Switch to Mod Folder. Stays in the codebase until ecosystem support
    /// catches up — flip the menu wiring back to `begin_export_flow` when
    /// it's safe to remove.
    pub dmm_v3_warning_pending: bool,
    /// Command palette state (Ctrl+P toggle). The window is rendered at
    /// the top of `update()` so it overlays everything else; actions
    /// dispatched from the palette route into the normal `action_*`
    /// handlers via [`crate::ui::command_palette::PaletteAction`].
    pub command_palette: CommandPalette,
    /// Per-entry user notes. Keyed by `(table, entry_key)` and embedded
    /// under `_notes` in v3 field-JSON exports so reasoning travels with
    /// the mod artifact. See [`crate::notes::NoteStore`].
    pub notes: NoteStore,
    /// Set true for one frame whenever a request lands to focus the entry
    /// table's search box (e.g. the user pressed `F`). Read and cleared by
    /// `entry_table::show` so the focus request happens on the same frame as
    /// the search box renders.
    pub entry_search_focus_pending: bool,
    /// Set true for one frame whenever a request lands to advance past the
    /// current selection in the filtered entry list (e.g. the user pressed
    /// `F3`). Read and cleared by `entry_table::show`.
    pub entry_search_advance_pending: bool,
    /// Mod metadata dialog state. Shown before any export flow (JSON /
    /// .modpkg / DMM bundle) so the user can attach attribution + version
    /// info to the artifact. Persists across showings so users don't have
    /// to retype between exports.
    pub metadata_dialog: MetadataDialog,
    /// Global "search across every PABGB" session state. Off by default;
    /// enabled by the checkbox next to the entry-table search bar. When
    /// enabled the search drives a worker job that loads + scans every
    /// table in the registry, streaming hits back. See
    /// [`crate::worker::Job::SearchAllPabgb`].
    pub global_search: GlobalSearchSession,
    /// Cached scan of the local mod library directory
    /// (`%APPDATA%/Crimson/ModWorkbench/mods/`). Populated lazily — the
    /// library panel triggers a refresh on first navigation, and any
    /// import / delete action re-scans afterwards so the list stays in
    /// sync with disk.
    pub library: Vec<LibraryMod>,
    /// Persistent profile store loaded from
    /// `%APPDATA%/Crimson/ModWorkbench/profiles.json`. Holds every saved
    /// profile plus a pointer to the active one. Saved on every mutation
    /// (add / remove / rename / reorder) so a crash never loses curation.
    pub profile_store: ProfileStore,
    /// True after the library panel has populated `library` at least once.
    /// Drives lazy first-load: opening the panel with this still false
    /// triggers a scan; subsequent frames don't.
    pub library_loaded: bool,
    /// User-defined templates loaded from
    /// `%APPDATA%/Crimson/ModWorkbench/templates/`. Populated lazily on
    /// first navigation to the templates panel. Built-in templates are not
    /// stored here — they're produced fresh by
    /// [`crate::templates::builtin_templates`].
    pub user_templates: Vec<Template>,
    /// Per-frame UI state for the templates panel: selected entry, filter
    /// toggle, etc. See [`crate::ui::templates_panel::TemplatesPanelState`].
    pub templates_panel: TemplatesPanelState,
    /// Currently running wizard, or `None` when the wizards panel is in
    /// its picker state. Wizards own their own multi-step UI; the panel
    /// just dispatches `show()` calls and inspects the returned
    /// [`crate::wizards::WizardResult`].
    pub active_wizard: Option<Box<dyn Wizard>>,
    /// One-shot CJK font load report from startup. Drained on the first
    /// frame and surfaced as a toast so the user can see whether Korean
    /// rendering is going to work without having to run from a terminal
    /// and read eprintln output.
    pub cjk_report_pending: Option<crate::fonts::CjkLoadReport>,
    /// EN+KR localization tables, populated by the worker on startup
    /// (cache hit) or first time the game directory is set (cache miss).
    /// `None` until the load completes — the field panel falls back to the
    /// catalog's `lookup_string` while this is missing so the UI degrades
    /// gracefully rather than refusing to render hash references.
    pub localization: Option<Localization>,
    /// Persistent state for the XML patcher view ([`crate::ui::xml_panel`]).
    /// Single-document — only one patch is open at a time.
    pub xml: XmlSession,
}

#[derive(Clone)]
pub struct TableMeta {
    pub dispatch_name: String,
    pub pabgb_filename: String,
    pub pabgh_filename: Option<String>,
}

/// Result of a successful deploy, used by the post-deploy follow-up modal
/// to drive the Quick Test workflow (start game, restore vanilla, or
/// dismiss). Stored on [`AppState::deploy_followup_modal`] for the duration
/// the modal is on screen.
#[derive(Clone, Debug)]
pub struct DeployFollowup {
    /// The dispatch name that was just deployed (e.g. "item_info"). Shown
    /// in the modal header for context.
    pub dispatch_name: String,
    /// The overlay group that was created (e.g. "0058"). Restore Vanilla
    /// uses this to know which group to wipe.
    pub overlay_group: String,
}

/// Per-tab load state. A tab can be in one of three phases:
///   - `Loading`: a worker job is in flight; show a spinner + "Loading..."
///     in the entry table area so the user knows something is happening.
///   - `Loaded`: the table parsed successfully and entries are populated.
///   - `Error(msg)`: the worker reply came back as Err; the message is shown
///     inline in the tab so the user can read why without hunting through
///     toasts. A "Retry" button next to the message resubmits the load.
#[derive(Clone)]
pub enum LoadState {
    Loading,
    Loaded,
    Error(String),
}

pub struct ActiveTable {
    pub dispatch_name: String,
    pub entries: Vec<serde_json::Value>,
    pub vanilla: Vec<serde_json::Value>,
    pub column_names: Vec<String>,
    pub load_state: LoadState,
    /// Snapshot of `entry_filter` at the time `filtered_indices` was last
    /// recomputed. Compared against the current filter each frame to detect
    /// pending edits.
    pub last_filter: String,
    /// Indices into [`Self::entries`] that pass the current filter. When the
    /// filter is empty this contains every index in order. Recomputed on a
    /// debounce — see [`Self::last_filter_change`].
    pub filtered_indices: Vec<usize>,
    /// Wall-clock time of the most recent **frame-to-frame change** in the
    /// filter text. Used to debounce expensive re-filters while the user is
    /// still typing. **Distinct from comparing against [`Self::last_filter`]**
    /// — that one is a snapshot from the last recompute, so while the filter
    /// is dirty (typed but not yet applied) it always differs. Bumping
    /// `last_filter_change` against `last_filter` made the timer reset every
    /// frame and the recompute never fired. We compare against
    /// [`Self::prev_frame_filter`] instead, which only differs on frames where
    /// the user actually edits the input.
    pub last_filter_change: Instant,
    /// The filter text seen on the previous render frame. Updated every
    /// frame; `last_filter_change` only bumps when this differs from the
    /// current frame's filter. Initialised to empty so a freshly-loaded tab
    /// with no filter doesn't trigger a spurious recompute on first render.
    pub prev_frame_filter: String,
    /// Index into `entries` of the currently selected entry, scoped to this
    /// tab so switching tabs preserves each table's selection state.
    pub selected_entry_idx: Option<usize>,
    /// Per-tab change tracker. Records which entry keys + field paths have
    /// been edited since this tab loaded; the tab bar shows a `●` indicator
    /// when [`ChangeTracker::change_count`] is non-zero.
    pub changes: ChangeTracker,
    /// Per-tab undo/redo log. Edits made on this tab don't pollute the
    /// history of any other open tab.
    pub history: EditHistory,
    /// Raw pabgb bytes captured during load, used as the source for the
    /// hex viewer fallback. Populated for both successful loads and
    /// parser failures so the user can still inspect the bytes when the
    /// schema is broken. `None` while a load is still in flight.
    pub raw_pabgb: Option<Vec<u8>>,
    /// Whether the entry table should be replaced by the hex viewer for
    /// this tab. Toggled by the "Hex" button in the entry-table top bar
    /// and the error-state action row.
    pub show_hex_view: bool,
    /// Persistent hex viewer state (page, page size, selected offset).
    /// Lives on the tab so each tab keeps its own scroll position.
    pub hex_view_state: crate::ui::hex_view::HexViewState,
}

impl ActiveTable {
    /// Construct a fresh ActiveTable with `filtered_indices` pre-populated to
    /// match the empty filter (all entries visible).
    pub fn new(
        dispatch_name: String,
        entries: Vec<serde_json::Value>,
        vanilla: Vec<serde_json::Value>,
        column_names: Vec<String>,
    ) -> Self {
        let filtered_indices = (0..entries.len()).collect();
        Self {
            dispatch_name,
            entries,
            vanilla,
            column_names,
            load_state: LoadState::Loaded,
            last_filter: String::new(),
            filtered_indices,
            last_filter_change: Instant::now(),
            prev_frame_filter: String::new(),
            selected_entry_idx: None,
            changes: ChangeTracker::new(),
            history: EditHistory::default(),
            raw_pabgb: None,
            show_hex_view: false,
            hex_view_state: crate::ui::hex_view::HexViewState::default(),
        }
    }

    /// Build a placeholder tab for a load that's in flight. The user clicks
    /// a table → we immediately push one of these so the tab strip shows
    /// the load attempt instead of leaving the user wondering whether their
    /// click registered. The worker reply (success or error) overwrites this
    /// in place.
    pub fn placeholder_loading(dispatch_name: String) -> Self {
        Self {
            dispatch_name,
            entries: Vec::new(),
            vanilla: Vec::new(),
            column_names: Vec::new(),
            load_state: LoadState::Loading,
            last_filter: String::new(),
            filtered_indices: Vec::new(),
            last_filter_change: Instant::now(),
            prev_frame_filter: String::new(),
            selected_entry_idx: None,
            changes: ChangeTracker::new(),
            history: EditHistory::default(),
            raw_pabgb: None,
            show_hex_view: false,
            hex_view_state: crate::ui::hex_view::HexViewState::default(),
        }
    }

    /// Build an error placeholder tab. Carries the failure message inline so
    /// the user can see why a table failed to load without digging through
    /// toasts, and the panel can offer a Retry action.
    pub fn placeholder_error(dispatch_name: String, message: String) -> Self {
        Self {
            dispatch_name,
            entries: Vec::new(),
            vanilla: Vec::new(),
            column_names: Vec::new(),
            load_state: LoadState::Error(message),
            last_filter: String::new(),
            filtered_indices: Vec::new(),
            last_filter_change: Instant::now(),
            prev_frame_filter: String::new(),
            selected_entry_idx: None,
            changes: ChangeTracker::new(),
            history: EditHistory::default(),
            raw_pabgb: None,
            show_hex_view: false,
            hex_view_state: crate::ui::hex_view::HexViewState::default(),
        }
    }
}

/// Persistent state for the "Search all PABGBs" feature. The user toggles
/// this on via the checkbox next to the entry-table search bar; we then
/// drive a worker job that loads + scans every table in the registry and
/// streams hits back. The session tracks:
///
/// - Whether the checkbox is enabled.
/// - The `request_id` of the currently-running scan so stale replies from
///   an earlier query (e.g. user changed the filter mid-scan) can be
///   discarded by `app.rs` instead of corrupting the live results.
/// - The filter the current scan was kicked off against — used to detect
///   when the user has typed something new and a fresh scan is needed.
/// - Progress counters and the hits accumulated so far.
pub struct GlobalSearchSession {
    /// Checkbox state; off by default. When the user ticks it, the next
    /// debounce-elapsed filter change kicks off a scan.
    pub enabled: bool,
    /// Filter the current scan was kicked off against. Empty when no
    /// scan is in flight or has been started for this session.
    pub filter_at_kick: String,
    /// Monotonic counter — bumped each time we kick a new scan so old
    /// replies can be filtered out by ID.
    pub request_id: u64,
    /// True between kick-off and `Reply::SearchComplete`.
    pub in_progress: bool,
    /// Tables scanned so far in the current run.
    pub scanned: usize,
    /// Total tables in the current run (snapshot of the registry size).
    pub total: usize,
    /// Name of the table currently being scanned (for the progress line).
    pub current_table: String,
    /// Accumulated hits, ordered by arrival.
    pub hits: Vec<crate::worker::GlobalSearchHit>,
    /// First error encountered during the run, if any (non-fatal — the
    /// scan continues after individual table failures).
    pub error: Option<String>,
}

impl Default for GlobalSearchSession {
    fn default() -> Self {
        Self {
            enabled: false,
            filter_at_kick: String::new(),
            request_id: 0,
            in_progress: false,
            scanned: 0,
            total: 0,
            current_table: String::new(),
            hits: Vec::new(),
            error: None,
        }
    }
}

pub struct ChangeTracker {
    /// Maps entry index -> set of changed field names
    pub modified: HashMap<u64, HashSet<String>>,
}

impl AppState {
    pub fn new() -> Self {
        let tables = crate::table_registry::build_registry();
        let mut config = Config::load();

        // Restore game_dir from config if the saved path still exists on disk.
        let mut game_dir = config
            .game_dir
            .as_ref()
            .filter(|p| p.exists())
            .cloned();

        // No usable saved game_dir? Try Steam auto-detection and persist on hit.
        let mut auto_detected = false;
        if game_dir.is_none() {
            if let Some(detected) = crate::steam::detect_crimson_desert() {
                config.game_dir = Some(detected.clone());
                let _ = config.save();
                game_dir = Some(detected);
                auto_detected = true;
            }
        }

        let status = match (&game_dir, auto_detected) {
            (Some(p), true) => format!("Auto-detected game directory: {}", p.display()),
            (Some(p), false) => format!("Game dir: {}", p.display()),
            (None, _) => "Ready".to_string(),
        };

        let mut worker = worker::Worker::spawn();

        // Try to fault in the cached EN+KR localization immediately so the
        // field panel can resolve hash references on the very first render.
        // `Localization::load_cached` is fast (a small JSON read) and
        // doesn't touch the game directory, so it's fine to do on the UI
        // thread. If the cache is missing or stale, the worker job below
        // builds a fresh copy off-thread once we know the game_dir.
        let cached_localization = crate::localization::Localization::load_cached().ok();

        // Kick off a background load when (a) we have a game_dir and (b) the
        // cache wasn't already populated above. The cache-hit case skips the
        // worker entirely; the cache-miss case runs PAZ extraction off-thread
        // so first-run users don't stall the UI.
        if cached_localization.is_none() {
            if let Some(dir) = &game_dir {
                worker.submit(worker::Job::LoadLocalization {
                    game_dir: dir.clone(),
                });
            }
        }

        Self {
            game_dir,
            tables,
            table_filter: String::new(),
            open_tabs: Vec::new(),
            active_tab_idx: None,
            entry_filter: String::new(),
            status,
            config,
            toasts: toast::ToastManager::default(),
            worker,
            catalog: None,
            pending_xref_nav: None,
            loaded_tables: HashSet::new(),
            main_view: MainView::PabgbTables,
            paloc_language: "eng".to_string(),
            paloc_session: None,
            paseq: PaseqSession::default(),
            backup_snapshots: Vec::new(),
            backup_loaded_once: false,
            backup_confirm_clear_all: false,
            loaded_mods: Vec::new(),
            conflict_report: None,
            lint_findings: Vec::new(),
            deploy_confirm_pending: false,
            deploy_followup_modal: None,
            restore_confirm_pending: false,
            dmm_v3_warning_pending: false,
            command_palette: CommandPalette::default(),
            notes: NoteStore::default(),
            entry_search_focus_pending: false,
            entry_search_advance_pending: false,
            metadata_dialog: MetadataDialog::default(),
            global_search: GlobalSearchSession::default(),
            // Mod library + profile store. Both load lazily — the library
            // panel kicks off its first scan on initial navigation, and we
            // try to read the profile store from disk here so any saved
            // profiles are visible immediately. A read failure (corrupt
            // profiles.json) demotes to "empty store" + a toast on first
            // panel render — see `library_panel`.
            library: Vec::new(),
            profile_store: crate::profile::load_store().unwrap_or_default(),
            library_loaded: false,
            // Templates / wizards initial state. We don't try to read user
            // templates here — the templates panel reads them on first
            // navigation so a missing/corrupt directory doesn't abort
            // app startup.
            user_templates: Vec::new(),
            templates_panel: TemplatesPanelState::default(),
            active_wizard: None,
            cjk_report_pending: None,
            localization: cached_localization,
            xml: XmlSession::default(),
        }
    }

    /// Borrow the currently focused tab, if any.
    pub fn active_table(&self) -> Option<&ActiveTable> {
        self.active_tab_idx.and_then(|i| self.open_tabs.get(i))
    }

    /// Mutably borrow the currently focused tab, if any.
    pub fn active_table_mut(&mut self) -> Option<&mut ActiveTable> {
        self.active_tab_idx
            .and_then(move |i| self.open_tabs.get_mut(i))
    }

    /// Find an existing tab for `dispatch_name` and focus it. Returns the
    /// tab's index when a match was found, or `None` when the caller still
    /// needs to submit a `LoadTable` job.
    pub fn open_or_focus_tab(&mut self, dispatch_name: &str) -> Option<usize> {
        if let Some(idx) = self
            .open_tabs
            .iter()
            .position(|t| t.dispatch_name == dispatch_name)
        {
            self.active_tab_idx = Some(idx);
            Some(idx)
        } else {
            None
        }
    }

    /// Close the tab at `idx`. Adjusts `active_tab_idx` so the focus moves
    /// to a sensible neighbour (the tab to the left, or the new last tab,
    /// or `None` when no tabs remain).
    pub fn close_tab(&mut self, idx: usize) {
        if idx >= self.open_tabs.len() {
            return;
        }
        self.open_tabs.remove(idx);

        if self.open_tabs.is_empty() {
            self.active_tab_idx = None;
            return;
        }

        match self.active_tab_idx {
            Some(active) if active == idx => {
                // The closed tab was active. Prefer the tab now sitting at
                // the same slot, else fall back to the new last index.
                let new_idx = active.min(self.open_tabs.len().saturating_sub(1));
                self.active_tab_idx = Some(new_idx);
            }
            Some(active) if active > idx => {
                self.active_tab_idx = Some(active - 1);
            }
            Some(_) | None => {
                // active < idx: still valid. None: nothing to do.
            }
        }
    }

    /// Synchronously load the game data catalog from `path` and store it on
    /// the state. Blocks for ~1-2 s on a release build; UI must call this
    /// off-thread (or accept the stall) until the async loader lands.
    ///
    /// On success, replaces any previously loaded catalog and returns the
    /// number of section entries loaded.
    pub fn load_catalog_blocking(&mut self, path: &Path) -> std::io::Result<usize> {
        let catalog = crate::catalog_loader::try_load(path)?;
        let n = catalog.total_entries();
        self.catalog = Some(catalog);
        Ok(n)
    }
}

impl ChangeTracker {
    pub fn new() -> Self {
        Self {
            modified: HashMap::new(),
        }
    }

    pub fn record_change(&mut self, entry_key: u64, field_name: String) {
        self.modified
            .entry(entry_key)
            .or_default()
            .insert(field_name);
    }

    pub fn is_entry_modified(&self, entry_key: u64) -> bool {
        self.modified.contains_key(&entry_key)
    }

    pub fn change_count(&self) -> usize {
        self.modified.len()
    }

    pub fn clear(&mut self) {
        self.modified.clear();
    }

    /// Remove a single changed field path for the given entry. If the entry
    /// has no remaining changed fields after the removal, the entry is
    /// dropped from the modified map entirely so [`is_entry_modified`]
    /// returns `false`.
    pub fn unrecord_field(&mut self, entry_key: u64, field_path: &str) {
        if let Some(set) = self.modified.get_mut(&entry_key) {
            set.remove(field_path);
            if set.is_empty() {
                self.modified.remove(&entry_key);
            }
        }
    }

    /// Drop all change tracking for `entry_key`.
    pub fn unrecord_entry(&mut self, entry_key: u64) {
        self.modified.remove(&entry_key);
    }

    /// Borrow the set of changed field paths for `entry_key`, if any.
    pub fn changed_fields(&self, entry_key: u64) -> Option<&HashSet<String>> {
        self.modified.get(&entry_key)
    }
}
