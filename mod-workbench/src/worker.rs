//! Background worker infrastructure for mod-workbench.
//!
//! Slow operations (table loading, catalog loading, deploy, restore) run on a
//! dedicated worker thread so the egui UI stays at 60fps. Communication is
//! via two `std::sync::mpsc` channels:
//!
//! ```text
//!     UI thread  --(Job)-->  Worker thread
//!     UI thread  <-(Reply)-- Worker thread
//! ```
//!
//! The UI submits a `Job` via `Worker::submit`, and every frame calls
//! `Worker::poll` to drain ready `Reply` values without blocking. Long
//! operations may emit multiple `Reply::Progress` updates before the
//! terminal completion reply.
//!
//! ## Design choices
//!
//! - **Single worker thread**, not a pool. Game-file I/O (PAZ, PAPGT) is
//!   not safe to parallelize against itself, and a single thread keeps
//!   ordering deterministic. Heavy CPU work that *is* safe to parallelize
//!   can `rayon::join` inside the worker without changing this contract.
//! - **Errors stringified** before crossing the thread boundary so we don't
//!   need every error type to be `Send + Sync + 'static`.
//! - **`in_flight` is owned by `Worker`** and updated only on the UI thread
//!   (incremented on `submit`, decremented in `poll` on terminal replies).
//!   The UI uses it to drive the busy spinner without any cross-thread
//!   atomics.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;

use crate::catalog::Catalog;
use crate::localization::Localization;
use crate::state::{SearchFormat, TableMeta};

/// A request from the UI to the worker.
///
/// Each variant is fire-and-forget: the worker will eventually reply with a
/// matching terminal `Reply` (and possibly several `Reply::Progress` along
/// the way). The UI is responsible for matching replies back to the right
/// in-flight job — `dispatch_name` on `LoadTable`/`TableLoaded` is the
/// natural correlator for the table case.
pub enum Job {
    /// Load and parse a single game data table from the PAZ archives.
    LoadTable {
        /// Dispatch name used by `dmm_parser_rust_only` (e.g. "gimmick_info").
        dispatch_name: String,
        /// Game directory (contains `meta/0.papgt` and the `0008/` group).
        game_dir: PathBuf,
        /// pabgb filename inside the PAZ (e.g. "iteminfo.pabgb").
        pabgb_filename: String,
        /// Optional pabgh filename (entry-offset index sidecar).
        pabgh_filename: Option<String>,
    },
    /// Load and parse the catalog (game_map_complete_v4.json + indexes).
    LoadCatalog {
        /// Path to the catalog JSON on disk.
        path: PathBuf,
    },
    /// Serialize the in-memory entries back to pabgb and deploy as a PAZ overlay.
    Deploy {
        game_dir: PathBuf,
        /// Dispatch name (used to route through the right serializer).
        table_name: String,
        /// Per-job snapshot of the registry meta (filename info).
        meta: TableMeta,
        /// Snapshot of the entries to serialize.
        entries: Vec<serde_json::Value>,
        /// Overlay group directory name (e.g. "0058").
        overlay_group: String,
    },
    /// Remove an overlay group and (if backed up) restore the original PAPGT.
    Restore {
        game_dir: PathBuf,
        overlay_group: String,
    },
    /// Load (or build) the EN+KR localization tables. Falls back to the
    /// JSON cache when present, otherwise extracts both paloc files from
    /// the game's PAZ archives. The reply carries the populated
    /// [`Localization`] which the UI thread stores on `AppState` so the
    /// field panel can resolve hash references to readable strings.
    LoadLocalization { game_dir: PathBuf },
    /// Search every supplied PABGB table for a substring (case-insensitive).
    /// Streams hits back via `Reply::SearchHit` as it walks each table, then
    /// emits `Reply::SearchComplete` when the entire registry has been
    /// scanned. The job is identified by a u64 `request_id` so the UI can
    /// discard stale results when the user changes the filter mid-scan.
    SearchAllPabgb {
        request_id: u64,
        game_dir: PathBuf,
        /// Lowercased filter substring (matched against string fields).
        filter: String,
        /// Numeric form of the filter, if it parses as decimal/hex. Used
        /// to match against the entry's `key` field.
        filter_as_number: Option<u64>,
        /// Snapshot of the registry — every table the worker should
        /// load + scan. Includes iteminfo (which uses the dedicated
        /// loader path inside the worker).
        tables: Vec<TableMeta>,
    },
    /// Scan one or more file formats for a substring. Drives the
    /// multi-format global search panel
    /// ([`crate::ui::global_search_panel`]). Streams hits via
    /// `Reply::MultiFormatHit`, per-format progress via
    /// `Reply::MultiFormatProgress`, and finishes with a single
    /// `Reply::MultiFormatComplete`. Independent of `SearchAllPabgb`
    /// — the two job kinds run side by side without sharing state.
    MultiFormatSearch {
        request_id: u64,
        game_dir: PathBuf,
        /// Original (case-preserving) query string for the snippet
        /// labels. The handler lowercases internally for matching.
        /// In hex mode, this is the user's typed hex string (kept for
        /// display; actual byte matching uses `query_kind`).
        query: String,
        /// Numeric form of the filter, if it parses as decimal/hex.
        filter_as_number: Option<u64>,
        /// Which formats to scan. Empty = no-op (the UI gates this
        /// before submitting).
        formats: HashSet<SearchFormat>,
        /// Snapshot of the registry — needed when `formats` includes
        /// `Pabgb` so the worker doesn't have to look it up.
        tables: Vec<TableMeta>,
        /// Kind of query — `Text` for the classic substring scan,
        /// `HexBytes` for raw byte-pattern search across binary
        /// formats. Defaults to `Text(query.clone())` when callers
        /// don't supply a value (kept the original `query` field for
        /// display continuity).
        query_kind: SearchQueryKind,
        /// When true (and `query_kind` is `Text`), also derive the
        /// 4-byte little-endian Jenkins hash of the query (lowercase,
        /// uppercase, original-case — deduped) and search every
        /// byte-level format for those bytes. Catches strings stored
        /// as 4-byte hashes (item keys, paloc IDs, etc.).
        match_jenkins_hash: bool,
        /// Cooperative cancellation flag. Cloned by the UI from the
        /// session's `cancel_flag`; the worker checks it at every
        /// iteration boundary (per-format dispatch, per-file, per-
        /// entry) and returns early when it flips to `true`. The UI
        /// rotates to a fresh `Arc` before each submit so the prior
        /// scan's flipped flag can't short-circuit the new run.
        ///
        /// Without this the search can grind for minutes after the
        /// user clicks Cancel, blocking subsequent jobs (LoadTable,
        /// Deploy, etc.) behind a dead scan.
        cancel_flag: Arc<AtomicBool>,
    },
}

/// What kind of payload `Job::MultiFormatSearch` is searching for.
///
/// Distinct from `query: String` because hex mode emits raw bytes
/// (no charset conversion, no lowercasing) — the worker has to keep
/// the parsed bytes untouched so a literal `00` byte in the pattern
/// matches a literal `00` byte in the file.
#[derive(Clone, Debug)]
pub enum SearchQueryKind {
    /// Classic substring scan — the worker lowercases internally and
    /// looks for matches in UTF-8 / UTF-16 LE / structured fields.
    Text(String),
    /// Raw byte pattern. Hex digits parsed by the UI before submit;
    /// the worker just memmems for these bytes across binary files.
    /// Empty `Vec` is rejected by the UI before kick.
    HexBytes(Vec<u8>),
    /// CJK (Hangul / Kana / Hanzi) text-run scan over every binary
    /// file. The worker walks each file with both UTF-8 and UTF-16 LE
    /// extractors (see [`crate::blob_text`]) and emits a hit per
    /// surviving CJK run. `filter`, when `Some` and non-empty,
    /// constrains the emitted runs to those whose lowercased text
    /// contains the lowercased filter — applied per-run, NOT to the
    /// whole file. Empty filter surfaces every CJK run found, capped
    /// per format by [`MULTI_FORMAT_HIT_CAP_PER_FORMAT`].
    KoreanScan {
        filter: Option<String>,
    },
}

/// A response from the worker to the UI.
///
/// Terminal variants (`TableLoaded`, `CatalogLoaded`, `DeployComplete`,
/// `RestoreComplete`) decrement `Worker::in_flight` when observed in
/// `poll`. `Progress` is non-terminal and does not affect the counter.
/// Payload sent back when a table load completes successfully.
///
/// Contains the live entries (mutable working copy) AND a vanilla clone
/// (immutable baseline for diff/reset). Both are computed on the worker
/// thread so the UI thread never blocks on the clone.
pub struct TableLoadPayload {
    pub entries: Vec<serde_json::Value>,
    pub vanilla: Vec<serde_json::Value>,
    pub column_names: Vec<String>,
}

pub enum Reply {
    /// Returned when `LoadTable` completes (success or failure).
    ///
    /// On success the payload carries BOTH the live entries and a separate
    /// vanilla clone. We do the clone on the worker thread so the UI thread
    /// doesn't have to: cloning a `Vec<serde_json::Value>` for tables with
    /// 10K+ deeply-nested entries can take 100ms-1s+, which would freeze the
    /// frame for tables like drop_set_info (11910) or multichange (17029).
    ///
    /// `raw_pabgb` is sent regardless of parse outcome (success or failure)
    /// so the hex viewer fallback can populate even when the schema parse
    /// blows up — that's the case where users most want byte-level access.
    TableLoaded {
        dispatch_name: String,
        result: Result<TableLoadPayload, String>,
        raw_pabgb: Option<Vec<u8>>,
    },
    /// Returned when `LoadCatalog` completes.
    CatalogLoaded {
        result: Result<Catalog, String>,
    },
    /// Returned when `Deploy` completes.
    DeployComplete {
        result: Result<(), String>,
    },
    /// Returned when `Restore` completes.
    RestoreComplete {
        result: Result<(), String>,
    },
    /// Returned when `LoadLocalization` completes.
    LocalizationLoaded {
        result: Result<Localization, String>,
    },
    /// One match found by `SearchAllPabgb`. Streamed — many of these per
    /// scan; the UI accumulates them as they arrive.
    SearchHit {
        request_id: u64,
        hit: GlobalSearchHit,
    },
    /// Per-table progress update emitted by `SearchAllPabgb`.
    SearchProgress {
        request_id: u64,
        scanned: usize,
        total: usize,
        current_table: String,
    },
    /// Terminal reply for `SearchAllPabgb` — fires once after every table
    /// has been scanned (or one of them errored, in which case `error`
    /// names the first failure).
    SearchComplete {
        request_id: u64,
        error: Option<String>,
    },
    /// One match found by `MultiFormatSearch`. The UI groups these by
    /// `hit.source` variant in the results panel.
    MultiFormatHit {
        request_id: u64,
        hit: MultiFormatHit,
    },
    /// Per-format progress update emitted by `MultiFormatSearch`.
    /// `message` is a free-form line like
    /// `"scanning XML... 12/418"`.
    MultiFormatProgress {
        request_id: u64,
        message: String,
    },
    /// Terminal reply for `MultiFormatSearch`. Fires exactly once per
    /// run. `error` is `Some(...)` for the first non-fatal failure
    /// encountered (per-format walk continues past individual file
    /// failures so one corrupted PAZ doesn't void the whole scan).
    MultiFormatComplete {
        request_id: u64,
        error: Option<String>,
        total_hits: usize,
    },
    /// Optional progress update emitted before a terminal reply.
    ///
    /// `fraction` is in `[0.0, 1.0]`, or `f32::NAN` for indeterminate.
    Progress {
        job_label: String,
        message: String,
        fraction: f32,
    },
}

/// One match returned by [`Job::SearchAllPabgb`]. The UI shows these in a
/// list; clicking a row should open the table and jump to the entry.
#[derive(Clone, Debug)]
pub struct GlobalSearchHit {
    /// Dispatch name of the table the hit lives in (e.g. `"item_info"`).
    pub dispatch_name: String,
    /// Index of the entry within the table's entries vec, so the UI can
    /// jump to it directly without re-resolving by key.
    pub entry_idx: usize,
    /// Numeric `key` field on the entry (or 0 if absent).
    pub entry_key: u64,
    /// `string_key` field on the entry, if present. Used as the display
    /// label in the results panel.
    pub string_key: String,
    /// Short snippet describing what matched (e.g. `string_key contains
    /// "Magic_Scythe"`). Plain text so the panel can render it directly.
    pub matched: String,
}

/// One match returned by [`Job::MultiFormatSearch`]. The `source` carries
/// format-specific identifiers so the UI can group results, jump into the
/// appropriate editor, and render an "expand" view with full context.
#[derive(Clone, Debug)]
pub struct MultiFormatHit {
    /// Where the hit was found. Drives the result group + editor jump.
    pub source: HitSource,
    /// One-line, plain-text snippet for the result row (e.g.
    /// `"string_key: Kliff_Sword"` or `"en[12345]: Hello"`).
    pub snippet: String,
    /// Optional richer payload shown when the user expands the row.
    /// Intentionally `String`-typed (formatted JSON / hex dump / full
    /// XML node text) so the UI can render it with a single label call.
    pub expand_data: Option<String>,
}

/// Format-specific identifier for a [`MultiFormatHit`]. Each variant
/// carries enough state for the UI to:
///   1. Group hits by source format in the results pane.
///   2. Render a meaningful row (`Pabgb` rows show the table + key,
///      `Paloc` rows show the language + hash, etc.).
///   3. Wire the "Open in editor" button to switch the active view +
///      load the right document.
#[derive(Clone, Debug)]
pub enum HitSource {
    /// PABGB table entry. Mirrors [`GlobalSearchHit`] so the UI can
    /// reuse the existing jump-to-entry plumbing.
    Pabgb {
        dispatch_name: String,
        entry_idx: usize,
        entry_key: u64,
        string_key: String,
    },
    /// Localization string. `lang` is `"en"` or `"kr"`, `hash_id` is the
    /// `unk_id` (Jenkins hash), `value` is the matched string.
    Paloc {
        lang: &'static str,
        hash_id: u64,
        value: String,
    },
    /// XML config inside a PAZ. The "Open in editor" button switches
    /// the view to `MainView::Xml` (the panel reuses the path to
    /// pre-populate the dropdown if practical).
    Xml {
        paz_group: String,
        dir_path: String,
        filename: String,
    },
    /// `.paatt` file. Same shape as `Xml` — the "Open in editor" button
    /// targets `MainView::Paatt`.
    Paatt {
        paz_group: String,
        dir_path: String,
        filename: String,
    },
    /// `.paac` file. Targets `MainView::Paac`.
    Paac {
        paz_group: String,
        dir_path: String,
        filename: String,
    },
    /// `.pappt` file. Targets `MainView::Pappt`.
    Pappt {
        paz_group: String,
        dir_path: String,
        filename: String,
    },
    /// `.pamhc` file. Targets `MainView::Pamhc`.
    Pamhc {
        paz_group: String,
        dir_path: String,
        filename: String,
    },
    /// Generic byte-level scan. `kind` tells the UI whether the match
    /// was found in raw UTF-8 bytes or as a UTF-16 LE wide string.
    Binary {
        ext: String,
        paz_group: String,
        dir_path: String,
        filename: String,
        byte_offset: usize,
        kind: ByteHitKind,
    },
    /// 4-byte Jenkins-hash-of-query match found in a binary file.
    /// Emitted when the user opted in to hash-aware search and a
    /// byte-level scan turned up the LE u32 of the query's hash.
    JenkinsHash {
        ext: String,
        paz_group: String,
        dir_path: String,
        filename: String,
        byte_offset: usize,
        /// The hash that matched. The same query can produce up to 3
        /// hashes (lowercase / uppercase / as-typed); this carries
        /// the specific value found at this offset.
        hash: u32,
        /// Which case-variant of the query produced this hash. Used
        /// to label the row so the user can tell `kliff` vs `KLIFF`
        /// vs `Kliff` apart at a glance.
        case_label: &'static str,
    },
    /// User-supplied hex byte pattern match. Distinct from `Binary`
    /// because the user's input was raw bytes, not text — the UI
    /// renders the pattern back as hex and skips the UTF-8 / UTF-16
    /// kind annotation.
    HexPattern {
        ext: String,
        paz_group: String,
        dir_path: String,
        filename: String,
        byte_offset: usize,
        /// Length of the pattern that matched, in bytes. The UI uses
        /// this to highlight the right span in the hex excerpt.
        pattern_len: usize,
    },
    /// CJK (Hangul / Kana / Hanzi) text run extracted from a binary
    /// file. Emitted by `KoreanScan` mode — the worker walks every
    /// binary file with both UTF-8 and UTF-16 LE extractors (see
    /// [`crate::blob_text`]) and surfaces every run that contains at
    /// least one CJK code point. `text` is the decoded run; `encoding`
    /// tells the UI which extractor produced it so the user can spot
    /// wide-string vs narrow-string content at a glance.
    KoreanString {
        ext: String,
        paz_group: String,
        dir_path: String,
        filename: String,
        byte_offset: usize,
        /// Decoded text run. Always contains at least one CJK code
        /// point by construction (runs without CJK are filtered out
        /// before emission).
        text: String,
        /// Which encoding the run was discovered in. Drives the
        /// snippet prefix (`UTF-8` vs `UTF-16 LE`) and lets the UI
        /// distinguish narrow vs wide string hits in the results
        /// pane.
        encoding: KoreanEncoding,
    },
}

/// Encoding the [`HitSource::KoreanString`] run was decoded under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KoreanEncoding {
    /// UTF-8 / variable-width run extracted by
    /// [`crate::blob_text::extract_text_runs`].
    Utf8,
    /// UTF-16 LE wide-string run extracted by
    /// [`crate::blob_text::extract_utf16le_text_runs`].
    Utf16Le,
}

impl HitSource {
    /// Stable group label used by the UI to bucket hits — one
    /// `CollapsingHeader` per distinct group.
    pub fn group_label(&self) -> &'static str {
        match self {
            HitSource::Pabgb { .. } => "PABGB Tables",
            HitSource::Paloc { .. } => "PALOC (Localization)",
            HitSource::Xml { .. } => "XML Configs",
            HitSource::Paatt { .. } => "PAATT (Attributes)",
            HitSource::Paac { .. } => "PAAC (Action Charts)",
            HitSource::Pappt { .. } => "PAPPT (Part-Prefabs)",
            HitSource::Pamhc { .. } => "PAMHC (Model Headers)",
            HitSource::Binary { .. } => "Binary Byte Scan",
            HitSource::JenkinsHash { .. } => "Jenkins Hash (4-byte LE)",
            HitSource::HexPattern { .. } => "Hex Byte Pattern",
            HitSource::KoreanString { .. } => "Korean Strings",
        }
    }
}

/// Distinguishes UTF-8 vs UTF-16 LE matches inside a binary file. The
/// scanner runs both passes; this lets the UI flag wide-string hits
/// distinctly so the user can spot localizable text vs raw ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteHitKind {
    /// Match found by scanning the file bytes as UTF-8 / ASCII.
    Utf8,
    /// Match found by scanning the file bytes as UTF-16 LE wide chars.
    /// Used for engine strings that ship in PA's wide-char form.
    Utf16Le,
}

impl Reply {
    /// True for the terminal variants. Used by `poll` to know when to
    /// decrement `in_flight`.
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Reply::TableLoaded { .. }
                | Reply::CatalogLoaded { .. }
                | Reply::DeployComplete { .. }
                | Reply::RestoreComplete { .. }
                | Reply::LocalizationLoaded { .. }
                | Reply::SearchComplete { .. }
                | Reply::MultiFormatComplete { .. }
        )
    }
}

/// Owns the worker thread handle and channels.
///
/// The thread is spawned once at startup via `Worker::spawn` and lives for
/// the lifetime of the app. It exits when `tx` is dropped (i.e. when the
/// `Worker` is dropped), at which point `rx.recv()` returns `Err` and the
/// loop falls through.
pub struct Worker {
    tx: Sender<Job>,
    rx: Receiver<Reply>,
    /// Number of jobs currently in flight (UI uses this for the spinner).
    /// Incremented on `submit`, decremented in `poll` on terminal replies.
    pub in_flight: u32,
    /// Kept so the thread isn't detached prematurely. We don't currently
    /// join on shutdown because the worker exits cleanly when the channel
    /// closes; holding the handle just ensures the thread is owned.
    _handle: thread::JoinHandle<()>,
}

impl Worker {
    /// Spawn the background worker thread and return a handle.
    pub fn spawn() -> Self {
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (reply_tx, reply_rx) = mpsc::channel::<Reply>();

        let handle = thread::Builder::new()
            .name("mod-workbench-worker".into())
            .spawn(move || worker_loop(job_rx, reply_tx))
            .expect("failed to spawn worker thread");

        Self {
            tx: job_tx,
            rx: reply_rx,
            in_flight: 0,
            _handle: handle,
        }
    }

    /// Submit a job. Increments `in_flight` on success.
    ///
    /// Returns `true` when the job was queued, `false` when the worker
    /// thread has died and the channel is closed. Callers that depend on
    /// the worker actually receiving the job (e.g. global search, which
    /// otherwise sticks in an `in_progress` state forever waiting for a
    /// reply that will never arrive) should branch on the return value
    /// and reset their UI state when the channel is gone.
    ///
    /// Callers that only kick off opportunistic loads (table opens,
    /// localization preload) can ignore the return value — they'll see
    /// the missing data on next interaction and the user can retry.
    ///
    /// We don't panic here because UI code calls `submit` from inside
    /// frame rendering and a worker death must surface as a toast, not
    /// a crash.
    pub fn submit(&mut self, job: Job) -> bool {
        if self.tx.send(job).is_ok() {
            self.in_flight = self.in_flight.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Drain pending replies. Should be called once per UI frame.
    ///
    /// Non-blocking: returns immediately if the channel is empty. Decrements
    /// `in_flight` for each terminal reply observed.
    pub fn poll(&mut self) -> Vec<Reply> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(reply) => {
                    if reply.is_terminal() {
                        self.in_flight = self.in_flight.saturating_sub(1);
                    }
                    out.push(reply);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        out
    }
}

/// Worker thread main loop. Exits when the job channel closes.
fn worker_loop(rx: Receiver<Job>, tx: Sender<Reply>) {
    while let Ok(job) = rx.recv() {
        handle_job(job, &tx);
    }
}

/// Dispatch a single job to its handler. Each handler is responsible for
/// emitting exactly one terminal `Reply` and any number of `Reply::Progress`
/// updates beforehand.
fn handle_job(job: Job, tx: &Sender<Reply>) {
    match job {
        Job::LoadTable {
            dispatch_name,
            game_dir,
            pabgb_filename,
            pabgh_filename,
        } => handle_load_table(dispatch_name, game_dir, pabgb_filename, pabgh_filename, tx),
        Job::LoadCatalog { path } => handle_load_catalog(path, tx),
        Job::Deploy {
            game_dir,
            table_name,
            meta,
            entries,
            overlay_group,
        } => handle_deploy(game_dir, table_name, meta, entries, overlay_group, tx),
        Job::Restore {
            game_dir,
            overlay_group,
        } => handle_restore(game_dir, overlay_group, tx),
        Job::LoadLocalization { game_dir } => handle_load_localization(game_dir, tx),
        Job::SearchAllPabgb {
            request_id,
            game_dir,
            filter,
            filter_as_number,
            tables,
        } => handle_search_all_pabgb(request_id, game_dir, filter, filter_as_number, tables, tx),
        Job::MultiFormatSearch {
            request_id,
            game_dir,
            query,
            filter_as_number,
            formats,
            tables,
            query_kind,
            match_jenkins_hash,
            cancel_flag,
        } => handle_multi_format_search(
            request_id,
            game_dir,
            query,
            filter_as_number,
            formats,
            tables,
            query_kind,
            match_jenkins_hash,
            cancel_flag,
            tx,
        ),
    }
}

/// Walk every supplied table, load it via [`crate::table_loader::load_table`],
/// and stream `Reply::SearchHit` for each entry whose `key` / `string_key`
/// or any nested string field matches the filter. Emits a per-table
/// `Reply::SearchProgress` before each load so the UI can show a meaningful
/// "scanning X..." line. Always finishes with one `Reply::SearchComplete`.
///
/// Errors loading individual tables are non-fatal — we record the first one
/// and keep going. The user gets partial results plus a one-line note about
/// which table failed.
fn handle_search_all_pabgb(
    request_id: u64,
    game_dir: PathBuf,
    filter: String,
    filter_as_number: Option<u64>,
    tables: Vec<TableMeta>,
    tx: &Sender<Reply>,
) {
    let total = tables.len();
    let mut first_error: Option<String> = None;

    for (idx, meta) in tables.iter().enumerate() {
        let _ = tx.send(Reply::SearchProgress {
            request_id,
            scanned: idx,
            total,
            current_table: meta.dispatch_name.clone(),
        });

        // Wrap each table load in catch_unwind so a parser panic on one
        // table can't kill the entire scan (which would also kill the
        // workbench process). On panic we record the first failure and
        // skip to the next table — same flow as a regular Err.
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let load = catch_unwind(AssertUnwindSafe(|| {
            crate::table_loader::load_table(&game_dir, meta)
        }));
        let entries = match load {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => {
                if first_error.is_none() {
                    first_error = Some(format!("{}: {}", meta.dispatch_name, e));
                }
                continue;
            }
            Err(payload) => {
                if first_error.is_none() {
                    first_error = Some(format!(
                        "{}: panic — {}",
                        meta.dispatch_name,
                        describe_panic(&payload)
                    ));
                }
                continue;
            }
        };

        for (entry_idx, entry) in entries.iter().enumerate() {
            if let Some(hit) =
                match_entry_for_search(&meta.dispatch_name, entry_idx, entry, &filter, filter_as_number)
            {
                if tx
                    .send(Reply::SearchHit {
                        request_id,
                        hit,
                    })
                    .is_err()
                {
                    // UI side hung up; bail.
                    return;
                }
            }
        }
    }

    let _ = tx.send(Reply::SearchProgress {
        request_id,
        scanned: total,
        total,
        current_table: String::new(),
    });
    let _ = tx.send(Reply::SearchComplete {
        request_id,
        error: first_error,
    });
}

/// Cheap version of `entry_matches` that runs on the worker. Returns a
/// hit when something matches; the UI side does name resolution for the
/// display label.
///
/// Match rules (in order):
/// 1. Numeric `entry["key"]` equals `filter_as_number`.
/// 2. `string_key` (lowercased) contains the filter.
/// 3. Any nested string leaf (depth-limited) contains the filter.
///
/// Reused by [`handle_multi_format_search`] so PABGB hits look identical
/// regardless of which job kind discovered them.
pub(crate) fn match_entry_for_search(
    dispatch_name: &str,
    entry_idx: usize,
    entry: &serde_json::Value,
    filter_lower: &str,
    filter_as_number: Option<u64>,
) -> Option<GlobalSearchHit> {
    let entry_key = entry
        .get("key")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let string_key = entry
        .get("string_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if let Some(target) = filter_as_number {
        if entry_key == target {
            return Some(GlobalSearchHit {
                dispatch_name: dispatch_name.to_string(),
                entry_idx,
                entry_key,
                string_key,
                matched: format!("key = {}", target),
            });
        }
    }

    if !string_key.is_empty() && string_key.to_lowercase().contains(filter_lower) {
        return Some(GlobalSearchHit {
            dispatch_name: dispatch_name.to_string(),
            entry_idx,
            entry_key,
            string_key: string_key.clone(),
            matched: format!("string_key: {}", string_key),
        });
    }

    if let Some((path, value)) = first_string_match(entry, filter_lower, "", 0) {
        return Some(GlobalSearchHit {
            dispatch_name: dispatch_name.to_string(),
            entry_idx,
            entry_key,
            string_key,
            matched: format!("{}: {}", path, value),
        });
    }

    None
}

/// Recursive walk that returns the first (path, value) leaf where the
/// string contains `filter_lower`. Path is dotted notation. Depth-limited
/// to keep pathologically nested entries cheap.
fn first_string_match(
    value: &serde_json::Value,
    filter_lower: &str,
    path: &str,
    depth: u32,
) -> Option<(String, String)> {
    if depth >= 16 {
        return None;
    }
    match value {
        serde_json::Value::String(s) if s.to_lowercase().contains(filter_lower) => {
            // Truncate long values so the result row stays compact.
            let trimmed = if s.len() > 80 {
                format!("{}...", &s[..80])
            } else {
                s.clone()
            };
            Some((path.to_string(), trimmed))
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let next_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", path, k)
                };
                if let Some(hit) = first_string_match(v, filter_lower, &next_path, depth + 1) {
                    return Some(hit);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let next_path = format!("{}[{}]", path, i);
                if let Some(hit) = first_string_match(v, filter_lower, &next_path, depth + 1) {
                    return Some(hit);
                }
            }
            None
        }
        _ => None,
    }
}

fn handle_load_table(
    dispatch_name: String,
    game_dir: PathBuf,
    pabgb_filename: String,
    pabgh_filename: Option<String>,
    tx: &Sender<Reply>,
) {
    let _ = tx.send(Reply::Progress {
        job_label: format!("Load {}", dispatch_name),
        message: "Reading PAZ archive...".into(),
        fraction: f32::NAN,
    });

    // Reconstruct an ephemeral TableMeta for the loader. The worker doesn't
    // need to share the registry's TableMeta — the three filename-bearing
    // fields are all the loader cares about.
    let meta = TableMeta {
        dispatch_name: dispatch_name.clone(),
        pabgb_filename,
        pabgh_filename,
    };

    // Heavy work happens on this worker thread:
    //   1. Read PAZ to capture raw bytes (also feeds the hex viewer)
    //   2. Parse JSON via dmm_parser_rust_only
    //   3. Clone the entries to build the vanilla snapshot
    //   4. Walk the entries to detect column names for the table view
    // Doing 3 + 4 here means the UI thread just has to move the payload
    // into ActiveTable when the reply lands, which is essentially free.
    //
    // The raw pabgb capture is independent of the parse: if the parser
    // chokes on a v1.0.5 schema change we still want to populate the hex
    // viewer so users can inspect / triage the bytes by hand.
    //
    // Both the PAZ extract and the parse run inside `catch_unwind` so a
    // panic inside dmm_parser_rust_only (e.g. a slice OOB on a schema
    // mismatch) becomes a TableLoaded(Err(...)) reply instead of taking
    // the whole workbench process down. The user-reported
    // "workbench forcefully closes" symptom (e.g. opening
    // `game_play_variable_info`) traces to a parser panic that wasn't
    // caught here.
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let raw_pabgb = catch_unwind(AssertUnwindSafe(|| {
        crate::table_loader::read_pabgb_and_pabgh(&game_dir, &meta)
            .map(|(pabgb, _pabgh)| pabgb)
            .ok()
    }))
    .unwrap_or(None);

    let result = match catch_unwind(AssertUnwindSafe(|| {
        crate::table_loader::load_table(&game_dir, &meta)
    })) {
        Ok(load_result) => load_result.map_err(|e| e.to_string()).map(|entries| {
            let column_names = crate::ui::table_list::detect_columns(&entries);
            let vanilla = entries.clone();
            TableLoadPayload {
                entries,
                vanilla,
                column_names,
            }
        }),
        Err(payload) => Err(format!(
            "panic while parsing {}: {}",
            dispatch_name,
            describe_panic(&payload)
        )),
    };

    let _ = tx.send(Reply::TableLoaded {
        dispatch_name,
        result,
        raw_pabgb,
    });
}

/// Best-effort string extraction from a panic payload (returned by
/// `catch_unwind`). Most stdlib panics carry a `&'static str` or `String`
/// payload; falls through to a generic notice when the message isn't
/// printable from this side of the unwind boundary.
fn describe_panic(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "(non-string panic payload)".to_string()
}

fn handle_load_catalog(path: PathBuf, tx: &Sender<Reply>) {
    let _ = tx.send(Reply::Progress {
        job_label: "Load catalog".into(),
        message: format!("Reading {}...", path.display()),
        fraction: f32::NAN,
    });

    let result = crate::catalog_loader::try_load(&path).map_err(|e| e.to_string());

    let _ = tx.send(Reply::CatalogLoaded { result });
}

fn handle_deploy(
    game_dir: PathBuf,
    table_name: String,
    meta: TableMeta,
    entries: Vec<serde_json::Value>,
    overlay_group: String,
    tx: &Sender<Reply>,
) {
    let _ = tx.send(Reply::Progress {
        job_label: format!("Deploy {}", table_name),
        message: "Serializing and packing overlay...".into(),
        fraction: f32::NAN,
    });

    let result = crate::deploy::deploy(&game_dir, &table_name, &meta, &entries, &overlay_group)
        .map_err(|e| e.to_string());

    let _ = tx.send(Reply::DeployComplete { result });
}

fn handle_restore(game_dir: PathBuf, overlay_group: String, tx: &Sender<Reply>) {
    let _ = tx.send(Reply::Progress {
        job_label: "Restore".into(),
        message: format!("Removing overlay {}...", overlay_group),
        fraction: f32::NAN,
    });

    let result = crate::restore::restore(&game_dir, &overlay_group).map_err(|e| e.to_string());

    let _ = tx.send(Reply::RestoreComplete { result });
}

/// Build (or load from cache) the EN+KR localization tables.
///
/// Cache hit is essentially free; cache miss reads two PAZ chunks (~50 MB
/// combined), decrypts them, and parses two ~38K-entry paloc files. We do
/// the heavy work on this thread rather than the UI thread so even a
/// freshly-installed game doesn't drop a frame on first launch.
fn handle_load_localization(game_dir: PathBuf, tx: &Sender<Reply>) {
    let _ = tx.send(Reply::Progress {
        job_label: "Load localization".into(),
        message: "Reading PALOC archives...".into(),
        fraction: f32::NAN,
    });

    let result = crate::localization::Localization::load_or_build(&game_dir)
        .map_err(|e| e.to_string());

    let _ = tx.send(Reply::LocalizationLoaded { result });
}

/// Cap on hits emitted per format. Prevents a runaway scan from
/// flooding the UI when (e.g.) a 3-letter substring matches half of
/// PALOC. Each format counts independently — if the user wants to keep
/// digging beyond the cap, they can narrow the query.
const MULTI_FORMAT_HIT_CAP_PER_FORMAT: usize = 500;

/// Auxiliary byte pattern attached to a multi-format scan.
///
/// Lets the byte-level scanners look for additional sequences beyond
/// the user's text query — used today for the Jenkins-hash-of-query
/// feature (3 hash variants → 3 patterns) and the hex-mode raw-byte
/// search (1 pattern). Each pattern carries enough metadata for the
/// scanner to emit the right `HitSource` variant.
#[derive(Clone, Debug)]
struct ExtraBytePattern {
    /// Bytes to memmem for. Empty patterns are skipped at construction.
    bytes: Vec<u8>,
    /// What kind of hit to emit. The factory closure inside the
    /// byte-scan helpers picks `HitSource::JenkinsHash` vs
    /// `HitSource::HexPattern` based on this discriminator.
    label: ExtraPatternLabel,
}

/// Discriminator for [`ExtraBytePattern`] — controls which `HitSource`
/// variant the scanner emits and what the snippet text looks like.
#[derive(Clone, Debug)]
enum ExtraPatternLabel {
    /// Jenkins hash of the user's query under a specific case-variant.
    /// Pattern length is implicitly 4.
    JenkinsHash {
        hash: u32,
        case_label: &'static str,
    },
    /// User-supplied hex byte pattern. Pattern length comes from the
    /// `ExtraBytePattern::bytes` Vec; the UI uses it to highlight the
    /// matched span in the hex excerpt.
    HexPattern,
}

/// Compute the up-to-3 Jenkins hashes derived from a text query — one
/// for each of: lowercase, uppercase, original-case. Skips duplicates
/// (e.g. when the query is already all-lowercase or has no letters).
///
/// Returns each hash paired with the case label that produced it so
/// the UI can show the user which variant fired.
fn jenkins_hash_variants(query: &str) -> Vec<(u32, &'static str)> {
    use dmm_parser_rust_only::crypto::checksum::calculate_checksum;
    let lower = query.to_lowercase();
    let upper = query.to_uppercase();
    let mut out: Vec<(u32, &'static str)> = Vec::with_capacity(3);
    let mut emit = |bytes: &[u8], label: &'static str| {
        let h = calculate_checksum(bytes);
        if !out.iter().any(|(prev, _)| *prev == h) {
            out.push((h, label));
        }
    };
    emit(lower.as_bytes(), "lowercase");
    emit(upper.as_bytes(), "uppercase");
    emit(query.as_bytes(), "as-typed");
    out
}

/// Build the list of extra byte patterns derived from a search job.
///
/// Hex mode → exactly one pattern (the parsed bytes). Text mode with
/// `match_jenkins_hash` → up to three Jenkins-hash patterns. Anything
/// else → empty.
fn build_extra_patterns(
    query_kind: &SearchQueryKind,
    match_jenkins_hash: bool,
) -> Vec<ExtraBytePattern> {
    match query_kind {
        SearchQueryKind::HexBytes(bytes) if !bytes.is_empty() => vec![ExtraBytePattern {
            bytes: bytes.clone(),
            label: ExtraPatternLabel::HexPattern,
        }],
        SearchQueryKind::Text(q) if match_jenkins_hash && !q.trim().is_empty() => {
            jenkins_hash_variants(q)
                .into_iter()
                .map(|(hash, case_label)| ExtraBytePattern {
                    bytes: hash.to_le_bytes().to_vec(),
                    label: ExtraPatternLabel::JenkinsHash { hash, case_label },
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Walk every enabled format for `query` and stream
/// [`Reply::MultiFormatHit`] / [`Reply::MultiFormatProgress`] back to
/// the UI. Always finishes with one [`Reply::MultiFormatComplete`].
///
/// Each format handler is wrapped in `catch_unwind` so a parser panic
/// on one file can't kill the whole scan (and the workbench process).
///
/// `cancel_flag` is the UI-side cancellation token. Every scanner
/// checks it at iteration boundaries (per-file, per-entry) and returns
/// the count emitted so far when it flips to `true`. The handler still
/// emits exactly one [`Reply::MultiFormatComplete`] in the cancelled
/// case (with `error: None` — cancel is intentional, not a failure)
/// so the UI's terminal-reply handler resets state cleanly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_multi_format_search(
    request_id: u64,
    game_dir: PathBuf,
    query: String,
    filter_as_number: Option<u64>,
    formats: HashSet<SearchFormat>,
    tables: Vec<TableMeta>,
    query_kind: SearchQueryKind,
    match_jenkins_hash: bool,
    cancel_flag: Arc<AtomicBool>,
    tx: &Sender<Reply>,
) {
    let query_lower = query.to_lowercase();
    let mut total_hits: usize = 0;
    let mut first_error: Option<String> = None;

    // Hex mode requires non-empty parsed bytes. Text mode requires a
    // non-empty trimmed string. Korean-scan mode allows an empty
    // filter (the UI gates that with a two-step confirm). Either way
    // we bail with a friendly message rather than running a wildcard
    // scan that would never match.
    let is_hex_mode = matches!(query_kind, SearchQueryKind::HexBytes(_));
    let is_korean_mode = matches!(query_kind, SearchQueryKind::KoreanScan { .. });
    let early_bail: Option<String> = match &query_kind {
        SearchQueryKind::HexBytes(bytes) if bytes.is_empty() => {
            Some("Hex pattern is empty.".to_string())
        }
        SearchQueryKind::Text(_) if query_lower.trim().is_empty() => {
            Some("Query is empty.".to_string())
        }
        // KoreanScan with `None`/empty filter is intentional — surface
        // the first 500 CJK runs from each scanned format. No bail.
        _ => None,
    };
    if let Some(msg) = early_bail {
        let _ = tx.send(Reply::MultiFormatComplete {
            request_id,
            error: Some(msg),
            total_hits: 0,
        });
        return;
    }

    // Korean-scan mode walks the binary inspector allow-list directly
    // and emits its own hits — the per-format byte scanners would
    // either re-do the work (wrong) or skip CJK extraction entirely
    // (also wrong). Dispatch to the dedicated handler and return early.
    if is_korean_mode {
        let SearchQueryKind::KoreanScan { filter } = &query_kind else {
            unreachable!("guarded by is_korean_mode");
        };
        let filter_lower = filter
            .as_deref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let scan = catch_unwind(AssertUnwindSafe(|| {
            scan_korean_strings(
                request_id,
                &game_dir,
                filter_lower.as_deref(),
                &cancel_flag,
                tx,
            )
        }));
        match scan {
            Ok(Ok(hits)) => total_hits = hits,
            Ok(Err(e)) => first_error = Some(format!("Korean Strings: {}", e)),
            Err(payload) => {
                first_error = Some(format!(
                    "Korean Strings: panic — {}",
                    describe_panic(&payload)
                ));
            }
        }
        let _ = tx.send(Reply::MultiFormatComplete {
            request_id,
            error: first_error,
            total_hits,
        });
        return;
    }

    let extra_patterns = build_extra_patterns(&query_kind, match_jenkins_hash);

    // In hex mode we don't run text-based scanners (PABGB / PALOC /
    // XML) — they're meaningless for raw bytes. The UI also disables
    // those toggles up-front, but we filter here defensively in case
    // a stale call sneaks through.
    let text_only_formats = [
        SearchFormat::Pabgb,
        SearchFormat::Paloc,
        SearchFormat::Xml,
    ];

    // Walk in display order so progress messages line up with the UI's
    // toggle row top-to-bottom. Check the cancellation flag before each
    // per-format dispatch so a click on Cancel between formats short-
    // circuits the rest of the scan.
    for fmt in SearchFormat::all() {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        if !formats.contains(fmt) {
            continue;
        }
        if is_hex_mode && text_only_formats.contains(fmt) {
            continue;
        }

        let _ = tx.send(Reply::MultiFormatProgress {
            request_id,
            message: format!("Scanning {}...", fmt.display_name()),
        });

        use std::panic::{catch_unwind, AssertUnwindSafe};
        let scan = catch_unwind(AssertUnwindSafe(|| match fmt {
            SearchFormat::Pabgb => scan_pabgb(
                request_id,
                &game_dir,
                &query_lower,
                filter_as_number,
                &tables,
                &cancel_flag,
                tx,
            ),
            SearchFormat::Paloc => {
                scan_paloc(request_id, &game_dir, &query_lower, &cancel_flag, tx)
            }
            SearchFormat::Xml => {
                scan_xml(request_id, &game_dir, &query_lower, &cancel_flag, tx)
            }
            SearchFormat::Paatt => scan_byte_files(
                request_id,
                &game_dir,
                &query_lower,
                is_hex_mode,
                ".paatt",
                make_paatt_source,
                &extra_patterns,
                &cancel_flag,
                tx,
            ),
            SearchFormat::Paac => scan_byte_files(
                request_id,
                &game_dir,
                &query_lower,
                is_hex_mode,
                ".paac",
                make_paac_source,
                &extra_patterns,
                &cancel_flag,
                tx,
            ),
            SearchFormat::Pappt => scan_byte_files(
                request_id,
                &game_dir,
                &query_lower,
                is_hex_mode,
                ".pappt",
                make_pappt_source,
                &extra_patterns,
                &cancel_flag,
                tx,
            ),
            SearchFormat::Pamhc => scan_byte_files(
                request_id,
                &game_dir,
                &query_lower,
                is_hex_mode,
                ".pamhc",
                make_pamhc_source,
                &extra_patterns,
                &cancel_flag,
                tx,
            ),
            SearchFormat::BinaryByte => scan_binary_byte(
                request_id,
                &game_dir,
                &query_lower,
                is_hex_mode,
                &extra_patterns,
                &cancel_flag,
                tx,
            ),
        }));

        match scan {
            Ok(Ok(hits)) => total_hits += hits,
            Ok(Err(e)) => {
                if first_error.is_none() {
                    first_error = Some(format!("{}: {}", fmt.display_name(), e));
                }
            }
            Err(payload) => {
                if first_error.is_none() {
                    first_error = Some(format!(
                        "{}: panic — {}",
                        fmt.display_name(),
                        describe_panic(&payload)
                    ));
                }
            }
        }
    }

    // Always emit a terminal Complete reply — including in the
    // cancelled case. Cancel is intentional, so we don't set
    // `error`; the UI uses the request_id mismatch to discard any
    // stale hits emitted before the worker noticed the flag.
    let _ = tx.send(Reply::MultiFormatComplete {
        request_id,
        error: first_error,
        total_hits,
    });
}

/// PABGB scan — reuses the same matcher as `Job::SearchAllPabgb` so
/// hits are identical between the quick-scan checkbox and the
/// multi-format panel. Returns the number of hits emitted.
///
/// Honours `cancel_flag` at table-list and per-entry granularity so a
/// scan halfway through a 10K-entry table can abort within milliseconds
/// of the UI flipping the flag.
#[allow(clippy::too_many_arguments)]
fn scan_pabgb(
    request_id: u64,
    game_dir: &std::path::Path,
    query_lower: &str,
    filter_as_number: Option<u64>,
    tables: &[TableMeta],
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String> {
    let total = tables.len();
    let mut emitted: usize = 0;

    for (idx, meta) in tables.iter().enumerate() {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(emitted);
        }
        if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
            break;
        }
        let _ = tx.send(Reply::MultiFormatProgress {
            request_id,
            message: format!(
                "Scanning PABGB Tables... {}/{} — {}",
                idx + 1,
                total,
                meta.dispatch_name
            ),
        });

        use std::panic::{catch_unwind, AssertUnwindSafe};
        let load = catch_unwind(AssertUnwindSafe(|| {
            crate::table_loader::load_table(game_dir, meta)
        }));
        let entries = match load {
            Ok(Ok(e)) => e,
            _ => continue,
        };

        for (entry_idx, entry) in entries.iter().enumerate() {
            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(emitted);
            }
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                break;
            }
            let Some(hit) = match_entry_for_search(
                &meta.dispatch_name,
                entry_idx,
                entry,
                query_lower,
                filter_as_number,
            ) else {
                continue;
            };
            // Build the rich expand_data once — pretty-printed JSON of the
            // matched entry. Falls back to debug repr when serde fails.
            let expand_data = serde_json::to_string_pretty(entry).ok();
            let multi_hit = MultiFormatHit {
                source: HitSource::Pabgb {
                    dispatch_name: hit.dispatch_name,
                    entry_idx: hit.entry_idx,
                    entry_key: hit.entry_key,
                    string_key: hit.string_key,
                },
                snippet: hit.matched,
                expand_data,
            };
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit: multi_hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
        }
    }

    Ok(emitted)
}

/// PALOC scan — load (or use cached) localization tables, walk both
/// language maps, emit hits where the value contains the query.
///
/// Cancellation: checked once after the (potentially slow) load and
/// then on every map entry — PALOC has ~38K rows per language, so a
/// per-entry check keeps cancel latency under a millisecond even on
/// the unfiltered case.
fn scan_paloc(
    request_id: u64,
    game_dir: &std::path::Path,
    query_lower: &str,
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String> {
    let _ = tx.send(Reply::MultiFormatProgress {
        request_id,
        message: "Scanning PALOC... loading localization (first run can be slow)".to_string(),
    });
    let loc = Localization::load_or_build(game_dir).map_err(|e| e.to_string())?;
    if cancel_flag.load(Ordering::Relaxed) {
        return Ok(0);
    }
    let mut emitted = 0;
    for (lang_label, map) in [("en", &loc.eng), ("kr", &loc.kor)] {
        for (id_str, value) in map.iter() {
            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(emitted);
            }
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                return Ok(emitted);
            }
            if value.is_empty() {
                continue;
            }
            if !value.to_lowercase().contains(query_lower) {
                continue;
            }
            let hash_id = id_str.parse::<u64>().unwrap_or(0);
            let snippet_value = if value.len() > 80 {
                format!("{}...", &value[..80])
            } else {
                value.clone()
            };
            let snippet = format!("{}[{}]: {}", lang_label, hash_id, snippet_value);
            let hit = MultiFormatHit {
                source: HitSource::Paloc {
                    lang: lang_label,
                    hash_id,
                    value: value.clone(),
                },
                snippet,
                expand_data: Some(value.clone()),
            };
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
        }
    }
    Ok(emitted)
}

/// XML scan — enumerate `.xml` files in PAZ and scan each one for the
/// query as UTF-8 text. Slow files are paged via [`scan_text_buffer`].
///
/// Cancellation is checked before each file is read so a click on
/// Cancel mid-scan doesn't have to wait for the next 50-file progress
/// boundary.
fn scan_xml(
    request_id: u64,
    game_dir: &std::path::Path,
    query_lower: &str,
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String> {
    let files = crate::xml_editor::enumerate_xml_files(game_dir).map_err(|e| e.to_string())?;
    let total = files.len();
    let mut emitted = 0usize;
    for (i, entry) in files.iter().enumerate() {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(emitted);
        }
        if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
            break;
        }
        if i % 50 == 0 {
            let _ = tx.send(Reply::MultiFormatProgress {
                request_id,
                message: format!("Scanning XML... {}/{}", i + 1, total),
            });
        }
        let bytes = match crate::xml_editor::read_xml_from_paz(game_dir, entry) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(snippet) = scan_text_buffer(&bytes, query_lower) {
            let hit = MultiFormatHit {
                source: HitSource::Xml {
                    paz_group: entry.group.clone(),
                    dir_path: entry.dir_path.clone(),
                    filename: entry.filename.clone(),
                },
                snippet: format!("[{}] {} — {}", entry.group, entry.filename, snippet),
                // Cap expand at ~4KB so a 1MB XML doesn't bloat the UI.
                expand_data: Some(text_excerpt(&bytes, query_lower, 4096)),
            };
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
        }
    }
    Ok(emitted)
}

/// Generic byte-file scanner used by PAATT / PAAC / PAPPT / PAMHC. The
/// `make_source` closure returns a `(HitSource, paz_group, dir, name)`
/// tuple given a `(group, dir, filename)` triple — that way the caller
/// can keep the format-specific HitSource variant inline.
///
/// `is_hex_mode` skips the text-substring scan (which would always
/// miss raw byte patterns anyway) and only emits hits from the extra
/// patterns. In text mode the original behaviour is preserved plus any
/// extra patterns are scanned alongside.
///
/// Cancellation is checked before reading each file from PAZ so a
/// click on Cancel mid-scan returns within the per-file decompress
/// time even on the slow extensions.
#[allow(clippy::too_many_arguments)]
fn scan_byte_files<F>(
    request_id: u64,
    game_dir: &std::path::Path,
    query_lower: &str,
    is_hex_mode: bool,
    extension: &str,
    make_source: F,
    extra_patterns: &[ExtraBytePattern],
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String>
where
    F: Fn(String, String, String) -> HitSource,
{
    let files = enumerate_extension(game_dir, extension).map_err(|e| e.to_string())?;
    let total = files.len();
    let ext_label = extension.trim_start_matches('.').to_string();
    let mut emitted = 0usize;
    for (i, (group, dir, filename)) in files.iter().enumerate() {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(emitted);
        }
        if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
            break;
        }
        if i % 50 == 0 {
            let _ = tx.send(Reply::MultiFormatProgress {
                request_id,
                message: format!(
                    "Scanning {} files... {}/{}",
                    ext_label,
                    i + 1,
                    total
                ),
            });
        }
        let bytes = match read_paz_file(game_dir, group, dir, filename) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Text-substring pass — only meaningful in text mode.
        if !is_hex_mode {
            if let Some(snippet) = scan_text_buffer(&bytes, query_lower) {
                let hit = MultiFormatHit {
                    source: make_source(group.clone(), dir.clone(), filename.clone()),
                    snippet: format!("[{}] {} — {}", group, filename, snippet),
                    expand_data: Some(text_excerpt(&bytes, query_lower, 1024)),
                };
                if tx
                    .send(Reply::MultiFormatHit {
                        request_id,
                        hit,
                    })
                    .is_err()
                {
                    return Ok(emitted);
                }
                emitted += 1;
                if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                    break;
                }
            }
        }

        // Extra patterns (Jenkins hashes / hex bytes). Each pattern is
        // searched for its first occurrence in the file — a single hit
        // per file per pattern keeps the result count reasonable.
        for pattern in extra_patterns {
            if pattern.bytes.is_empty() {
                continue;
            }
            let Some(offset) = find_byte_pattern(&bytes, &pattern.bytes) else {
                continue;
            };
            let hit = build_extra_pattern_hit(
                pattern,
                &bytes,
                offset,
                &ext_label,
                group,
                dir,
                filename,
            );
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                return Ok(emitted);
            }
        }
    }
    Ok(emitted)
}

fn make_paatt_source(group: String, dir_path: String, filename: String) -> HitSource {
    HitSource::Paatt {
        paz_group: group,
        dir_path,
        filename,
    }
}
fn make_paac_source(group: String, dir_path: String, filename: String) -> HitSource {
    HitSource::Paac {
        paz_group: group,
        dir_path,
        filename,
    }
}
fn make_pappt_source(group: String, dir_path: String, filename: String) -> HitSource {
    HitSource::Pappt {
        paz_group: group,
        dir_path,
        filename,
    }
}
fn make_pamhc_source(group: String, dir_path: String, filename: String) -> HitSource {
    HitSource::Pamhc {
        paz_group: group,
        dir_path,
        filename,
    }
}

/// Slow path — walk every file the binary inspector knows about and
/// scan each one byte-level (UTF-8 + UTF-16 LE).
///
/// `is_hex_mode` skips the text-byte UTF-8/UTF-16 pass and emits hits
/// only from `extra_patterns`. The user picked hex mode specifically
/// to look for raw bytes, so the text scan would never match anyway.
///
/// Cancellation is checked before reading each file from PAZ so a
/// click on Cancel exits within one file's read time — critical for
/// this scanner because it walks 4000+ files.
fn scan_binary_byte(
    request_id: u64,
    game_dir: &std::path::Path,
    query_lower: &str,
    is_hex_mode: bool,
    extra_patterns: &[ExtraBytePattern],
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String> {
    let allowed: Vec<&'static str> = crate::ui::binary_inspector_panel::ALLOWED_EXTENSIONS.to_vec();
    let files =
        crate::binary_inspector::enumerate_files(game_dir, &allowed).map_err(|e| e.to_string())?;
    let total = files.len();
    let mut emitted = 0usize;
    for (i, entry) in files.iter().enumerate() {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(emitted);
        }
        if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
            break;
        }
        if i % 100 == 0 {
            let _ = tx.send(Reply::MultiFormatProgress {
                request_id,
                message: format!("Scanning binary files... {}/{}", i + 1, total),
            });
        }
        let bytes = match crate::binary_inspector::read_file_from_paz(game_dir, entry) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Text-byte pass — UTF-8 + UTF-16 LE. Skipped in hex mode.
        if !is_hex_mode {
            if let Some((offset, snippet, kind)) = scan_byte_buffer(&bytes, query_lower) {
                let hit = MultiFormatHit {
                    source: HitSource::Binary {
                        ext: entry.extension.clone(),
                        paz_group: entry.group.clone(),
                        dir_path: entry.dir_path.clone(),
                        filename: entry.filename.clone(),
                        byte_offset: offset,
                        kind,
                    },
                    snippet: format!(
                        "[{}] {} @0x{:X} — {}",
                        entry.group, entry.filename, offset, snippet
                    ),
                    expand_data: Some(byte_excerpt(&bytes, offset, 96)),
                };
                if tx
                    .send(Reply::MultiFormatHit {
                        request_id,
                        hit,
                    })
                    .is_err()
                {
                    return Ok(emitted);
                }
                emitted += 1;
                if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                    break;
                }
            }
        }

        // Extra patterns (Jenkins hashes / hex bytes).
        for pattern in extra_patterns {
            if pattern.bytes.is_empty() {
                continue;
            }
            let Some(offset) = find_byte_pattern(&bytes, &pattern.bytes) else {
                continue;
            };
            let hit = build_extra_pattern_hit(
                pattern,
                &bytes,
                offset,
                &entry.extension,
                &entry.group,
                &entry.dir_path,
                &entry.filename,
            );
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                return Ok(emitted);
            }
        }
    }
    Ok(emitted)
}

/// Korean-strings mode walker.
///
/// Walks every binary file in the binary inspector's allow-list (same
/// enumeration as [`scan_binary_byte`]) and runs both UTF-8 and UTF-16
/// LE CJK extractors against the bytes. Every surviving CJK run is
/// emitted as a [`HitSource::KoreanString`] hit. When `filter_lower`
/// is supplied, runs whose lowercased text doesn't contain the filter
/// are dropped — applied per-run, not whole-file, so the user can
/// browse extracted strings even when no filter is set.
///
/// Capped per-format by [`MULTI_FORMAT_HIT_CAP_PER_FORMAT`] so an
/// unfiltered scan can't drown the UI with tens of thousands of hits.
///
/// Cancellation is checked before each file is read — Korean
/// extraction is one of the most expensive scanners in the pipeline
/// (it walks every file twice, once per encoding), so per-file cancel
/// granularity is the minimum needed to make Cancel feel instant.
pub(crate) fn scan_korean_strings(
    request_id: u64,
    game_dir: &std::path::Path,
    filter_lower: Option<&str>,
    cancel_flag: &Arc<AtomicBool>,
    tx: &Sender<Reply>,
) -> Result<usize, String> {
    let allowed: Vec<&'static str> = crate::ui::binary_inspector_panel::ALLOWED_EXTENSIONS.to_vec();
    let files =
        crate::binary_inspector::enumerate_files(game_dir, &allowed).map_err(|e| e.to_string())?;
    let total = files.len();
    let mut emitted = 0usize;
    for (i, entry) in files.iter().enumerate() {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(emitted);
        }
        if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
            break;
        }
        if i % 100 == 0 {
            let _ = tx.send(Reply::MultiFormatProgress {
                request_id,
                message: format!("Scanning Korean strings... {}/{}", i + 1, total),
            });
        }
        let bytes = match crate::binary_inspector::read_file_from_paz(game_dir, entry) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // UTF-8 pass — the dominant case for in-game Korean (PA stores
        // most localized strings as length-prefixed UTF-8).
        let utf8_runs = crate::blob_text::extract_text_runs(&bytes);
        for run in utf8_runs {
            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(emitted);
            }
            if !run.has_cjk {
                continue;
            }
            if let Some(needle) = filter_lower {
                if !run.text.to_lowercase().contains(needle) {
                    continue;
                }
            }
            let hit = build_korean_hit(
                entry,
                run.offset,
                run.text,
                KoreanEncoding::Utf8,
                &bytes,
            );
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                return Ok(emitted);
            }
        }

        // UTF-16 LE pass — secondary, with a stricter min-length floor
        // baked into the extractor (>= 4 chars) since well-aligned
        // `0x00 0xAC` byte pairs are common in random binary data and
        // would otherwise dominate the result list.
        let utf16_runs = crate::blob_text::extract_utf16le_text_runs(&bytes);
        for run in utf16_runs {
            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(emitted);
            }
            if !run.has_cjk {
                continue;
            }
            if let Some(needle) = filter_lower {
                if !run.text.to_lowercase().contains(needle) {
                    continue;
                }
            }
            let hit = build_korean_hit(
                entry,
                run.offset,
                run.text,
                KoreanEncoding::Utf16Le,
                &bytes,
            );
            if tx
                .send(Reply::MultiFormatHit {
                    request_id,
                    hit,
                })
                .is_err()
            {
                return Ok(emitted);
            }
            emitted += 1;
            if emitted >= MULTI_FORMAT_HIT_CAP_PER_FORMAT {
                return Ok(emitted);
            }
        }
    }
    Ok(emitted)
}

/// Construct one [`HitSource::KoreanString`] hit. The snippet
/// embeds the encoding label and a truncated copy of the text run so
/// the result row is informative without expanding; `expand_data`
/// carries the surrounding hex dump for raw-byte inspection.
fn build_korean_hit(
    entry: &crate::binary_inspector::BinaryFileEntry,
    byte_offset: usize,
    text: String,
    encoding: KoreanEncoding,
    bytes: &[u8],
) -> MultiFormatHit {
    let enc_label = match encoding {
        KoreanEncoding::Utf8 => "UTF-8",
        KoreanEncoding::Utf16Le => "UTF-16 LE",
    };
    let display_text = if text.chars().count() > 80 {
        let truncated: String = text.chars().take(80).collect();
        format!("{}...", truncated)
    } else {
        text.clone()
    };
    let snippet = format!(
        "[{}] {} @0x{:X} {} — {}",
        entry.group, entry.filename, byte_offset, enc_label, display_text
    );
    MultiFormatHit {
        source: HitSource::KoreanString {
            ext: entry.extension.clone(),
            paz_group: entry.group.clone(),
            dir_path: entry.dir_path.clone(),
            filename: entry.filename.clone(),
            byte_offset,
            text,
            encoding,
        },
        snippet,
        expand_data: Some(byte_excerpt(bytes, byte_offset, 96)),
    }
}

/// PAZ-aware enumerator for one extension. Returns `(group, dir,
/// filename)` triples sorted for stability. Internal helper shared by
/// the PAATT / PAAC / PAPPT / PAMHC handlers — those have their own
/// editor-side enumerators but each returns a different concrete entry
/// type, so we use a tuple here to keep the byte-scan plumbing
/// extension-agnostic.
fn enumerate_extension(
    game_dir: &std::path::Path,
    dot_extension: &str,
) -> std::io::Result<Vec<(String, String, String)>> {
    let ext_lower = dot_extension.to_ascii_lowercase();
    let trimmed: &str = ext_lower.trim_start_matches('.');
    // The binary_inspector enumerator already implements this exact
    // walk (and is panic-safe). Reuse it instead of re-implementing
    // the PAZ scan a fifth time.
    let allowed = [trimmed];
    let bin_entries = crate::binary_inspector::enumerate_files(game_dir, &allowed)?;
    Ok(bin_entries
        .into_iter()
        .map(|e| (e.group, e.dir_path, e.filename))
        .collect())
}

/// Read raw bytes for a single file from its PAZ group. Mirrors
/// [`crate::binary_inspector::read_file_from_paz`] but takes the path
/// pieces directly so callers don't have to construct a
/// `BinaryFileEntry` first.
fn read_paz_file(
    game_dir: &std::path::Path,
    group: &str,
    dir_path: &str,
    filename: &str,
) -> std::io::Result<Vec<u8>> {
    let entry = crate::binary_inspector::BinaryFileEntry {
        group: group.to_string(),
        dir_path: dir_path.to_string(),
        filename: filename.to_string(),
        extension: filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase(),
    };
    crate::binary_inspector::read_file_from_paz(game_dir, &entry)
}

/// UTF-8 substring scan over the buffer. Returns a short snippet
/// centered on the first match for the result row.
fn scan_text_buffer(bytes: &[u8], query_lower: &str) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let lower = s.to_lowercase();
    let pos = lower.find(query_lower)?;
    Some(snippet_around(s, pos, 80))
}

/// Byte-level scan: tries UTF-8 first, then a UTF-16 LE pass.
/// Returns `(byte_offset, snippet, kind)` for the first hit.
fn scan_byte_buffer(bytes: &[u8], query_lower: &str) -> Option<(usize, String, ByteHitKind)> {
    // UTF-8 / ASCII pass — lossy decode so a binary file with valid
    // ASCII strings inside still matches.
    let text = String::from_utf8_lossy(bytes);
    let lower = text.to_lowercase();
    if let Some(pos) = lower.find(query_lower) {
        return Some((pos, snippet_around(&text, pos, 64), ByteHitKind::Utf8));
    }
    // UTF-16 LE pass for engine wide-strings. Decode by stride 2 with
    // a soft skip past invalid surrogate pairs so a single byte slip
    // doesn't void the whole scan.
    if bytes.len() >= 4 {
        let pairs: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let wide = String::from_utf16_lossy(&pairs);
        let wide_lower = wide.to_lowercase();
        if let Some(char_pos) = wide_lower.find(query_lower) {
            // Map back to a byte offset (each u16 is 2 bytes).
            let byte_offset = char_pos.saturating_mul(2);
            return Some((
                byte_offset,
                snippet_around(&wide, char_pos, 64),
                ByteHitKind::Utf16Le,
            ));
        }
    }
    None
}

/// Produce a snippet of `text` around `byte_pos`, capped to roughly
/// `radius` chars on either side and stripped of newlines so it fits
/// on one line in the result table.
fn snippet_around(text: &str, byte_pos: usize, radius: usize) -> String {
    let start = byte_pos.saturating_sub(radius);
    // Walk forward to a char boundary so the slice is valid UTF-8.
    let start = adjust_to_char_boundary(text, start, /* forward = */ true);
    let raw_end = (byte_pos + radius).min(text.len());
    let end = adjust_to_char_boundary(text, raw_end, /* forward = */ false);
    let slice = &text[start..end];
    // Compact whitespace runs so multi-line matches stay readable.
    let mut out = String::with_capacity(slice.len());
    let mut last_was_space = false;
    for c in slice.chars() {
        let is_space = c.is_whitespace();
        if is_space {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out
}

/// Find the next char boundary at or after / before `pos` so a slice
/// at that index is valid UTF-8. `forward = true` walks toward higher
/// indices; `forward = false` walks toward lower.
fn adjust_to_char_boundary(text: &str, pos: usize, forward: bool) -> usize {
    let mut p = pos.min(text.len());
    if forward {
        while p < text.len() && !text.is_char_boundary(p) {
            p += 1;
        }
    } else {
        while p > 0 && !text.is_char_boundary(p) {
            p -= 1;
        }
    }
    p
}

/// Pretty excerpt for the expand-data view of a text file. Returns at
/// most `cap` chars centered on the first occurrence of the query.
fn text_excerpt(bytes: &[u8], query_lower: &str, cap: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    let lower = s.to_lowercase();
    let Some(pos) = lower.find(query_lower) else {
        return s.chars().take(cap).collect();
    };
    let half = cap / 2;
    let start = pos.saturating_sub(half);
    let start = adjust_to_char_boundary(&s, start, true);
    let end = (pos + half).min(s.len());
    let end = adjust_to_char_boundary(&s, end, false);
    s[start..end].to_string()
}

/// Hex dump for the expand-data view of a binary file. Shows up to
/// `radius * 2` bytes centred on `offset`, formatted as a 16-byte-wide
/// hex grid for readability.
fn byte_excerpt(bytes: &[u8], offset: usize, radius: usize) -> String {
    let start = offset.saturating_sub(radius);
    let end = (offset + radius).min(bytes.len());
    let slice = &bytes[start..end];
    let mut out = String::with_capacity(slice.len() * 4);
    for (i, byte) in slice.iter().enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("{:08X}: ", start + i));
        }
        out.push_str(&format!("{:02X} ", byte));
    }
    out
}

/// Naive byte-pattern memmem. Returns the index of the first match in
/// `haystack` or `None` when no match exists. Used by the extra-byte
/// patterns (Jenkins hashes / hex byte search).
///
/// We deliberately use `windows().position()` instead of pulling in a
/// full memmem crate — the haystacks are typically a few KB to a few
/// MB and the patterns are short (4 bytes for hashes, ~1-32 bytes for
/// hex), so the naive approach is plenty fast and avoids a new dep.
fn find_byte_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Render a compact one-line hex preview centred on `offset`, showing
/// up to `radius` bytes on either side. Used for the inline snippet
/// of hex/Jenkins hits so the user can see the immediate byte context
/// without having to expand the row.
fn inline_byte_preview(bytes: &[u8], offset: usize, radius: usize) -> String {
    let start = offset.saturating_sub(radius);
    let end = (offset + radius).min(bytes.len());
    let mut out = String::with_capacity((end - start) * 3);
    for (i, b) in bytes[start..end].iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02X}", b));
    }
    out
}

/// Build the [`MultiFormatHit`] for one extra-pattern match. Centralised
/// so both [`scan_byte_files`] and [`scan_binary_byte`] emit identical
/// labels for Jenkins-hash and hex-pattern hits.
fn build_extra_pattern_hit(
    pattern: &ExtraBytePattern,
    bytes: &[u8],
    offset: usize,
    ext_label: &str,
    paz_group: &str,
    dir_path: &str,
    filename: &str,
) -> MultiFormatHit {
    match &pattern.label {
        ExtraPatternLabel::JenkinsHash { hash, case_label } => {
            let snippet = format!(
                "[{}] {} @0x{:X} — Jenkins hash 0x{:08X} ({})",
                paz_group, filename, offset, hash, case_label,
            );
            MultiFormatHit {
                source: HitSource::JenkinsHash {
                    ext: ext_label.to_string(),
                    paz_group: paz_group.to_string(),
                    dir_path: dir_path.to_string(),
                    filename: filename.to_string(),
                    byte_offset: offset,
                    hash: *hash,
                    case_label,
                },
                snippet,
                expand_data: Some(byte_excerpt(bytes, offset, 96)),
            }
        }
        ExtraPatternLabel::HexPattern => {
            let pattern_hex = pattern
                .bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            // 16-byte hex preview centred on the match — gives the
            // user immediate visual context without expanding the row.
            let preview = inline_byte_preview(bytes, offset, 16);
            let snippet = format!(
                "[{}] {} @0x{:X} — pattern {} | ctx: {}",
                paz_group, filename, offset, pattern_hex, preview,
            );
            MultiFormatHit {
                source: HitSource::HexPattern {
                    ext: ext_label.to_string(),
                    paz_group: paz_group.to_string(),
                    dir_path: dir_path.to_string(),
                    filename: filename.to_string(),
                    byte_offset: offset,
                    pattern_len: pattern.bytes.len(),
                },
                snippet,
                expand_data: Some(byte_excerpt(bytes, offset, 96)),
            }
        }
    }
}

/// Parse a hex pattern string typed by the user.
///
/// Accepts:
///   - Pure hex digits, no whitespace: `"5A4C0000"` → `[0x5A, 0x4C,
///     0x00, 0x00]`.
///   - Hex digits with arbitrary whitespace between them: `"5A 4C
///     00 00"` → same. Leading / trailing whitespace also stripped.
///   - Mixed case: `"5a4C"` → `[0x5A, 0x4C]`.
///
/// Rejects:
///   - Odd hex digit count after stripping whitespace.
///   - Anything that isn't `[0-9a-fA-F]` after stripping whitespace.
///   - Empty input (after stripping).
///
/// Returns a human-readable error string on rejection — the UI shows
/// it verbatim under the search box.
pub fn parse_hex_pattern(input: &str) -> Result<Vec<u8>, String> {
    // Strip every whitespace char so the user can paste in `5A 4C` or
    // `5A\n4C` interchangeably with `5A4C`.
    let mut compact = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_whitespace() {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return Err(format!("invalid hex character '{}'", c));
        }
        compact.push(c);
    }
    if compact.is_empty() {
        return Err("hex pattern is empty".to_string());
    }
    if compact.len() % 2 != 0 {
        return Err(format!(
            "odd hex digit count ({} digits) — need pairs",
            compact.len()
        ));
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    let bytes = compact.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        // `from_str_radix` over a 2-char ASCII slice is safe — we
        // already verified every char is `is_ascii_hexdigit`.
        let s = std::str::from_utf8(chunk)
            .expect("chunk is ASCII by construction");
        let byte = u8::from_str_radix(s, 16)
            .expect("two hex digits parse as u8 by construction");
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_increments_in_flight_and_poll_decrements_on_terminal() {
        // Use a job whose handler will fail fast (no game_dir on disk) so we
        // get a terminal reply quickly without depending on real data.
        let mut w = Worker::spawn();
        assert_eq!(w.in_flight, 0);

        let queued = w.submit(Job::Restore {
            game_dir: PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            overlay_group: "0058".into(),
        });
        assert!(queued, "submit should report success on a live worker");
        assert_eq!(w.in_flight, 1);

        // Spin until we see a terminal reply (with a sane upper bound).
        let mut saw_terminal = false;
        for _ in 0..200 {
            let replies = w.poll();
            for r in &replies {
                if matches!(r, Reply::RestoreComplete { .. }) {
                    saw_terminal = true;
                }
            }
            if saw_terminal {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(saw_terminal, "worker never produced a terminal reply");
        assert_eq!(w.in_flight, 0);
    }

    #[test]
    fn submit_returns_false_when_channel_closed() {
        // Build a Worker, immediately drop the receiver-side of the job
        // channel by forcing the worker thread to exit. We can't reach
        // into `Worker` to do that directly, but constructing a fresh
        // pair and dropping the receiver gives us the same observable
        // shape: `submit` returns false and `in_flight` stays at 0.
        //
        // We test the underlying invariant — `submit` returns false on
        // send error — by stubbing a Worker with a closed channel.
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let (_reply_tx, reply_rx) = std::sync::mpsc::channel::<Reply>();
        // Drop the receiver — any subsequent `tx.send(...)` will fail
        // with `SendError`, which is exactly what `submit` checks.
        drop(rx);
        // Spawn a no-op join handle so Worker::_handle has something
        // legal to own. We don't actually need this thread to do
        // anything since we're not exercising the worker loop.
        let handle = thread::Builder::new()
            .name("test-noop".into())
            .spawn(|| {})
            .expect("failed to spawn no-op worker thread");
        let mut w = Worker {
            tx,
            rx: reply_rx,
            in_flight: 0,
            _handle: handle,
        };
        let queued = w.submit(Job::Restore {
            game_dir: PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            overlay_group: "0058".into(),
        });
        assert!(
            !queued,
            "submit must return false when the channel is closed"
        );
        assert_eq!(
            w.in_flight, 0,
            "in_flight must not increment when send fails"
        );
    }

    #[test]
    fn progress_does_not_decrement_in_flight() {
        // Synthesize a Progress reply and verify is_terminal == false.
        let r = Reply::Progress {
            job_label: "x".into(),
            message: "y".into(),
            fraction: 0.5,
        };
        assert!(!r.is_terminal());
    }

    #[test]
    fn parse_hex_pattern_accepts_compact_and_spaced() {
        // Compact form.
        assert_eq!(parse_hex_pattern("5A4C").unwrap(), vec![0x5A, 0x4C]);
        // Spaced form maps to identical bytes.
        assert_eq!(parse_hex_pattern("5A 4C").unwrap(), vec![0x5A, 0x4C]);
        // Mixed-case.
        assert_eq!(parse_hex_pattern("5a4C").unwrap(), vec![0x5A, 0x4C]);
        // Mixed whitespace + leading/trailing space.
        assert_eq!(
            parse_hex_pattern("  5A 4C  00\t00 ").unwrap(),
            vec![0x5A, 0x4C, 0x00, 0x00]
        );
    }

    #[test]
    fn parse_hex_pattern_rejects_invalid() {
        // Odd digit count.
        assert!(parse_hex_pattern("5").is_err());
        assert!(parse_hex_pattern("5A4").is_err());
        // Non-hex character.
        assert!(parse_hex_pattern("5G").is_err());
        // Empty input.
        assert!(parse_hex_pattern("").is_err());
        // Whitespace-only input.
        assert!(parse_hex_pattern("   \t  ").is_err());
    }

    #[test]
    fn jenkins_hash_variants_produce_distinct_hashes_for_mixed_case() {
        // "Kliff" should generate three distinct hashes (lowercase,
        // uppercase, as-typed are all different strings).
        let hashes = jenkins_hash_variants("Kliff");
        assert_eq!(hashes.len(), 3);
        // Already-lowercase: lowercase == as-typed, so we expect just
        // one or two entries depending on whether uppercase coincides
        // (it doesn't for letters).
        let lower_hashes = jenkins_hash_variants("kliff");
        assert!(
            lower_hashes.len() <= 2,
            "lowercase 'kliff' should dedupe with as-typed"
        );
    }

    #[test]
    fn find_byte_pattern_basic() {
        let hay = b"abcdef";
        assert_eq!(find_byte_pattern(hay, b"cd"), Some(2));
        assert_eq!(find_byte_pattern(hay, b"abc"), Some(0));
        assert_eq!(find_byte_pattern(hay, b"ef"), Some(4));
        assert_eq!(find_byte_pattern(hay, b"xyz"), None);
        assert_eq!(find_byte_pattern(hay, b""), None);
        // Needle longer than haystack.
        assert_eq!(find_byte_pattern(b"a", b"ab"), None);
    }

    /// Pre-flipping the cancel flag before invoking
    /// `handle_multi_format_search` must short-circuit the scan: no
    /// `MultiFormatHit` replies, exactly one `MultiFormatComplete`
    /// with `total_hits == 0` and `error == None` (cancel is
    /// intentional, not a failure). Uses a non-existent game_dir so
    /// no real PAZ I/O can succeed even if the cancel were ignored —
    /// belt + braces.
    #[test]
    fn cancel_flag_short_circuits_scan() {
        let (tx, rx) = mpsc::channel::<Reply>();
        let cancel = Arc::new(AtomicBool::new(true));

        // Enable every format to maximise the surface that has to
        // honour the flag — text scanners (PABGB / PALOC / XML) and
        // byte scanners (PAATT / PAAC / PAPPT / PAMHC / BinaryByte)
        // all have to no-op when the flag is set on entry.
        let mut formats: HashSet<SearchFormat> = HashSet::new();
        for f in SearchFormat::all() {
            formats.insert(*f);
        }

        handle_multi_format_search(
            42,
            PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            "kliff".to_string(),
            None,
            formats,
            Vec::new(),
            SearchQueryKind::Text("kliff".to_string()),
            false,
            cancel,
            &tx,
        );
        drop(tx);

        let mut saw_complete = false;
        let mut hit_count = 0usize;
        let mut complete_total: Option<usize> = None;
        let mut complete_error: Option<Option<String>> = None;
        while let Ok(reply) = rx.recv() {
            match reply {
                Reply::MultiFormatHit { request_id, .. } => {
                    assert_eq!(request_id, 42, "hit must carry the submitted request_id");
                    hit_count += 1;
                }
                Reply::MultiFormatComplete {
                    request_id,
                    error,
                    total_hits,
                } => {
                    assert_eq!(request_id, 42);
                    saw_complete = true;
                    complete_total = Some(total_hits);
                    complete_error = Some(error);
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_complete, "must emit MultiFormatComplete on cancel");
        assert_eq!(hit_count, 0, "no hits should fire when cancel flag is pre-set");
        assert_eq!(
            complete_total,
            Some(0),
            "total_hits must be zero on early cancel"
        );
        assert_eq!(
            complete_error.flatten(),
            None,
            "cancel is intentional — error must stay None"
        );
    }

    /// Korean-strings dispatch path is a separate early-return branch
    /// inside `handle_multi_format_search`; assert that it also
    /// honours a pre-flipped cancel flag and emits a clean Complete.
    #[test]
    fn cancel_flag_short_circuits_korean_scan() {
        let (tx, rx) = mpsc::channel::<Reply>();
        let cancel = Arc::new(AtomicBool::new(true));

        let mut formats: HashSet<SearchFormat> = HashSet::new();
        formats.insert(SearchFormat::BinaryByte);

        handle_multi_format_search(
            7,
            PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            "(no filter — all CJK runs)".to_string(),
            None,
            formats,
            Vec::new(),
            SearchQueryKind::KoreanScan { filter: None },
            false,
            cancel,
            &tx,
        );
        drop(tx);

        let mut saw_complete = false;
        let mut hit_count = 0usize;
        while let Ok(reply) = rx.recv() {
            match reply {
                Reply::MultiFormatHit { .. } => hit_count += 1,
                Reply::MultiFormatComplete {
                    request_id,
                    error: _,
                    total_hits,
                } => {
                    assert_eq!(request_id, 7);
                    assert_eq!(total_hits, 0);
                    saw_complete = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_complete);
        assert_eq!(hit_count, 0);
    }

    /// Setting the cancel flag at the *outer-loop* boundary (i.e.
    /// after dispatch but between formats) is functionally identical
    /// to pre-flipping it: every format check loads the flag, sees
    /// `true`, and breaks. Same observable shape — exactly one
    /// Complete, zero hits.
    #[test]
    fn cancel_flag_set_after_submit_still_aborts() {
        let (tx, rx) = mpsc::channel::<Reply>();
        let cancel = Arc::new(AtomicBool::new(false));

        let mut formats: HashSet<SearchFormat> = HashSet::new();
        formats.insert(SearchFormat::Pabgb);

        // Flip after construction but before invocation. The handler
        // sees the flag at the very first format-loop check.
        cancel.store(true, Ordering::Relaxed);

        handle_multi_format_search(
            1,
            PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            "x".to_string(),
            None,
            formats,
            Vec::new(),
            SearchQueryKind::Text("x".to_string()),
            false,
            cancel,
            &tx,
        );
        drop(tx);

        let mut saw_complete = false;
        while let Ok(reply) = rx.recv() {
            if let Reply::MultiFormatComplete { total_hits, .. } = reply {
                saw_complete = true;
                assert_eq!(total_hits, 0);
                break;
            }
        }
        assert!(saw_complete);
    }
}
