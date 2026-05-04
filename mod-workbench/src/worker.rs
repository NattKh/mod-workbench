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

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

use crate::catalog::Catalog;
use crate::localization::Localization;
use crate::state::TableMeta;

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

    /// Submit a job. Increments `in_flight`.
    ///
    /// If the worker thread has somehow died, the send fails silently and
    /// `in_flight` is left unchanged; the UI will see no reply and can
    /// recover on its own. We don't panic here because UI code calls
    /// `submit` from inside frame rendering.
    pub fn submit(&mut self, job: Job) {
        if self.tx.send(job).is_ok() {
            self.in_flight = self.in_flight.saturating_add(1);
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

        let entries = match crate::table_loader::load_table(&game_dir, meta) {
            Ok(e) => e,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("{}: {}", meta.dispatch_name, e));
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
fn match_entry_for_search(
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
    let raw_pabgb = crate::table_loader::read_pabgb_and_pabgh(&game_dir, &meta)
        .map(|(pabgb, _pabgh)| pabgb)
        .ok();

    let result = crate::table_loader::load_table(&game_dir, &meta)
        .map_err(|e| e.to_string())
        .map(|entries| {
            let column_names = crate::ui::table_list::detect_columns(&entries);
            let vanilla = entries.clone();
            TableLoadPayload {
                entries,
                vanilla,
                column_names,
            }
        });

    let _ = tx.send(Reply::TableLoaded {
        dispatch_name,
        result,
        raw_pabgb,
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_increments_in_flight_and_poll_decrements_on_terminal() {
        // Use a job whose handler will fail fast (no game_dir on disk) so we
        // get a terminal reply quickly without depending on real data.
        let mut w = Worker::spawn();
        assert_eq!(w.in_flight, 0);

        w.submit(Job::Restore {
            game_dir: PathBuf::from("\\\\?\\Z:\\definitely\\does\\not\\exist"),
            overlay_group: "0058".into(),
        });
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
    fn progress_does_not_decrement_in_flight() {
        // Synthesize a Progress reply and verify is_terminal == false.
        let r = Reply::Progress {
            job_label: "x".into(),
            message: "y".into(),
            fraction: 0.5,
        };
        assert!(!r.is_terminal());
    }
}
