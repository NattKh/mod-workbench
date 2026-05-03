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
    TableLoaded {
        dispatch_name: String,
        result: Result<TableLoadPayload, String>,
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
    /// Optional progress update emitted before a terminal reply.
    ///
    /// `fraction` is in `[0.0, 1.0]`, or `f32::NAN` for indeterminate.
    Progress {
        job_label: String,
        message: String,
        fraction: f32,
    },
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
    //   1. Read PAZ + parse JSON via dmm_parser_rust_only
    //   2. Clone the entries to build the vanilla snapshot
    //   3. Walk the entries to detect column names for the table view
    // Doing 2 + 3 here means the UI thread just has to move the payload
    // into ActiveTable when the reply lands, which is essentially free.
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
