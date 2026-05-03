//! Snapshot / restore system for game-state safety.
//!
//! Every deploy auto-creates a snapshot of the files the deploy is about to
//! mutate (the global `meta/0.papgt` plus the overlay group directory) so the
//! user can roll back to any previous state if a deploy turns out to break the
//! game.
//!
//! ## Storage layout
//!
//! Snapshots live under a per-user data directory, currently
//! `%APPDATA%/Crimson/ModWorkbench/backups/` on Windows (or the platform-
//! equivalent dir resolved via [`directories::ProjectDirs`]). Each snapshot is
//! its own subdirectory, named after a stable timestamp ID:
//!
//! ```text
//! backups/
//!   2026-05-03_18-42-15/
//!     snapshot.json          <- metadata (Snapshot serialized)
//!     papgt.bak              <- copy of game_dir/meta/0.papgt
//!     0058/                  <- copy of game_dir/<overlay_group>/
//!       0.paz
//!       0.pamt
//! ```
//!
//! The snapshot ID itself is the directory name, so listing simply scans the
//! `backups/` parent and parses each child's `snapshot.json`.
//!
//! ## Failure policy
//!
//! `create_snapshot` is best-effort: missing source files are skipped (they
//! just won't appear in the snapshot dir) rather than aborting the snapshot
//! entirely. The deploy path treats backup failure as non-fatal — the user
//! still gets to deploy even if the backup machinery is broken — but the
//! caller is responsible for that policy; this module returns `io::Result`
//! and lets the caller decide.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const META_PAPGT_REL: &str = "meta/0.papgt";
const PAPGT_BACKUP_NAME: &str = "papgt.bak";
const SNAPSHOT_JSON_NAME: &str = "snapshot.json";

/// Metadata describing a single snapshot.
///
/// Stored as `snapshot.json` inside the snapshot directory. The struct is the
/// public API surface for callers (UI list rows, restore lookups).
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Timestamp-based ID, also the directory name on disk.
    /// Format: `YYYY-MM-DD_HH-MM-SS` (UTC).
    pub id: String,
    /// Same instant as `id`, formatted for human display.
    pub created_at: String,
    /// User-supplied label or auto-generated one (e.g. "Pre-deploy: gimmick_info").
    pub label: String,
    /// Overlay group whose files were captured (e.g. "0058").
    pub overlay_group: String,
    /// Size of the captured `papgt.bak` in bytes (0 if PAPGT was missing).
    pub papgt_size: u64,
    /// Cumulative size of all files captured under `<overlay_group>/` (0 if
    /// the overlay didn't exist at snapshot time).
    pub paz_size: u64,
}

/// Resolved path to the per-user backups directory.
///
/// Returns `None` when no platform home/data dir is available — callers
/// should treat this as "snapshots disabled" rather than an error.
pub fn backup_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
    Some(dirs.data_dir().join("backups"))
}

/// Capture a snapshot of the files that a deploy is about to touch.
///
/// Copies (when present):
/// - `<game_dir>/meta/0.papgt` -> `<backup_dir>/<id>/papgt.bak`
/// - `<game_dir>/<overlay_group>/*` -> `<backup_dir>/<id>/<overlay_group>/*`
///
/// Then writes `snapshot.json` describing the capture. Missing source files
/// are skipped silently — a fresh game with no overlay yet produces a
/// snapshot whose `paz_size` is 0, which is the correct "nothing to restore"
/// state.
///
/// Returns the populated [`Snapshot`] on success.
pub fn create_snapshot(
    game_dir: &Path,
    overlay_group: &str,
    label: &str,
) -> io::Result<Snapshot> {
    let root = backup_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no platform data directory available for backups",
        )
    })?;

    let id = generate_snapshot_id();
    let snap_dir = root.join(&id);
    std::fs::create_dir_all(&snap_dir)?;

    // Copy meta/0.papgt if present.
    let mut papgt_size: u64 = 0;
    let papgt_src = game_dir.join(META_PAPGT_REL);
    if papgt_src.is_file() {
        let papgt_dst = snap_dir.join(PAPGT_BACKUP_NAME);
        papgt_size = std::fs::copy(&papgt_src, &papgt_dst)?;
    }

    // Copy the overlay group directory if present.
    let mut paz_size: u64 = 0;
    let overlay_src = game_dir.join(overlay_group);
    if overlay_src.is_dir() {
        let overlay_dst = snap_dir.join(overlay_group);
        std::fs::create_dir_all(&overlay_dst)?;
        paz_size = copy_dir_recursive(&overlay_src, &overlay_dst)?;
    }

    let snapshot = Snapshot {
        id: id.clone(),
        created_at: format_human_timestamp_now(),
        label: label.to_string(),
        overlay_group: overlay_group.to_string(),
        papgt_size,
        paz_size,
    };

    // Persist metadata last — if anything above failed we don't have a stale
    // metadata file claiming files exist that don't.
    let meta_path = snap_dir.join(SNAPSHOT_JSON_NAME);
    let json = serde_json::to_string_pretty(&snapshot).map_err(io_invalid_data)?;
    std::fs::write(&meta_path, json)?;

    Ok(snapshot)
}

/// List all snapshots under [`backup_dir`], newest first.
///
/// Sub-directories without a parseable `snapshot.json` are silently skipped
/// (they're either in-progress or corrupt; either way we don't want to crash
/// the UI list). When the backups dir itself doesn't exist yet, returns
/// `Ok(vec![])` rather than erroring.
pub fn list_snapshots() -> io::Result<Vec<Snapshot>> {
    let root = match backup_dir() {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };
    if !root.is_dir() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let meta_path = entry.path().join(SNAPSHOT_JSON_NAME);
        let data = match std::fs::read_to_string(&meta_path) {
            Ok(d) => d,
            Err(_) => continue, // skip dirs without metadata
        };
        match serde_json::from_str::<Snapshot>(&data) {
            Ok(s) => out.push(s),
            Err(e) => {
                eprintln!(
                    "backup: skipping unparseable snapshot {}: {}",
                    meta_path.display(),
                    e
                );
            }
        }
    }

    // Newest first — IDs are lexicographically sortable since they're
    // zero-padded `YYYY-MM-DD_HH-MM-SS`.
    out.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(out)
}

/// Restore the snapshot with the given ID into `game_dir`.
///
/// Steps:
/// 1. Read `snapshot.json` to learn which overlay group the snapshot covers.
/// 2. If `papgt.bak` exists, copy it back to `<game_dir>/meta/0.papgt`.
/// 3. Wipe `<game_dir>/<overlay_group>/` and replace it with the snapshot
///    copy of that directory (if any).
///
/// If the snapshot didn't capture an overlay (paz_size == 0 / dir absent),
/// step 3 just removes whatever overlay is currently there, returning the
/// game to the pre-overlay state.
pub fn restore_snapshot(snapshot_id: &str, game_dir: &Path) -> io::Result<()> {
    let root = backup_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no platform data directory available for backups",
        )
    })?;
    let snap_dir = root.join(snapshot_id);
    if !snap_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("snapshot '{}' not found", snapshot_id),
        ));
    }

    // Read metadata to learn the overlay group.
    let meta_path = snap_dir.join(SNAPSHOT_JSON_NAME);
    let meta_data = std::fs::read_to_string(&meta_path)?;
    let snapshot: Snapshot = serde_json::from_str(&meta_data).map_err(io_invalid_data)?;

    // Restore PAPGT if we have a copy.
    let papgt_src = snap_dir.join(PAPGT_BACKUP_NAME);
    if papgt_src.is_file() {
        let papgt_dst = game_dir.join(META_PAPGT_REL);
        if let Some(parent) = papgt_dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&papgt_src, &papgt_dst)?;
    }

    // Replace the overlay group directory.
    let overlay_dst = game_dir.join(&snapshot.overlay_group);
    if overlay_dst.is_dir() {
        std::fs::remove_dir_all(&overlay_dst)?;
    }
    let overlay_src = snap_dir.join(&snapshot.overlay_group);
    if overlay_src.is_dir() {
        std::fs::create_dir_all(&overlay_dst)?;
        copy_dir_recursive(&overlay_src, &overlay_dst)?;
    }

    Ok(())
}

/// Delete a snapshot directory (metadata + captured files) by ID.
pub fn delete_snapshot(snapshot_id: &str) -> io::Result<()> {
    let root = backup_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no platform data directory available for backups",
        )
    })?;
    let snap_dir = root.join(snapshot_id);
    if snap_dir.is_dir() {
        std::fs::remove_dir_all(&snap_dir)?;
    }
    Ok(())
}

/// Trim the snapshot directory down to the newest `keep_count` entries.
///
/// Returns the number of snapshots deleted. Used post-deploy to cap the
/// backup directory size so it can't grow without bound.
pub fn cleanup_old_snapshots(keep_count: usize) -> io::Result<usize> {
    let snapshots = list_snapshots()?;
    if snapshots.len() <= keep_count {
        return Ok(0);
    }
    let to_delete = &snapshots[keep_count..];
    let mut deleted = 0;
    for s in to_delete {
        if delete_snapshot(&s.id).is_ok() {
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Recursively copy `src` into `dst` (which must already exist). Returns the
/// total number of bytes copied so callers can report `paz_size` etc.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let entry_dst = dst.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir_all(&entry_dst)?;
            total = total.saturating_add(copy_dir_recursive(&entry.path(), &entry_dst)?);
        } else if file_type.is_file() {
            total = total.saturating_add(std::fs::copy(entry.path(), &entry_dst)?);
        }
        // Symlinks and special files are skipped — game directories
        // shouldn't contain them and pretending to back them up would just
        // create restore-time confusion.
    }
    Ok(total)
}

/// Build a snapshot ID from the current UTC time. Format
/// `YYYY-MM-DD_HH-MM-SS`, zero-padded so lexicographic sort == chronological
/// sort. Falls back to seconds-since-epoch if the system clock is wedged
/// pre-1970 — IDs stay unique either way.
fn generate_snapshot_id() -> String {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(dur) => format_utc_compact(dur.as_secs()),
        Err(_) => format!("snap-{:?}", now),
    }
}

/// Same instant as the snapshot ID but formatted for human display
/// (`YYYY-MM-DD HH:MM:SS UTC`).
fn format_human_timestamp_now() -> String {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(dur) => format_utc_human(dur.as_secs()),
        Err(_) => "unknown time".to_string(),
    }
}

/// Convert seconds-since-epoch to a compact ID-friendly UTC string.
fn format_utc_compact(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}",
        y, mo, d, h, mi, s
    )
}

/// Convert seconds-since-epoch to a readable UTC string.
fn format_utc_human(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, mo, d, h, mi, s
    )
}

/// Decompose seconds-since-Unix-epoch into a `(year, month, day, hour,
/// minute, second)` UTC tuple using the proleptic Gregorian calendar.
///
/// Pulled in here so we don't have to add `chrono` / `time` as deps for one
/// formatter. The algorithm is a standard civil-from-days conversion (Howard
/// Hinnant's `civil_from_days`); it's correct for all dates in
/// `[0001-01-01, 9999-12-31]` which is far more than we need.
fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;

    // 1970-01-01 -> day number with epoch shifted to 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy as u32 - (153 * mp as u32 + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { (y + 1) as i32 } else { y as i32 };

    (year, m, d, h, mi, s)
}

fn io_invalid_data<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_1970_01_01() {
        assert_eq!(epoch_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn known_timestamp_round_trips() {
        // 2024-01-01 00:00:00 UTC == 1704067200 (a leap year, exercises the
        // Mar-1 epoch shift in the Hinnant algorithm).
        assert_eq!(epoch_to_ymdhms(1_704_067_200), (2024, 1, 1, 0, 0, 0));
        // 2024-02-29 12:34:56 UTC -- specifically tests Feb 29 in a leap year.
        assert_eq!(epoch_to_ymdhms(1_709_210_096), (2024, 2, 29, 12, 34, 56));
        // 2026-05-03 12:00:00 UTC == 20576 * 86400 + 12*3600 = 1777809600
        assert_eq!(epoch_to_ymdhms(1_777_809_600), (2026, 5, 3, 12, 0, 0));
        assert_eq!(format_utc_compact(1_777_809_600), "2026-05-03_12-00-00");
        assert_eq!(
            format_utc_human(1_777_809_600),
            "2026-05-03 12:00:00 UTC"
        );
    }

    #[test]
    fn ids_sort_lexicographically_in_time_order() {
        let a = format_utc_compact(1_700_000_000);
        let b = format_utc_compact(1_777_999_335);
        assert!(a < b, "{} should sort before {}", a, b);
    }

    /// Round-trip a snapshot through create / list / restore / delete using
    /// a temp directory as the "game dir". We can't easily redirect
    /// `backup_dir()` to a temp path without dependency injection, so this
    /// test only exercises the directory-copy machinery directly.
    #[test]
    fn copy_dir_recursive_handles_nested_files() {
        let tmp = std::env::temp_dir().join(format!(
            "modworkbench-test-{}",
            generate_snapshot_id()
        ));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("a.bin"), b"hello").unwrap();
        std::fs::write(src.join("nested").join("b.bin"), b"world!").unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        let total = copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(total, 5 + 6);
        assert_eq!(std::fs::read(dst.join("a.bin")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(dst.join("nested").join("b.bin")).unwrap(),
            b"world!"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }
}
