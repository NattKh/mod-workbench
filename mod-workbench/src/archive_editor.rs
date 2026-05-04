//! PAZ archive inspector — read-only enumeration over every numeric PAZ
//! group folder under the configured Game Directory plus a thin layer of
//! revert / extract helpers.
//!
//! The workbench already has plenty of code that *writes* PAZ overlays
//! ([`crate::deploy`], [`crate::xml_editor::deploy_xml_overlay`], etc.).
//! This module is deliberately the read-only sibling: enumerate, summarise,
//! cross-check against PAPGT, drill into PAMT, and on demand pull a single
//! file's bytes back out via [`paz::extract_file`].
//!
//! Two write paths are exposed and routed through here so they go through
//! the same code as the rest of the workbench:
//!
//! - [`remove_overlay`]: delete an overlay group's directory + drop its
//!   PAPGT entry (mirrors [`crate::restore::restore`]).
//! - [`extract_one_file`]: read one file's uncompressed bytes (used by the
//!   "Open in Hex" action).
//!
//! Everything else is observation only — we never rebuild the on-disk PAMT
//! or PAZ from this module.
//!
//! ## Group enumeration
//!
//! Numeric PAZ group folders are 4-digit names (`0000`–`0099+`). For each
//! we look at the `0.pamt` inside; failures (missing pamt, invalid
//! checksum, parser blew up) are *not* fatal — we still surface the group
//! with a flag so the user can see something is off, instead of pretending
//! the folder doesn't exist.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta, ResolvedFile};
use dmm_parser_rust_only::binary::papgt::PackGroupTreeMeta;
use dmm_parser_rust_only::binary::paz;
use dmm_parser_rust_only::crypto::checksum;

/// Top-level summary for one PAZ group folder. One row in the inspector's
/// group list.
#[derive(Clone, Debug)]
pub struct ArchiveGroup {
    /// 4-digit folder name (e.g. `"0008"`, `"0058"`).
    pub name: String,
    /// Absolute path to the group directory.
    pub group_dir: PathBuf,
    /// Whether this group is registered in `meta/0.papgt`. Unregistered
    /// groups are still listed (the user might want to clean them up) but
    /// flagged so it's obvious they aren't actually loaded by the game.
    pub registered_in_papgt: bool,
    /// Checksum stored in the PAPGT entry for this group, if any.
    pub papgt_checksum: Option<u32>,
    /// Checksum stored in the PAMT header on disk. `None` when the PAMT
    /// is missing or unreadable.
    pub pamt_checksum: Option<u32>,
    /// Re-computed checksum over the on-disk PAMT's post-header bytes.
    /// `None` when the PAMT is missing or unreadable.
    pub computed_checksum: Option<u32>,
    /// Number of files across every directory in the PAMT.
    pub file_count: usize,
    /// Sum of every file's `uncompressed_size` in the PAMT.
    pub total_uncompressed_size: u64,
    /// Whether a `.workbench_backup` sibling exists for this group's PAZ
    /// (`<group>/0.paz.workbench_backup`) or a global PAPGT backup.
    pub has_workbench_backup: bool,
    /// The first error encountered while reading this group's metadata,
    /// if any. Surfaced inline in the row so users don't have to fish
    /// through toasts.
    pub error: Option<String>,
}

impl ArchiveGroup {
    /// True when both checksum sources are present and disagree. The UI
    /// uses this to colour the row red.
    pub fn checksum_mismatch(&self) -> bool {
        match (self.papgt_checksum, self.pamt_checksum) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    /// True when the on-disk PAMT header's stored checksum doesn't match
    /// the freshly-computed value from the same bytes. Indicates either
    /// in-place tampering or a parser bug — either way the user should
    /// know.
    pub fn pamt_self_mismatch(&self) -> bool {
        match (self.pamt_checksum, self.computed_checksum) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }
}

/// Resolved view of one directory inside a PAMT.
#[derive(Clone, Debug)]
pub struct ArchiveDirectory {
    pub path: String,
    pub files: Vec<ArchiveFile>,
}

/// Resolved view of one file in a PAMT directory. Carries enough metadata
/// for the panel to render rows and the extract helper to find the bytes
/// again.
#[derive(Clone, Debug)]
pub struct ArchiveFile {
    pub name: String,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub compression: Compression,
    pub crypto: CryptoType,
    /// Chunk id within the group's PAZ. Used to identify which `<id>.paz`
    /// to open when extracting.
    pub chunk_id: u16,
}

impl ArchiveFile {
    pub fn compression_label(&self) -> &'static str {
        match self.compression {
            Compression::None => "none",
            Compression::Partial => "partial",
            Compression::Lz4 => "lz4",
            Compression::Zlib => "zlib",
            Compression::QuickLz => "quicklz",
        }
    }

    pub fn crypto_label(&self) -> &'static str {
        match self.crypto {
            CryptoType::None => "none",
            CryptoType::Ice => "ice",
            CryptoType::Aes => "aes",
            CryptoType::ChaCha20 => "chacha20",
        }
    }
}

/// Detailed view of a single group's PAMT — directories + files. Returned
/// from [`load_group_detail`] when the user drills into a row.
#[derive(Clone, Debug)]
pub struct ArchiveGroupDetail {
    pub name: String,
    pub directories: Vec<ArchiveDirectory>,
    /// Encrypt info from the PAMT header, needed by [`extract_one_file`].
    pub encrypt_info: [u8; 3],
}

/// Walk every numeric PAZ group folder under `game_dir` and build a list
/// of [`ArchiveGroup`] summaries.
///
/// Sorting is stable and lexicographic by group name. Errors reading any
/// individual group are captured into the row's `error` field rather than
/// aborting the whole scan; the list always reflects what's on disk.
pub fn enumerate_groups(game_dir: &Path) -> io::Result<Vec<ArchiveGroup>> {
    // First pass: walk the directory and pick out numeric folders.
    let mut group_names: Vec<String> = Vec::new();
    for entry in fs::read_dir(game_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if !is_numeric_group_name(&name) {
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        group_names.push(name);
    }
    group_names.sort();

    // Second pass: load PAPGT once so every row can reference it without
    // re-parsing per group.
    let papgt = read_papgt(game_dir).ok();

    let mut out: Vec<ArchiveGroup> = Vec::with_capacity(group_names.len());
    for name in group_names {
        let group_dir = game_dir.join(&name);
        let summary = summarise_group(&name, &group_dir, papgt.as_ref());
        out.push(summary);
    }

    Ok(out)
}

/// Drill into one group: parse its PAMT and resolve every directory + file.
///
/// Failures bubble up as `io::Result::Err` because by the time a user has
/// clicked "drill in" we want a clear error rather than an empty
/// silently-rendered detail panel.
pub fn load_group_detail(group_dir: &Path) -> io::Result<ArchiveGroupDetail> {
    let pamt_path = group_dir.join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

    let mut directories: Vec<ArchiveDirectory> = Vec::with_capacity(pamt.directories.len());
    for dir in &pamt.directories {
        let mut files: Vec<ArchiveFile> = Vec::with_capacity(dir.files.len());
        for f in &dir.files {
            files.push(ArchiveFile {
                name: f.name.clone(),
                uncompressed_size: f.file.uncompressed_size,
                compressed_size: f.file.compressed_size,
                compression: f.file.compression,
                crypto: f.file.crypto,
                chunk_id: f.file.chunk_id,
            });
        }
        directories.push(ArchiveDirectory {
            path: dir.path.clone(),
            files,
        });
    }

    let group_name = group_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    Ok(ArchiveGroupDetail {
        name: group_name,
        directories,
        encrypt_info,
    })
}

/// Extract the uncompressed bytes for a single file inside a group. Used
/// by the "Open in Hex" path and any future "Save Bytes…" feature.
pub fn extract_one_file(
    group_dir: &Path,
    dir_path: &str,
    file_name: &str,
) -> io::Result<Vec<u8>> {
    let pamt_path = group_dir.join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == dir_path)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("dir '{}' not found in PAMT", dir_path),
            )
        })?;
    let file: &ResolvedFile = dir
        .files
        .iter()
        .find(|f| f.name == file_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found in '{}'", file_name, dir_path),
            )
        })?;

    paz::extract_file(group_dir, file, dir_path, &encrypt_info)
}

/// Remove an overlay group: delete its directory and drop its PAPGT entry.
/// Mirrors [`crate::restore::restore`] but is callable from the archive
/// inspector for any group the user picks (not just the canonical overlay
/// numbers).
pub fn remove_overlay(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    crate::restore::restore(game_dir, overlay_group)
}

// ── PAPGT diff ─────────────────────────────────────────────────────────────

/// Per-entry info pulled out of a PAPGT. We don't expose
/// [`dmm_parser_rust_only::binary::papgt::ResolvedEntry`] directly because
/// the caller only ever wants the human-comparable subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PapgtEntrySummary {
    pub group_name: String,
    pub pack_meta_checksum: u32,
    pub is_optional: u8,
    pub language: u16,
}

/// Result of comparing the live PAPGT against the workbench backup.
#[derive(Clone, Debug)]
pub struct PapgtDiff {
    /// Groups that exist in the live file but not in the backup — usually
    /// our own overlays.
    pub added: Vec<PapgtEntrySummary>,
    /// Groups that exist in the backup but not in the live file — usually
    /// vanilla entries that got removed by mistake.
    pub removed: Vec<PapgtEntrySummary>,
    /// Groups present in both, but with different checksum / optional /
    /// language fields. Each entry is `(backup, live)`.
    pub changed: Vec<(PapgtEntrySummary, PapgtEntrySummary)>,
}

impl PapgtDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Read both PAPGTs and return a grouped diff. Returns `Ok(None)` when the
/// backup file doesn't exist — the caller can render "no backup yet" rather
/// than treating it as an error.
pub fn diff_papgt_against_backup(game_dir: &Path) -> io::Result<Option<PapgtDiff>> {
    let papgt_path = game_dir.join("meta").join("0.papgt");
    let backup_path = game_dir.join("meta").join("0.papgt.workbench_backup");

    if !backup_path.exists() {
        return Ok(None);
    }

    let live = read_papgt_summaries(&papgt_path)?;
    let backup = read_papgt_summaries(&backup_path)?;

    let mut added: Vec<PapgtEntrySummary> = Vec::new();
    let mut removed: Vec<PapgtEntrySummary> = Vec::new();
    let mut changed: Vec<(PapgtEntrySummary, PapgtEntrySummary)> = Vec::new();

    for live_entry in &live {
        match backup.iter().find(|b| b.group_name == live_entry.group_name) {
            None => added.push(live_entry.clone()),
            Some(backup_entry) => {
                if backup_entry != live_entry {
                    changed.push((backup_entry.clone(), live_entry.clone()));
                }
            }
        }
    }
    for backup_entry in &backup {
        if !live.iter().any(|l| l.group_name == backup_entry.group_name) {
            removed.push(backup_entry.clone());
        }
    }

    Ok(Some(PapgtDiff {
        added,
        removed,
        changed,
    }))
}

// ── Internals ──────────────────────────────────────────────────────────────

fn is_numeric_group_name(name: &str) -> bool {
    name.len() == 4 && name.chars().all(|c| c.is_ascii_digit())
}

fn read_papgt(game_dir: &Path) -> io::Result<PackGroupTreeMeta> {
    let papgt_path = game_dir.join("meta").join("0.papgt");
    let bytes = fs::read(&papgt_path)?;
    PackGroupTreeMeta::parse(&bytes)
}

fn read_papgt_summaries(papgt_path: &Path) -> io::Result<Vec<PapgtEntrySummary>> {
    let bytes = fs::read(papgt_path)?;
    let papgt = PackGroupTreeMeta::parse(&bytes)?;
    Ok(papgt
        .entries
        .iter()
        .map(|e| PapgtEntrySummary {
            group_name: e.group_name.clone(),
            pack_meta_checksum: e.entry.pack_meta_checksum,
            is_optional: e.entry.is_optional,
            language: e.entry.language.0,
        })
        .collect())
}

fn summarise_group(
    name: &str,
    group_dir: &Path,
    papgt: Option<&PackGroupTreeMeta>,
) -> ArchiveGroup {
    let mut group = ArchiveGroup {
        name: name.to_string(),
        group_dir: group_dir.to_path_buf(),
        registered_in_papgt: false,
        papgt_checksum: None,
        pamt_checksum: None,
        computed_checksum: None,
        file_count: 0,
        total_uncompressed_size: 0,
        has_workbench_backup: workbench_backup_exists(group_dir),
        error: None,
    };

    // PAPGT lookup is cheap and never blocks the rest of the pipeline.
    if let Some(papgt) = papgt {
        if let Some(entry) = papgt.entries.iter().find(|e| e.group_name == name) {
            group.registered_in_papgt = true;
            group.papgt_checksum = Some(entry.entry.pack_meta_checksum);
        }
    }

    // PAMT parse — the bulk of the work. Soft-fail by stuffing the error
    // into the group row instead of bubbling up.
    let pamt_path = group_dir.join("0.pamt");
    if !pamt_path.exists() {
        group.error = Some("0.pamt missing".to_string());
        return group;
    }
    let pamt_bytes = match fs::read(&pamt_path) {
        Ok(b) => b,
        Err(e) => {
            group.error = Some(format!("read 0.pamt: {}", e));
            return group;
        }
    };
    // Compute fresh checksum over the post-header region. The header is
    // 10 bytes (PackMetaHeader = u32 + u16 + u16 + PackEncryptInfo[4]).
    if pamt_bytes.len() > 10 {
        let computed = checksum::calculate_checksum(&pamt_bytes[10..]);
        group.computed_checksum = Some(computed);
    }
    let pamt = match PackMeta::parse(&pamt_bytes, None) {
        Ok(p) => p,
        Err(e) => {
            group.error = Some(format!("parse 0.pamt: {}", e));
            return group;
        }
    };

    group.pamt_checksum = Some(pamt.header.checksum);

    let mut file_count = 0usize;
    let mut total: u64 = 0;
    for dir in &pamt.directories {
        for f in &dir.files {
            file_count += 1;
            total += u64::from(f.file.uncompressed_size);
        }
    }
    group.file_count = file_count;
    group.total_uncompressed_size = total;

    group
}

fn workbench_backup_exists(group_dir: &Path) -> bool {
    // We check both per-group and per-file backup conventions; only the
    // first ones the workbench actually creates today are necessary for
    // truth, but extending this is fine.
    group_dir.join("0.paz.workbench_backup").exists()
        || group_dir.join("0.pamt.workbench_backup").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_group_names_only() {
        assert!(is_numeric_group_name("0000"));
        assert!(is_numeric_group_name("0058"));
        assert!(is_numeric_group_name("9999"));
        assert!(!is_numeric_group_name("00"));
        assert!(!is_numeric_group_name("00000"));
        assert!(!is_numeric_group_name("abcd"));
        assert!(!is_numeric_group_name("00a8"));
        assert!(!is_numeric_group_name(""));
        assert!(!is_numeric_group_name("meta"));
    }

    #[test]
    fn checksum_mismatch_only_when_both_present() {
        let mut g = ArchiveGroup {
            name: "0058".to_string(),
            group_dir: PathBuf::new(),
            registered_in_papgt: false,
            papgt_checksum: None,
            pamt_checksum: None,
            computed_checksum: None,
            file_count: 0,
            total_uncompressed_size: 0,
            has_workbench_backup: false,
            error: None,
        };
        assert!(!g.checksum_mismatch());
        g.papgt_checksum = Some(0xDEAD);
        assert!(!g.checksum_mismatch());
        g.pamt_checksum = Some(0xDEAD);
        assert!(!g.checksum_mismatch());
        g.pamt_checksum = Some(0xBEEF);
        assert!(g.checksum_mismatch());
    }

    #[test]
    fn pamt_self_mismatch_triggers_only_with_disagreement() {
        let mut g = ArchiveGroup {
            name: "0058".to_string(),
            group_dir: PathBuf::new(),
            registered_in_papgt: false,
            papgt_checksum: None,
            pamt_checksum: None,
            computed_checksum: None,
            file_count: 0,
            total_uncompressed_size: 0,
            has_workbench_backup: false,
            error: None,
        };
        g.pamt_checksum = Some(0xCAFE);
        g.computed_checksum = Some(0xCAFE);
        assert!(!g.pamt_self_mismatch());
        g.computed_checksum = Some(0xBABE);
        assert!(g.pamt_self_mismatch());
    }

    #[test]
    fn diff_classifies_added_removed_changed() {
        let backup = vec![
            PapgtEntrySummary {
                group_name: "0008".to_string(),
                pack_meta_checksum: 0xAA,
                is_optional: 0,
                language: 0x3FFF,
            },
            PapgtEntrySummary {
                group_name: "0014".to_string(),
                pack_meta_checksum: 0xBB,
                is_optional: 0,
                language: 0x3FFF,
            },
        ];
        let live = vec![
            PapgtEntrySummary {
                group_name: "0058".to_string(),
                pack_meta_checksum: 0xCC,
                is_optional: 1,
                language: 0x3FFF,
            },
            PapgtEntrySummary {
                group_name: "0008".to_string(),
                pack_meta_checksum: 0xAA,
                is_optional: 0,
                language: 0x3FFF,
            },
            PapgtEntrySummary {
                group_name: "0014".to_string(),
                pack_meta_checksum: 0xDD,
                is_optional: 0,
                language: 0x3FFF,
            },
        ];

        // Replicate the diff loop for the test (we don't have a real
        // PAPGT on disk in unit-test land).
        let mut added: Vec<PapgtEntrySummary> = Vec::new();
        let mut removed: Vec<PapgtEntrySummary> = Vec::new();
        let mut changed: Vec<(PapgtEntrySummary, PapgtEntrySummary)> = Vec::new();
        for l in &live {
            match backup.iter().find(|b| b.group_name == l.group_name) {
                None => added.push(l.clone()),
                Some(b) if b != l => changed.push((b.clone(), l.clone())),
                Some(_) => {}
            }
        }
        for b in &backup {
            if !live.iter().any(|l| l.group_name == b.group_name) {
                removed.push(b.clone());
            }
        }

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].group_name, "0058");
        assert!(removed.is_empty());
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0.group_name, "0014");
        assert_eq!(changed[0].0.pack_meta_checksum, 0xBB);
        assert_eq!(changed[0].1.pack_meta_checksum, 0xDD);
    }
}
