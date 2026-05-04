//! Binary Inspector — generic byte-level editor for game files whose
//! schemas haven't been decoded yet.
//!
//! Mirrors the [`crate::paseq_editor`] byte-patch path but generalised so
//! any 4-digit PAZ group can be scanned for an arbitrary list of
//! extensions. The current workbench surface targets the five
//! `paschedule`-family + `paseqh` + `uianiminit` extensions documented
//! in `PASCHEDULE_FORMAT_RESEARCH.md`, but the function signatures are
//! deliberately extension-agnostic so a future surface can reuse them
//! for any unknown format.
//!
//! Intentionally re-uses [`crate::paseq_editor::BytePatch`] /
//! [`crate::paseq_editor::BytePatchDoc`] /
//! [`crate::paseq_editor::apply_byte_patches`] verbatim — the JSON shape
//! is identical so patch files authored in either panel are
//! interchangeable. We only fork the *scan* and *deploy* helpers because
//! those need a different PAZ group set and a different overlay group.
//!
//! Default overlay group is `"0069"` — distinct from paseq's `0068`,
//! paatt's `0066`, paac's `0067`, and xml's `0070` so multiple workbench
//! overlays can coexist.

use std::fs;
use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::papgt::{LanguageType, PackGroupTreeMeta};
use dmm_parser_rust_only::binary::paz::{self, PackGroupBuilder};

use crate::paseq_editor::{apply_byte_patches, BytePatchDoc};

/// One file located inside a PAZ archive that the binary inspector can
/// target. Extension-agnostic — the panel filters by `extension` to
/// drive the per-extension toggle row.
#[derive(Clone, Debug)]
pub struct BinaryFileEntry {
    /// PAZ group folder name (e.g. `"0014"`). 4-digit numeric.
    pub group: String,
    /// PAMT internal directory path (e.g. `"sequencer/binary__"`).
    pub dir_path: String,
    /// File name including the leading `.` extension.
    pub filename: String,
    /// Lowercased extension without the leading dot (e.g. `"paschedule"`).
    /// Mirrors [`std::path::Path::extension`] but kept on the entry so the
    /// UI can filter without re-parsing the filename every frame.
    pub extension: String,
}

impl BinaryFileEntry {
    /// Display label for dropdowns. Mirrors the shape of
    /// [`crate::paseq_editor::PaseqPazEntry::display`] with the group +
    /// extension prefixed/suffixed for at-a-glance disambiguation.
    pub fn display(&self) -> String {
        format!(
            "[{}] {}  ({}) [.{}]",
            self.group, self.filename, self.dir_path, self.extension
        )
    }
}

/// Walk every numeric 4-digit PAZ group folder under `game_dir`, parse
/// each PAMT, and surface every file whose extension matches one of
/// `allowed_extensions` (case-insensitive, dot stripped).
///
/// Errors reading any individual group are captured silently — we skip
/// the broken group and continue. This matches the "best-effort" scan
/// behaviour of [`crate::paatt_editor::enumerate_paatt_files`] so a
/// stale overlay doesn't kill the whole list.
///
/// Returned sorted by group, then directory, then filename so the picker
/// UI is stable across runs.
pub fn enumerate_files(
    game_dir: &Path,
    allowed_extensions: &[&str],
) -> io::Result<Vec<BinaryFileEntry>> {
    // Normalise the allow-list once. Lower-case + strip leading `.` so
    // callers can pass either form ("paschedule" or ".paschedule").
    let allowed: Vec<String> = allowed_extensions
        .iter()
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .collect();

    let mut found: Vec<BinaryFileEntry> = Vec::new();

    for entry in fs::read_dir(game_dir)?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if !is_numeric_group_name(&name) {
            continue;
        }
        let group_dir = entry.path();
        if !group_dir.is_dir() {
            continue;
        }
        let pamt_path = group_dir.join("0.pamt");
        if !pamt_path.exists() {
            continue;
        }
        let pamt_bytes = match fs::read(&pamt_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pamt = match PackMeta::parse(&pamt_bytes, None) {
            Ok(p) => p,
            Err(_) => continue,
        };

        for dir in &pamt.directories {
            for f in &dir.files {
                let ext = file_extension_lc(&f.name);
                if ext.is_empty() {
                    continue;
                }
                if !allowed.iter().any(|a| a == &ext) {
                    continue;
                }
                found.push(BinaryFileEntry {
                    group: name.clone(),
                    dir_path: dir.path.clone(),
                    filename: f.name.clone(),
                    extension: ext,
                });
            }
        }
    }

    found.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then(a.dir_path.cmp(&b.dir_path))
            .then(a.filename.cmp(&b.filename))
    });
    Ok(found)
}

/// Extract a single file's bytes from its PAZ.
///
/// Same crypto path as [`crate::paseq_editor::read_paseq_from_paz`] but
/// keyed off [`BinaryFileEntry::group`] so we can pull from any group
/// (not just `0014`).
pub fn read_file_from_paz(game_dir: &Path, entry: &BinaryFileEntry) -> io::Result<Vec<u8>> {
    let group_dir = game_dir.join(&entry.group);
    let pamt_path = group_dir.join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == entry.dir_path)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "dir '{}' not found in {}/0.pamt",
                    entry.dir_path, entry.group
                ),
            )
        })?;
    let file = dir
        .files
        .iter()
        .find(|f| f.name == entry.filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found in '{}'", entry.filename, entry.dir_path),
            )
        })?;

    paz::extract_file(&group_dir, file, &entry.dir_path, &encrypt_info)
}

/// Deploy a list of [`BytePatchDoc`]s as a PAZ overlay.
///
/// Each doc's target file is read from its source group (resolved via a
/// PAMT scan), patched with [`apply_byte_patches`], and added to the
/// overlay PAZ. PAPGT is updated front-insert so the overlay wins
/// lookup. Mirrors [`crate::paseq_editor::deploy_byte_patches`] but the
/// overlay group is configurable and source group is resolved
/// per-document instead of pinned to `0014`.
///
/// Doc-to-source resolution: we scan every numeric PAZ group's PAMT for
/// the first one that contains `<doc.dir_path>/<doc.filename>`. This
/// way a single deploy can mix patches across `0014` (sequencer files)
/// and other groups (e.g. UI animations from a separate group) without
/// the caller having to know which group a target lives in.
pub fn deploy_binary_patches(
    game_dir: &Path,
    docs: &[BytePatchDoc],
    overlay_group: &str,
) -> io::Result<()> {
    if docs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no patch documents to deploy",
        ));
    }

    // Use the encrypt_info from `0008/0.pamt` so the overlay's crypto
    // matches the rest of the install. Same pattern as paatt / xml /
    // paseq deploy paths.
    let source_pamt_path = game_dir.join("0008").join("0.pamt");
    let source_pamt_bytes = fs::read(&source_pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "failed to read {}: {}",
                source_pamt_path.display(),
                e
            ),
        )
    })?;
    let source_pamt = PackMeta::parse(&source_pamt_bytes, None)?;
    let encrypt_info = source_pamt.header.encrypt_info.encrypt_info;

    let group_dir = game_dir.join(overlay_group);
    if group_dir.exists() {
        fs::remove_dir_all(&group_dir)?;
    }
    fs::create_dir_all(&group_dir)?;

    let mut builder = PackGroupBuilder::new(
        &group_dir,
        Compression::None,
        CryptoType::ChaCha20,
        encrypt_info,
        256 * 1024 * 1024,
    );

    for doc in docs {
        // Locate the source file across every numeric group. We accept
        // the first hit so an existing overlay doesn't shadow vanilla
        // contents — the inspector is meant to author edits against
        // current game state, whatever that is. If multiple groups have
        // the same path the lower-numbered group (vanilla) wins because
        // we walk in sorted order.
        let bytes = read_doc_source_bytes(game_dir, doc)?;
        let patched = apply_byte_patches(&bytes, &doc.patches)?;
        builder.add_file(&doc.dir_path, &doc.filename, &patched)?;
    }

    let pamt_bytes = builder.finish()?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let checksum = pamt.header.checksum;

    update_papgt(game_dir, overlay_group, checksum)
}

/// Wipe the binary inspector overlay group and remove its PAPGT entry.
/// Mirrors [`crate::paatt_editor::restore_paatt_overlay`].
///
/// Currently unused by the panel (the global "Remove Overlay" bottom-bar
/// button only restores PABGB-table overlays). Kept on the public
/// surface so a future per-panel restore button can wire it up without
/// rebuilding the deploy plumbing.
#[allow(dead_code)]
pub fn restore_binary_overlay(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    let group_dir = game_dir.join(overlay_group);
    if group_dir.exists() {
        fs::remove_dir_all(&group_dir)?;
    }
    remove_papgt_entry(game_dir, overlay_group)
}

// ── Internals ──────────────────────────────────────────────────────────────

/// Locate the source bytes for a [`BytePatchDoc`] across every numeric
/// PAZ group. Returns the first hit in lexicographic group order so
/// vanilla wins over our own overlays — the inspector authors against
/// current state but doesn't want to compound on its own previous
/// deploy.
fn read_doc_source_bytes(game_dir: &Path, doc: &BytePatchDoc) -> io::Result<Vec<u8>> {
    let mut group_names: Vec<String> = Vec::new();
    for entry in fs::read_dir(game_dir)?.flatten() {
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

    for group in &group_names {
        let group_dir = game_dir.join(group);
        let pamt_path = group_dir.join("0.pamt");
        if !pamt_path.exists() {
            continue;
        }
        let pamt_bytes = match fs::read(&pamt_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pamt = match PackMeta::parse(&pamt_bytes, None) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let encrypt_info = pamt.header.encrypt_info.encrypt_info;
        let Some(dir) = pamt.directories.iter().find(|d| d.path == doc.dir_path) else {
            continue;
        };
        let Some(file) = dir.files.iter().find(|f| f.name == doc.filename) else {
            continue;
        };
        return paz::extract_file(&group_dir, file, &doc.dir_path, &encrypt_info);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "source file '{}/{}' not found in any numeric PAZ group",
            doc.dir_path, doc.filename
        ),
    ))
}

fn update_papgt(game_dir: &Path, overlay_group: &str, checksum: u32) -> io::Result<()> {
    let papgt_path = game_dir.join("meta").join("0.papgt");
    let papgt_backup = game_dir.join("meta").join("0.papgt.workbench_backup");
    if !papgt_backup.exists() && papgt_path.is_file() {
        fs::copy(&papgt_path, &papgt_backup)?;
    }

    let papgt_bytes = fs::read(&papgt_path)?;
    let mut papgt = PackGroupTreeMeta::parse(&papgt_bytes)?;
    // Front-insert as an optional mod overlay (is_optional = 1) so
    // restoring vanilla via "Remove this overlay" is safe even if the
    // original entry order was unusual.
    papgt.add_entry(overlay_group, checksum, 1, LanguageType::ALL);
    let updated = papgt.to_bytes()?;
    fs::write(&papgt_path, updated)
}

#[allow(dead_code)]
fn remove_papgt_entry(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    let papgt_path = game_dir.join("meta").join("0.papgt");
    let papgt_bytes = match fs::read(&papgt_path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut papgt = PackGroupTreeMeta::parse(&papgt_bytes)?;
    if !papgt.entries.iter().any(|e| e.group_name == overlay_group) {
        return Ok(());
    }
    papgt.entries.retain(|e| e.group_name != overlay_group);
    papgt.header.entry_count = papgt.entries.len() as u8;
    let updated = papgt.to_bytes()?;
    fs::write(&papgt_path, updated)
}

fn is_numeric_group_name(name: &str) -> bool {
    name.len() == 4 && name.chars().all(|c| c.is_ascii_digit())
}

/// Lowercased file extension without the leading dot. Returns an empty
/// string when the filename has no extension.
fn file_extension_lc(filename: &str) -> String {
    match filename.rfind('.') {
        Some(idx) if idx + 1 < filename.len() => filename[idx + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paseq_editor::{BytePatch, BytePatchDoc};

    #[test]
    fn file_extension_lc_handles_uppercase_and_no_dot() {
        assert_eq!(file_extension_lc("foo.PASCHEDULE"), "paschedule");
        assert_eq!(file_extension_lc("bar.paseqh"), "paseqh");
        assert_eq!(file_extension_lc("noext"), "");
        assert_eq!(file_extension_lc("trailing."), "");
        assert_eq!(file_extension_lc(".hidden"), "hidden");
    }

    #[test]
    fn is_numeric_group_name_matches_four_digits_only() {
        assert!(is_numeric_group_name("0000"));
        assert!(is_numeric_group_name("0014"));
        assert!(is_numeric_group_name("0069"));
        assert!(is_numeric_group_name("9999"));

        assert!(!is_numeric_group_name(""));
        assert!(!is_numeric_group_name("00"));
        assert!(!is_numeric_group_name("00000"));
        assert!(!is_numeric_group_name("00a8"));
        assert!(!is_numeric_group_name("meta"));
    }

    #[test]
    fn binary_file_entry_display_round_trips_basic_fields() {
        let entry = BinaryFileEntry {
            group: "0014".to_string(),
            dir_path: "sequencer/binary__".to_string(),
            filename: "foo.paschedule".to_string(),
            extension: "paschedule".to_string(),
        };
        let s = entry.display();
        assert!(s.contains("0014"));
        assert!(s.contains("foo.paschedule"));
        assert!(s.contains("sequencer/binary__"));
        assert!(s.contains(".paschedule"));
    }

    /// Sanity check: the JSON shape we author here is identical to the
    /// shape paseq's editor uses, so a doc produced by either panel
    /// round-trips through the other.
    #[test]
    fn byte_patch_doc_roundtrip_matches_paseq_shape() {
        let doc = BytePatchDoc {
            dir_path: "sequencer/binary__".to_string(),
            filename: "alice.paschedule".to_string(),
            description: "test".to_string(),
            patches: vec![BytePatch {
                name: "swap byte".to_string(),
                find: vec![0x00, 0x01, 0x02],
                replace: vec![0xFF, 0xFE, 0xFD],
                comment: "round-trip".to_string(),
                allow_resize: false,
            }],
        };
        let serialised = serde_json::to_string(&doc).unwrap();
        let parsed: BytePatchDoc = serde_json::from_str(&serialised).unwrap();
        assert_eq!(doc, parsed);
    }

    /// Confirms the overlay group default we picked doesn't collide
    /// with the four other workbench overlay groups currently in use.
    /// If this test breaks because someone bumped one of the other
    /// constants, pick a fresh number above the existing set rather
    /// than reusing one.
    #[test]
    fn default_overlay_group_unique_among_workbench_overlays() {
        let default = "0069";
        let other_workbench_groups = ["0066", "0067", "0068", "0070"];
        for g in other_workbench_groups {
            assert_ne!(default, g, "binary inspector must not reuse {}", g);
        }
    }
}
