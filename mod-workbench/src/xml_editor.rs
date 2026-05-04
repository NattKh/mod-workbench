//! XML tree editor — load XML files from the game's PAZ archives, edit
//! the tree directly (rename / set text / set attrs / add / remove
//! children), and deploy the result as a PAZ overlay.
//!
//! The patch-builder UI in `xml_patcher.rs` is still available for users
//! who want shareable JSON ops, but most authoring is faster as direct
//! tree edits. Both modes share the same `XmlTree` representation, so a
//! file edited in the tree mode can be saved either as a deployable
//! overlay or, after a vanilla diff, as a v3 patch.
//!
//! ## PAZ enumeration
//!
//! Game XML files live in several PAZ groups (0008 has the bulk of the
//! configs; cosmetic / dye XMLs sometimes live in 0014 or higher). We
//! enumerate every PAZ group under the configured Game Directory, parse
//! its PAMT, and surface every file ending in `.xml` together with the
//! group + internal directory it lives in. The editor surfaces this as
//! a flat list ordered by directory + name.
//!
//! ## Deploy
//!
//! Writes a fresh PAZ overlay group at `<game_dir>/<overlay_group>/`
//! (default `0070`) holding only the modified XML, then front-inserts
//! the group into PAPGT so it wins the lookup for that file's path.
//! Mirrors the deploy flow used for ItemBuffs / paseq presets.

use std::fs;
use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::papgt::{LanguageType, PackGroupTreeMeta};
use dmm_parser_rust_only::binary::paz::{extract_file, PackGroupBuilder};

/// One XML file found inside a PAZ archive. Returned by
/// [`enumerate_xml_files`]; the editor stores these in its dropdown so
/// the user can pick a file by display name without remembering the
/// internal PAZ directory.
#[derive(Clone, Debug)]
pub struct XmlPazEntry {
    /// PAZ group folder name (e.g. `"0008"`).
    pub group: String,
    /// Internal PAMT directory path (e.g.
    /// `"gamedata/binary__/client/bin"`).
    pub dir_path: String,
    /// File name including the `.xml` extension.
    pub filename: String,
}

impl XmlPazEntry {
    /// Display label for the dropdown — group + filename, with the
    /// directory in parentheses for disambiguation when the same name
    /// appears under different paths.
    pub fn display(&self) -> String {
        format!("[{}] {}  ({})", self.group, self.filename, self.dir_path)
    }
}

/// Walk every numeric PAZ group folder under `game_dir`, parse its PAMT,
/// and collect every `.xml` file. Sorted by group then filename so the
/// resulting list is stable across runs.
///
/// Errors loading individual PAMTs are non-fatal — we skip the broken
/// group and continue, returning what we found from the rest.
pub fn enumerate_xml_files(game_dir: &Path) -> io::Result<Vec<XmlPazEntry>> {
    let mut found: Vec<XmlPazEntry> = Vec::new();

    let entries = fs::read_dir(game_dir)?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        // PAZ group folders are 4-digit numeric (0008, 0014, etc.).
        if name.len() != 4 || !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let group_dir = entry.path();
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
            for file in &dir.files {
                if file.name.to_ascii_lowercase().ends_with(".xml") {
                    found.push(XmlPazEntry {
                        group: name.clone(),
                        dir_path: dir.path.clone(),
                        filename: file.name.clone(),
                    });
                }
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

/// Read the raw bytes for a single XML file from the game's PAZ. Used by
/// the editor to populate the tree on file selection.
pub fn read_xml_from_paz(game_dir: &Path, entry: &XmlPazEntry) -> io::Result<Vec<u8>> {
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
                format!("dir '{}' not found in {}/0.pamt", entry.dir_path, entry.group),
            )
        })?;

    let file = dir
        .files
        .iter()
        .find(|f| f.name == entry.filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found in {}", entry.filename, entry.dir_path),
            )
        })?;

    extract_file(&group_dir, file, &entry.dir_path, &encrypt_info)
}

/// Deploy a single modified XML as a PAZ overlay.
///
/// Builds `<game_dir>/<overlay_group>/0.paz + 0.pamt` containing just
/// `<dir_path>/<filename>` with the new bytes, then front-inserts the
/// group into PAPGT so the next game launch loads our XML instead of
/// the vanilla one.
///
/// `overlay_group` should be a 4-digit numeric folder name not currently
/// used by the game (default `0070` for the XML editor — kept distinct
/// from other tools' groups so multiple workbench overlays can coexist).
pub fn deploy_xml_overlay(
    game_dir: &Path,
    dir_path: &str,
    filename: &str,
    xml_bytes: &[u8],
    overlay_group: &str,
) -> io::Result<()> {
    // Use the encrypt_info from the source PAZ group's PAMT so the
    // overlay's crypto matches the rest of the install. We always read
    // 0008 here because XMLs typically live there; if a future XML lives
    // in a different group the user can edit it just fine — the encrypt
    // material is shared across the install in practice.
    let source_pamt = game_dir.join("0008").join("0.pamt");
    let source_pamt_bytes = fs::read(&source_pamt)?;
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
    builder.add_file(dir_path, filename, xml_bytes)?;

    let pamt_bytes = builder.finish()?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let checksum = pamt.header.checksum;

    update_papgt(game_dir, overlay_group, checksum)
}

/// Restore vanilla by deleting the overlay group's directory and
/// removing its PAPGT entry. Mirrors `restore::restore` but scoped to
/// the XML editor's overlay group so the user can revert just this
/// edit without nuking unrelated overlays.
pub fn restore_xml_overlay(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    let group_dir = game_dir.join(overlay_group);
    if group_dir.exists() {
        fs::remove_dir_all(&group_dir)?;
    }
    remove_papgt_entry(game_dir, overlay_group)
}

/// Front-insert a PAPGT entry for `<group>` with the given pamt
/// checksum. Mirrors the deploy.rs flow so the workbench backup file
/// (`meta/0.papgt.workbench_backup`) is preserved across overlays.
fn update_papgt(game_dir: &Path, overlay_group: &str, checksum: u32) -> io::Result<()> {
    let papgt_path = game_dir.join("meta").join("0.papgt");
    let papgt_backup = game_dir.join("meta").join("0.papgt.workbench_backup");
    if !papgt_backup.exists() {
        fs::copy(&papgt_path, &papgt_backup)?;
    }

    let papgt_bytes = fs::read(&papgt_path)?;
    let mut papgt = PackGroupTreeMeta::parse(&papgt_bytes)?;

    // Front-insert as an optional mod overlay (is_optional = 1).
    papgt.add_entry(overlay_group, checksum, 1, LanguageType::ALL);

    let updated = papgt.to_bytes()?;
    fs::write(&papgt_path, updated)
}

/// Remove a PAPGT entry by group name. No-op when the entry doesn't
/// exist. Mirrors the path used by `restore::restore`.
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
