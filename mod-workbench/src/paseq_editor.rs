//! PASEQ / PASTAGE editor — sleep mod and NPC sequencer swaps.
//!
//! PASEQ and PASTAGE files contain NPC sequencer data and stage definitions.
//! There are no parsers for them yet — we treat them as raw bytes with known
//! patterns:
//!
//! 1. **Sleep mod**: replace `False` with `True ` (trailing space, identical
//!    byte length) at every occurrence inside the three sleep-related
//!    `.pastage` files. The check that gates sleep cooldowns evaluates to
//!    `True` afterwards, so the cooldown effectively disappears.
//!
//! 2. **NPC sequencer swap**: copy one NPC's `.paseq` / `.paseqc` /
//!    `.pastage` files into another NPC's filenames inside the overlay. The
//!    game then loads the source NPC's behavior + visuals while the target
//!    NPC keeps its world placement.
//!
//! All edits are written into a fresh PAZ overlay group (e.g. `0068/`) and
//! the PAPGT is updated with a front-inserted entry so the overlay wins
//! over vanilla (`0014/`) at lookup time.

use std::fs;
use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::papgt::{LanguageType, PackGroupTreeMeta};
use dmm_parser_rust_only::binary::paz::{self, PackGroupBuilder};

/// Sequencer files all live under PAZ group 0014 in retail.
const PAZ_GROUP: &str = "0014";

/// Directory holding `cd_seq_minigame_sleep.*` (the sleep minigame sequencer).
const SLEEP_SEQ_DIR: &str = "sequencer/binary__/baseseq/contents";
/// Directory holding the bed gimmick sequencers (`gimmick_sleep_bed_*`).
const SLEEP_BED_DIR: &str = "sequencer/binary__/baseseq/gimmickcalledseq";

/// The three sleep-related file *stems* (no extension). Each has a
/// matching `.paseq` and `.pastage` pair.
const SLEEP_FILE_STEMS: &[(&str, &str)] = &[
    (SLEEP_SEQ_DIR, "cd_seq_minigame_sleep"),
    (SLEEP_BED_DIR, "gimmick_sleep_bed_left"),
    (SLEEP_BED_DIR, "gimmick_sleep_bed_right"),
];

/// PAMT directories that contain swappable NPC sequencer entries.
///
/// `funcnpc/` is the typical "function NPC" location (vendors, trainers,
/// etc.) and `basecamp/` mirrors a smaller set of basecamp-only NPCs. Any
/// entry whose directory path *starts with* one of these is in scope —
/// nested sub-directories are accepted so we don't miss future additions.
const NPC_DIRS: &[&str] = &[
    "sequencer/binary__/stageseq/funcnpc",
    "sequencer/binary__/stageseq/basecamp",
];

/// One NPC's bundle of sequencer files. Returned by [`list_npcs`].
#[derive(Debug, Clone)]
pub struct NpcEntry {
    /// Filename stem common to this NPC's `.paseq` / `.paseqc` files.
    /// For pastages with a hash suffix the stem is recovered by stripping
    /// the trailing `_<hex>` chunk.
    pub stem: String,
    /// Human-readable label for dropdowns (e.g. `"Butcher (funcnpc)"`).
    pub display_name: String,
    /// PAMT directory path the NPC lives in (e.g.
    /// `"sequencer/binary__/stageseq/funcnpc"`).
    pub dir_path: String,
    /// All files belonging to this NPC, sorted alphabetically. Exposed for
    /// debugging / future "preview" affordances; the swap pipeline rescans
    /// the PAMT internally rather than trusting this snapshot.
    #[allow(dead_code)]
    pub files: Vec<String>,
}

/// Apply the "Let me sleep" mod.
///
/// Builds an overlay PAZ at `<game_dir>/<overlay_group>/` containing patched
/// `.pastage` files for the three sleep sequences (and their unmodified
/// `.paseq` siblings — the game expects both halves to be present in the
/// overlay or it falls back to vanilla). Updates the PAPGT to register the
/// new group at the front of the entry list.
///
/// Existing overlay contents at `overlay_group` are wiped first so repeated
/// runs don't accumulate stale chunks.
pub fn apply_sleep_mod(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_data = fs::read(&pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", pamt_path.display(), e),
        )
    })?;
    let pamt = PackMeta::parse(&pamt_data, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

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

    for (dir_path, stem) in SLEEP_FILE_STEMS {
        let pastage_name = format!("{}.pastage", stem);
        let paseq_name = format!("{}.paseq", stem);

        // Pastage: extract, replace, repack. `False`->`True ` keeps the byte
        // length identical so file-internal offsets stay valid.
        let pastage_data = extract_named_file(&pamt, game_dir, dir_path, &pastage_name)?;
        let patched = patch_false_to_true(&pastage_data);
        builder.add_file(dir_path, &pastage_name, &patched)?;

        // Paseq: must be present alongside the patched pastage or the game
        // ignores the overlay entry. We copy it through unchanged. Missing
        // paseqs are non-fatal (some sequences have a single file).
        match extract_named_file(&pamt, game_dir, dir_path, &paseq_name) {
            Ok(data) => builder.add_file(dir_path, &paseq_name, &data)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    finalize_overlay(&builder_finish_with_checksum(builder)?, game_dir, overlay_group)
}

/// Swap NPC `target_npc` with NPC `source_npc` by copying the source's
/// `.paseq` / `.paseqc` / `.pastage` files into the target's PAMT
/// directory under the target's filenames.
///
/// `source_dir` and `target_dir` are the PAMT directory paths discovered by
/// [`list_npcs`] — they're kept as separate parameters so callers don't
/// have to re-scan the PAMT just to find them. Pastages with hash suffixes
/// are re-keyed: source pastages are paired with target pastages in
/// alphabetical order, and any extras inherit the source's hash with the
/// stem rewritten to the target's stem.
pub fn swap_npcs(
    game_dir: &Path,
    source_npc: &str,
    source_dir: &str,
    target_npc: &str,
    target_dir: &str,
    overlay_group: &str,
) -> io::Result<()> {
    if source_npc.is_empty() || target_npc.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source_npc and target_npc must both be non-empty",
        ));
    }
    if source_npc == target_npc && source_dir == target_dir {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and target NPC are the same — nothing to swap",
        ));
    }

    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_data = fs::read(&pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", pamt_path.display(), e),
        )
    })?;
    let pamt = PackMeta::parse(&pamt_data, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

    let source_files = collect_npc_files(&pamt, source_dir, source_npc)?;
    let target_files = collect_npc_files(&pamt, target_dir, target_npc)?;
    if source_files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no sequencer files found for source NPC '{}'", source_npc),
        ));
    }

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

    // Split source/target into pastages vs the rest (paseq/paseqc) — the
    // pastage rename rule needs to consume them in pairs but the
    // .paseq/.paseqc rename is a simple stem replacement.
    let mut source_pastages: Vec<&String> = source_files
        .iter()
        .filter(|f| f.ends_with(".pastage"))
        .collect();
    source_pastages.sort();
    let mut target_pastages: Vec<&String> = target_files
        .iter()
        .filter(|f| f.ends_with(".pastage"))
        .collect();
    target_pastages.sort();

    for src_file in &source_files {
        if src_file.ends_with(".pastage") {
            continue;
        }
        let ext = if src_file.ends_with(".paseqc") {
            ".paseqc"
        } else if src_file.ends_with(".paseq") {
            ".paseq"
        } else {
            // Unknown extension; copy across with the source filename as-is
            // so we never silently drop data.
            let data = extract_named_file(&pamt, game_dir, source_dir, src_file)?;
            builder.add_file(target_dir, src_file, &data)?;
            continue;
        };
        let data = extract_named_file(&pamt, game_dir, source_dir, src_file)?;
        let target_filename = format!("{}{}", target_npc, ext);
        builder.add_file(target_dir, &target_filename, &data)?;
    }

    for (i, src_pastage) in source_pastages.iter().enumerate() {
        let data = extract_named_file(&pamt, game_dir, source_dir, src_pastage)?;
        let target_filename = if i < target_pastages.len() {
            target_pastages[i].clone()
        } else {
            // No target slot → keep source's hash, just rewrite the stem.
            src_pastage.replacen(source_npc, target_npc, 1)
        };
        builder.add_file(target_dir, &target_filename, &data)?;
    }

    finalize_overlay(&builder_finish_with_checksum(builder)?, game_dir, overlay_group)
}

/// Scan PAZ group 0014's PAMT for NPC sequencer entries.
///
/// Returns one [`NpcEntry`] per unique stem. NPCs are deduplicated by stem
/// — if the same stem appears under both `funcnpc/` and `basecamp/` only
/// the first directory wins (alphabetical).
pub fn list_npcs(game_dir: &Path) -> io::Result<Vec<NpcEntry>> {
    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_data = fs::read(&pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", pamt_path.display(), e),
        )
    })?;
    let pamt = PackMeta::parse(&pamt_data, None)?;

    let mut npcs: Vec<NpcEntry> = Vec::new();
    let mut seen_stems: std::collections::HashSet<String> = std::collections::HashSet::new();

    for dir in &pamt.directories {
        if !NPC_DIRS.iter().any(|prefix| dir.path.starts_with(prefix)) {
            continue;
        }

        // Collect every file name in this directory once so the per-stem
        // bundle build below doesn't pay O(n^2) PAMT lookups.
        let file_names: Vec<&str> = dir.files.iter().map(|f| f.name.as_str()).collect();

        let paseqs: Vec<&str> = file_names
            .iter()
            .copied()
            .filter(|n| n.ends_with(".paseq"))
            .collect();

        for paseq in paseqs {
            let stem = &paseq[..paseq.len() - ".paseq".len()];
            if !seen_stems.insert(stem.to_string()) {
                continue;
            }

            let mut bundle: Vec<String> = Vec::new();
            bundle.push(paseq.to_string());

            let paseqc = format!("{}.paseqc", stem);
            if file_names.iter().any(|n| *n == paseqc) {
                bundle.push(paseqc);
            }

            for n in &file_names {
                if n.ends_with(".pastage") && stem_from_pastage(n) == stem {
                    bundle.push((*n).to_string());
                }
            }
            bundle.sort();

            npcs.push(NpcEntry {
                stem: stem.to_string(),
                display_name: format_display_name(&dir.path, stem),
                dir_path: dir.path.clone(),
                files: bundle,
            });
        }
    }

    npcs.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(npcs)
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Extract a single file by directory + filename via the parsed PAMT.
///
/// `NotFound` errors are kept distinct from other I/O failures so the sleep
/// mod can fall back gracefully when an optional sibling file is missing.
fn extract_named_file(
    pamt: &PackMeta,
    game_dir: &Path,
    dir_path: &str,
    file_name: &str,
) -> io::Result<Vec<u8>> {
    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == dir_path)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("PAMT directory '{}' not found", dir_path),
            )
        })?;
    let file = dir
        .files
        .iter()
        .find(|f| f.name == file_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found in '{}'", file_name, dir_path),
            )
        })?;
    let group_dir = game_dir.join(PAZ_GROUP);
    paz::extract_file(
        &group_dir,
        file,
        dir_path,
        &pamt.header.encrypt_info.encrypt_info,
    )
}

/// Replace every occurrence of `False` with `True ` (trailing space) so
/// the byte length is preserved. Returns a new buffer.
fn patch_false_to_true(data: &[u8]) -> Vec<u8> {
    let needle = b"False";
    let replacement = b"True ";
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + needle.len() <= data.len() && &data[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    debug_assert_eq!(out.len(), data.len(), "patch must preserve byte length");
    out
}

/// Collect every file in `dir_path` whose stem matches `npc_stem`.
fn collect_npc_files(pamt: &PackMeta, dir_path: &str, npc_stem: &str) -> io::Result<Vec<String>> {
    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == dir_path)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("PAMT directory '{}' not found", dir_path),
            )
        })?;

    let mut out: Vec<String> = Vec::new();
    for f in &dir.files {
        let n = &f.name;
        let matches = if n.ends_with(".paseq") {
            &n[..n.len() - ".paseq".len()] == npc_stem
        } else if n.ends_with(".paseqc") {
            &n[..n.len() - ".paseqc".len()] == npc_stem
        } else if n.ends_with(".pastage") {
            stem_from_pastage(n) == npc_stem
        } else {
            false
        };
        if matches {
            out.push(n.clone());
        }
    }
    out.sort();
    Ok(out)
}

/// Recover the bare stem from a `.pastage` filename, stripping a trailing
/// `_<hex>` hash chunk if present (e.g.
/// `cd_seq_funcnpc_butcher_1056405172.pastage` -> `cd_seq_funcnpc_butcher`).
fn stem_from_pastage(filename: &str) -> &str {
    let name = filename.strip_suffix(".pastage").unwrap_or(filename);
    if let Some(idx) = name.rfind('_') {
        let suffix = &name[idx + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return &name[..idx];
        }
    }
    name
}

/// Build a friendly dropdown label from the directory + stem.
fn format_display_name(dir_path: &str, stem: &str) -> String {
    let mut label = stem;
    for prefix in [
        "cd_seq_basecamp_funcnpc_",
        "cd_seq_funcnpc_",
        "cd_seq_basecamp_",
    ] {
        if let Some(rest) = label.strip_prefix(prefix) {
            label = rest;
            break;
        }
    }
    let mut pretty: String = label
        .replace('_', " ")
        .trim()
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if dir_path.contains("basecamp") {
        pretty.push_str(" (basecamp)");
    } else {
        pretty.push_str(" (funcnpc)");
    }
    pretty
}

/// Wrap [`PackGroupBuilder::finish`] and immediately re-parse the emitted
/// PAMT so we have its computed checksum on hand for the PAPGT update.
fn builder_finish_with_checksum(builder: PackGroupBuilder) -> io::Result<PamtWithChecksum> {
    let pamt_bytes = builder.finish()?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    Ok(PamtWithChecksum {
        checksum: pamt.header.checksum,
    })
}

struct PamtWithChecksum {
    checksum: u32,
}

/// Front-insert (or replace) the PAPGT entry for `overlay_group` with the
/// freshly computed PAMT checksum, then write it back.
fn finalize_overlay(
    pamt: &PamtWithChecksum,
    game_dir: &Path,
    overlay_group: &str,
) -> io::Result<()> {
    let papgt_path = game_dir.join("meta/0.papgt");
    let backup_path = game_dir.join("meta/0.papgt.workbench_paseq_backup");
    if !backup_path.exists() && papgt_path.is_file() {
        fs::copy(&papgt_path, &backup_path)?;
    }

    let papgt_data = fs::read(&papgt_path)?;
    let mut papgt = PackGroupTreeMeta::parse(&papgt_data)?;
    papgt.add_entry(overlay_group, pamt.checksum, 0, LanguageType::ALL);
    let papgt_bytes = papgt.to_bytes()?;
    fs::write(&papgt_path, &papgt_bytes)?;
    Ok(())
}

// ── Byte-patch editor (generic) ─────────────────────────────────────────────
//
// The presets above (sleep mod + NPC swap) cover two well-known recipes.
// The byte-patch editor below is the general-purpose authoring path: list
// every `.paseq` / `.paseqc` / `.pastage` file in 0014, read one as raw
// bytes, and apply user-authored find/replace patches against it. Saves
// to a new overlay group so users can iterate without touching the preset
// flows.
//
// PASEQ binary format isn't decoded yet, so the editor is byte-level by
// design — when the format is reverse-engineered later, the byte-patch
// JSON files authored here remain useful as raw fallbacks.

use serde::{Deserialize, Serialize};
use dmm_parser_rust_only::binary::pamt::ResolvedFile;

/// One file in the sequencer PAZ that the byte-patch editor can target.
#[derive(Clone, Debug)]
pub struct PaseqPazEntry {
    /// PAMT directory path the file lives under (e.g.
    /// `"sequencer/binary__/stageseq/funcnpc"`).
    pub dir_path: String,
    /// File name including the `.paseq` / `.paseqc` / `.pastage` extension.
    pub filename: String,
}

impl PaseqPazEntry {
    /// Display label for dropdowns — directory + filename.
    pub fn display(&self) -> String {
        format!("{}  ({})", self.filename, self.dir_path)
    }

    /// File extension lowercased (e.g. `"paseq"` / `"pastage"`). Used to
    /// pick a default icon / tab in the UI.
    pub fn extension(&self) -> &'static str {
        if self.filename.ends_with(".paseqc") {
            "paseqc"
        } else if self.filename.ends_with(".pastage") {
            "pastage"
        } else if self.filename.ends_with(".paseq") {
            "paseq"
        } else {
            "bin"
        }
    }
}

/// One find/replace byte patch. Authored in the editor, saved as JSON
/// for sharing, applied against a target file's bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BytePatch {
    /// Human-readable name shown in the patch list. Required so users
    /// can tell their patches apart.
    pub name: String,
    /// Bytes to find. Encoded as a hex string in JSON
    /// (e.g. `"46 61 6c 73 65"`); whitespace is ignored on parse.
    #[serde(with = "hex_bytes_serde")]
    pub find: Vec<u8>,
    /// Bytes to substitute. Must equal `find.len()` unless `allow_resize`
    /// is true — different-length replacements break file-internal
    /// offsets and should be opt-in.
    #[serde(with = "hex_bytes_serde")]
    pub replace: Vec<u8>,
    /// Optional comment (why this patch exists, source citation, etc.).
    #[serde(default)]
    pub comment: String,
    /// Allow `find.len() != replace.len()`. Defaults to false because
    /// most game-binary patches break if the file size changes — even
    /// when the format isn't decoded, file-level pointers still point
    /// at fixed offsets.
    #[serde(default)]
    pub allow_resize: bool,
}

/// A complete byte-patch document: target file + ops. Mirrors
/// [`crate::xml_patcher::XmlPatch`] in shape so users can author either
/// flavour with the same mental model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BytePatchDoc {
    /// `dir_path/filename` — used by the deploy path to know where the
    /// target lives in the PAZ.
    pub dir_path: String,
    pub filename: String,
    /// Free-form description for the UI.
    #[serde(default)]
    pub description: String,
    pub patches: Vec<BytePatch>,
}

impl BytePatchDoc {
    pub fn new(dir_path: impl Into<String>, filename: impl Into<String>) -> Self {
        Self {
            dir_path: dir_path.into(),
            filename: filename.into(),
            description: String::new(),
            patches: Vec::new(),
        }
    }
}

/// List every `.paseq` / `.paseqc` / `.pastage` file in PAZ group 0014.
/// Returned sorted by dir_path then filename.
pub fn enumerate_paseq_files(game_dir: &Path) -> io::Result<Vec<PaseqPazEntry>> {
    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;

    let mut out: Vec<PaseqPazEntry> = Vec::new();
    for dir in &pamt.directories {
        for f in &dir.files {
            let ext_ok = f.filename_lc_ends(&[".paseq", ".paseqc", ".pastage"]);
            if ext_ok {
                out.push(PaseqPazEntry {
                    dir_path: dir.path.clone(),
                    filename: f.name.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| {
        a.dir_path
            .cmp(&b.dir_path)
            .then(a.filename.cmp(&b.filename))
    });
    Ok(out)
}

/// Read a single file from group 0014 by directory + name.
pub fn read_paseq_from_paz(game_dir: &Path, entry: &PaseqPazEntry) -> io::Result<Vec<u8>> {
    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    extract_named_file(&pamt, game_dir, &entry.dir_path, &entry.filename)
}

/// Apply a list of byte patches to `data` in order. Each patch replaces
/// every non-overlapping occurrence of `find` with `replace`. Errors if
/// `replace.len() != find.len()` and the patch doesn't have
/// `allow_resize` set (length-changing patches are rejected by default
/// because they break file-internal offsets).
pub fn apply_byte_patches(data: &[u8], patches: &[BytePatch]) -> io::Result<Vec<u8>> {
    let mut buf = data.to_vec();
    for (i, p) in patches.iter().enumerate() {
        if p.find.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("patch[{}] '{}': find is empty", i, p.name),
            ));
        }
        if p.find.len() != p.replace.len() && !p.allow_resize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "patch[{}] '{}': find ({}B) and replace ({}B) differ in length \
                     — set allow_resize=true to opt in",
                    i,
                    p.name,
                    p.find.len(),
                    p.replace.len()
                ),
            ));
        }
        buf = replace_bytes(&buf, &p.find, &p.replace);
    }
    Ok(buf)
}

/// Deploy one or more byte-patch documents as a PAZ overlay.
///
/// Each doc's target file is read from vanilla 0014, patched, and added
/// to the overlay PAZ. PAPGT is updated front-insert so the overlay
/// wins lookup. Mirrors `apply_sleep_mod` but driven by user-authored
/// patches instead of the hardcoded preset.
pub fn deploy_byte_patches(
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

    let pamt_path = game_dir.join(PAZ_GROUP).join("0.pamt");
    let pamt_bytes = fs::read(&pamt_path)?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let encrypt_info = pamt.header.encrypt_info.encrypt_info;

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
        let data = extract_named_file(&pamt, game_dir, &doc.dir_path, &doc.filename)?;
        let patched = apply_byte_patches(&data, &doc.patches)?;
        builder.add_file(&doc.dir_path, &doc.filename, &patched)?;
    }

    finalize_overlay(&builder_finish_with_checksum(builder)?, game_dir, overlay_group)
}

/// Find every non-overlapping occurrence of `needle` in `haystack` and
/// substitute it with `replacement`. Identical to
/// `patch_false_to_true` but generalised to arbitrary needles.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// `serde_with`-style helper to (de)serialise `Vec<u8>` as a hex string
/// with optional whitespace separators. Stored on disk as
/// `"46 61 6c 73 65"` rather than a base64 blob so users can hand-edit
/// patch JSON files easily.
mod hex_bytes_serde {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let mut out = Vec::new();
        let mut buf = String::new();
        for ch in s.chars() {
            if ch.is_ascii_whitespace() || ch == ',' {
                continue;
            }
            buf.push(ch);
            if buf.len() == 2 {
                let byte = u8::from_str_radix(&buf, 16).map_err(de::Error::custom)?;
                out.push(byte);
                buf.clear();
            }
        }
        if !buf.is_empty() {
            return Err(de::Error::custom("hex string has odd nibble count"));
        }
        Ok(out)
    }
}

trait FileExt {
    fn filename_lc_ends(&self, exts: &[&str]) -> bool;
}

impl FileExt for ResolvedFile {
    fn filename_lc_ends(&self, exts: &[&str]) -> bool {
        let lc = self.name.to_ascii_lowercase();
        exts.iter().any(|e| lc.ends_with(*e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_false_to_true_replaces_in_place_and_preserves_length() {
        let input = b"if (cooldown == False) {} else if (other == False)";
        let out = patch_false_to_true(input);
        assert_eq!(out.len(), input.len());
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "if (cooldown == True ) {} else if (other == True )"
        );
    }

    #[test]
    fn patch_false_to_true_no_match_returns_clone() {
        let input = b"nothing to do";
        let out = patch_false_to_true(input);
        assert_eq!(out, input);
    }

    #[test]
    fn stem_from_pastage_strips_hex_suffix() {
        assert_eq!(
            stem_from_pastage("cd_seq_funcnpc_butcher_1056405172.pastage"),
            "cd_seq_funcnpc_butcher"
        );
    }

    #[test]
    fn stem_from_pastage_keeps_non_hex_suffix() {
        // `barbershop` ends in non-hex letters, so the rsplit must NOT strip
        // the trailing word.
        assert_eq!(
            stem_from_pastage("cd_seq_funcnpc_barbershop.pastage"),
            "cd_seq_funcnpc_barbershop"
        );
    }

    #[test]
    fn format_display_name_strips_known_prefixes_and_tags_dir() {
        assert_eq!(
            format_display_name(
                "sequencer/binary__/stageseq/funcnpc",
                "cd_seq_funcnpc_butcher"
            ),
            "Butcher (funcnpc)"
        );
        assert_eq!(
            format_display_name(
                "sequencer/binary__/stageseq/basecamp",
                "cd_seq_basecamp_innkeeper"
            ),
            "Innkeeper (basecamp)"
        );
    }
}
