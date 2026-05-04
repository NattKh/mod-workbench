//! PALOC (localization string) editor.
//!
//! Loads `localizationstring_<lang>.paloc` from the game's PAZ archives,
//! lets the user edit individual entries, and writes the modified file
//! back as a PAZ overlay.
//!
//! The paloc binary format is parsed by `dmm_parser_rust_only::binary::paloc::
//! LocalizationFile`, which holds borrowed slices into the source bytes. We
//! own each entry as `String` here so the UI can mutate them freely without
//! lifetime juggling, then serialize directly to the same wire format on
//! save (u64 unk_id + u32-length-prefixed UTF-8 strings, count appended at
//! the end).

use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::paloc::LocalizationFile;
use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::papgt::{LanguageType, PackGroupTreeMeta};
use dmm_parser_rust_only::binary::paz::{self, PackGroupBuilder};

/// Internal PAZ directory path that holds every `localizationstring_*.paloc`.
pub const PALOC_DIR: &str = "gamedata/stringtable/binary__";

/// Language code -> source group mapping used by the vanilla game.
///
/// The order here is also the order shown in the language dropdown. The codes
/// are the suffix used in the paloc filename (e.g. `eng` -> `localizationstring_eng.paloc`).
pub const LANGUAGES: &[(&str, &str)] = &[
    ("kor", "0019"),
    ("eng", "0020"),
    ("jpn", "0021"),
    ("cht", "0022"),
    ("ger", "0023"),
    ("fra", "0024"),
    ("spa", "0025"),
    ("por", "0026"),
    ("rus", "0027"),
    ("tur", "0028"),
    ("tha", "0029"),
    ("ind", "0030"),
    ("chs", "0031"),
    ("ara", "0032"),
];

/// Owned mirror of a `LocalizationEntry` that the UI can mutate freely.
#[derive(Clone, Debug)]
pub struct PalocEntryEdit {
    pub unk_id: u64,
    pub string_key: String,
    pub string_value: String,
}

/// In-memory editing session for a single paloc file.
pub struct PalocSession {
    /// Language suffix (e.g. `"eng"`).
    pub language: String,
    /// Source PAZ group (e.g. `"0020"` for English).
    pub group: String,
    /// Full internal path of the paloc file (used for ChaCha20 nonce derivation).
    pub paloc_path: String,
    /// Filename only (e.g. `"localizationstring_eng.paloc"`).
    pub paloc_filename: String,
    /// Live entries shown in the editor.
    pub entries: Vec<PalocEntryEdit>,
    /// Vanilla snapshot for diffing. Same order/length as `entries` immediately
    /// after [`load_paloc`]; if entries are added/removed this is no longer a
    /// 1:1 match (the UI just shows the change count, not a full diff).
    pub vanilla: Vec<PalocEntryEdit>,
    /// Search filter (case-insensitive substring on key OR value).
    pub filter: String,
    /// One-shot scroll target — index into the **filtered** row list. Set
    /// by global-search "Open in editor" navigation; consumed by the
    /// table renderer on the first frame after the load lands so the user
    /// arrives on the matching row.
    pub pending_scroll_row: Option<usize>,
}

impl PalocSession {
    /// Number of entries that differ from `vanilla` at the same index.
    ///
    /// If the entry counts no longer match (after add/remove), every entry
    /// past `vanilla.len()` counts as changed.
    pub fn change_count(&self) -> usize {
        let mut n = 0;
        for (i, cur) in self.entries.iter().enumerate() {
            match self.vanilla.get(i) {
                Some(v) => {
                    if v.unk_id != cur.unk_id
                        || v.string_key != cur.string_key
                        || v.string_value != cur.string_value
                    {
                        n += 1;
                    }
                }
                None => n += 1,
            }
        }
        n
    }

    /// True when `entry` matches the case-insensitive filter on key OR value.
    /// Empty filter matches everything.
    pub fn matches_filter(&self, entry: &PalocEntryEdit) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_lowercase();
        entry.string_key.to_lowercase().contains(&needle)
            || entry.string_value.to_lowercase().contains(&needle)
    }
}

/// Look up the PAZ group that ships the given language's paloc.
pub fn group_for_language(language: &str) -> Option<&'static str> {
    LANGUAGES
        .iter()
        .find(|(lang, _)| *lang == language)
        .map(|(_, group)| *group)
}

/// Build the paloc filename from its language suffix.
pub fn paloc_filename(language: &str) -> String {
    format!("localizationstring_{}.paloc", language)
}

/// Load and parse the vanilla paloc for `language` from the game directory.
pub fn load_paloc(game_dir: &Path, language: &str) -> io::Result<PalocSession> {
    let group = group_for_language(language).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown language code: {}", language),
        )
    })?;
    let paloc_filename = paloc_filename(language);

    let group_dir = game_dir.join(group);
    let pamt_path = group_dir.join("0.pamt");
    let pamt_data = std::fs::read(&pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Cannot read PAMT at {}: {}", pamt_path.display(), e),
        )
    })?;
    let pamt = PackMeta::parse(&pamt_data, None)?;

    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == PALOC_DIR)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory '{}' not found in {}/0.pamt", PALOC_DIR, group),
            )
        })?;

    let file = dir
        .files
        .iter()
        .find(|f| f.name == paloc_filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("File '{}' not found in {}", paloc_filename, PALOC_DIR),
            )
        })?;

    let bytes = paz::extract_file(
        &group_dir,
        file,
        PALOC_DIR,
        &pamt.header.encrypt_info.encrypt_info,
    )?;

    let parsed = LocalizationFile::parse(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("paloc parse failed for {}: {}", paloc_filename, e),
        )
    })?;

    let entries: Vec<PalocEntryEdit> = parsed
        .entries
        .iter()
        .map(|e| PalocEntryEdit {
            unk_id: e.unk_id,
            string_key: e.string_key.data.to_string(),
            string_value: e.string_value.data.to_string(),
        })
        .collect();

    let paloc_path = format!("{}/{}", PALOC_DIR, paloc_filename);

    Ok(PalocSession {
        language: language.to_string(),
        group: group.to_string(),
        paloc_path,
        paloc_filename,
        vanilla: entries.clone(),
        entries,
        filter: String::new(),
        pending_scroll_row: None,
    })
}

/// Serialize the in-memory entries back to paloc wire format.
///
/// Format: each entry = u64 unk_id + u32 key_len + utf8 key + u32 val_len + utf8 val.
/// The total entry count is appended as a u32 at the end of the buffer.
pub fn serialize_entries(entries: &[PalocEntryEdit]) -> Vec<u8> {
    // Reserve a generous initial capacity so most files avoid reallocs.
    // Worst case is fine — we don't keep the buffer around.
    let mut out: Vec<u8> = Vec::with_capacity(entries.len() * 64);
    for e in entries {
        out.extend_from_slice(&e.unk_id.to_le_bytes());
        let key_bytes = e.string_key.as_bytes();
        out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(key_bytes);
        let val_bytes = e.string_value.as_bytes();
        out.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(val_bytes);
    }
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out
}

/// Deploy the modified paloc as a PAZ overlay under `overlay_group`.
///
/// Mirrors `crate::deploy::deploy` but for paloc files: writes a PAZ chunk
/// + 0.pamt into `<game_dir>/<overlay_group>/`, then registers that group
/// in PAPGT (after backing it up). Restoration goes through the same
/// `crate::restore::restore` path used by pabgb mods.
pub fn save_paloc_overlay(
    session: &PalocSession,
    game_dir: &Path,
    overlay_group: &str,
) -> io::Result<()> {
    let paloc_bytes = serialize_entries(&session.entries);

    // Sanity-check that we can re-parse what we just wrote.
    LocalizationFile::parse(&paloc_bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "internal: serialized paloc fails to re-parse: {}. \
                 Refusing to deploy a corrupt overlay.",
                e
            ),
        )
    })?;

    let overlay_dir = game_dir.join(overlay_group);
    std::fs::create_dir_all(&overlay_dir)?;

    // Borrow the encrypt_info from the source group's PAMT (not 0008 — the
    // string tables live in 00xx groups and may use a different encrypt_info
    // in theory; in practice all groups share the same value, but reading
    // the matching one is cheap and resilient).
    let src_pamt_data = std::fs::read(game_dir.join(&session.group).join("0.pamt"))?;
    let src_pamt = PackMeta::parse(&src_pamt_data, None)?;
    let encrypt_info = src_pamt.header.encrypt_info.encrypt_info;

    let mut builder = PackGroupBuilder::new(
        &overlay_dir,
        Compression::None,
        CryptoType::ChaCha20,
        encrypt_info,
        256 * 1024 * 1024,
    );
    builder.add_file(PALOC_DIR, &session.paloc_filename, &paloc_bytes)?;

    let pamt_bytes = builder.finish()?;
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let pamt_checksum = pamt.header.checksum;

    let papgt_path = game_dir.join("meta/0.papgt");
    let papgt_backup = game_dir.join("meta/0.papgt.workbench_backup");
    if !papgt_backup.exists() {
        std::fs::copy(&papgt_path, &papgt_backup)?;
    }

    let papgt_data = std::fs::read(&papgt_path)?;
    let mut papgt = PackGroupTreeMeta::parse(&papgt_data)?;
    papgt.add_entry(
        overlay_group,
        pamt_checksum,
        1, // is_optional = 1 (mod overlay)
        LanguageType::ALL,
    );
    let papgt_bytes = papgt.to_bytes()?;
    std::fs::write(&papgt_path, &papgt_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip() {
        let entries = vec![
            PalocEntryEdit {
                unk_id: 0x1234,
                string_key: "hello".to_string(),
                string_value: "world".to_string(),
            },
            PalocEntryEdit {
                unk_id: 0xdeadbeef,
                string_key: "key2".to_string(),
                string_value: "second value".to_string(),
            },
        ];
        let bytes = serialize_entries(&entries);
        let parsed = LocalizationFile::parse(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), entries.len());
        for (a, b) in entries.iter().zip(parsed.entries.iter()) {
            assert_eq!(a.unk_id, b.unk_id);
            assert_eq!(a.string_key, b.string_key.data);
            assert_eq!(a.string_value, b.string_value.data);
        }
    }

    #[test]
    fn group_lookup() {
        assert_eq!(group_for_language("eng"), Some("0020"));
        assert_eq!(group_for_language("kor"), Some("0019"));
        assert_eq!(group_for_language("ara"), Some("0032"));
        assert_eq!(group_for_language("invalid"), None);
    }
}
