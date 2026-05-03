//! Localization loader.
//!
//! Extracts the English and Korean PALOC files from the game's PAZ archives
//! and builds two `unk_id -> string` maps that the rest of the workbench can
//! consult when displaying hash-referenced fields.
//!
//! The PALOC `unk_id` field is the Jenkins hashlittle of the localization
//! `string_key`; pabgb tables that point at strings store the same hash, so a
//! lookup against either language map turns a raw 0xDEAD_BEEF reference back
//! into a human-readable English (or Korean) value.
//!
//! ## Cache
//!
//! Extracting + parsing two ~38K-entry paloc files is roughly a second on a
//! release build, so we cache the joined map JSON under the standard
//! `%APPDATA%/Crimson/ModWorkbench/localization.json` path. Subsequent app
//! launches load the JSON synchronously, which is much cheaper than going
//! through PAZ + ChaCha20 + paloc parse again.
//!
//! Cache invalidation is intentionally manual: there's no version detection
//! today, so when the user updates the game they delete the cache file (or
//! the future "Reload Localization" menu item drops it).
//!
//! ## Error handling
//!
//! Anything goes wrong (missing PAMT, missing language directory, parse
//! failure) bubbles up as `io::Error`. The caller — currently the worker job
//! handler — surfaces it as a toast in the UI; a missing cache + missing
//! game_dir simply means the rest of the app keeps using raw hashes.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use dmm_parser_rust_only::binary::paloc::LocalizationFile;
use dmm_parser_rust_only::binary::pamt::PackMeta;
use dmm_parser_rust_only::binary::paz;

/// Internal PAZ directory holding every `localizationstring_*.paloc`. Mirrors
/// [`crate::paloc_editor::PALOC_DIR`] — duplicated here so the localization
/// loader doesn't pull in the editor module just for one constant.
const PALOC_DIR: &str = "gamedata/stringtable/binary__";

/// Language code targeted by the loader.
///
/// Only English + Korean are extracted: English is the primary display form
/// (it's what most users want to see in tooltips), and Korean is the original
/// authoring locale, useful as a fallback when an English string is empty or
/// for users who prefer it. Other languages are out of scope — they'd add
/// extraction time + cache size without a clear use.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lang {
    Eng,
    Kor,
}

/// Per-language source group + filename.
struct LangSource {
    lang: Lang,
    /// PAZ group containing the paloc (e.g. `"0020"` for English).
    group: &'static str,
    /// Filename inside [`PALOC_DIR`] (e.g. `"localizationstring_eng.paloc"`).
    filename: &'static str,
}

const SOURCES: &[LangSource] = &[
    LangSource {
        lang: Lang::Eng,
        group: "0020",
        filename: "localizationstring_eng.paloc",
    },
    LangSource {
        lang: Lang::Kor,
        group: "0019",
        filename: "localizationstring_kor.paloc",
    },
];

/// In-memory localization tables.
///
/// Both maps are keyed by the paloc `unk_id` rendered as a base-10 string —
/// `serde_json` only supports string keys, and converting at the boundary
/// once is cheaper than installing a `serde_with` dependency for one struct.
#[derive(Default, Serialize, Deserialize)]
pub struct Localization {
    /// `unk_id` (decimal string) -> English string.
    pub eng: HashMap<String, String>,
    /// `unk_id` (decimal string) -> Korean string.
    pub kor: HashMap<String, String>,
    /// Game version string captured at extraction time. We don't compare it
    /// today (manual invalidation only), but storing it lets a future
    /// "Reload Localization" UX show "cached for v1.0.5, current v1.0.6".
    pub game_version: String,
}

impl Localization {
    /// Load from cache if present; otherwise extract from `game_dir` and
    /// persist the result. Cache misses propagate any extraction or write
    /// errors so the caller can surface them.
    pub fn load_or_build(game_dir: &Path) -> io::Result<Self> {
        if let Ok(cached) = Self::load_cached() {
            // Treat an empty cache file (both maps empty) as a miss — most
            // likely a previous run wrote the file before extraction
            // completed. Fall through to a fresh extract.
            if !cached.is_empty() {
                return Ok(cached);
            }
        }
        let fresh = Self::extract_from_game(game_dir)?;
        if let Err(e) = fresh.save_cache() {
            eprintln!("localization: cache save failed: {}", e);
        }
        Ok(fresh)
    }

    /// Extract both language maps from the game directory. Slow path: reads
    /// two PAZ chunks, decrypts them, parses the paloc payload, and inserts
    /// every entry into the corresponding map.
    pub fn extract_from_game(game_dir: &Path) -> io::Result<Self> {
        let mut out = Self::default();
        for src in SOURCES {
            let entries = read_paloc(game_dir, src.group, src.filename)?;
            let target = match src.lang {
                Lang::Eng => &mut out.eng,
                Lang::Kor => &mut out.kor,
            };
            target.reserve(entries.len());
            for (unk_id, value) in entries {
                target.insert(unk_id.to_string(), value);
            }
        }
        Ok(out)
    }

    /// Read the cached localization JSON.
    pub fn load_cached() -> io::Result<Self> {
        let path = cache_path().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no platform data directory available for localization cache",
            )
        })?;
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "localization cache parse failed at {}: {}",
                    path.display(),
                    e
                ),
            )
        })
    }

    /// Persist the in-memory tables to the cache JSON.
    pub fn save_cache(&self) -> io::Result<()> {
        let path = cache_path().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no platform data directory available for localization cache",
            )
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e))
        })?;
        std::fs::write(&path, bytes)
    }

    /// Look up the localized string for a given `unk_id` hash. Picks the
    /// language explicitly so callers can fall back if the primary is empty.
    pub fn lookup(&self, hash: u64, lang: Lang) -> Option<&str> {
        let key = hash.to_string();
        let map = match lang {
            Lang::Eng => &self.eng,
            Lang::Kor => &self.kor,
        };
        let s = map.get(&key)?;
        if s.is_empty() {
            None
        } else {
            Some(s.as_str())
        }
    }

    /// Convenience: return both languages at once. The field panel uses the
    /// English value as the primary inline annotation and Korean for a hover
    /// tooltip.
    pub fn lookup_pair(&self, hash: u64) -> (Option<&str>, Option<&str>) {
        (self.lookup(hash, Lang::Eng), self.lookup(hash, Lang::Kor))
    }

    /// Total entries across both languages. Used by status messages.
    pub fn len(&self) -> usize {
        self.eng.len() + self.kor.len()
    }

    /// True when both language maps are empty. We use this to detect bogus
    /// caches in [`load_or_build`] so a corrupt write doesn't permanently
    /// disable the feature.
    pub fn is_empty(&self) -> bool {
        self.eng.is_empty() && self.kor.is_empty()
    }

    /// Entries in just the English table. Convenience for UI labels.
    pub fn eng_len(&self) -> usize {
        self.eng.len()
    }

    /// Entries in just the Korean table.
    pub fn kor_len(&self) -> usize {
        self.kor.len()
    }
}

/// Resolve the cache file path under the standard ProjectDirs data dir.
///
/// Mirrors `Config::config_path` style — returns `None` when no platform home
/// is available, which collapses gracefully to "feature disabled" rather than
/// erroring out the whole app.
fn cache_path() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
    Some(dirs.data_dir().join("localization.json"))
}

/// Extract one paloc file from the game's PAZ archives and return its
/// `(unk_id, string_value)` pairs.
///
/// This duplicates a small slice of [`crate::paloc_editor::load_paloc`] but
/// stays self-contained so the localization loader doesn't pull in the
/// editor's session-management types just to grab strings.
fn read_paloc(
    game_dir: &Path,
    group: &str,
    filename: &str,
) -> io::Result<Vec<(u64, String)>> {
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
        .find(|f| f.name == filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("File '{}' not found in {}", filename, PALOC_DIR),
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
            format!("paloc parse failed for {}: {}", filename, e),
        )
    })?;

    Ok(parsed
        .entries
        .into_iter()
        .map(|e| (e.unk_id, e.string_value.data.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_some_when_key_present() {
        let mut loc = Localization::default();
        loc.eng.insert("12345".to_string(), "Hello".to_string());
        loc.kor.insert("12345".to_string(), "안녕".to_string());

        assert_eq!(loc.lookup(12345, Lang::Eng), Some("Hello"));
        assert_eq!(loc.lookup(12345, Lang::Kor), Some("안녕"));
        let pair = loc.lookup_pair(12345);
        assert_eq!(pair, (Some("Hello"), Some("안녕")));
    }

    #[test]
    fn lookup_treats_empty_strings_as_missing() {
        // Some paloc rows ship with an empty value — we want "no translation"
        // semantics rather than an empty bubble in the UI.
        let mut loc = Localization::default();
        loc.eng.insert("999".to_string(), String::new());
        assert_eq!(loc.lookup(999, Lang::Eng), None);
    }

    #[test]
    fn lookup_returns_none_when_key_missing() {
        let loc = Localization::default();
        assert_eq!(loc.lookup(7, Lang::Eng), None);
        assert_eq!(loc.lookup_pair(7), (None, None));
    }

    #[test]
    fn json_roundtrip_preserves_entries() {
        let mut loc = Localization {
            game_version: "test-1.0".to_string(),
            ..Default::default()
        };
        loc.eng.insert("1".into(), "one".into());
        loc.kor.insert("1".into(), "하나".into());

        let bytes = serde_json::to_vec(&loc).unwrap();
        let back: Localization = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.lookup(1, Lang::Eng), Some("one"));
        assert_eq!(back.lookup(1, Lang::Kor), Some("하나"));
        assert_eq!(back.game_version, "test-1.0");
    }

    #[test]
    fn is_empty_only_true_when_both_maps_empty() {
        let mut loc = Localization::default();
        assert!(loc.is_empty());
        loc.eng.insert("1".into(), "x".into());
        assert!(!loc.is_empty());
    }
}
