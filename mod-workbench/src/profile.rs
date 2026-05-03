//! Profile system — named sets of active mods.
//!
//! A [`Profile`] is "the user's curated bundle": a name plus an ordered list
//! of paths into the mod library. The [`ProfileStore`] persists every
//! profile the user has authored alongside the *active* one, so re-launching
//! the workbench restores the same profile context.
//!
//! ## Persistence
//!
//! Stored as JSON at `%APPDATA%/Crimson/ModWorkbench/profiles.json`. JSON
//! over TOML because profiles can carry arbitrary path strings that are
//! easier to round-trip cleanly through serde_json than via toml's stricter
//! escaping (Windows backslashes in particular).
//!
//! ## Apply semantics
//!
//! [`apply_profile`] is the v1 deployment path. It is intentionally simple:
//!
//! 1. Restore (remove) the workbench overlay group, putting the game back
//!    to vanilla for our slot.
//! 2. For each active mod, in priority order (front of the list = highest
//!    priority), deploy it as its own overlay group (`0058`, `0059`, …).
//!
//! v1 deploys mods as separate overlay groups so PAPGT priority ordering
//! handles conflict resolution — later overlay entries win on PAPGT lookup,
//! so we *flip* `active_mods` (front = highest priority) onto increasing
//! group numbers (later in PAPGT). A future v2 will merge intents in-process
//! before producing a single overlay; for now this gets the user a working
//! profile-switching loop without inventing a new merge engine.
//!
//! ## Mod targeting
//!
//! v1 supports the workbench-native v3 field JSON format only — that's the
//! shape every workbench-exported mod ships in, and it tells us up-front
//! which table the mod targets so we can pick the right overlay group + the
//! right pabgb file. DMM v3 (multi-target intent format) is *parsed* by
//! [`crate::conflict::load_mod`] for the conflict viewer but is rejected by
//! [`apply_profile`]: applying intent-style mods correctly requires merging
//! them with the live game data and re-serializing the whole table, which
//! the workbench can do only via the editor (load tab, edit, deploy).
//! Surfacing that as a clear error here is preferable to silently dropping
//! the mod from the deploy.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::deploy;
use crate::restore;
use crate::state::TableMeta;
use crate::table_loader;

/// One named profile.
///
/// `active_mods` is **priority-ordered**: index 0 is highest priority. When
/// two mods change the same field, the one earlier in the list wins.
/// [`apply_profile`] enforces this by deploying the highest-priority mod
/// last (so its overlay group ends up later in PAPGT, and PAPGT lookup
/// returns the last-added entry first — a quirk of the format we exploit
/// here).
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    /// Paths into the mod library (see [`crate::mod_library`]). Stored as
    /// absolute paths so a profile is portable across workbench launches
    /// even if the user's working directory changes.
    pub active_mods: Vec<PathBuf>,
}

impl Profile {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            active_mods: Vec::new(),
        }
    }
}

/// Disk-resident container of every profile the user has authored, plus
/// which one is currently active (referenced by name — names are unique
/// per [`save_store`]).
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ProfileStore {
    pub profiles: Vec<Profile>,
    pub active_profile: Option<String>,
}

impl ProfileStore {
    /// Look up a profile by name. Case-sensitive; the UI keeps a single
    /// source of truth for the name string so this is fine in practice.
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.name == name)
    }

    /// Borrow the currently-active profile, if one is set and still exists.
    pub fn active(&self) -> Option<&Profile> {
        self.active_profile
            .as_deref()
            .and_then(|n| self.get(n))
    }

    pub fn active_mut(&mut self) -> Option<&mut Profile> {
        let name = self.active_profile.clone()?;
        self.get_mut(&name)
    }

    /// Append a profile, ensuring its name is unique by suffixing `_1`,
    /// `_2`, … until we find a free slot. Returns the final name written.
    ///
    /// Used by the UI's "New Profile" button so a duplicate name doesn't
    /// silently overwrite an existing profile.
    pub fn add_unique(&mut self, base_name: impl Into<String>) -> String {
        let base = base_name.into();
        let mut candidate = base.clone();
        let mut i = 1u32;
        while self.profiles.iter().any(|p| p.name == candidate) {
            candidate = format!("{}_{}", base, i);
            i += 1;
        }
        self.profiles.push(Profile::new(candidate.clone()));
        candidate
    }

    /// Remove a profile by name. If the removed profile was active, the
    /// active pointer is cleared (the UI is expected to pick a fallback).
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.name != name);
        if self.active_profile.as_deref() == Some(name) {
            self.active_profile = None;
        }
        self.profiles.len() != before
    }

    /// Rename a profile. If the renamed profile was active, the active
    /// pointer follows the new name. Returns `false` when no profile with
    /// `old` exists, or when `new` is already taken.
    pub fn rename(&mut self, old: &str, new: &str) -> bool {
        if old == new {
            return true;
        }
        if self.profiles.iter().any(|p| p.name == new) {
            return false;
        }
        let Some(p) = self.get_mut(old) else {
            return false;
        };
        p.name = new.to_string();
        if self.active_profile.as_deref() == Some(old) {
            self.active_profile = Some(new.to_string());
        }
        true
    }
}

/// Resolved profiles file path:
/// `%APPDATA%/Crimson/ModWorkbench/profiles.json`.
///
/// Returns `None` if no platform data dir is available — callers should
/// treat that as "profile system disabled" rather than an error.
pub fn store_path() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
    Some(dirs.data_dir().join("profiles.json"))
}

/// Load the profile store from disk, returning a default (empty) store on
/// any non-fatal error (missing file, parse failure, no home dir).
///
/// Hard errors propagate so the UI can surface "your profiles file is
/// corrupt" instead of silently nuking the user's data; the file is small
/// and the user almost certainly wants to know.
pub fn load_store() -> std::io::Result<ProfileStore> {
    let path = match store_path() {
        Some(p) => p,
        None => return Ok(ProfileStore::default()),
    };

    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProfileStore::default());
        }
        Err(e) => return Err(e),
    };

    serde_json::from_str(&data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("profiles.json parse error: {}", e),
        )
    })
}

/// Persist the profile store to disk. Creates the parent directory if it
/// doesn't exist so a fresh install can save without ceremony.
pub fn save_store(store: &ProfileStore) -> std::io::Result<()> {
    let path = match store_path() {
        Some(p) => p,
        None => return Ok(()),
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let pretty = serde_json::to_string_pretty(store).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    std::fs::write(&path, pretty)
}

/// Result of [`apply_profile`].
///
/// Returned instead of a bare `()` so the UI can surface per-mod outcomes
/// (some succeeded, some failed) without losing the partial-success
/// information that a single `Result<(), io::Error>` would erase.
pub struct ApplyReport {
    pub deployed: Vec<DeployedEntry>,
    pub skipped: Vec<SkippedEntry>,
    pub restore_failed: Option<String>,
}

/// One mod that successfully deployed during [`apply_profile`].
///
/// Fields are part of the public API surface so callers (today the library
/// panel renders only the count; tomorrow a "deploy log" view may render
/// each row) can introspect what landed where without re-deriving from
/// the active profile.
#[allow(dead_code)]
#[derive(Clone)]
pub struct DeployedEntry {
    pub mod_path: PathBuf,
    pub overlay_group: String,
    pub table: String,
}

#[derive(Clone)]
pub struct SkippedEntry {
    pub mod_path: PathBuf,
    pub reason: String,
}

/// Apply a profile to the game.
///
/// Steps:
/// 1. Restore the standard workbench overlay slots (`0058`..`0058 + N`) so
///    we start from a known-clean baseline. We restore *exactly* the slots
///    we intend to write to so we never blow away a foreign overlay group
///    a user might be hand-managing outside the workbench.
/// 2. For each mod in `profile.active_mods`, parse it, identify its target
///    table, run [`crate::deploy::deploy`] against an overlay group derived
///    from its rank.
///
/// Priority handling:
/// - The *first* entry in `active_mods` should win on conflict. PAPGT
///   lookups return later entries first, so we deploy in **reverse** order
///   so the highest-priority mod ends up last in PAPGT.
///
/// Mod loading:
/// - We invoke [`dmm_parser_rust_only::parse_table_from_pabgb`] on the
///   game's vanilla pabgb (extracted from group `0008`), apply the mod's
///   field overrides, and ship the modified entries through the normal
///   deploy path. This is the same pipeline the editor uses, just driven
///   by a JSON instead of a tab.
///
/// Failure policy:
/// - Per-mod failures are recorded in [`ApplyReport::skipped`] and the
///   apply continues. The user gets a UI summary at the end so a single
///   broken mod doesn't kill the whole profile.
pub fn apply_profile(
    profile: &Profile,
    game_dir: &Path,
    tables: &[TableMeta],
) -> std::io::Result<ApplyReport> {
    let mut report = ApplyReport {
        deployed: Vec::new(),
        skipped: Vec::new(),
        restore_failed: None,
    };

    // Step 1 — clean baseline. We restore every slot we might write to so
    // the profile's deploy starts from vanilla for our managed groups.
    // Slots beyond the highest-numbered mod are left untouched so a
    // user with hand-managed overlays elsewhere isn't surprised.
    let max_slot = profile.active_mods.len();
    for i in 0..max_slot {
        let group = overlay_group_for_rank(i);
        if let Err(e) = restore::restore(game_dir, &group) {
            // Don't bail — a single dirty slot shouldn't block the whole
            // profile. We surface it so the user can investigate.
            report.restore_failed = Some(format!("{}: {}", group, e));
        }
    }

    if profile.active_mods.is_empty() {
        return Ok(report);
    }

    // Step 2 — deploy in reverse priority order. The *last* entry in
    // active_mods is the lowest-priority mod, so it goes first (lowest
    // PAPGT precedence); the first entry (highest priority) goes last so
    // PAPGT lookup picks it up first.
    let total = profile.active_mods.len();
    for (i, mod_path) in profile.active_mods.iter().enumerate().rev() {
        // Rank-from-front (0 = highest priority) → group number. We invert
        // so the highest-priority mod gets the *highest* group number,
        // landing it last in PAPGT.
        let rank = total - 1 - i;
        let overlay_group = overlay_group_for_rank(rank);
        match deploy_one_mod(game_dir, mod_path, &overlay_group, tables) {
            Ok(table) => report.deployed.push(DeployedEntry {
                mod_path: mod_path.clone(),
                overlay_group,
                table,
            }),
            Err(e) => report.skipped.push(SkippedEntry {
                mod_path: mod_path.clone(),
                reason: e.to_string(),
            }),
        }
    }

    Ok(report)
}

/// Map a rank in `active_mods` to an overlay group string.
///
/// Group 0 ⇒ `"0058"`, 1 ⇒ `"0059"`, … We zero-pad to 4 digits because the
/// PAPGT entry encoding fixes the group name to that width — cf.
/// [`crate::deploy::deploy`] which writes `"0058"` for the editor.
pub fn overlay_group_for_rank(rank: usize) -> String {
    format!("{:04}", 58 + rank)
}

/// Apply one mod's field overrides to vanilla and deploy it.
///
/// Returns the dispatch name of the table that was deployed so the caller
/// can record it in the [`ApplyReport`].
fn deploy_one_mod(
    game_dir: &Path,
    mod_path: &Path,
    overlay_group: &str,
    tables: &[TableMeta],
) -> std::io::Result<String> {
    // We deliberately don't use `crate::conflict::load_mod` here because
    // that flattens the file shape down to a generic change map, which
    // loses the per-format details we need (single-target table name,
    // which `key`s map to which fields). We re-parse the JSON directly so
    // the apply path can pick the right pabgb file and patch it.
    let raw = std::fs::read_to_string(mod_path)?;
    let root: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: JSON parse error: {}", mod_path.display(), e),
        )
    })?;

    // v1: only crimson_field_json_v3 is supported by the auto-apply path.
    // DMM v3 intents are parsed by the conflict viewer but require the
    // editor's full re-serialization pipeline to deploy correctly.
    let format = root.get("format").and_then(|v| v.as_str()).unwrap_or("");
    if format != "crimson_field_json_v3" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: only crimson_field_json_v3 is auto-deployable; got format={:?}",
                mod_path.display(),
                root.get("format").cloned().unwrap_or(serde_json::Value::Null),
            ),
        ));
    }

    let table_name = root
        .get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: missing 'table' field", mod_path.display()),
            )
        })?
        .to_string();

    let meta = tables
        .iter()
        .find(|m| m.dispatch_name == table_name)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{}: unknown table '{}' (not in registry)",
                    mod_path.display(),
                    table_name
                ),
            )
        })?
        .clone();

    // Pull the vanilla entries out of group 0008 via the same path the
    // editor uses so dispatch / pabgh handling matches table-by-table.
    // We always read from 0008 (vanilla), independent of any overlays our
    // current apply pass might already have deployed, so each mod patches
    // a clean baseline.
    let mut entries = table_loader::load_table(game_dir, &meta)?;

    // Apply the mod's field overrides via the existing import path so the
    // patch logic stays consistent with the editor's "Import Mod..." action.
    crate::mod_io::import_mod(&root, &mut entries).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;

    deploy::deploy(game_dir, &meta.dispatch_name, &meta, &entries, overlay_group)?;
    Ok(meta.dispatch_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_unique_dedupes_names() {
        let mut store = ProfileStore::default();
        let n1 = store.add_unique("Vanilla++");
        let n2 = store.add_unique("Vanilla++");
        let n3 = store.add_unique("Vanilla++");
        assert_eq!(n1, "Vanilla++");
        assert_eq!(n2, "Vanilla++_1");
        assert_eq!(n3, "Vanilla++_2");
        assert_eq!(store.profiles.len(), 3);
    }

    #[test]
    fn remove_clears_active_pointer() {
        let mut store = ProfileStore::default();
        store.add_unique("A");
        store.active_profile = Some("A".to_string());
        assert!(store.remove("A"));
        assert_eq!(store.active_profile, None);
    }

    #[test]
    fn rename_follows_active() {
        let mut store = ProfileStore::default();
        store.add_unique("A");
        store.active_profile = Some("A".to_string());
        assert!(store.rename("A", "B"));
        assert_eq!(store.active_profile.as_deref(), Some("B"));
    }

    #[test]
    fn rename_rejects_collision() {
        let mut store = ProfileStore::default();
        store.add_unique("A");
        store.add_unique("B");
        assert!(!store.rename("A", "B"));
        // A still exists.
        assert!(store.get("A").is_some());
    }

    #[test]
    fn overlay_group_for_rank_is_zero_padded() {
        assert_eq!(overlay_group_for_rank(0), "0058");
        assert_eq!(overlay_group_for_rank(1), "0059");
        assert_eq!(overlay_group_for_rank(10), "0068");
    }

    #[test]
    fn store_round_trips_through_json() {
        let mut store = ProfileStore::default();
        store.add_unique("Vanilla++");
        store.profiles[0]
            .active_mods
            .push(PathBuf::from("foo/bar.json"));
        store.active_profile = Some("Vanilla++".to_string());
        let raw = serde_json::to_string(&store).unwrap();
        let back: ProfileStore = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.profiles.len(), 1);
        assert_eq!(back.profiles[0].name, "Vanilla++");
        assert_eq!(back.profiles[0].active_mods.len(), 1);
        assert_eq!(back.active_profile.as_deref(), Some("Vanilla++"));
    }
}
