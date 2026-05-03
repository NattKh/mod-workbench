//! Game data catalog.
//!
//! Loads the `game_map_complete_v4.json` (~29 MB) produced by the research
//! pipeline and exposes:
//!
//! - **Sections** of typed entries (`items`, `skills`, `knowledge`, ...).
//!   Each section is a `HashMap<String, serde_json::Value>` so all fields of
//!   each entry are preserved as-is.
//! - **Cross-table links** (`Vec<Link>`) plus inverse indexes for fast
//!   outgoing / incoming lookups by `(section_name, key)`.
//! - **String tables** (`strings`, `localstrings`) for hash-to-string lookup.
//! - A **`dispatch_to_section`** map that translates dmm-parser-rust-only's
//!   snake_case dispatch names (e.g. `gimmick_info`) into catalog section
//!   names (e.g. `gimmickgroups`). Built explicitly + heuristically.
//!
//! Loading is fully synchronous today (~1-2 s on a release build); async /
//! cached binary form is left for a later sprint (see ROADMAP 1.3).
//!
//! Lookups never panic — missing keys / missing sections return `None` /
//! empty slices.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Top-level catalog.
///
/// `sections` is keyed by *catalog* section name (e.g. `"items"`, not
/// `"item_info"`). Use [`Catalog::lookup_name_for_dispatch`] when you have a
/// dmm-parser-rust-only dispatch name.
#[derive(Default)]
pub struct Catalog {
    /// Map: section_name -> (key -> entry).
    /// Section names: "items", "skills", "knowledge", "quests", etc.
    /// Each entry is a `serde_json::Value` so all fields are preserved.
    pub sections: HashMap<String, HashMap<String, serde_json::Value>>,

    /// All cross-table links from the `links` array.
    pub links: Vec<Link>,

    /// Raw string lookup (key -> value). May be empty in some catalog builds
    /// where the actual string text wasn't joined back in.
    pub strings: HashMap<String, String>,

    /// PALOC localized strings (key -> English value). May be empty in some
    /// catalog builds.
    pub localstrings: HashMap<String, String>,

    /// Map: dispatch_table_name -> catalog_section_name.
    /// e.g. `"gimmick_group_info"` -> `"gimmickgroups"`.
    /// Built by combining explicit overrides with a heuristic fallback.
    pub dispatch_to_section: HashMap<String, String>,

    /// Inverse index: (section_name, key) -> indices into [`Self::links`]
    /// for outgoing edges (links whose `from` is this entry).
    pub outgoing: HashMap<(String, String), Vec<usize>>,

    /// Inverse index: (section_name, key) -> indices into [`Self::links`]
    /// for incoming edges (links whose `to` is this entry).
    pub incoming: HashMap<(String, String), Vec<usize>>,
}

/// One cross-table link (e.g. `knowledge:40001` --unlocks_skill--> `skill:1025`).
#[derive(Clone, Debug, Deserialize)]
pub struct Link {
    /// Source endpoint, formatted `"section:key"`.
    pub from: String,
    /// Target endpoint, formatted `"section:key"`.
    pub to: String,
    /// Edge label (e.g. `"unlocks_skill"`, `"drops_item"`).
    #[serde(rename = "type")]
    pub link_type: String,
}

impl Catalog {
    /// Load and fully parse the catalog from `path`. Builds all inverse
    /// indexes before returning.
    ///
    /// On a release build of mod-workbench this takes ~1-2 s for the
    /// production v4 JSON. On debug builds expect 5-10 s.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        // Parse the entire JSON into a single Value. This is the simplest
        // approach and avoids writing 100+ struct definitions for every
        // metadata key. The catalog is dict-of-dicts, so memory footprint
        // is roughly equivalent to the on-disk size.
        let root: serde_json::Value = serde_json::from_reader(reader).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("catalog json parse: {}", e),
            )
        })?;

        let root_obj = root.as_object().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "catalog root is not a JSON object",
            )
        })?;

        // ---- 1) Sections --------------------------------------------------
        // A "section" is any top-level dict whose values are dicts containing
        // both a `key` and a `type` field. This filters out metadata blobs
        // like `pa_classes_all`, `_v4_metadata`, etc.
        let mut sections: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();
        for (top_name, top_val) in root_obj {
            let Some(obj) = top_val.as_object() else { continue };
            if obj.is_empty() {
                continue;
            }

            // Sample the first entry to detect a real section.
            let Some((_, first_val)) = obj.iter().next() else { continue };
            let Some(first_obj) = first_val.as_object() else { continue };
            if !first_obj.contains_key("key") || !first_obj.contains_key("type") {
                continue;
            }

            let mut section_map = HashMap::with_capacity(obj.len());
            for (k, v) in obj {
                section_map.insert(k.clone(), v.clone());
            }
            sections.insert(top_name.clone(), section_map);
        }

        // ---- 2) Links -----------------------------------------------------
        let links: Vec<Link> = match root_obj.get("links") {
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| serde_json::from_value::<Link>(v.clone()).ok())
                .collect(),
            _ => Vec::new(),
        };

        // ---- 3) Strings / localstrings -----------------------------------
        // Each entry in the v4 catalog is `{key, name, type}`. We extract the
        // `name` field as the string value. In some catalog builds the names
        // are empty placeholders — that's fine, lookups will just return "".
        let strings = extract_string_section(root_obj, "strings");
        let localstrings = extract_string_section(root_obj, "localstrings");

        // ---- 4) dispatch_to_section --------------------------------------
        let dispatch_to_section = build_dispatch_to_section(&sections);

        // ---- 5) outgoing / incoming indexes ------------------------------
        let mut outgoing: HashMap<(String, String), Vec<usize>> = HashMap::new();
        let mut incoming: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for (idx, link) in links.iter().enumerate() {
            if let Some((sec, key)) = split_endpoint(&link.from) {
                outgoing.entry((sec, key)).or_default().push(idx);
            }
            if let Some((sec, key)) = split_endpoint(&link.to) {
                incoming.entry((sec, key)).or_default().push(idx);
            }
        }

        Ok(Self {
            sections,
            links,
            strings,
            localstrings,
            dispatch_to_section,
            outgoing,
            incoming,
        })
    }

    /// Resolve a key in `section` to its `name`.
    ///
    /// Example: `lookup_name("items", 2200) -> Some("Pyeonjeon_Arrow")`.
    pub fn lookup_name(&self, section: &str, key: u64) -> Option<&str> {
        let entries = self.sections.get(section)?;
        let key_str = key.to_string();
        let entry = entries.get(&key_str)?;
        entry.get("name")?.as_str()
    }

    /// Resolve via a dmm-parser-rust-only dispatch name (e.g. `"gimmick_info"`)
    /// rather than a catalog section name.
    pub fn lookup_name_for_dispatch(&self, dispatch_name: &str, key: u64) -> Option<&str> {
        let section = self.dispatch_to_section.get(dispatch_name)?;
        self.lookup_name(section, key)
    }

    /// Resolve a 32-bit string hash to its English string via PALOC
    /// (`localstrings`). Falls back to the raw `strings` table if missing.
    pub fn lookup_string(&self, hash: u32) -> Option<&str> {
        let key = hash.to_string();
        if let Some(s) = self.localstrings.get(&key) {
            if !s.is_empty() {
                return Some(s.as_str());
            }
        }
        let s = self.strings.get(&key)?;
        Some(s.as_str())
    }

    /// All outgoing links from `(section, key)`. Empty if none.
    pub fn outgoing_links(&self, section: &str, key: u64) -> Vec<&Link> {
        let lookup = (section.to_string(), key.to_string());
        match self.outgoing.get(&lookup) {
            Some(idxs) => idxs.iter().filter_map(|&i| self.links.get(i)).collect(),
            None => Vec::new(),
        }
    }

    /// All incoming links to `(section, key)`. Empty if none.
    pub fn incoming_links(&self, section: &str, key: u64) -> Vec<&Link> {
        let lookup = (section.to_string(), key.to_string());
        match self.incoming.get(&lookup) {
            Some(idxs) => idxs.iter().filter_map(|&i| self.links.get(i)).collect(),
            None => Vec::new(),
        }
    }

    /// Total entry count across every section. Useful for status reporting.
    pub fn total_entries(&self) -> usize {
        self.sections.values().map(|m| m.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a `{key -> string}` map from a section whose values look like
/// `{"key": ..., "name": "...", "type": "..."}`. Used for `strings` and
/// `localstrings`.
fn extract_string_section(
    root: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> HashMap<String, String> {
    let Some(obj) = root.get(name).and_then(|v| v.as_object()) else {
        return HashMap::new();
    };
    let mut out = HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        let s = v
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        out.insert(k.clone(), s);
    }
    out
}

/// Split a `"section:key"` endpoint into its parts.
fn split_endpoint(s: &str) -> Option<(String, String)> {
    let mut it = s.splitn(2, ':');
    let sec = it.next()?.to_string();
    let key = it.next()?.to_string();
    if sec.is_empty() || key.is_empty() {
        return None;
    }
    Some((sec, key))
}

/// Build the dispatch-name -> catalog-section mapping.
///
/// Strategy:
/// 1. Apply explicit overrides for known mismatches (catalog uses
///    `gimmickgroups`, dispatch uses `gimmick_group_info`, etc.).
/// 2. For the rest, drop the trailing `_info`, strip underscores, and append
///    `s` for the heuristic. If that name doesn't exist in the catalog, try
///    without the trailing `s`. If neither matches, fall through with the
///    heuristic name (lookups will simply miss — fine, avoids surprises).
fn build_dispatch_to_section(
    sections: &HashMap<String, HashMap<String, serde_json::Value>>,
) -> HashMap<String, String> {
    // Known dispatch names that diverge from the simple heuristic. Listed in
    // the task spec plus a few obvious ones inferred from the catalog.
    let explicit: &[(&str, &str)] = &[
        ("gimmick_info", "gimmicks"),
        ("store_info", "stores"),
        ("skill_info", "skills"),
        ("buff_info", "buffs"),
        ("npc_info", "npcs"),
        ("quest_info", "quests"),
        ("mission_info", "missions"),
        ("knowledge_info", "knowledge"),
        ("character_info", "characters"),
        ("condition_info", "conditions"),
        ("drop_set_info", "drop_sets"),
        ("equip_type_info", "equiptypes"),
        ("faction_info", "factions"),
        ("faction_node_info", "factionnodes"),
        ("faction_group_info", "factiongroups"),
        ("faction_relation_group_info", "factionrelationgroups"),
        ("faction_spawn_data_info", "factionspawndatas"),
        ("faction_waypoint_info", "factionwaypoints"),
        ("gimmick_group_info", "gimmickgroups"),
        ("gimmick_gate_info", "gimmickgates"),
        ("gimmick_gate_connection_info", "gimmickgateconnections"),
        ("mercenary_info", "mercenarys"),
        ("region_info", "regions"),
        ("sub_level_info", "sublevels"),
        ("item_use_info", "itemuses"),
        // Inferred from catalog inspection (sections that didn't match the
        // straight heuristic):
        ("character_appearance_index_info", "characterappearanceindexes"),
        ("character_group_info", "char_groups"),
        ("knowledge_group_info", "knowledge_groups"),
        ("skill_group_info", "skill_groups"),
        ("skill_tree_info", "skill_trees"),
        ("field_revive_info", "reviepoints"),
        ("game_level_info", "levels"),
        ("platform_entitlement_info", "entitlements"),
        ("key_map_setting_list_info", "keymaps"),
        // No item_info dispatch exists today, but if one is added later
        // it should resolve to the `items` section.
        ("item_info", "items"),
    ];

    let mut map = HashMap::new();
    for (d, s) in explicit {
        map.insert((*d).to_string(), (*s).to_string());
    }

    // Heuristic fallback for any dispatch we know about via the registry.
    // We don't have the dispatch list in scope here — the caller doesn't
    // pass it in either — so we just enumerate dispatch names lazily at
    // lookup time. But to make `dispatch_to_section` complete for all known
    // dispatches now, we pull the list from the parser crate.
    for &name in dmm_parser_rust_only::supported_tables() {
        if map.contains_key(name) {
            continue;
        }
        let candidate = heuristic_section_name(name);
        // Prefer the exact heuristic match; fall back to "no trailing s"
        // (e.g. `status_info` -> `status`) if needed.
        let resolved = if sections.contains_key(&candidate) {
            candidate
        } else if candidate.ends_with('s') {
            let trimmed = candidate.trim_end_matches('s').to_string();
            if sections.contains_key(&trimmed) {
                trimmed
            } else {
                candidate
            }
        } else {
            candidate
        };
        map.insert(name.to_string(), resolved);
    }

    map
}

/// Heuristic: drop trailing `_info`, strip remaining underscores, append `s`.
/// `gimmick_event_table_info` -> `gimmickeventtables`.
fn heuristic_section_name(dispatch_name: &str) -> String {
    let stripped = dispatch_name.strip_suffix("_info").unwrap_or(dispatch_name);
    let stripped = stripped.replace('_', "");
    format!("{}s", stripped)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_basic() {
        assert_eq!(heuristic_section_name("buff_info"), "buffs");
        assert_eq!(heuristic_section_name("gimmick_event_table_info"), "gimmickeventtables");
        assert_eq!(heuristic_section_name("category_info"), "categorys");
    }

    #[test]
    fn split_endpoint_basic() {
        assert_eq!(
            split_endpoint("knowledge:40001"),
            Some(("knowledge".to_string(), "40001".to_string()))
        );
        assert_eq!(split_endpoint("malformed"), None);
        assert_eq!(split_endpoint(":42"), None);
        assert_eq!(split_endpoint("section:"), None);
    }

    #[test]
    fn empty_catalog_lookups_are_safe() {
        let cat = Catalog::default();
        assert_eq!(cat.lookup_name("items", 2200), None);
        assert_eq!(cat.lookup_string(0xDEAD_BEEF), None);
        assert!(cat.outgoing_links("items", 1).is_empty());
        assert!(cat.incoming_links("items", 1).is_empty());
        assert_eq!(cat.total_entries(), 0);
    }

    /// Smoke test that loads the real production catalog. Skipped unless
    /// the file is reachable on disk so this doesn't break clean checkouts.
    #[test]
    fn smoke_real_catalog() {
        let path = std::path::PathBuf::from(
            r"C:\Users\Coding\CrimsonDesertModding\ResearchFolder\game_map_complete_v4.json",
        );
        if !path.exists() {
            eprintln!("smoke_real_catalog: skipped (no catalog at {})", path.display());
            return;
        }
        let cat = Catalog::load(&path).expect("catalog load");
        // Spot checks against documented entries.
        assert_eq!(cat.lookup_name("items", 2200), Some("Pyeonjeon_Arrow"));
        // Dispatch resolution: knowledge_info routes to the `knowledge` section.
        assert!(cat
            .lookup_name_for_dispatch("knowledge_info", 40001)
            .is_some());
        // Cross-ref index has at least the documented link count (+/- catalog churn).
        assert!(cat.links.len() >= 1000, "expected many links, got {}", cat.links.len());
        // Outgoing/incoming indexes are populated.
        assert!(!cat.outgoing.is_empty());
        assert!(!cat.incoming.is_empty());
    }
}
