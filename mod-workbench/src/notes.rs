//! Per-entry user notes / annotations.
//!
//! [`NoteStore`] keeps a flat string-keyed map of user-authored text notes
//! attached to a specific (table, entry_key) pair. Notes are intentionally
//! free-form — they exist purely to let modders leave themselves (or
//! downstream consumers) reminders of *why* a particular entry was changed,
//! what range of values is safe, links to research docs, etc.
//!
//! The store is travel-ready: notes are embedded under `_notes` in the v3
//! field-JSON export and round-tripped on import, so a mod author can ship
//! their reasoning alongside the actual data overrides without needing a
//! companion document.
//!
//! ## Storage shape
//!
//! Notes are keyed by a synthesised `"<table>:<entry_key>"` string. The
//! flat-map shape (rather than a `HashMap<(String, u64), String>`) is
//! deliberate: `serde_json` cannot serialise tuples as object keys, and the
//! flat string form survives round-tripping through any JSON pipeline
//! without bespoke (de)serialisers.
//!
//! Empty notes are removed on `set` to avoid silently growing the store
//! with whitespace as users tab through entries.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Map: `"<table>:<entry_key>"` -> note text.
///
/// Embedded in v3 field JSON exports under `_notes`. See [`Self::get`] /
/// [`Self::set`] for the typed accessors callers should prefer over poking
/// at the inner [`HashMap`] directly.
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct NoteStore {
    /// Map: `"<table>:<entry_key>"` -> note text.
    pub notes: HashMap<String, String>,
}

impl NoteStore {
    /// Build the composite map key. Pulled out so callers can't mis-format
    /// the separator (e.g. dropping the colon would silently shadow other
    /// tables' notes).
    fn make_key(table: &str, entry_key: u64) -> String {
        format!("{}:{}", table, entry_key)
    }

    /// Fetch the note text for a given (table, entry_key), if any.
    ///
    /// Returns `None` when the entry has no note attached. Empty strings are
    /// never stored — callers don't need to distinguish "empty" from
    /// "missing".
    pub fn get(&self, table: &str, entry_key: u64) -> Option<&str> {
        self.notes
            .get(&Self::make_key(table, entry_key))
            .map(|s| s.as_str())
    }

    /// Store (or replace) the note for the given (table, entry_key).
    ///
    /// Empty / whitespace-only notes are removed instead of stored — this
    /// keeps the store tight when users delete a note they no longer need
    /// without forcing them to navigate elsewhere first.
    pub fn set(&mut self, table: &str, entry_key: u64, note: String) {
        let key = Self::make_key(table, entry_key);
        if note.trim().is_empty() {
            self.notes.remove(&key);
        } else {
            self.notes.insert(key, note);
        }
    }

    /// Drop the note for the given (table, entry_key). No-op when no note
    /// exists at that location.
    pub fn remove(&mut self, table: &str, entry_key: u64) {
        self.notes.remove(&Self::make_key(table, entry_key));
    }

    /// Iterate over notes that belong to `table`. Yields
    /// `(entry_key, note_text)` pairs. Keys whose composite form doesn't
    /// parse cleanly are skipped — those would be data shipped from a
    /// future workbench version that we don't recognise yet.
    pub fn iter_table<'a>(
        &'a self,
        table: &'a str,
    ) -> impl Iterator<Item = (u64, &'a str)> + 'a {
        let prefix = format!("{}:", table);
        self.notes.iter().filter_map(move |(k, v)| {
            let rest = k.strip_prefix(&prefix)?;
            let key = rest.parse::<u64>().ok()?;
            Some((key, v.as_str()))
        })
    }

    /// Total number of notes across all tables. Used by the UI to show a
    /// quick "{n} notes" summary without iterating.
    pub fn len(&self) -> usize {
        self.notes.len()
    }

    /// True when no notes exist anywhere.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get_roundtrips() {
        let mut s = NoteStore::default();
        s.set("iteminfo", 42, "watch out for stack of 0".into());
        assert_eq!(s.get("iteminfo", 42), Some("watch out for stack of 0"));
        assert_eq!(s.get("iteminfo", 43), None);
        assert_eq!(s.get("buffinfo", 42), None);
    }

    #[test]
    fn empty_note_is_removed() {
        let mut s = NoteStore::default();
        s.set("t", 1, "real note".into());
        assert_eq!(s.len(), 1);
        s.set("t", 1, "   ".into());
        assert_eq!(s.len(), 0);
        assert_eq!(s.get("t", 1), None);
    }

    #[test]
    fn remove_is_noop_for_missing() {
        let mut s = NoteStore::default();
        s.remove("t", 7);
        assert!(s.is_empty());
        s.set("t", 7, "x".into());
        s.remove("t", 7);
        assert!(s.is_empty());
    }

    #[test]
    fn iter_table_filters_to_table() {
        let mut s = NoteStore::default();
        s.set("a", 1, "alpha".into());
        s.set("a", 2, "beta".into());
        s.set("b", 1, "gamma".into());
        let mut got: Vec<(u64, &str)> = s.iter_table("a").collect();
        got.sort_by_key(|(k, _)| *k);
        assert_eq!(got, vec![(1u64, "alpha"), (2u64, "beta")]);
    }

    #[test]
    fn serde_roundtrip() {
        let mut s = NoteStore::default();
        s.set("t", 1, "hello".into());
        s.set("t", 2, "world".into());
        let json = serde_json::to_string(&s).unwrap();
        let back: NoteStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get("t", 1), Some("hello"));
        assert_eq!(back.get("t", 2), Some("world"));
    }
}
