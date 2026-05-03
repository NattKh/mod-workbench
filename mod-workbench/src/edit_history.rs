//! Undo/redo history for field edits.
//!
//! Every mutation of a field flows through [`EditHistory::record`]. The history
//! holds an ordered `Vec<EditOp>`; `undo_pos` separates "applied" ops (everything
//! before the index) from "redoable" ops (everything from the index onward).
//!
//! - `undo()` returns the op at `undo_pos - 1` and decrements the cursor; the
//!   caller is responsible for reverting the entry to `op.old_value`.
//! - `redo()` returns the op at `undo_pos` and increments the cursor; the
//!   caller applies `op.new_value`.
//! - Recording a brand new op truncates anything after `undo_pos` (the
//!   redoable tail), since we can't keep a divergent timeline.
//!
//! Field paths use the same dot-and-bracket notation that the field panel
//! already produces — e.g. `foo.bar`, `_buff_list[3].buff_key`. The
//! [`set_at_path`] / [`get_at_path`] helpers walk that notation against a
//! `serde_json::Value`.
//!
//! The history runs alongside the existing change tracker — the tracker stays
//! the source of truth for export, while the history powers the undo UI.

use std::time::Instant;

use serde_json::Value;

#[derive(Clone)]
pub struct EditOp {
    /// Active table dispatch name at the time of the edit.
    pub table: String,
    /// Numeric entry key extracted via `mod_io::extract_entry_key`.
    pub entry_key: u64,
    /// Dot-and-bracket path within the entry, e.g. `foo.bar` or `list[3].x`.
    pub field_path: String,
    /// Value before the edit. Used by `undo`.
    pub old_value: Value,
    /// Value after the edit. Used by `redo`.
    pub new_value: Value,
    /// When the edit happened. Rendered as relative time in the history panel.
    pub timestamp: Instant,
}

#[derive(Default)]
pub struct EditHistory {
    /// All ops in order. Indexes `[..undo_pos]` are currently applied;
    /// `[undo_pos..]` are redoable (i.e. we've undone them).
    ops: Vec<EditOp>,
    /// Cursor: number of ops currently applied. `0` means everything is
    /// undone, `ops.len()` means everything is applied.
    undo_pos: usize,
}

impl EditHistory {
    /// Record a brand-new edit. Truncates any redoable ops past the current
    /// position, since recording diverges from the previously redoable future.
    pub fn record(&mut self, op: EditOp) {
        // Drop any redoable tail — once the user makes a fresh edit after
        // undoing, the redo history is no longer reachable.
        self.ops.truncate(self.undo_pos);
        self.ops.push(op);
        self.undo_pos = self.ops.len();
    }

    pub fn can_undo(&self) -> bool {
        self.undo_pos > 0
    }

    pub fn can_redo(&self) -> bool {
        self.undo_pos < self.ops.len()
    }

    /// Step the cursor back by one and return a borrow of the op the caller
    /// must invert. Returns `None` when there's nothing to undo.
    pub fn undo(&mut self) -> Option<&EditOp> {
        if !self.can_undo() {
            return None;
        }
        self.undo_pos -= 1;
        self.ops.get(self.undo_pos)
    }

    /// Step the cursor forward by one and return a borrow of the op the
    /// caller must reapply. Returns `None` when there's nothing to redo.
    pub fn redo(&mut self) -> Option<&EditOp> {
        if !self.can_redo() {
            return None;
        }
        let op = self.ops.get(self.undo_pos);
        self.undo_pos += 1;
        op
    }

    pub fn ops(&self) -> &[EditOp] {
        &self.ops
    }

    /// Number of ops currently applied (== the redo cursor).
    pub fn current_position(&self) -> usize {
        self.undo_pos
    }

    /// Set the cursor directly. Caller is responsible for applying any
    /// intermediate ops — this only moves the marker. Clamped to a valid
    /// range.
    pub fn jump_to(&mut self, pos: usize) {
        self.undo_pos = pos.min(self.ops.len());
    }

    pub fn clear(&mut self) {
        self.ops.clear();
        self.undo_pos = 0;
    }
}

/// Get a borrowed reference to the value at `path` inside `entry`.
///
/// Path syntax matches what the field panel produces: dot-separated object
/// keys with optional bracketed array indices, e.g. `foo.bar[3].baz`. Returns
/// `None` if any segment misses (wrong type, missing key, or out-of-range
/// index).
pub fn get_at_path<'a>(entry: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = entry;
    for segment in PathParser::new(path) {
        current = match (segment, current) {
            (PathSegment::Field(name), Value::Object(map)) => map.get(&name)?,
            (PathSegment::Index(i), Value::Array(arr)) => arr.get(i)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Set `entry`'s value at `path` to `value`.
///
/// Returns `true` when the path resolved end-to-end and the value was written;
/// `false` if any intermediate segment was missing or had the wrong shape.
/// Existing values at the leaf are replaced.
pub fn set_at_path(entry: &mut Value, path: &str, value: Value) -> bool {
    let segments: Vec<PathSegment> = PathParser::new(path).collect();
    if segments.is_empty() {
        return false;
    }
    set_recursive(entry, &segments, value)
}

fn set_recursive(current: &mut Value, segments: &[PathSegment], value: Value) -> bool {
    let (head, tail) = match segments.split_first() {
        Some(pair) => pair,
        None => return false,
    };
    match (head, current) {
        (PathSegment::Field(name), Value::Object(map)) => {
            if tail.is_empty() {
                map.insert(name.clone(), value);
                true
            } else {
                match map.get_mut(name) {
                    Some(child) => set_recursive(child, tail, value),
                    None => false,
                }
            }
        }
        (PathSegment::Index(i), Value::Array(arr)) => {
            if *i >= arr.len() {
                return false;
            }
            if tail.is_empty() {
                arr[*i] = value;
                true
            } else {
                set_recursive(&mut arr[*i], tail, value)
            }
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Field(String),
    Index(usize),
}

/// Iterator that splits `foo.bar[3].baz` into [Field("foo"), Field("bar"),
/// Index(3), Field("baz")]. Tolerant of malformed input — bad segments simply
/// terminate the iterator (callers will see a `None`/`false` resolution and
/// fall through cleanly).
struct PathParser<'a> {
    rest: &'a str,
    /// True after we just returned a `Field`. The next iteration may either
    /// see `.` (consume and parse another field), `[` (parse an index without
    /// a separator), or end of input.
    pending_separator: bool,
}

impl<'a> PathParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            rest: s,
            pending_separator: false,
        }
    }
}

impl<'a> Iterator for PathParser<'a> {
    type Item = PathSegment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }

        // After a previous segment we may need to consume a `.` separator.
        // A `[` doesn't need one — `foo[3]` chains directly.
        if self.pending_separator {
            if let Some(rest) = self.rest.strip_prefix('.') {
                self.rest = rest;
            }
            self.pending_separator = false;
        }

        if let Some(rest) = self.rest.strip_prefix('[') {
            // Parse `<digits>]`.
            let close = rest.find(']')?;
            let num_str = &rest[..close];
            let idx: usize = num_str.parse().ok()?;
            self.rest = &rest[close + 1..];
            self.pending_separator = true;
            return Some(PathSegment::Index(idx));
        }

        // Field name runs until the next `.` or `[`.
        let end = self
            .rest
            .find(|c: char| c == '.' || c == '[')
            .unwrap_or(self.rest.len());
        if end == 0 {
            // Empty segment — stop cleanly.
            return None;
        }
        let name = self.rest[..end].to_string();
        self.rest = &self.rest[end..];
        self.pending_separator = true;
        Some(PathSegment::Field(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(path: &str, old: Value, new: Value) -> EditOp {
        EditOp {
            table: "test".to_string(),
            entry_key: 1,
            field_path: path.to_string(),
            old_value: old,
            new_value: new,
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn path_parser_splits_dotted_and_indexed() {
        let segs: Vec<PathSegment> = PathParser::new("foo.bar[3].baz").collect();
        assert_eq!(
            segs,
            vec![
                PathSegment::Field("foo".to_string()),
                PathSegment::Field("bar".to_string()),
                PathSegment::Index(3),
                PathSegment::Field("baz".to_string()),
            ]
        );
    }

    #[test]
    fn path_parser_top_level_field() {
        let segs: Vec<PathSegment> = PathParser::new("hp").collect();
        assert_eq!(segs, vec![PathSegment::Field("hp".to_string())]);
    }

    #[test]
    fn path_parser_top_level_array_index() {
        let segs: Vec<PathSegment> = PathParser::new("list[0]").collect();
        assert_eq!(
            segs,
            vec![PathSegment::Field("list".to_string()), PathSegment::Index(0)]
        );
    }

    #[test]
    fn get_at_path_top_level() {
        let v = json!({"hp": 100});
        assert_eq!(get_at_path(&v, "hp"), Some(&json!(100)));
        assert_eq!(get_at_path(&v, "missing"), None);
    }

    #[test]
    fn get_at_path_nested_and_array() {
        let v = json!({"foo": {"bar": [10, 20, 30]}});
        assert_eq!(get_at_path(&v, "foo.bar[1]"), Some(&json!(20)));
        assert_eq!(get_at_path(&v, "foo.bar[5]"), None);
        assert_eq!(get_at_path(&v, "foo.bar.x"), None);
    }

    #[test]
    fn set_at_path_top_level() {
        let mut v = json!({"hp": 100});
        assert!(set_at_path(&mut v, "hp", json!(200)));
        assert_eq!(v["hp"], json!(200));
    }

    #[test]
    fn set_at_path_creates_top_level_field_when_missing() {
        // Match the existing `obj.insert(name, value)` behavior at the leaf —
        // top-level inserts succeed even when the key is new.
        let mut v = json!({});
        assert!(set_at_path(&mut v, "new_field", json!(7)));
        assert_eq!(v["new_field"], json!(7));
    }

    #[test]
    fn set_at_path_nested() {
        let mut v = json!({"foo": {"bar": 10}});
        assert!(set_at_path(&mut v, "foo.bar", json!(99)));
        assert_eq!(v["foo"]["bar"], json!(99));
    }

    #[test]
    fn set_at_path_array_element() {
        let mut v = json!({"list": [1, 2, 3]});
        assert!(set_at_path(&mut v, "list[1]", json!(20)));
        assert_eq!(v["list"], json!([1, 20, 3]));
    }

    #[test]
    fn set_at_path_fails_on_missing_intermediate() {
        let mut v = json!({"foo": 10});
        // foo isn't an object, so foo.bar can't resolve.
        assert!(!set_at_path(&mut v, "foo.bar", json!(99)));
    }

    #[test]
    fn set_at_path_array_out_of_range() {
        let mut v = json!({"list": [1, 2, 3]});
        assert!(!set_at_path(&mut v, "list[10]", json!(0)));
    }

    #[test]
    fn history_record_and_undo_redo() {
        let mut h = EditHistory::default();
        assert!(!h.can_undo());
        assert!(!h.can_redo());

        h.record(op("hp", json!(50), json!(100)));
        h.record(op("name", json!("a"), json!("b")));
        assert_eq!(h.current_position(), 2);
        assert!(h.can_undo());
        assert!(!h.can_redo());

        let undone = h.undo().cloned().unwrap();
        assert_eq!(undone.field_path, "name");
        assert_eq!(h.current_position(), 1);
        assert!(h.can_redo());

        let redone = h.redo().cloned().unwrap();
        assert_eq!(redone.field_path, "name");
        assert_eq!(h.current_position(), 2);
        assert!(!h.can_redo());
    }

    #[test]
    fn history_record_truncates_redo_tail() {
        let mut h = EditHistory::default();
        h.record(op("a", json!(0), json!(1)));
        h.record(op("b", json!(0), json!(1)));
        h.undo();
        // After undo, position is 1; recording a new op should drop "b" and
        // leave only [a, c].
        h.record(op("c", json!(0), json!(1)));
        assert_eq!(h.ops().len(), 2);
        assert_eq!(h.ops()[1].field_path, "c");
        assert!(!h.can_redo());
    }

    #[test]
    fn history_jump_to_clamps() {
        let mut h = EditHistory::default();
        h.record(op("a", json!(0), json!(1)));
        h.record(op("b", json!(0), json!(1)));
        h.jump_to(99);
        assert_eq!(h.current_position(), 2);
        h.jump_to(0);
        assert_eq!(h.current_position(), 0);
    }

    #[test]
    fn history_clear_resets_state() {
        let mut h = EditHistory::default();
        h.record(op("a", json!(0), json!(1)));
        h.clear();
        assert!(!h.can_undo());
        assert!(!h.can_redo());
        assert_eq!(h.ops().len(), 0);
    }
}
