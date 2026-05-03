//! Validation / lint framework.
//!
//! Catches common modding mistakes *before* deploy — when a hand-edited table
//! reaches the game with a malformed reference or an out-of-range value the
//! result is at best a graphical glitch and at worst an infinite-loading +
//! 50GB-RAM crash. This module wires up:
//!
//! 1. A small data model: [`LintFinding`] (a single issue), [`Severity`]
//!    (Info / Warn / Error — Errors block deploy by default), and
//!    [`AutoFix`] (an optional, applicable repair recorded against the
//!    finding).
//! 2. A trait, [`LintRule`], that lets callers add new checks without
//!    touching this module.
//! 3. A runner, [`LintRunner`], that owns a vector of rules and walks every
//!    entry in a table once per `check_table` call.
//!
//! ## Built-in rules
//!
//! - [`InfiniteLoadingRule`]   — Critical. Blocks the weapon-condition-passive
//!   crash by checking that any item with a weapon-conditional passive
//!   (skills 91101/91102/91104/91105) also has a weapon `equip_type_info`.
//!   Suggests `1086980273` (TwoHandSword) as the safe default fix.
//! - [`MissingDependencyRule`] — Warns when a foreign-key field references
//!   a key that doesn't exist in the catalog's target section. Skipped
//!   cleanly when the catalog isn't loaded.
//! - [`NumericRangeRule`]      — Warns when known-bounded fields go out of
//!   range (e.g. `cooltime` outside 0..=86400).
//!
//! ## Catalog handling
//!
//! Rules that need cross-table data take an `Option<&Catalog>`. When the
//! catalog is missing they should return `vec![]` rather than fabricating
//! findings — that keeps the lint usable on a fresh checkout where the
//! catalog hasn't been loaded yet.

use serde_json::Value;

use crate::catalog::Catalog;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One issue produced by a [`LintRule`].
#[derive(Clone, Debug)]
pub struct LintFinding {
    /// `LintRule::name()` of the rule that produced this finding. Used to
    /// group findings in the panel.
    pub rule_name: String,
    pub severity: Severity,
    /// Dispatch name of the table the entry belongs to (e.g. `"item_info"`).
    pub table: String,
    /// Numeric primary key of the offending entry.
    pub entry_key: u64,
    /// Optional human-readable name (from `name`/`item_name` if present).
    pub entry_name: Option<String>,
    /// Long-form, user-facing message. Should describe the problem *and*
    /// the suggested resolution when an [`AutoFix`] is attached.
    pub message: String,
    /// Optional one-click repair the panel can offer.
    pub fix_suggestion: Option<AutoFix>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    Info,
    Warn,
    /// Blocks deploy by default. The deploy action prompts the user to
    /// confirm before going through anyway.
    Error,
}

impl Severity {
    /// Stable ordering: Error > Warn > Info, used to surface the worst
    /// findings first in the panel.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Error => 0,
            Severity::Warn => 1,
            Severity::Info => 2,
        }
    }
}

/// A repair action that can be applied to fix a finding.
///
/// `field_path` follows the same dot-and-bracket notation used by
/// `edit_history::set_at_path` / `get_at_path` (e.g. `foo.bar`,
/// `equip_passive_skill_list[0].skill`). `Custom` carries a human-readable
/// description for fixes that aren't safely automatable.
///
/// `RemoveField` and `Custom` are part of the public API even when no
/// built-in rule currently emits them — third-party rules and future
/// built-ins will need them, and the lint panel already renders both.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum AutoFix {
    SetField {
        field_path: String,
        new_value: Value,
    },
    RemoveField {
        field_path: String,
    },
    /// Manual fix description. The panel renders this as text and offers no
    /// "apply" button.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Rule trait + runner
// ---------------------------------------------------------------------------

/// A single check that can be run against table entries.
///
/// Implementors should be cheap to construct (the runner stores them in a
/// vector) and stateless across `check` calls — the runner makes no ordering
/// guarantees and may invoke `check` from multiple threads in the future.
pub trait LintRule: Send + Sync {
    /// Stable identifier surfaced in [`LintFinding::rule_name`]. Used to
    /// group findings in the panel and to filter rules in tests.
    fn name(&self) -> &str;
    /// One-line description shown in tooltips / docs. Not parsed by the
    /// runner. The lint panel could surface this in a help tooltip; today
    /// it's used by tests / future docs tooling.
    #[allow(dead_code)]
    fn description(&self) -> &str;
    /// Returns `true` when this rule has anything to say about `table`.
    /// The runner uses this as a quick filter before calling `check`.
    fn applies_to(&self, table: &str) -> bool;
    /// Run the check against a single entry. Returning an empty vec means
    /// "all good". The catalog is `None` when the user hasn't loaded one
    /// yet — rules that depend on it should return `vec![]` in that case.
    fn check(&self, table: &str, entry: &Value, catalog: Option<&Catalog>) -> Vec<LintFinding>;
}

/// Owns the registered rules and runs them over a table's entries.
pub struct LintRunner {
    pub rules: Vec<Box<dyn LintRule>>,
}

impl LintRunner {
    /// Construct an empty runner. Call [`Self::with_default_rules`] to seed
    /// with the built-in lint set.
    ///
    /// Exposed publicly even when not used in-tree — third-party / test
    /// callers occasionally want a clean runner they can populate
    /// themselves.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Build a runner pre-loaded with the production lint set. New built-in
    /// rules should be appended here so the UI picks them up automatically.
    pub fn with_default_rules() -> Self {
        Self {
            rules: vec![
                Box::new(InfiniteLoadingRule),
                Box::new(MissingDependencyRule),
                Box::new(NumericRangeRule),
            ],
        }
    }

    /// Run every applicable rule against every entry in `entries`. Returns
    /// findings sorted by severity (worst first) so the panel can render
    /// straight off the returned vec.
    pub fn check_table(
        &self,
        table: &str,
        entries: &[Value],
        catalog: Option<&Catalog>,
    ) -> Vec<LintFinding> {
        let mut out = Vec::new();
        for rule in &self.rules {
            if !rule.applies_to(table) {
                continue;
            }
            for entry in entries {
                out.extend(rule.check(table, entry, catalog));
            }
        }
        // Sort by severity, then rule name, then entry key for a stable,
        // user-friendly grouping.
        out.sort_by(|a, b| {
            a.severity
                .rank()
                .cmp(&b.severity.rank())
                .then_with(|| a.rule_name.cmp(&b.rule_name))
                .then_with(|| a.entry_key.cmp(&b.entry_key))
        });
        out
    }

    /// Convenience: how many findings of each severity exist in `findings`.
    /// Used by the deploy gating to ask "are there any errors?".
    pub fn count_by_severity(findings: &[LintFinding]) -> (usize, usize, usize) {
        let mut errors = 0;
        let mut warns = 0;
        let mut infos = 0;
        for f in findings {
            match f.severity {
                Severity::Error => errors += 1,
                Severity::Warn => warns += 1,
                Severity::Info => infos += 1,
            }
        }
        (errors, warns, infos)
    }
}

impl Default for LintRunner {
    fn default() -> Self {
        Self::with_default_rules()
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by built-in rules
// ---------------------------------------------------------------------------

/// Pull the entry's primary key as a u64. Mirrors `mod_io::extract_entry_key`
/// but kept private so this module doesn't have a hard dep on `mod_io`'s
/// public surface.
fn entry_key(entry: &Value) -> u64 {
    entry
        .get("key")
        .or_else(|| entry.get("_key"))
        .or_else(|| entry.get("unk_key"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Best-effort human-readable label for `entry`. Tries `item_name.local`
/// (LocalizableString shape from dmm-parser), `name`, `string_key`, then
/// falls back to `None`.
fn entry_display_name(entry: &Value) -> Option<String> {
    // LocalizableString in dmm-parser typically serialises as
    // `{"local": "...", "key": ...}` or similar. Probe a few common shapes.
    if let Some(name) = entry
        .get("item_name")
        .and_then(|v| v.get("local"))
        .and_then(|v| v.as_str())
    {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    if let Some(name) = entry.get("string_key").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rule 1: InfiniteLoadingRule
// ---------------------------------------------------------------------------

/// Skill keys whose behaviour is gated on the wielder having a weapon
/// equipped. If the item carrying one of these passives doesn't have a
/// weapon-class `equip_type_info`, save load loops and balloons RAM until
/// the process is killed.
///
/// See research notes in PROJECT_INFINITE_LOADING_RESEARCH.md.
const WEAPON_CONDITION_PASSIVES: &[u64] = &[91101, 91102, 91104, 91105];

/// EquipType hashes the engine treats as "is a weapon" for the purposes of
/// the weapon-condition passives. Anything outside this set hits the
/// pathological code path.
const WEAPON_HASHES: &[u64] = &[
    1086980073, // TwoHandSword
    2914941932,
    604374103,
    3628286577,
    2327795645,
    1584411264,
    1921528741,
    585399773,
    2594511993,
    3150053877,
    2269940786,
];

/// Safe default `equip_type_info` value used by the auto-fix. TwoHandSword
/// is the most common weapon class in the catalog and causes no further
/// downstream issues.
const SAFE_WEAPON_DEFAULT: u64 = 1086980073;

/// Detects weapon-conditional passives on non-weapon items.
///
/// Defensive: even though `item_info` isn't currently in the dmm-parser
/// dispatch list, we apply this rule to *any* table whose entries expose
/// `equip_passive_skill_list`. Future tables (or external mods that
/// hand-craft entries) should still be caught.
pub struct InfiniteLoadingRule;

impl LintRule for InfiniteLoadingRule {
    fn name(&self) -> &str {
        "infinite_loading"
    }

    fn description(&self) -> &str {
        "Items with weapon-conditional passives (e.g. 91101) must have a weapon equip_type_info, \
         otherwise the game spirals into an infinite save-load loop."
    }

    fn applies_to(&self, _table: &str) -> bool {
        // Defensive: per spec, apply to any table — the per-entry check
        // below will short-circuit when the field isn't present.
        true
    }

    fn check(&self, table: &str, entry: &Value, _catalog: Option<&Catalog>) -> Vec<LintFinding> {
        let Some(passives) = entry
            .get("equip_passive_skill_list")
            .and_then(|v| v.as_array())
        else {
            return Vec::new();
        };

        // Find the first weapon-conditional passive on this entry. Reporting
        // just the first keeps the panel signal-to-noise sane — fixing the
        // equip_type_info clears every passive on this item at once, so
        // emitting N copies of the same finding is just spam.
        let mut offending_skill: Option<u64> = None;
        for elem in passives {
            // Element shape: {"skill": <u64>, "level": <u32>}.
            let skill = elem
                .get("skill")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if WEAPON_CONDITION_PASSIVES.contains(&skill) {
                offending_skill = Some(skill);
                break;
            }
        }
        let Some(skill) = offending_skill else {
            return Vec::new();
        };

        // Read equip_type_info. Missing field counts as not-a-weapon.
        let equip_type = entry
            .get("equip_type_info")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if WEAPON_HASHES.contains(&equip_type) {
            return Vec::new();
        }

        let key = entry_key(entry);
        let name = entry_display_name(entry);
        let display_name = name.clone().unwrap_or_else(|| format!("(key={})", key));

        let message = format!(
            "Item '{name}' (key={key}) has weapon-condition passive {skill} but \
             equip_type_info {value} is not a weapon type. This will cause \
             infinite loading at scale. Suggested fix: set equip_type_info to \
             {fix} (TwoHandSword).",
            name = display_name,
            key = key,
            skill = skill,
            value = equip_type,
            fix = SAFE_WEAPON_DEFAULT,
        );

        vec![LintFinding {
            rule_name: self.name().to_string(),
            severity: Severity::Error,
            table: table.to_string(),
            entry_key: key,
            entry_name: name,
            message,
            fix_suggestion: Some(AutoFix::SetField {
                field_path: "equip_type_info".to_string(),
                new_value: Value::Number(SAFE_WEAPON_DEFAULT.into()),
            }),
        }]
    }
}

// ---------------------------------------------------------------------------
// Rule 2: MissingDependencyRule
// ---------------------------------------------------------------------------

/// Suffix-to-target dispatch mapping for foreign-key style fields. Mirrors
/// `ui::field_panel::FIELD_TARGETS` but stripped of the `"STRING"` sentinel
/// — string lookups are checked separately and require the catalog's
/// string table, not its sections. Out-of-section string keys are very
/// common and would just spam the panel.
///
/// Keep this list narrow on purpose: only suffixes that unambiguously
/// identify a single target dispatch belong here.
const REFERENCE_FIELDS: &[(&str, &str)] = &[
    ("equip_type_info", "equip_type_info"),
    ("equip_slot_info", "equip_slot_info"),
    ("item_use_info", "item_use_info"),
    ("breakable_object_info", "breakable_object_info"),
    ("category_info", "category_info"),
    ("drop_set_info", "drop_set_info"),
    ("gimmick_info_key", "gimmick_info"),
    ("gimmick_info", "gimmick_info"),
    ("region_info", "region_info"),
    ("skill_key", "skill_info"),
    ("buff_key", "buff_info"),
    ("character_info_key", "character_info"),
    ("character_info", "character_info"),
    ("npc_info", "npc_info"),
    ("knowledge_info", "knowledge_info"),
    ("quest_info", "quest_info"),
    ("mission_info", "mission_info"),
    ("faction_info", "faction_info"),
    ("condition_info", "condition_info"),
    ("ai_action_attribute_info", "aiaction_attribute_info"),
    ("effect_info", "effect_info"),
    ("status_info", "status_info"),
];

/// Verifies foreign-key references resolve to a real catalog entry.
pub struct MissingDependencyRule;

impl MissingDependencyRule {
    /// Try to recognise `field_name` as a foreign-key field. Returns the
    /// referenced dispatch name on a hit, `None` when the field is just a
    /// regular value.
    ///
    /// Mirrors `ui::field_panel::normalize_field_name`'s suffix logic but
    /// stripped down to what's needed here.
    fn target_dispatch(field_name: &str) -> Option<&'static str> {
        let last = field_name.rsplit('.').next().unwrap_or(field_name);
        let mut name = last.trim_start_matches('_').to_lowercase();
        if let Some(open) = name.rfind('[') {
            if name.ends_with(']') {
                name.truncate(open);
            }
        }
        if let Some(stripped) = name.strip_suffix("_list") {
            name = stripped.to_string();
        }
        if name.ends_with('s') && name.len() > 1 {
            name.pop();
        }
        for (suffix, target) in REFERENCE_FIELDS {
            if name == *suffix
                || name.ends_with(&format!("_{}", suffix))
                || name.ends_with(*suffix)
            {
                return Some(*target);
            }
        }
        None
    }

    /// Walk one entry, collecting all (field_path, referenced_key,
    /// target_dispatch) triples. Recurses into nested objects + arrays so
    /// list-of-objects (e.g. `equip_passive_skill_list[N].skill`) is also
    /// covered.
    fn collect_refs(entry: &Value) -> Vec<(String, u64, &'static str)> {
        let mut out = Vec::new();
        Self::walk(entry, "", &mut out);
        out
    }

    fn walk(value: &Value, path: &str, out: &mut Vec<(String, u64, &'static str)>) {
        match value {
            Value::Object(obj) => {
                for (k, v) in obj {
                    let child_path = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", path, k)
                    };
                    // If this leaf itself looks like a reference, capture
                    // its numeric value before recursing.
                    if let Some(target) = Self::target_dispatch(k) {
                        if let Some(num) = v.as_u64() {
                            // 0 typically means "no reference" in this
                            // codebase. Skip to avoid spam.
                            if num != 0 {
                                out.push((child_path.clone(), num, target));
                            }
                        }
                    }
                    Self::walk(v, &child_path, out);
                }
            }
            Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    let child_path = format!("{}[{}]", path, i);
                    Self::walk(elem, &child_path, out);
                }
            }
            _ => {}
        }
    }

    /// Look up `(target_dispatch, key)` in the catalog. Returns `true` when
    /// the entry exists (i.e. *not* a missing dependency).
    fn key_exists(catalog: &Catalog, target_dispatch: &str, key: u64) -> bool {
        let Some(section) = catalog.dispatch_to_section.get(target_dispatch) else {
            // Catalog has no section mapping for this dispatch — we can't
            // prove the key is missing, so don't flag.
            return true;
        };
        let Some(entries) = catalog.sections.get(section) else {
            return true;
        };
        entries.contains_key(&key.to_string())
    }
}

impl LintRule for MissingDependencyRule {
    fn name(&self) -> &str {
        "missing_dependency"
    }

    fn description(&self) -> &str {
        "Foreign-key fields (e.g. skill_key, gimmick_info) should reference an existing entry \
         in the target table."
    }

    fn applies_to(&self, _table: &str) -> bool {
        true
    }

    fn check(&self, table: &str, entry: &Value, catalog: Option<&Catalog>) -> Vec<LintFinding> {
        let Some(catalog) = catalog else {
            // Spec: skip cleanly when the catalog isn't loaded.
            return Vec::new();
        };
        let key = entry_key(entry);
        let entry_name = entry_display_name(entry);
        let mut findings = Vec::new();
        for (path, ref_key, target_dispatch) in Self::collect_refs(entry) {
            if Self::key_exists(catalog, target_dispatch, ref_key) {
                continue;
            }
            let display = entry_name
                .clone()
                .unwrap_or_else(|| format!("(key={})", key));
            let message = format!(
                "Entry '{name}' (key={entry_key}) field '{path}' references {target}:{ref_key} \
                 but no such entry exists.",
                name = display,
                entry_key = key,
                path = path,
                target = target_dispatch,
                ref_key = ref_key,
            );
            findings.push(LintFinding {
                rule_name: self.name().to_string(),
                severity: Severity::Warn,
                table: table.to_string(),
                entry_key: key,
                entry_name: entry_name.clone(),
                message,
                fix_suggestion: None,
            });
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// Rule 3: NumericRangeRule
// ---------------------------------------------------------------------------

/// Ranges for known-bounded fields. Tuple is `(field_name, min, max)`.
///
/// Hardcoded for v1 — there's no catalog-driven schema info to lean on yet.
/// Add new fields here as the wider research catches up.
const NUMERIC_RANGES: &[(&str, i64, i64)] = &[
    // 24h in seconds. Cooltime is stored as seconds in iteminfo.
    ("cooltime", 0, 86_400),
    // Stack count is stored as u64 in iteminfo, but the UI / inventory
    // only handles 1..=9999 reliably.
    ("max_stack_count", 1, 9_999),
];

/// Flags numeric fields that fall outside their documented range.
pub struct NumericRangeRule;

impl LintRule for NumericRangeRule {
    fn name(&self) -> &str {
        "numeric_range"
    }

    fn description(&self) -> &str {
        "Common fields with documented ranges (cooltime, max_stack_count, ...) shouldn't go \
         outside those bounds."
    }

    fn applies_to(&self, _table: &str) -> bool {
        true
    }

    fn check(&self, table: &str, entry: &Value, _catalog: Option<&Catalog>) -> Vec<LintFinding> {
        let key = entry_key(entry);
        let entry_name = entry_display_name(entry);
        let mut findings = Vec::new();
        let Some(obj) = entry.as_object() else {
            return findings;
        };
        for (field, min, max) in NUMERIC_RANGES {
            let Some(raw) = obj.get(*field) else { continue };
            // Accept either signed or unsigned integers; floats fall
            // through (they're not currently in the bound list).
            let n: Option<i64> = raw
                .as_i64()
                .or_else(|| raw.as_u64().and_then(|u| i64::try_from(u).ok()));
            let Some(n) = n else { continue };
            if n < *min || n > *max {
                let display = entry_name
                    .clone()
                    .unwrap_or_else(|| format!("(key={})", key));
                let message = format!(
                    "Entry '{name}' (key={key}) field '{field}' = {value} is outside the \
                     expected range [{min}, {max}].",
                    name = display,
                    key = key,
                    field = field,
                    value = n,
                    min = min,
                    max = max,
                );
                findings.push(LintFinding {
                    rule_name: self.name().to_string(),
                    severity: Severity::Warn,
                    table: table.to_string(),
                    entry_key: key,
                    entry_name: entry_name.clone(),
                    message,
                    fix_suggestion: None,
                });
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_rank_orders_error_first() {
        assert!(Severity::Error.rank() < Severity::Warn.rank());
        assert!(Severity::Warn.rank() < Severity::Info.rank());
    }

    #[test]
    fn infinite_loading_flags_passive_on_non_weapon() {
        let entry = json!({
            "key": 12345,
            "item_name": {"local": "Bad Ring"},
            "equip_type_info": 999, // not in WEAPON_HASHES
            "equip_passive_skill_list": [
                {"skill": 91101, "level": 1},
            ],
        });
        let rule = InfiniteLoadingRule;
        let findings = rule.check("item_info", &entry, None);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.entry_key, 12345);
        assert_eq!(f.entry_name.as_deref(), Some("Bad Ring"));
        // Auto-fix should target equip_type_info with the safe default.
        match &f.fix_suggestion {
            Some(AutoFix::SetField { field_path, new_value }) => {
                assert_eq!(field_path, "equip_type_info");
                assert_eq!(new_value, &json!(SAFE_WEAPON_DEFAULT));
            }
            other => panic!("unexpected fix: {:?}", other),
        }
    }

    #[test]
    fn infinite_loading_silent_when_equip_type_is_weapon() {
        let entry = json!({
            "key": 1,
            "equip_type_info": 1086980073, // in WEAPON_HASHES
            "equip_passive_skill_list": [
                {"skill": 91101, "level": 1},
            ],
        });
        let rule = InfiniteLoadingRule;
        assert!(rule.check("item_info", &entry, None).is_empty());
    }

    #[test]
    fn infinite_loading_silent_when_no_passive_present() {
        let entry = json!({
            "key": 1,
            "equip_type_info": 999, // not a weapon, but no relevant passive
            "equip_passive_skill_list": [
                {"skill": 12345, "level": 1},
            ],
        });
        let rule = InfiniteLoadingRule;
        assert!(rule.check("item_info", &entry, None).is_empty());
    }

    #[test]
    fn infinite_loading_silent_without_passive_field() {
        let entry = json!({"key": 1, "equip_type_info": 999});
        assert!(InfiniteLoadingRule.check("item_info", &entry, None).is_empty());
    }

    #[test]
    fn missing_dependency_skips_when_no_catalog() {
        let entry = json!({"key": 1, "skill_key": 999});
        let findings = MissingDependencyRule.check("buff_info", &entry, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_dependency_target_dispatch_recognises_suffixes() {
        assert_eq!(
            MissingDependencyRule::target_dispatch("skill_key"),
            Some("skill_info")
        );
        assert_eq!(
            MissingDependencyRule::target_dispatch("foo.gimmick_info"),
            Some("gimmick_info")
        );
        assert_eq!(MissingDependencyRule::target_dispatch("hp"), None);
    }

    #[test]
    fn numeric_range_flags_out_of_bound_cooltime() {
        let entry = json!({"key": 1, "cooltime": 999_999});
        let findings = NumericRangeRule.check("item_info", &entry, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn numeric_range_silent_for_in_bounds() {
        let entry = json!({"key": 1, "cooltime": 60, "max_stack_count": 99});
        let findings = NumericRangeRule.check("item_info", &entry, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn numeric_range_skips_missing_field() {
        let entry = json!({"key": 1});
        let findings = NumericRangeRule.check("item_info", &entry, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn lint_runner_sorts_errors_first() {
        let entries = vec![
            // Triggers MissingDependencyRule? No (no catalog) — but triggers
            // NumericRangeRule (warn).
            json!({"key": 2, "cooltime": -50}),
            // Triggers InfiniteLoadingRule (error).
            json!({
                "key": 1,
                "equip_type_info": 0,
                "equip_passive_skill_list": [{"skill": 91101, "level": 1}],
            }),
        ];
        let runner = LintRunner::with_default_rules();
        let findings = runner.check_table("item_info", &entries, None);
        // Expect at least one error from rule 1 sorted before any warn.
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn count_by_severity_reports_each_bucket() {
        let findings = vec![
            LintFinding {
                rule_name: "a".into(),
                severity: Severity::Error,
                table: "t".into(),
                entry_key: 1,
                entry_name: None,
                message: String::new(),
                fix_suggestion: None,
            },
            LintFinding {
                rule_name: "b".into(),
                severity: Severity::Warn,
                table: "t".into(),
                entry_key: 1,
                entry_name: None,
                message: String::new(),
                fix_suggestion: None,
            },
            LintFinding {
                rule_name: "b".into(),
                severity: Severity::Warn,
                table: "t".into(),
                entry_key: 2,
                entry_name: None,
                message: String::new(),
                fix_suggestion: None,
            },
        ];
        let (e, w, i) = LintRunner::count_by_severity(&findings);
        assert_eq!((e, w, i), (1, 2, 0));
    }
}
