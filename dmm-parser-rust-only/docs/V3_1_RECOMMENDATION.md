# Field JSON v3.1 — Recommendation Memo (PROMOTED TO SPEC)

**Author**: dmm-parser team (exodiaprivate-eng)
**Date**: 2026-05-01
**Audience**: NattKh (CrimsonGameMods), modders, mod managers
**Status**: ✅ Implemented — see formal spec at
[CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS / FIELD_JSON_V3_1_SPEC.md](https://github.com/NattKh/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS/blob/main/CrimsonGameMods/FIELD_JSON_V3_1_SPEC.md)
**License**: This memo is MPL 2.0; the v3.1 marks ("Field JSON v3.1",
"Multi-Target Field Patching") are RicePaddySoftware unregistered
trademarks per the formal spec.

> **Note**: This document is the original recommendation memo that led to
> the formal v3.1 specification. The authoritative spec is now
> `FIELD_JSON_V3_1_SPEC.md` in the CrimsonGameMods repo. This memo is
> retained for historical context — implementation status is current as
> of 2026-05-01.

---

## TL;DR

V3 works perfectly for `iteminfo.pabgb` mods. But the modding community now has access to **125 typed tables** (gimmicks, skills, characters, drops, etc.). V3's single-target design doesn't scale. We recommend a **minimal v3.1** that:

1. Keeps every v3 mod working unchanged (100% backward compatible)
2. Adds multi-table targeting via per-intent `target` field
3. Adds list ops (`list_set` / `list_append` / `list_remove`) for fine-grained list edits
4. Defines a discoverable schema so modders see what's editable without reading source

---

## Why v3 alone is insufficient now

### v3 was designed for one table

The current spec hard-codes `"target": "iteminfo.pabgb"` at the document level. Every intent in the doc applies to the same table. This was correct in 2026-04 when only `iteminfo` was field-typed.

### dmm-parser now exposes 125 tables

As of 2026-05-01, our parser has full typed read/write/JSON support for:

| Category | Tables | Modder use case |
|---|---|---|
| **Items & equipment** | `iteminfo`, `equip_slot_info`, `equip_type_info` | weapons, armor stats |
| **Skills & buffs** | `skill_info`, `buff_info`, `passive_skill_info` | combat balance, skill tree |
| **Characters** | `character_info` (174 fields × 6966 entries), `character_change_info` | NPC stats, mob HP |
| **Gimmicks** | `gimmick_info` (12393 entries, 2926 typed fields, 90% bytes typed) | environmental effects |
| **Quests** | `quest_info`, `quest_dialog_filter_data_list` | quest content |
| **Drops** | `drop_set_info`, `item_use_info` | loot tables (huge modder demand) |
| **Conditions** | `condition_info` (8919/8934 = 99.83%) | combat triggers |
| **Effects** | `effect_info`, `frame_event_attr_group_info` | VFX |
| **AI & spawn** | `aievent_table_info`, `faction_*`, `terrain_region_auto_spawn_info` | mob behavior |
| **Interactions** | `interaction_info` (363/363 = 100%) | NPC dialogue triggers |

A modder who wants to "buff a sword AND change its drop rate AND modify the gimmick triggered by it" needs to edit **3 different tables**. v3 cannot express this in a single mod file.

### v3 list ops are too coarse

V3 only supports `set` which **replaces the entire value**. For `enchant_data_list` with 10 levels, replacing requires re-stating all 10 levels. Two mods that each edit different enchant levels conflict (last-writer-wins eats the other).

For lists with stable keys (e.g., `equip_passive_skill_list[].skill = 70994`), modders want to say "add this skill" or "remove this skill" without re-listing the whole array.

### Modders can't discover what's editable

There's no machine-readable schema. Modders learn fields by:
1. Reading source code
2. Trial and error (parse → edit → serialize → check roundtrip)
3. Asking on Discord

Mod managers must hardcode field knowledge, breaking when we add tables.

---

## v3.1 design (minimal, backward-compatible)

### Core principle: opt-in evolution

A v3 mod that doesn't use any v3.1 features is byte-identical to v3.1. The detection algorithm becomes:

```python
def detect_format(doc):
    if doc.get("format") != 3:
        return "unsupported"
    if doc.get("format_minor", 0) >= 1:
        return "v3.1"
    return "v3"
```

A v3.1-aware loader handles both. A v3-only loader skips intents with `target` ≠ document-level `target`.

### Change 1: Per-intent `target` (multi-table)

```json
{
  "format": 3,
  "format_minor": 1,
  "target": "iteminfo.pabgb",
  "intents": [
    { "entry": "Sword_X", "key": 100, "field": "cooltime", "op": "set", "new": 1 },
    {
      "target": "skillinfo.pabgb",
      "entry": "Slash_Skill", "key": 50001,
      "field": "damage", "op": "set", "new": 5000
    },
    {
      "target": "gimmickinfo.pabgb",
      "entry": "Sword_Aura", "key": 70001,
      "field": "duration", "op": "set", "new": 10
    }
  ]
}
```

- Document-level `target` becomes the **default** for intents that omit `target`.
- Per-intent `target` overrides the default.
- All v3 mods work unchanged because no per-intent `target` means "use the doc default" = same as v3.

### Change 2: List operations

Add 4 new ops alongside `set`:

| Op | Description | Example |
|---|---|---|
| `set` (existing) | Replace entire value | `{ "field": "enchant_data_list", "op": "set", "new": [...] }` |
| `list_set` | Replace single element by index or key | `{ "field": "enchant_data_list", "op": "list_set", "where": {"level": 3}, "new": {...} }` |
| `list_append` | Add element to end of list | `{ "field": "equip_passive_skill_list", "op": "list_append", "new": {"skill": 70994, "level": 1} }` |
| `list_remove` | Remove element by index or key | `{ "field": "enchant_data_list", "op": "list_remove", "where": {"level": 3} }` |
| `list_merge` | Merge by key field (upsert) | `{ "field": "stat_list_static", "op": "list_merge", "key": "stat", "new": [{"stat": 100, "change_mb": 50}] }` |

**Where clause** (used by `list_set` / `list_remove`):
- `{"level": 3}` — match element with `level == 3`
- `{"index": 0}` — match by 0-indexed position
- `{"$and": [{"level": 3}, {"slot": 0}]}` — multi-field match

### Change 3: Schema discovery

Each parser exposes a `describe()` that returns the field schema:

```python
import dmm_parser

schema = dmm_parser.describe_table("iteminfo.pabgb")
# Returns:
{
    "table": "iteminfo.pabgb",
    "entry_key": "string_key",
    "entry_id": "key",
    "fields": {
        "cooltime": { "type": "u32", "constraints": "> 0" },
        "max_stack_count": { "type": "u32" },
        "enchant_data_list": {
            "type": "list",
            "element": {
                "type": "object",
                "fields": {
                    "level": { "type": "u32", "key": true },
                    "equip_buffs": {
                        "type": "list",
                        "element": { "type": "object", "fields": {
                            "buff": { "type": "u32" },
                            "level": { "type": "u32" }
                        }}
                    }
                }
            }
        }
    }
}
```

Mod managers can:
- Render UI dynamically (no hardcoded field lists)
- Validate intents before applying (type check, range check)
- Show field documentation inline
- Auto-complete field paths

### Change 4: Cross-table references (later v3.2)

Items reference gimmicks. Skills reference buffs. Drops reference items. A useful future feature is named refs:

```json
{
  "entry": "Sword_X", "field": "gimmick_info",
  "op": "set", "new": "@gimmickinfo.Sword_Aura"
}
```

The loader resolves `@gimmickinfo.Sword_Aura` to the runtime key. This makes mods stable across game updates even when keys change.

We recommend **deferring this to v3.2** to keep v3.1 small.

---

## What dmm-parser needs to ship

To enable v3.1 in mod managers, the parser library needs:

### Already done ✅
- 122 tables typed at field level
- JSON parse/serialize for every typed table
- Byte-perfect roundtrip on all 449 vanilla `.pabgb` files
- 308 passing tests
- **Generic Python dispatcher** (`parse_table` / `serialize_table` / `write_table_to_file`)
  exposes all 122 tables uniformly — see `docs/api.md` Generic Table API section

### Gap 1: Python bindings expose only ~13 of 125 tables
**RESOLVED** (PR #5 merged 2026-04-30; pulled locally 2026-05-01).
The PR adds three generic dispatch functions:

```python
items = dmm_parser.parse_table("gimmick_info", pabgb_bytes, pabgh_bytes)
binary = dmm_parser.serialize_table("gimmick_info", items)
dmm_parser.write_table_to_file("gimmick_info", items, "out.pabgb")
```

`parse_table(table_name, pabgb, pabgh=None)` dispatches to the correct
typed parser by string name. **120 tables wired up** via macro-generated
match arms: 47 pabgh-bounded tables (those that need both files) + 73
sequential tables. Plus 2 inline-handled tables (`equip_slot_info`,
`skill_info`) that have non-standard parse signatures.

**Post-merge improvements (13 hours of follow-up work, 2026-05-01):**
The dispatcher API is unchanged but the underlying typing improved
significantly for the most-used table:

| Table | Before merge | After 13h work |
|---|---|---|
| `gimmick_info` typed fields | 1376 per entry | **2926 per entry** |
| `gimmick_info` post_blob avg | ~191 bytes | **108 bytes** (90% reduction) |
| Entries with zero residual | ~1073 / 12393 | **11676 / 12393** (94%) |

These are `parse_table("gimmick_info", ...)` improvements with no API
change — modders get richer JSON dicts automatically. Specifically added:
- Smart-probe alt chains (f31_alt 256, f32_alt 192, f39_alt 192)
- Extended alt_body chain to 1536 fields (covers 99% of alt-format gimmicks)
- 4× tail_pad u8 chain (drains 1-3 trailing pad bytes seen in 10500 entries)
- Structural CString detection in alt_body 1409..1536 (recovers
  `alt_post_cstr_a` typing for entries with embedded XML payloads)
- Loosened `alt_post_cstr_a/b` length cap (1000 → 65536) to type long
  XML CStrings up to 64KB

This makes v3.1 multi-table support directly buildable on top.

### Gap 2: No `describe_table()` API
**Action**: Each table's parser already has all the type info. Add a static schema dump:

```rust
// In src/tables/iteminfo/info.rs:
pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "table": "iteminfo.pabgb",
        "entry_key": "string_key",
        "fields": {
            "cooltime": {"type": "u32"},
            // ... auto-generate from struct
        }
    })
}
```

**Priority**: MEDIUM. Modders can work without it (use trial-and-error JSON), but mod managers need it for good UX.

### Gap 3: List op helpers
**Action**: Add path-resolution code that handles `list_set`/`list_append`/`list_remove` ops. Pure JSON manipulation, no parser changes needed.

**Priority**: HIGH. Without list ops, mod conflicts are common.

### Gap 4: Mod stacking semantics
**Action**: Document and test how multiple `field.json` files combine when targeting the same table.

**Priority**: MEDIUM. Stacker Tool already does this for v3; need to extend to v3.1's per-intent target.

---

## Migration path (v3 → v3.1)

| Day | Action |
|---|---|
| **0** | Ship v3.1 spec doc + reference loader. Existing v3 mods continue working unchanged. |
| **+7** | Update CrimsonGameMods Stacker Tool to read v3.1 (multi-target + list ops). |
| **+14** | Add `describe_table()` API to dmm-parser; expose remaining 112 table parsers. |
| **+30** | Write modder tutorial for cross-table edits using v3.1. Discord announcement. |
| **+60** | Cross-table reference resolution (`@table.entry`) — defer if not needed. |

**Total parser-side work**: ~2 days for table exposure + ~1 day for schema dump + ~1 day for list-op helpers = **~1 week of focused work**.

---

## Recommendation summary

| Question | Answer |
|---|---|
| Is v3 sufficient for current modders? | For iteminfo-only mods, **yes**. For everything else, **no**. |
| Do we need v3.1? | **Yes** — multi-table is the killer feature. List ops resolve mod-stacking conflicts. |
| Backward compatible? | **Yes** — v3 mods work unchanged in v3.1 loaders. |
| Effort for parser team? | **~1 week**: expose 112 more tables + add `describe()` + list ops helpers. |
| Effort for mod managers? | **~1 week**: handle per-intent `target` + 4 new list ops. |
| Should v3.1 ship now? | **Yes** — current 90% field-parsing milestone is the right time. The infrastructure exists; we just need to wire it up. |

---

## Concrete next steps

1. **Get NattKh's signoff** on v3.1 spec direction (this doc).
2. **Pick the first cross-table mod** as a tracer bullet — e.g., "buff a weapon's damage AND increase its drop rate AND change its visual gimmick". This exercises every v3.1 feature.
3. **Expose 5 high-value tables** in Python first (`drop_set_info`, `gimmick_info`, `skill_info`, `buff_info`, `character_info`). 80% of modder demand will be on these.
4. **Add `describe()` API** for those 5 tables. Mod manager UI built on top.
5. **Write the v3.1 reference loader** as a Python module shipped with `dmm-parser`. Mod managers import and call it; no need to reimplement path resolution + list ops.

The current parser handles **the entire data layer**. v3.1 just needs to expose it cleanly to modders.
