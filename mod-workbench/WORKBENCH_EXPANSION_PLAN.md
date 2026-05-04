# Mod Workbench — Non-3D File-Type Expansion Plan

Goal: turn the workbench into the editor for **everything** in
Crimson Desert that isn't a 3D model or a texture. The user already
has dedicated tools for those (3D modding pipeline / `pa::TextureMap`
work), so the workbench focuses on data + behaviour.

> **2026-05-04 status:** Waves 0–5 + 7 (pappt structural) + 9 (pamhc
> structural) shipped. Wave 4 byte-level inspector now handles 17
> formats (added palevel/pamhc/pab/paem/paver/pacpph this round).
> Wave 6 not yet built (small polish items deferred). Detailed format
> catalogue at `FILE_FORMAT_CATALOG.md`. Format research docs:
> `PASCHEDULE_FORMAT_RESEARCH.md`, `PAI_FORMAT_RESEARCH.md`,
> `PAPPT_FORMAT_RESEARCH.md`, `PATAG_FORMAT_RESEARCH.md`,
> `PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md`.

## Scope (in)

Editable from the workbench:

| Extension | Type | Status | Priority |
|---|---|---|---|
| `pabgb` / `pabgh` | Game data tables (122) | Shipped | done |
| `xml` | Config XML | Shipped (tree editor + patch builder) | done |
| `paloc` | Localization (14 langs) | Shipped | done |
| `paseq` / `paseqc` / `pastage` | NPC sequencers | Shipped (presets + byte editor) | done |
| `paatt` | Physics / projectile attributes | **NEW** (this plan) | high |
| `paac` | Action charts (commonactioninfo) | **NEW** (this plan) | medium |
| `papgt` / `pamt` | Archive pack metadata | **NEW** (this plan) | high |
| `paschedule` / `paschedulepath` / `paschedulectx` | NPC schedules (4000+ files) | **NEW** (this plan) | low |
| `uianiminit` | UI animation init | **NEW** (this plan) | low |

## Scope (out)

Out of scope per user direction:

- `*.fbx`, `*.pam`, `*.pac` (geometry/anim curves) — 3D pipeline.
- `*.dds`, `*.ptex`, `*.pbr` — texture pipeline.
- `*.road` — pathfinding navmesh, considered 3D-adjacent.
- `*.save` — covered by the separate Crimson Save Editor; we only
  surface basic info if useful.

## Wave 0 — Crash safety net (done in this session)

**Problem report**: workbench "forcefully closes" when a user opens
certain tables (`game_play_variable_info` cited).

**Fix**: wrapped `table_loader::load_table` and the global-search
per-table load in `std::panic::catch_unwind` with `AssertUnwindSafe`.
Parser panics now become `TableLoaded(Err("panic — <msg>"))` replies
instead of process kills. Same panic was extracting payload via
`describe_panic` (handles `&str` and `String` payload forms).

**Result**: tested locally. Parser parses 47 items from the live
1.0.5 PAZ for `game_play_variable_info` cleanly — so the crash
isn't reproducible from our copy of the binary, but the safety net
catches whatever variant the user hits.

## Wave 1 — `paatt` editor (next agent)

Crimson Desert's projectile attributes (`game_projectileinfo_*.paatt`)
hold per-projectile physics: radius, speed, gravity, lifetime, etc.
Modders want to edit these for things like "make arrows fly faster",
"increase explosion radius", etc.

**Existing research**: `ResearchFolder/paac/paatt_parser.py` +
`paatt_inspect.py` + `paatt_deploy.py`. Sample files:
- `ResearchFolder/paac/game_projectileinfo_pc.paatt`
- `ResearchFolder/paac/sample_projectileinfo*.paatt`

Per memory: physics entries are 546 bytes each, `PhysicsData.projectileRadius`
is at runtime offset `0x440`, default `0.01f`.

**Deliverable**: a Rust port of the Python parser into
`dmm-parser-rust-only::tables::paatt::*` (or a sibling crate), plus
a workbench `Paatt` panel that lists every projectile entry with
its named fields editable via the same diff/reset machinery the
pabgb panels use.

**PAZ I/O**: same overlay pipeline as XML — pack into a fresh group,
front-insert PAPGT entry. The deploy reuses
`xml_editor::deploy_xml_overlay`'s shape.

## Wave 2 — `paac` editor (parallel agent)

Action charts (`commonactioninfo.paac`) define every animation/
ability the game's character controllers can dispatch into. Big
modding target — "add new combo to Damiane's halberd" et al.

**Existing research**: `ResearchFolder/paac/paac_parser.py` +
`paac_class_dictionary.json` + `paac_parser_seed.py`. Sample files:
- `CrimsonSaveEditorGUI/extracted_actionchart/actionchart/commonactioninfo.paac`
- `ResearchFolder/paac/sample_*.paac`

**Deliverable**: Rust port of the parser + a workbench panel for
inspecting / editing action chart entries.

**Risk**: paac is more structurally complex than paatt — the entry
schema is class-driven (per `paac_class_dictionary.json`, hundreds
of distinct shapes). First pass should be a tree viewer with
read-only field display + targeted edit on a few common
fields (cooldown, damage scaling). Full schema editing in a
follow-up.

## Wave 3 — PAPGT / PAMT inspector tab (parallel agent)

The user already loads tables via the implicit `0008/0.pamt`
parsing. Surface a dedicated panel that:

- Lists every PAZ group (`0000`–`0099+`) in the configured Game Dir.
- For each group, shows its PAPGT-registered checksum and active state.
- For each group, dumps its PAMT directories + files with sizes.
- One-click "Open in Hex View" for any file.
- "Remove this overlay" button per group (with confirm).
- "Compare PAPGT to backup" diff.

This is mostly UI on top of `dmm-parser-rust-only::binary::pamt` /
`papgt`. No new parsing.

**Deliverable**: new view mode `MainView::Archive` + panel
`ui/archive_panel.rs`. State on `AppState::archive: ArchiveSession`.

## Wave 4 — `paschedule` + Binary Inspector (DONE)

Reverse-engineered the paschedule object schema from
`sub_101677EEC` in the Mac binary — full 208-byte object layout
captured in `PASCHEDULE_FORMAT_RESEARCH.md`. The deserializer calls
13+ inner helpers; structural Rust port deferred in favour of a
generic byte-level editor that covers the whole tail of unknown
formats with one panel.

Built: `MainView::BinaryInspector` + `binary_inspector_panel.rs` +
`binary_inspector.rs` backend. Same find/replace/deploy pattern as
the PASEQ "Editor" mode, generalised to walk every numeric PAZ
group and accept any of these extensions:

- Schedule family: `paschedule`, `paschedulepath`, `paschedulectx`
- Sequencer-adjacent: `paseqh`, `uianiminit`
- AI: `pai` (`aichart.pai`, `PathFindTable.pai`)
- Character data: `pappt` (also has a structural editor — see Wave 7)
- Declarative: `patag`, `padock`
- Unknown: `pabc`, `paccd`, `pasg`, `parg`, `pati`

Default overlay group `0069`.

## Wave 7 — `pappt` structural editor (DONE)

Schema fully captured in `PAPPT_FORMAT_RESEARCH.md`. Built parser at
`dmm-parser-rust-only/src/tables/pappt/`, backend at
`mod-workbench/src/pappt_editor.rs`, panel at
`mod-workbench/src/ui/pappt_panel.rs`. Two-tab layout: Primary
entries (with editable child list) + Secondary aliases. Round-trip
tested with 5 unit tests covering empty file, max child_count,
truncated body, etc. Default overlay group `0071`.

## Wave 9 — `pamhc` model property header collection (DONE)

Schema fully decoded from `sub_102484E3C` — 28-byte header (8-byte
opaque preamble + 5 `u32` section sizes), Section A is a `u32` array,
B/C/D/E are opaque byte ranges. Built parser at
`dmm-parser-rust-only/src/tables/pamhc/`, backend at
`mod-workbench/src/pamhc_editor.rs`, panel at
`mod-workbench/src/ui/pamhc_panel.rs`. 5-tab UI: Section A as `u32`
array editor + B/C/D/E paged hex viewers (read-only — point users at
Binary Inspector for byte-level edits). Default overlay group `0072`.
6 unit tests covering empty file, alignment-rejection, and the
`<28-byte` prologue rejection path. Round-trip safe.

## Wave 8 — `pai` AI chart structural editor (filed)

`PAI_FORMAT_RESEARCH.md` captured the file envelope, `AIPackage`
96-byte struct, slot-keyed dispatch table, and the schema for the
AIPackage_Normal slot's `vtable[14]` deserializer. 728 of 730 slot
deserializers remain "not walked" — graduate one slot at a time as
mod use-cases land. The byte-level Binary Inspector handles `.pai`
in the meantime so users aren't blocked.

## Wave 5 — Crash-report UX polish (small)

When a parser panic is caught, the error UI should:
- Differentiate panic from PAZ-lookup-fail from parse-error (already
  done in `entry_table.rs`).
- Add a **"Copy bug report"** button that puts onto the clipboard:
  the dispatch name, the panic message, the file's PAZ path, the
  first 256 bytes of the pabgb in hex, and the workbench version.
  User can paste into a GitHub issue.

This makes user reports actionable instead of "it crashed."

## Wave 6 — Polish surface

- Status bar shows "X tables loaded / Y / Z" instead of just one
  count.
- Settings panel surface for: snapshot retention, default overlay
  group numbers, max in-memory tables (LRU eviction).
- Dark/Light/Crimson theme already there; no work.

## Sequencing — what to do *first*

The crash fix is in. Wave 1 (paatt) is the highest user-value next
step because:
- Format is small and well-researched.
- Use case is concrete and not covered elsewhere.
- Same overlay pipeline as everything else, no new crypto.

Wave 3 (PAPGT/PAMT inspector) is parallelisable — different code
path, different panel, no overlap with paatt.

Wave 5 (bug-report polish) is half a day's work and helps every
future bug we triage.

Wave 2 (paac) is the biggest single unit of work. Defer until
after Wave 1 is shipped and tested.

Wave 4 (paschedule) is research-bounded, not engineering-bounded —
scoping that requires actually opening the files in IDA / hexpat
and figuring out the schema. Filed for a later session.

## Build / release

Same rule as everything else: build locally, hand to the user for
verification, do not push to GitHub or cut a release until they
confirm it works in their game.
