# Mod Workbench — Changelog

## v0.6.0 — global search, top tab bar, real cancellation (2026-05-04)

This release turns the workbench into a *findable* tool. The
View menu is replaced (in parallel — menu still works) by a top
tab bar so all 18 views are one click away. A new Global Search
panel scans every supported format for a query, with three
modes: text substring, raw hex bytes, and CJK string discovery
(UTF-8 + UTF-16 LE).

### New: Top tab bar (`src/ui/view_tab_bar.rs`)

Horizontal tab strip at the top of the central panel. Four
logical groups separated by vertical separators:

- **Data**: PABGB Tables, PALOC, XML, PASEQ, PAATT, PAAC,
  PAPPT, PAMHC.
- **Tools**: Archive, Binary Inspector, Global Search.
- **Workflow**: Library, Templates, Wizards, Lint, Conflicts,
  Backups.
- **System**: Settings.

Each button shows the human display name with a one-line
tooltip. `selectable_value` highlights the active view. The
existing View menu in the menu bar still works in parallel.
Side-effects (cache flushes, lazy loads) only fire on the
click that flips the view, never on steady-state re-renders.

### New: `pamhc` structural editor

Continued from v0.5.0's structural-editor wave. Loader
`sub_102484E3C` decoded — 28-byte header (8-byte opaque
preamble + 5 `u32` section sizes), Section A is a `u32`
array, B/C/D/E are opaque byte ranges. Parser at
`dmm-parser-rust-only/src/tables/pamhc/` round-trips
byte-for-byte. 5-tab UI (Section A as `u32` array editor +
B/C/D/E paged hex viewers, read-only). Default overlay
group `0072`. 6 unit tests.

### New: Global Search panel (`MainView::GlobalSearch`)

Multi-format search with one shared session. Three search
modes:

- **Text** — substring search across PABGB tables, PALOC
  (EN + KR), XML configs, the small-file editors (PAATT /
  PAAC / PAPPT / PAMHC), and an opt-in byte-level scan of
  the binary inspector formats (UTF-8 + UTF-16 LE passes).
- **Hex bytes** — paste hex (`5A 4C 00 00` or `5A4C0000`),
  the worker memmems for those bytes across binary formats
  only. Text-only formats greyed out in this mode.
- **Korean strings** — walks every binary file and surfaces
  every CJK (Hangul / Kana / Hanzi) text run found inside,
  in both UTF-8 and UTF-16 LE form. Optional filter narrows
  by case-insensitive substring on each run's text. Two-step
  confirmation gate when filter is empty (yellow warning row
  + "Run anyway" button) to prevent accidental unfiltered
  scans.

Per-format toggle grid with notes (e.g. *PALOC — fast*,
*BinaryByte — SLOW (~4000+ files)*) so users can scope the
scan up front. Each format capped at 500 hits per scan.
Results group by source format under `CollapsingHeader`s.
Each hit has a snippet, an expandable rich payload (full
entry JSON for PABGB, full XML node for XML, paged hex for
binaries), and an "Open in editor" button.

### New: Jenkins hash search

Optional checkbox in Text mode: *Also match Jenkins hash of
query (4-byte LE)*. Computes Bob Jenkins `hashlittle` of the
query (lowercase / uppercase / as-typed, deduped) and adds
the resulting `u32`s as 4-byte little-endian patterns to the
binary scan. Catches strings stored as 4-byte hashes — item
keys, paloc IDs, character keys — which substring search
completely misses. Reuses
`dmm_parser_rust_only::crypto::checksum::calculate_checksum`
with the universal PA seed `0xDEBA1DCD`.

### New: Editor jump-to-file

Clicking "Open in editor" on a hit now actually navigates:

- **PABGB** — full (table loaded + entry pre-positioned).
- **PALOC** — full (language switched, file loaded, table
  scrolled to row).
- **XML** — full (file loaded in tree editor).
- **PAATT / PAAC / PAPPT / PAMHC** — partial (file loaded;
  these editors are structural and don't have a global
  byte offset to position on).
- **Binary Inspector** — full (extension filter set, file
  loaded, hex view paged + selected at byte offset). Used
  for `Binary`, `JenkinsHash`, `HexPattern`, and
  `KoreanString` hits.

Implementation: new `PendingNav` enum on `AppState`, mirrors
the existing `pending_xref_nav` pattern. Each editor's draw
function calls a `consume_pending_nav` helper that takes the
pending nav and dispatches to that editor's load path.

### New: Real search cancellation

`Worker` is single-threaded — a long Global Search would
block every other job (LoadTable, Deploy, Restore) for
minutes until the scan finished. Cancel button used to only
update UI state, leaving the worker grinding.

Now: `Arc<AtomicBool>` cancel flag shared between the search
session and the running scan. Every scan loop checks at
iteration boundaries (per-file, per-entry, per-CJK-run) and
bails immediately when the flag flips. Triggers:

- **Cancel button** — flips the flag.
- **Reset button** — flips the flag (and clears results).
- **Mode selector switch** — flips the flag.
- **"Open in editor" while a scan is in flight** — auto-flips
  the flag so the editor's load runs immediately instead of
  queueing behind the still-running scan. This is the fix
  for the "Loading character_info... forever" symptom users
  saw when clicking through search results mid-scan.

The flag is rotated to a fresh `Arc` on each `kick_scan`, so
a stale `true` from a prior cancel can't kill a new scan
instantly.

### Search panel hardening

- **Reset button** next to Cancel — bumps `request_id`,
  clears results / error / progress / expanded-hit /
  confirm-no-filter, but preserves typed query, hex query,
  search mode, format toggles, and Jenkins-hash checkbox.
  Always escapes a stuck panel.
- **Worker disconnect detection** — `Worker::submit` now
  returns `bool`. On `false` (channel closed = worker
  thread died), `kick_scan` immediately resets `in_progress`
  and surfaces a red toast: *Worker channel closed —
  restart the workbench.* Replaces the previous silent
  failure mode that left `in_progress=true` forever.
- **Stuck-state hint** — after 5+ seconds with no progress
  message change, an inline yellow warning appears under
  the spinner: *No progress for Ns — looks stuck. Click
  Reset above to recover.* Threshold pulled into a named
  const.
- **Korean two-step gate clarity** — when the empty-filter
  guard is armed, the panel renders a high-contrast yellow
  frame with a clear instruction line. Replaces the
  easy-to-miss button-label-only signal.

### Extended Binary Inspector coverage

Added 6 extensions to the byte-level allow-list this round:

- `palevel` — level / sector streaming data. Discoverer
  decoded (`sub_101A0AEB0`) but actual file deserializer is
  buried in resource-manager `vtable+64` indirection;
  multi-session RE project. Companion `palevel_xml` already
  covered by XML editor.
- `pamhc` — model property header collection. Now has a
  full structural editor (see above) but stays in the
  byte-level allow-list as fallback.
- `pab` — skeletal collision volumes. 3D-adjacent;
  byte-level only by design. Companion `pab.sockets.xml`
  already covered by XML editor.
- `paem` — effect emitter data (borderline 3D — opt-in).
- `paver` — build version metadata (`meta/0.paver`).
- `pacpph` — compiled-script header
  (`objectList.pacpph`).

Total Binary Inspector format count: **20** extensions.

### Format research docs added

- `PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md` — pamhc fully
  decoded (loader `sub_102484E3C`); palevel discoverer
  mapped (`sub_101A0AEB0`) with revised "large effort,
  defer" assessment after walking
  `sub_101A01FD4` (recursive ID-stamp, not deserializer)
  and `sub_101A0978C` (parent-link, not deserializer); pab
  documented as 3D collision data, recommended to stay
  byte-level.

### Tests

- 188 passing total, +6 vs v0.5.0 baseline. 2 pre-existing
  `blob_text` failures unchanged. New tests cover: hex
  pattern parsing, Jenkins hash variants, byte-pattern
  search, View menu / tab bar label coverage, worker
  channel-closed contract, cancel-flag short-circuit
  (general scan + Korean dispatch), `kick_scan` flag
  rotation.

## v0.5.0 — non-3D file-format expansion (2026-05-04)

The workbench now covers **every non-3D / non-texture / non-audio
file format** in Crimson Desert at either structural or byte-level
fidelity. Eight new editor surfaces, four format research docs, one
crash-safety net, one persistent-delivery DLL.

### Crash safety

- Wrapped `table_loader::load_table` and the global-search per-table
  load in `std::panic::catch_unwind`. A parser panic on any pabgb
  (e.g. the user-reported `game_play_variable_info` crash) now
  becomes a `Failed to load — panic — <msg>` toast/error instead of
  a process kill. `describe_panic()` extracts the message from
  `&'static str` and `String` payloads; non-string payloads fall
  through to a generic notice.

### New editors (structural)

- **`paatt`** — Crimson Desert physics / projectile attribute file.
  New `dmm-parser-rust-only/src/tables/paatt/` parser (round-trips
  byte-for-byte against all 5 sample fixtures from the research
  folder), `mod-workbench/src/paatt_editor.rs` PAZ I/O, and
  `src/ui/paatt_panel.rs` UI. Anchor-based field editing aligned
  with the Python reference (`projectileRadius` / `endEffectLifeTime`
  pair). Default overlay group `0066`. 4 roundtrip tests.
- **`paac`** — action chart heuristic walker.
  `dmm-parser-rust-only/src/tables/paac/` ports the 479-line Python
  parser faithfully — header, M0%D state markers (Format A/B), inline
  transitions, 260-byte condition records, identifier strings, float
  hunt. Counts match the Python reference exactly on all 4 sample
  files (47 / 374 / 513 / 757 strings). UI has 5 sub-tabs (States /
  Transitions / Conditions / Strings / Float Hunt). `patch_float`
  and `patch_transition` write helpers for the editor's mutation
  path. Default overlay group `0067`. 6 tests including roundtrip
  parity assertions.
- **`pappt`** — character part-prefab table. Schema fully captured
  from the macOS retail binary (`PAPPT_FORMAT_RESEARCH.md`). New
  parser at `dmm-parser-rust-only/src/tables/pappt/` round-trips
  cleanly (5 tests covering empty file, max child_count = 255,
  truncated body, etc.). Two-tab UI (Primary entries with editable
  child list / Secondary aliases) at `src/ui/pappt_panel.rs`.
  Default overlay group `0071`.
- **`pamhc`** — model property header collection
  (`miscellaneous/modelpropertyheadercollection.pamhc`). Schema
  reverse-engineered from `sub_102484E3C` in the Mac retail binary —
  28-byte header (8-byte opaque preamble + 5 `u32` section sizes),
  Section A is a `u32` array, B/C/D/E are opaque byte ranges. Full
  decode in `PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md`. New parser at
  `dmm-parser-rust-only/src/tables/pamhc/` round-trips byte-for-byte.
  5-tab UI at `src/ui/pamhc_panel.rs`: Section A as `u32` array
  editor + B/C/D/E paged hex viewers (read-only with a hint to use
  Binary Inspector for byte-level edits). Default overlay group
  `0072`. 6 tests (empty file, alignment-rejection, missing-prologue,
  round-trip parity).

### New editors (byte-level)

- **PAZ Archive Inspector**. `MainView::Archive` + new
  `archive_editor.rs` + `ui/archive_panel.rs`. Walks every numeric
  PAZ group, shows PAPGT registration with checksum verification
  (red flag on mismatch), file count, total size. Drill-in:
  per-group PAMT directories + files, Open in Hex, Remove Overlay
  with confirm, PAPGT-vs-backup diff. 6 tests.
- **Binary Inspector** (`MainView::BinaryInspector`). Generic
  byte-level patcher — find/replace patches, hex view, deploy as
  PAZ overlay. Covers **20 formats** in one panel: schedule family
  (`paschedule`, `paschedulepath`, `paschedulectx`), sequencer-
  adjacent (`paseqh`, `uianiminit`), AI (`pai`), character data
  (`pappt`), declarative (`patag`, `padock`), unknowns (`pabc`,
  `paccd`, `pasg`, `parg`, `pati`), effect emitters (`paem`),
  build metadata (`paver`), compiled-script header (`pacpph`),
  and the new 3D-adjacent borderline cases (`palevel`, `pamhc`,
  `pab`). Reuses `paseq_editor::BytePatch` / `BytePatchDoc` so
  JSON patch files interop with the PASEQ editor. Default overlay
  group `0069`. 5 tests.

### Bug-report polish

- "Copy bug report" button on the table-load error UI. Builds a
  formatted multi-section report (workbench version, table name,
  error category from `classify_error()`, full message, PAZ-relative
  path when applicable, hex dump of first 256 raw pabgb bytes) and
  copies to clipboard. "First 256 bytes" preview also inline behind
  a `CollapsingHeader`. 8 tests.

### Format research

Reverse-engineered five file formats from the Mac retail binary
(image base `0x100000000`, full auto-analysis):

- `PASCHEDULE_FORMAT_RESEARCH.md` — paschedule object 208-byte
  layout, deserializer at `sub_101677EEC` walked field-by-field.
  Inner array element format (`sub_1016C2B08`, 40-byte entries) and
  scheduleContext three-pass loader documented.
- `PAI_FORMAT_RESEARCH.md` — AI chart envelope, 730-slot dispatch
  table, `AIPackage` 96-byte payload, full slot-name list (352
  unique class names — `AIPackage_*`, `AIBranch_*`, `AIState_*`,
  `AIPathFindDesc_*`, `AIFunction_*`).
- `PAPPT_FORMAT_RESEARCH.md` — full schema including the 8-byte
  opaque header, primary/secondary entry layouts, asset_id
  cross-reference into the engine's intern table.
- `PATAG_FORMAT_RESEARCH.md` — TagManager class layout
  (`pa::ReflectDerive<TagManager, ReflectObjectExtension>`,
  vtable `0x107B0FDF0`), single reflected `_tagElements`
  ObjectList field at `+0x28/+0x30`.
- `PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md` — pamhc fully decoded
  (loader `sub_102484E3C`); palevel discoverer mapped
  (`sub_101A0AEB0`) but actual file deserializer deferred — buried
  in resource-manager `vtable+64` indirection, multi-session RE
  project; pab documented as 3D skeletal collision data, recommended
  to stay byte-level.

Plus `FILE_FORMAT_CATALOG.md` — complete extension survey across
the binary's string table with status per extension and loader
function addresses for future structural decode work.

### Persistent-delivery infrastructure (in-flight)

`tools/cd-infinite-loading-fix/` — Rust `cdylib` that ships as
`version.dll`, proxies the host's `version.dll` calls to the system
DLL, and on `DLL_PROCESS_ATTACH` spawns a worker thread that
pattern-scans the loaded `CrimsonDesert.exe` image for the matcher
prologue signature and writes 3 bytes (`B0 01 C3` = `mov al, 1; ret`)
at the function start. Built clean to a 144 KB DLL. Real-game
verification still pending.

### Notes

- The `version.dll` proxy and the in-game patch are not yet
  confirmed in a long play session.
- The `pai` structural decode walked 2 of 730 slot deserializers;
  remaining slots graduate from byte-level (Binary Inspector) to
  structural one at a time as mod use-cases land.
- The schedule context (`paschedulectx`) loader has three
  deserialization passes; only the file-level call chain is
  documented, not the per-pass field schema.
- 20 new tests added across the four structural editors (paatt,
  paac, pappt, pamhc) plus test increments in the workbench
  (171 passing total, +14 vs v0.4.0 baseline; dmm-parser 329
  passing, +20 vs v0.4.0 baseline). Pre-existing 2 `blob_text`
  failures unchanged.

## v0.4.0 — search overhaul: working filter + cross-PABGB scan (2026-05-03)

### Bug fix: per-table search never narrowed

Reported case: typing `Equip_Magic_Scythe` or `1001196` into the entry-table
search bar in iteminfo left the table showing "6236 of 6236 entries" — the
filter wasn't actually being applied.

Root cause: the debounce timer was being reset every frame the filter was
dirty. The bump check compared `entry_filter` against `last_filter` (a
snapshot from the last *recompute*) — and that always differs while the
user is typing. So `last_filter_change` got bumped to `now` on every
frame, the duration check `now - last_filter_change >= FILTER_DEBOUNCE`
never passed, and `recompute_filter` never ran. The initial `(0..N)`
all-pass `filtered_indices` carried through unchanged.

Fix: added a `prev_frame_filter` field on `ActiveTable` and only bump
`last_filter_change` when the filter text changes between consecutive
frames (i.e. the user actually typed or deleted a character). Once the
user pauses for 200 ms the recompute now fires and matches against:

- `entry["key"]` numeric equality (decimal or `0x`-prefixed hex).
- `entry["string_key"]` substring (case-insensitive).
- Catalog-resolved name substring.
- Localization-table substring (any numeric leaf treated as a possible
  string hash and looked up in EN + KR).
- Any nested string field, depth-limited.

So `1001196` now matches by key and `Equip_Magic_Scythe` matches by
`string_key`.

### New: "Search all PABGBs" checkbox

A new checkbox sits next to the search input. **Off by default** — the
heavy path it enables loads ~120 tables from the game's PAZ on each
fresh query, which is 30–60 s on a cold run. When ticked plus a
non-empty filter plus 200 ms idle, the workbench fires a worker job that:

1. Walks the entire table registry.
2. For each: loads + parses via `table_loader::load_table` (so iteminfo
   uses its dedicated loader, the rest go through the dispatch layer).
3. Scans every entry against the filter (numeric key match, `string_key`
   substring, plus a depth-limited nested-string walk).
4. **Streams** every match back via `Reply::SearchHit` so results
   accumulate in the panel as the scan progresses.
5. Emits `Reply::SearchProgress` per table so the UI can render a
   progress bar with the current table name.
6. Finishes with `Reply::SearchComplete`, optionally carrying the first
   error the scan encountered (errors are non-fatal — the scan keeps
   going past a broken table and returns partial results).

The entry-table view is replaced by a three-column results panel
(`Table`, `Entry`, `Match`) when the checkbox is on. Clicking a hit
opens its source table — focuses the existing tab if it's already open,
otherwise pushes a placeholder + submits a `LoadTable` job and uses the
`pending_xref_nav` machinery to pre-select the matched entry on arrival.
The checkbox auto-disables on click so you land in the per-table view.

Stale replies from a previous scan are discarded by `request_id` so
typing a new filter mid-scan doesn't pollute the results — `app.rs`
checks the id on every `SearchHit` / `SearchProgress` / `SearchComplete`
reply and drops mismatches.

### New / changed code

- `src/state.rs` — added `prev_frame_filter` to `ActiveTable` (the bug
  fix anchor) and a `GlobalSearchSession` carrying `enabled`,
  `request_id`, `in_progress`, `scanned`/`total`, `current_table`,
  streaming `hits`, and the first `error`.
- `src/worker.rs` — added `Job::SearchAllPabgb` and three new replies
  (`SearchHit`, `SearchProgress`, `SearchComplete`). Worker handler
  loops every table, loads it on its thread, scans, and streams. Match
  helper returns the first hit per entry — by numeric `key`, by
  `string_key` substring, or by a recursive string-leaf walk with
  dotted-path notation in the displayed match summary.
- `src/app.rs::handle_worker_reply` — three new arms for the streaming
  replies. Stale-id guard drops replies from earlier scans.
- `src/ui/entry_table.rs` — checkbox in the search row, per-table-vs-
  global counter swap, debounce-fix, scan kick-off, results panel with
  `TableBuilder`, click-to-jump dispatch.

## v0.3.0 — full XML & PASEQ/PASTAGE editors (2026-05-03)

The previous release shipped two tabs that called themselves "PASEQ Editor"
and "XML Patcher" but were really:

- A two-button preset runner (Sleep Mod + NPC Swap) for sequencer files.
- A path-based JSON-patch authoring tool for XML.

This release replaces both with full structural editors. Presets are
preserved — they're now one mode inside the new tabs.

### XML Editor (`Tree Editor` mode, default)

- **PAZ browser** — `xml_editor::enumerate_xml_files` scans every numeric
  PAZ group folder under the configured Game Directory, parses each
  `0.pamt`, and surfaces every `.xml` file in a filter-able dropdown
  (group, internal directory, filename). No more "load XML from disk"
  guessing.
- **Game-XML normalisation** — ported from CdModCreator's
  `XmlPatchApplier.NormaliseGameXml`:
  - `</>` shorthand (the non-standard "close innermost" closing tag) is
    rewritten to `</TagName>` based on an open-tag stack before
    quick-xml sees it.
  - Multi-root documents are wrapped in a sentinel `<__cdmm_root__>`
    element on parse, and the wrapper is stripped on serialise so the
    output is byte-compatible with the source.
- **Tree view** — recursive collapsing headers showing each node's tag,
  attribute count, child count, and text-byte count. Click any node to
  select; the selection panel shows / lets you edit:
  - Tag name (rename)
  - Text content (multiline edit)
  - Attribute list (rename / edit / remove / add)
  - Child list (rename / edit / remove individual children, or add a
    new child by tag name)
  - "Remove this node" — deletes the node from its parent (disabled at
    root since removing root invalidates the document).
- **Apply to Game** — serialises the modified tree, packs as a single-
  file PAZ overlay (no compression on either pabgb or pabgh — the
  workbench convention for overlays), and front-inserts a PAPGT entry
  so the overlay wins lookup for the file's path. Default overlay
  group `0070` (configurable in the panel).
- **Restore Vanilla** — deletes the overlay group dir and removes its
  PAPGT entry. One click revert.
- **Save XML to disk** — writes the serialised tree to a chosen path
  for inspection / comparison without touching the game.
- **Patch Builder mode** — the v1 path-based JSON-op surface is still
  reachable via the mode toggle for users who want shareable JSON
  patches. Same op set (`set_text` / `set_attr` / `append_child`),
  same JSON shape — patches authored before this release still load.

### PASEQ / PASTAGE Editor (`Editor` mode, default)

The PASEQ binary format isn't decoded yet, so the editor is byte-level
by design — when the format is reverse-engineered later, the byte-
patch JSON files authored here remain useful as raw fallbacks.

- **PAZ browser** — `paseq_editor::enumerate_paseq_files` scans group
  0014 and surfaces every `.paseq` / `.paseqc` / `.pastage` file.
- **Hex view** — the existing paged hex viewer (16 bytes/row, ASCII
  gutter, page navigation) reused inline so users can navigate the
  bytes while authoring patches.
- **Byte patch authoring** — find/replace patches with optional
  per-patch comment. Inputs accepted as either ASCII (default) or
  hex pairs (toggle). Same-length replacements are required by
  default (file-internal offsets break otherwise); the user can
  opt in to length-changing patches via "Allow length change".
- **Patch JSON** — patches save / load as JSON for sharing. On-disk
  shape is hex pairs with whitespace separators so files are
  hand-editable. Round-trip-safe.
- **Apply to Game** — reads the vanilla file from group 0014, applies
  the patch list in order, packs the result as a fresh PAZ overlay
  (group `0068` by default, configurable), front-inserts the PAPGT
  entry. Same plumbing as the existing presets, just driven by user-
  authored patches.
- **Preview output (toast)** — dry-applies the patches and toasts the
  number of changed bytes so you can sanity-check before deploying.
- **Sleep Mod (preset)** mode — the original one-button "False → True "
  recipe, untouched.
- **NPC Swap (preset)** mode — the original NPC sequencer swap,
  untouched.

### New modules

- `src/xml_editor.rs` — PAZ enumeration, read, deploy, and restore
  helpers for XML files. PAPGT integration mirrors `deploy.rs`.
- `src/xml_patcher.rs` — `XmlNode`, `XmlTree`, `parse_to_tree`, and
  `serialize_tree` are now public so `xml_panel.rs` can edit the tree
  directly. Added `resolve_short_close_tags`, `wrap_multi_root`, and
  `has_multiple_roots` for game-XML normalisation. Sentinel-wrapped
  trees track the wrap so re-serialisation strips it.
- `src/paseq_editor.rs` — added `BytePatch`, `BytePatchDoc`,
  `PaseqPazEntry`, `enumerate_paseq_files`, `read_paseq_from_paz`,
  `apply_byte_patches`, and `deploy_byte_patches`. Hex-pair JSON
  serialisation (`hex_bytes_serde`) for human-editable patch files.

### UI changes

- `src/ui/xml_panel.rs` — full rewrite. Mode toggle (Tree Editor /
  Patch Builder), PAZ file picker with substring filter and
  500-result cap, two-column layout (tree on the left, node-detail
  panel on the right), deploy / restore / save buttons.
- `src/ui/paseq_panel.rs` — full rewrite. Mode toggle (Editor / Sleep
  Mod / NPC Swap), PAZ file picker, hex-view side panel, patch list
  with summary lines, add-patch form (ASCII / hex modes, optional
  resize), deploy / preview buttons. Presets preserved verbatim under
  their tabs.

### Misc

- The original "PASEQ Editor" header and "XML Patcher" header are
  renamed to "PASEQ / PASTAGE Editor" and "XML Editor" respectively
  to match what the tabs now do.

## v0.2.2 — fix 17 ghost tables (2026-05-03)

The pabgb filename mapping in the startup registry was out of sync
with the export-time mapping. 17 dispatch tables got the wrong filename
at load time and silently failed PAZ lookup with a misleading "parser
PR #11" hint.

- `table_registry::dispatch_name_to_pabgb_stem` now has all 25 special
  cases (was 7).
- `mod_io::dispatch_to_pabgb_filename` delegates to the registry
  function. Single source of truth — the two can no longer drift.
- `entry_table.rs` error UI is now context-aware: picks one of three
  hints based on the actual error (`PAZ lookup failed` /
  `Game data lookup failed` / `Parser error`).
- `equip_info` is the only remaining ghost table — it doesn't ship in
  retail (lives in `bin_dev/`, gated off). Now shows the accurate
  "not in your install" hint instead of the misleading parser-PR one.

## v0.2.1 — Field JSON v3 warning + license + docs (2026-05-03)

- Pre-export warning modal for `Export Mod → As Field JSON v3...`.
  Mod-manager support for the v3 single-file format is still rolling
  out, so the modal warns the user and offers Cancel / Continue
  anyway / Use Mod Folder Instead. Modal stays in the codebase until
  ecosystem support is universal.
- `mod-workbench/LICENSE.txt` — CDMWL v1.0 (Crimson Desert Mod
  Workbench License). Modeled on CDMTL v1.0 with the same enforcement
  teeth: copyleft, authorized-suite requirement, no independent-tool
  integration, trademark / naming rules, DMCA §1202 CMI, authorized
  distribution channels, no-competing-implementation 3-year clause,
  acceptance-by-access including AI / LLM agents. Joint copyright with
  RicePaddySoftware for the embedded `dmm-parser-rust-only`.
- `STATUS.md` refreshed to current state (52 files, ~21K LOC, 154
  tests).
- Root `README.md` updated with the new license section.

## v0.2 — DMM v3 export fix (2026-05-03)

- `mod_io::export_dmm_v3` rewritten to emit the DMM 1.3.3+ shape:
  `{ modinfo, format: 3, targets: [{ file, intents[] }] }`.
- `mod_package::export_dmm_v3_json` — single-file writer; replaces
  the deprecated folder-style `export_dmm` / `export_dmm_full`.
- `app::action_export_dmm` uses `save_file()` with a `.json` filter
  instead of `pick_folder()`.
- `conflict::extract_meta` reads either `_meta` (workbench-native) or
  DMM-style `modinfo.title/author/version` so re-imported DMM mods
  display attribution correctly.

## v0.1 — Initial release (2026-05-03)

Standalone Rust + egui mod editor. 122 pabgb tables (+ iteminfo via
dedicated parser) with parse / serialize round-trip, async loading,
virtualised tables, catalog-driven name resolution, cross-references,
PALOC localization (EN+KR) with disk cache, CJK font loading, field-
level diff highlighting, undo/redo, type-aware editors, lint rules,
backup / snapshot system, conflict detection, profiles, templates,
wizards, command palette, 3 themes, 15 keyboard shortcuts.
