# Mod Workbench — Changelog

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
