# Mod Workbench — Current State

**Last updated:** 2026-05-03
**Latest build:** `target/release/mod-workbench.exe` (~23 MB, release / optimized)
**Tests:** 152 passing (2 unrelated `blob_text` failures pre-existing)
**Source:** 52 files / ~21K LOC Rust

A standalone Rust + egui desktop tool for editing every parseable Crimson
Desert pabgb table, packaging the result as a PAZ overlay, and deploying
it to a live game install with a single click. Built on top of
`dmm-parser-rust-only` (PyO3-stripped fork of `dmm-parser`).

## Modules (src/)

### Foundations
- `config.rs` — persistent config in `%APPDATA%/Crimson/ModWorkbench/config.toml` (game_dir, theme, panel widths, recent mods).
- `steam.rs` — auto-detection via Steam registry + `libraryfolders.vdf` walk.
- `catalog.rs` + `catalog_loader.rs` — loads `game_map_complete_v4.json` (29 MB), 161 sections, 41,974 cross-table links, 38,246 PALOC strings, dispatch→section name mapping. Cached to disk.
- `worker.rs` — background worker (mpsc) for table loads, catalog parse, deploy, restore. UI never blocks.
- `toast.rs` — Info/Warn/Error notifications with auto-dismiss + click-to-expand details.
- `theme.rs` — Dark / Light / Crimson themes, persisted in config.
- `fonts.rs` — loads Malgun Gothic / Yu Gothic / SimSun from system fonts and **prepends** to the egui family vec so CJK glyphs render in Korean / Japanese / Chinese game data.
- `localization.rs` — loads PALOC EN + KR, caches to `%APPDATA%/Crimson/ModWorkbench/localization.json`. Hash → string lookup used for name resolution.
- `blob_text.rs` — extracts UTF-8 text runs (Hangul / Kana / Hanzi / printable ASCII ≥ 3 chars) from `_blob_b64` fields so Korean strings render inline instead of opaque base64.

### Editor
- Field-level diff highlighting (orange "●", vanilla tooltip, per-field reset).
- `edit_history.rs` — full undo/redo with visible history panel + "jump to state".
- Type-aware editors: hex toggle for hashes, color picker for RGBA, bitmask checkbox grid, percent slider for rates, catalog dropdown for hash references.
- Multi-tab editing (`open_tabs` + `active_tab_idx`), tab modified indicator, Ctrl+W close, Ctrl+Tab cycle.
- `notes.rs` — per-entry text annotations, embedded in mod export, 📝 indicator in entry table.

### Catalog Integration
- Field name resolution (numeric IDs → `equip_type_info: 1086980073 (TwoHandSword)`).
- Cross-reference panel — outgoing + incoming links, click to jump to target table+entry.
- Catalog-aware search — matches key, string_key, resolved name, any string field.
- Debounced filtering (200 ms), virtualized rendering (50K+ rows tested).

### Special File Types
- `paloc_editor.rs` — PALOC localization editor (14 languages, multiline string edit, overlay deploy).
- `paseq_editor.rs` — Sleep mod (`False`→`True ` patches at known offsets) + NPC sequencer swap (file-level replacement).
- `xml_patcher.rs` + `ui/xml_panel.rs` — XML patching with quick-xml: set_text, set_attr, append_child.
- `ui/hex_view.rs` — paged hex viewer (16 bytes/row, ASCII gutter) for raw blob inspection.
- iteminfo special integration — manual `TableMeta` entry plus dedicated loader path; the iteminfo parser walks `ItemInfo::read_from` in a loop on the worker thread.

### Validation
- `validation.rs` — `LintRule` trait + `LintRunner`. Built-in rules:
  - **InfiniteLoadingRule** — catches the elemental-passives-on-non-weapon equip_type mismatch (the bug we discovered in production).
  - **MissingDependencyRule** — flags references to non-existent keys.
  - **NumericRangeRule** — out-of-range field values.
- Auto-fix support; deploy is gated on errors (confirmation required).

### Backup / Conflict
- `backup.rs` — auto-snapshot before every deploy, restore any prior state, retain last 20 by default.
- `conflict.rs` — load multiple mods, detect direct conflicts + partial overlaps, severity-coded UI. Importer accepts both shapes:
  - workbench-native `crimson_field_json_v3` (string format tag)
  - DMM `format: 3` (single `target` legacy shape **or** multi-target `targets[]`).
- `extract_meta` reads either `_meta` or DMM-style `modinfo` so re-imported DMM mods display attribution correctly.

### Distribution
- `mod_io.rs::export_dmm_v3` — DMM 1.3.3+ shape: `{ modinfo, format: 3, targets: [{ file, intents[] }] }`. Single self-contained `.json` file.
- `mod_package.rs::export_dmm_v3_json` — single-file writer for the above. (The legacy folder export with mod.json + metadata.json + README.md was removed; DMM 1.3.3 rejected it.)
- `mod_package.rs::export_paz_mod_folder` — full-fidelity PAZ overlay folder mod (`<name>/<group>/0.paz + 0.pamt + modinfo.json`), mirroring the `gui/tabs/buffs_v319.py::_buff_export_mod_folder` workflow:
  - pabgb serialised from the active table.
  - vanilla pabgh extracted from `0008/` and packed unchanged.
  - `Compression::None` for both files (PackGroupBuilder), ChaCha20 with `encrypt_info` lifted from `0008/0.pamt`.
  - Internal PAZ path `gamedata/binary__/client/bin/` (anything else silently fails).
- `mod_package.rs::export_v3_json` + `export_modpkg` — workbench-native v3 JSON and `.modpkg` zip (kept for backwards compatibility but not wired to the menu).
- `metadata_dialog.rs` — name/author/version/description/nexus/dependencies prompt before any export.
- `mod_library.rs` — local mod library at `%APPDATA%/Crimson/ModWorkbench/mods/`.
- `profile.rs` — named profiles (Vanilla++ / Custom / Test), one-click apply, ordered priority.
- `templates.rs` — built-in templates (God Stats, Infinite Stack, Free Items, 100% Drop) + user templates.
- `wizards.rs` — guided flows (StatBoostWizard, BlankTemplateWizard) with multi-step UI.

### Deploy / Quick-Test Loop
- **Apply to Game (Quick Test)** — `app.rs::action_deploy` → `deploy.rs`: pack the active table as a PAZ overlay, copy into game dir, update PAPGT. Auto-snapshot first.
- **Remove Overlay (Restore Vanilla)** — `app.rs::action_restore` → `restore.rs`: delete overlay group dir, remove its PAPGT entry. One-shot.
- **Start Game** — `app.rs::action_start_game`: launch `CrimsonDesert.exe` from the configured game dir.
- All three are reachable from:
  - File menu (with descriptive tooltips).
  - **Bottom-bar quick-action buttons** (`ui/bottom_bar.rs`): ⬆ Apply (blue, primary) / ✖ Remove Overlay (red, destructive) / ▶ Start Game (green). Color-coded so the destructive action stands out.

### UX
- `ui/command_palette.rs` — Ctrl+P searchable action / entry / table / mod palette (VS Code style).
- `ui/settings_panel.rs` — game dir, catalog path, theme, snapshot retention.
- 15 keyboard shortcuts (F, F3, Ctrl+S/D/R/Z/Y/W/Tab/L/P/,/Esc, Ctrl+Shift+S/Z/Tab).

## Architecture

```
mod-workbench/
├── Cargo.toml                     deps: dmm-parser-rust-only (path), eframe 0.31, egui 0.31,
│                                        egui_extras, serde/serde_json, toml, rfd, directories,
│                                        zip, base64, quick-xml, winreg (windows)
├── build_release.bat              guided release-build script (shows progress)
├── ROADMAP.md                     historical master plan
├── STATUS.md                      this file — current feature inventory
├── LICENSE.txt                    CDMWL v1.0 (CDMTL-compatible, see LICENSE)
└── src/
    ├── main.rs                    entry point
    ├── app.rs                     WorkbenchApp + eframe::App impl + action handlers
    ├── state.rs                   AppState, ActiveTable, ChangeTracker, MainView, LoadState
    ├── config.rs                  Config load/save
    ├── steam.rs                   Steam install detection
    ├── catalog.rs                 Catalog (game_map_complete_v4.json)
    ├── catalog_loader.rs          try_load wrapper with worker-thread parsing
    ├── worker.rs                  BG worker (Job/Reply via mpsc)
    ├── toast.rs                   ToastManager
    ├── theme.rs                   apply_theme(ctx, theme)
    ├── fonts.rs                   CJK font loading (Malgun/Yu/SimSun → prepended)
    ├── localization.rs            PALOC EN+KR cache
    ├── blob_text.rs               UTF-8 text-run extraction from _blob_b64
    ├── edit_history.rs            EditOp + EditHistory
    ├── notes.rs                   NoteStore
    ├── validation.rs              LintRule + 3 built-in rules
    ├── backup.rs                  Snapshot system (auto-snapshot pre-deploy)
    ├── conflict.rs                Mod conflict analyzer (workbench v3 + DMM v3 single/multi-target)
    ├── mod_io.rs                  v3 JSON import/export, DMM v3 export (modinfo+targets), ModMetadata
    ├── mod_package.rs             export_v3_json / export_modpkg / export_dmm_v3_json /
    │                              export_paz_mod_folder
    ├── mod_library.rs             Library scan/import/delete
    ├── profile.rs                 Profile + ProfileStore
    ├── templates.rs               Template + builtin
    ├── wizards.rs                 Wizard trait + 2 implementations
    ├── paloc_editor.rs            PALOC load/save
    ├── paseq_editor.rs            Sleep mod + NPC swap
    ├── xml_patcher.rs             quick-xml patcher (set_text, set_attr, append_child)
    ├── deploy.rs                  Deploy with auto-snapshot
    ├── restore.rs                 Remove overlay + PAPGT entry
    ├── table_loader.rs            Extract+parse via dmm-parser-rust-only (with iteminfo special path)
    ├── table_registry.rs          122-table registry + manual iteminfo entry
    └── ui/
        ├── mod.rs
        ├── tab_bar.rs             Multi-tab switcher
        ├── table_list.rs          Left panel (122 tables)
        ├── entry_table.rs         Center panel (entries with virtualized rows + search)
        ├── field_panel.rs         Right panel (recursive editor with name resolution + reset)
        ├── xref_panel.rs          Cross-reference panel
        ├── history_panel.rs       Undo/redo history
        ├── bottom_bar.rs          Status bar + Apply/Remove/Start Game quick actions
        ├── lint_panel.rs          Validation findings + Apply Fix
        ├── backup_panel.rs        Snapshot browser
        ├── conflict_panel.rs      Mod conflict viewer
        ├── library_panel.rs       Mod library + profiles
        ├── templates_panel.rs     Template list + apply
        ├── wizards_panel.rs       Wizard runner
        ├── paloc_panel.rs         Localization editor
        ├── paseq_panel.rs         Sleep mod + NPC swap UI
        ├── xml_panel.rs           XML patcher UI
        ├── hex_view.rs            Paged hex viewer
        ├── command_palette.rs     Ctrl+P palette
        ├── metadata_dialog.rs     Pre-export prompt
        └── settings_panel.rs      App settings
```

## Stats
- 52 source files / ~21K LOC Rust.
- 154 unit tests (152 passing — the two `blob_text` failures pre-date this feature work).
- 11 main views (PabgbTables, Paloc, Paseq, Backups, Lint, Conflicts, Settings, Library, Templates, Wizards, Xml).
- 3 themes, 15 keyboard shortcuts.
- 2 export formats wired to the menu (DMM v3 JSON, DMM Mod Folder); 2 retained for compatibility (workbench v3 JSON, .modpkg).
- 122 pabgb tables parseable via `dmm-parser-rust-only` + iteminfo via dedicated parser.
- Auto-detects Crimson Desert install via Steam registry + library walks.

## Recent fixes (post v0.2)
- **DMM v3 single-file export shape** — moved from the old folder layout
  (`mod.json + metadata.json + README.md`) and the older single-file
  `{ format: 3, target, intents }` shape to the
  `{ modinfo, format: 3, targets: [{ file, intents[] }] }` shape that
  DMM 1.3.3+ ingests directly. Multi-target ready.
- **Bottom-bar quick actions** — Apply / Remove Overlay / Start Game,
  colour-coded, available on every screen so the iterate-and-test loop
  doesn't require the menu.
- **Korean text rendering** — CJK system fonts loaded into egui's font
  family vec so Hangul actually renders instead of boxes.

## Roadmap (open)
- Item icons next to item rows.
- Global search across all loaded tables.
- Crash recovery / autosave.
- Update checker.
- First-run guided tour.
