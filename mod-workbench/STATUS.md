# Mod Workbench — Build Status

## Current State (autonomous build session 2026-05-03)

**Build**: Clean (`cargo check`, `cargo build`, 132/132 tests pass)
**Binary**: `target/debug/mod-workbench.exe` (~22 MB debug)

## Modules Implemented

### Foundations
- `config.rs` — persistent config in `%APPDATA%/Crimson/ModWorkbench/config.toml`
- `steam.rs` — Steam library auto-detection via registry + libraryfolders.vdf
- `catalog.rs` + `catalog_loader.rs` — loads `game_map_complete_v4.json` (29 MB), 161 sections, 41,974 cross-table links, 38,246 PALOC strings, dispatch→section name mapping
- `worker.rs` — background thread for table loads, catalog loads, deploy, restore (non-blocking UI)
- `toast.rs` — multi-level notifications (Info/Warn/Error) with timeout + click-to-expand
- `theme.rs` — Dark / Light / Crimson themes

### Editor Power
- Field-level diff highlighting (orange "●" indicator, vanilla tooltip, reset buttons)
- `edit_history.rs` — full undo/redo with visible history panel + "jump to state"
- Type-aware editors: hex toggle for hashes, color picker for RGBA, bitmask checkbox grid, percent slider for rates, catalog dropdown for hash references
- Multi-tab system (`open_tabs` + `active_tab_idx`), tab modified indicator, Ctrl+W close, Ctrl+Tab cycle

### Catalog Integration
- Field name resolution (numeric IDs → resolved names from catalog, e.g. `gimmick_info: 1001961 (Gimmick_Weapon_00_Socket)`)
- Cross-reference panel (outgoing + incoming links, click to jump to target table+entry)
- Catalog-aware search (matches key, string_key, resolved name, any string field)
- Debounced filtering (200ms), virtualized rendering (50k+ rows)

### Special File Types
- `paloc_editor.rs` — PALOC localization editor (14 languages, multiline string edit, overlay deploy)
- `paseq_editor.rs` — Sleep mod (False→True patches), NPC sequencer swap (file-level replacement)

### Validation
- `validation.rs` — lint framework with `LintRule` trait, `LintRunner`
  - **InfiniteLoadingRule** — catches the elemental-passives-on-non-weapon bug we discovered
  - **MissingDependencyRule** — flags references to non-existent keys
  - **NumericRangeRule** — out-of-range field values
  - Auto-fix support, deploy gating (errors block deploy with confirmation)

### Backup / Conflict
- `backup.rs` — auto-snapshot before every deploy, restore any prior state, retain last 20
- `conflict.rs` — load multiple mods, detect direct conflicts + partial overlaps, severity-coded UI

### Distribution
- `mod_package.rs` — three exporters: raw v3 JSON, .modpkg zip (with auto-README), DMM bundle
- `metadata_dialog.rs` — name/author/version/description/nexus/dependencies prompt before export
- `mod_library.rs` — local mod library at `%APPDATA%/Crimson/ModWorkbench/mods/`
- `profile.rs` — named profiles (Vanilla++ / Custom / Test), one-click apply, ordered priority
- `templates.rs` — built-in templates (God Stats, Infinite Stack, Free Items, 100% Drop, etc.) + user templates
- `wizards.rs` — guided flows (StatBoostWizard, BlankTemplateWizard) with multi-step UI

### UX
- `command_palette.rs` — Ctrl+P searchable action/entry/table/mod palette (VS Code style)
- `notes.rs` — per-entry text annotations, embedded in mod export, 📝 indicator in entry table
- `settings_panel.rs` — game dir, catalog, theme, snapshot retention
- 15 keyboard shortcuts (F, F3, Ctrl+S/D/R/Z/Y/W/Tab/L/P/,/Esc, Ctrl+Shift+S/Z/Tab)

## Architecture

```
mod-workbench/
├── Cargo.toml                  (deps: dmm-parser-rust-only, eframe, egui_extras, zip, ...)
├── src/
│   ├── main.rs                 entry point
│   ├── app.rs                  WorkbenchApp + eframe::App impl + action handlers
│   ├── state.rs                AppState + ActiveTable + ChangeTracker
│   ├── config.rs               Config load/save
│   ├── steam.rs                Steam install detection
│   ├── catalog.rs              Catalog (game_map_complete_v4.json)
│   ├── catalog_loader.rs       try_load wrapper
│   ├── worker.rs               BG worker (Job/Reply via mpsc)
│   ├── toast.rs                ToastManager
│   ├── theme.rs                apply_theme(ctx, theme)
│   ├── edit_history.rs         EditOp + EditHistory
│   ├── notes.rs                NoteStore
│   ├── validation.rs           LintRule + 3 built-in rules
│   ├── backup.rs               Snapshot system
│   ├── conflict.rs             Mod conflict analyzer
│   ├── mod_io.rs               v3 JSON import/export + ModMetadata
│   ├── mod_package.rs          modpkg/DMM exporters
│   ├── mod_library.rs          Library scan/import/delete
│   ├── profile.rs              Profile + ProfileStore
│   ├── templates.rs            Template + builtin
│   ├── wizards.rs              Wizard trait + 2 implementations
│   ├── paloc_editor.rs         PALOC load/save
│   ├── paseq_editor.rs         Sleep mod + NPC swap
│   ├── deploy.rs               Deploy with auto-snapshot
│   ├── restore.rs              Remove overlay
│   ├── table_loader.rs         Extract+parse via dmm-parser-rust-only
│   ├── table_registry.rs       122-table registry
│   └── ui/
│       ├── mod.rs
│       ├── tab_bar.rs          Multi-tab switcher
│       ├── table_list.rs       Left panel (122 tables)
│       ├── entry_table.rs      Center panel (entries with virtualized rows + search)
│       ├── field_panel.rs      Right panel (recursive editor with name resolution + reset)
│       ├── xref_panel.rs       Cross-reference panel
│       ├── history_panel.rs    Undo/redo history
│       ├── bottom_bar.rs       Status bar
│       ├── lint_panel.rs       Validation findings + Apply Fix
│       ├── backup_panel.rs     Snapshot browser
│       ├── conflict_panel.rs   Mod conflict viewer
│       ├── library_panel.rs    Mod library + profiles
│       ├── templates_panel.rs  Template list + apply
│       ├── wizards_panel.rs    Wizard runner
│       ├── paloc_panel.rs      Localization editor
│       ├── paseq_panel.rs      Sleep mod + NPC swap UI
│       ├── command_palette.rs  Ctrl+P palette
│       ├── metadata_dialog.rs  Pre-export prompt
│       └── settings_panel.rs   App settings
```

## Stats
- **40 source files**
- **~10,000 LOC Rust**
- **132 unit tests** all passing
- **8 main view modes** (PabgbTables, Paloc, Paseq, Backups, Lint, Conflicts, Library, Templates, Wizards, Settings)
- **3 themes**, **15 keyboard shortcuts**, **3 export formats**
- **Auto-detects Crimson Desert install** via Steam registry + library walks
- **122 pabgb tables** parseable via dmm-parser-rust-only

## Next (Wave 8+ if needed)
- Item icons next to item rows (Phase 7.4)
- Global search across all loaded tables (Phase 7.5)
- iteminfo special integration (Phase 4.3 — currently uses dedicated parser, not in dispatch)
- Crash recovery / autosave
- Update checker
- Tutorial / first-run tour
