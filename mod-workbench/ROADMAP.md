# Mod Workbench — Master Plan (Gold-Standard Features)

## North Star
A modding tool on par with **TES5Edit + Mod Organizer 2 + Vortex** for Crimson Desert. Take the guesswork out, surface every relationship, validate before deploy, distribute with confidence.

## Source of Inspiration (Gold-Standard Tools Studied)
- **TES5Edit** — cross-record refs, color-coded conflicts, copy-as-override, error checking
- **Mod Organizer 2** — profiles, virtual filesystem, priority order, archive support
- **Vortex** — one-click conflict resolution, dependency graphs, auto load order
- **Creation Kit** — preset templates, drag-drop relationships, in-context preview
- **WolvenKit (Cyberpunk)** — live preview, asset pipeline, type-aware editor with validation
- **Content Patcher (Stardew)** — hot reload, conditional changes, mod metadata + deps
- **CurseForge / Modrinth** — mod browser, ratings, auto-updates

## User Stated Priorities
1. Field names everywhere (no raw hashes)
2. Persistent config + Steam auto-detect
3. No freezing on big tables (virtualization + search)
4. Cross-table relationships (research folder data)
5. PALOC, PASEQ, PASTAGE editing (skip save integration)
6. Mod distribution
7. Polish (themes, keyboard, tabs, search, icons)

---

# Sprint 1 — Foundations + Catalog

## 1.1 Persistent Config
- `directories::ProjectDirs("com", "Crimson", "ModWorkbench")` → `%APPDATA%/Crimson/ModWorkbench/config.toml`
- Stores: game_dir, window_size, panel_widths, theme, last_table, recent_mods (5)
- Load on startup, save on close + every meaningful change

## 1.2 Steam Auto-Detection
- Read registry: `HKLM\SOFTWARE\WOW6432Node\Valve\Steam` → InstallPath
- Parse `steamapps/libraryfolders.vdf` for additional libraries
- Walk all libraries looking for `Crimson Desert/meta/0.papgt`
- Auto-set on first launch if found; never override user's manual choice

## 1.3 Catalog System (THE big one)
- Load `game_map_complete_v4.json` from `ResearchFolder/` (29 MB)
- Parse to typed `Catalog` struct with sections
- Build inverse indexes:
  - `(table_name, key) → name` for resolution
  - `from_key → Vec<Link>` for cross-ref
  - `to_key → Vec<Link>` for reverse cross-ref
- Lazy load — don't block UI; show progress
- Cache parsed form to disk (`.catalog.bin` via bincode)

## 1.4 Field Name Resolution
- Field editor renders each numeric field with name lookup
- `equip_type_info: 1086980073` → `equip_type_info: 1086980073 (TwoHandSword)`
- `gimmick_info: 1001961` → `gimmick_info: 1001961 (Gimmick_Weapon_00_Socket)`
- String hashes resolved against PALOC catalog
- Hover shows full entry preview

## 1.5 Cross-Reference Panel
- New section in field editor: "Related Entries"
- Lists outgoing + incoming links
- Each link is clickable → loads target table + selects entry
- Back/Forward navigation history (browser-style)

## 1.6 Virtualized Table View
- Already partly there (`TableBuilder::body.rows`)
- Verify performance on 50k-entry tables (multichanges has 17k, drop_sets has 11k)
- Async load with progress bar
- Cache loaded tables in memory (LRU, max 10 cached)
- Switching between cached tables is instant

## 1.7 Universal Search Bar
- Top of entry table panel: TextEdit with placeholder
- Searches: key (numeric/hex/dec), string_key substring, resolved name, all string field values
- Debounced 200ms
- Result count: "47 of 12648 entries"
- Clear button + Esc to reset

## 1.8 Error Toast System
- `Toast { level: Info | Warn | Error, message, details }`
- Bottom-right corner, fade after 5s, click to expand
- Errors include stack/context
- Never panic, never crash — always show error toast and recover

## 1.9 Async Background Worker
- `crossbeam_channel` for UI ↔ worker
- `BackgroundJob` enum: LoadTable, LoadCatalog, Deploy, Search, etc.
- Worker thread pool (rayon)
- UI shows progress per job

---

# Sprint 2 — Editor Power

## 2.1 Field-Level Diff Highlighting
- Compare each field recursively against vanilla
- Colored highlight: changed = orange, added = green, removed = red
- Side-by-side vanilla preview on hover
- "Reset this field" / "Reset this entry" buttons

## 2.2 Undo / Redo with Visual History
- `EditOp { table, entry_key, field_path, old, new, timestamp }`
- Full history stack (no truncation)
- Ctrl+Z / Ctrl+Y
- "History" panel: scroll back through every change
- "Jump to this state" to revert to any prior point

## 2.3 Type-Aware Field Editors
- Detect hash fields → show dropdown of known names
- Detect enum fields → constrain to valid values
- Detect range-bounded fields → use slider with min/max
- Detect color fields (RGBA) → color picker
- Detect arrays of skills/items → "+/-" buttons with autocomplete
- Detect bitmasks → checkbox grid

## 2.4 Multi-Select + Bulk Edit
- Ctrl+click / Shift+click in entry table
- Right-click selection → bulk operations menu
- "Set field X to Y" on all selected
- "Multiply numeric field by N" (math expressions)
- "Reset all to vanilla"
- "Copy fields from entry A to entries B, C, D"

## 2.5 Copy / Paste Entries
- Right-click entry → Copy
- Paste options: Duplicate (new key), Overwrite Fields, Merge Fields
- Cross-table paste of compatible field subsets
- Paste from clipboard JSON

## 2.6 Tabs (Multiple Tables Open)
- Open table → new tab at top of entry panel
- Click tab to switch (instant — already cached)
- Drag to reorder
- Right-click → close, close others, close to right
- Modified indicator on tab title
- Keyboard: Ctrl+W close, Ctrl+Tab cycle

---

# Sprint 3 — Special File Types

## 3.1 PALOC (Localization) Editor
- New tab type for `.paloc` files
- Tabs per language (KOR, ENG, JPN, CHT, GER, FRA, SPA, POR, RUS, TUR, THA, IND, CHS, ARA)
- Edit string values inline
- Add/remove entries
- Search by key or substring
- Export as PALOC overlay
- Syntax highlighting for placeholders (`%s`, `%d`, `{key}`)

## 3.2 PASEQ + PASTAGE Editor
- Sleep mod preset (`False` → `True ` patches at known offsets)
- NPC sequencer swap (file-level swap between NPCs from list)
- Generic byte-level patcher with named patterns
- Preset library: "Remove sleep cooldown", "Make X always available", etc.

## 3.3 iteminfo Special Integration
- Wrap `parse_iteminfo_from_bytes` as a virtual table in registry
- Same UI, but route through dedicated parser
- Unlocks the most-used modding target

---

# Sprint 4 — Validation & Safety

## 4.1 Lint Rules
- Pre-deploy validation pass
- Built-in rules:
  - **InfiniteLoadingRule**: equip_type_info match check (the one we discovered)
  - **MissingDependencyRule**: referenced key exists
  - **OutOfRangeRule**: field within valid range
  - **CircularReferenceRule**: detect loops
  - **OrphanRule**: changes to entries that nothing references
- Display rule violations in bottom panel before allowing deploy
- "Fix automatically" button for some rules

## 4.2 Backup System
- Auto-snapshot before every deploy: `%APPDATA%/Crimson/ModWorkbench/backups/<timestamp>/`
- Backup includes: PAPGT, modified overlay PAZ, mod JSON
- "Restore Point" UI: list snapshots, click to roll back
- Cleanup: keep last 20

## 4.3 Diff Viewer
- Tab-style: "Vanilla | Current | Mod"
- Side-by-side field comparison
- Visual indicator of differences
- Apply individual fields from one side to the other

## 4.4 Mod Conflict Detection
- Load multiple mods → detect overlapping field changes
- Visual conflict graph: which mods touch which entries
- Resolution UI: pick winner per conflict, or merge values
- Color-coded: green = compatible, yellow = partial overlap, red = direct conflict

---

# Sprint 5 — Distribution & Workflow

## 5.1 Mod Metadata Dialog
- Before export: name, author, version, description, nexus_url, dependencies
- Embedded as `_meta` in mod JSON
- Read on import → show metadata card

## 5.2 Mod Packaging (.modpkg)
- Zip with: `mod.json`, `README.md` (auto-gen), `manifest.json` (DMM-compatible), preview screenshots
- Compatible with Definitive Mod Manager + Perfect Mod Loader
- One-click "Export as DMM" / "Export as PML" / "Export as Raw JSON"

## 5.3 Mod Library Browser
- Local: `%APPDATA%/Crimson/ModWorkbench/mods/`
- Cards view: name, author, version, status (active/inactive), conflict warnings
- Drag to reorder priority
- Toggle active/inactive (deploys/restores accordingly)
- Search + filter

## 5.4 Profile / Loadout System
- Multiple named profiles: "Vanilla++", "Custom Game+", "Test Build"
- Each profile = ordered list of active mods
- One-click switch profile (auto-deploys correct overlays)
- Export/import profile (so users can share entire setups)

## 5.5 Templates / Presets Library
- Named templates for common patterns
- Built-in:
  - "God Mode Stats" (max DPV/DDD/HP)
  - "Infinite Stack" (max stack 9999)
  - "All Items 100% Drop" (drop sets)
  - "Lightning Weapon" (elemental passive preset)
- User can save current edits as new template
- Distributable via export

## 5.6 Wizard / Assistant for Common Tasks
- "Create a stat boost mod" — step-by-step
- "Make an item always available" — guided
- "Swap NPC X with Y" — drag-drop
- Each wizard generates the mod via standard editor primitives

---

# Sprint 6 — Polish

## 6.1 Themes
- Dark (default), Light, Crimson (game-themed)
- Custom accent color picker
- Saved per profile

## 6.2 Keyboard Shortcuts
| Key | Action |
|-----|--------|
| F | Focus search |
| F3 | Find next match |
| Ctrl+S | Save mod |
| Ctrl+D | Deploy |
| Ctrl+Z/Y | Undo/redo |
| Ctrl+W | Close tab |
| Ctrl+Tab | Cycle tabs |
| Ctrl+, | Settings |
| Ctrl+P | Quick action palette |
| Esc | Clear selection |

## 6.3 Item Icons
- Load icon cache from game data
- Show 32x32 next to item rows
- Tooltip with full info

## 6.4 Global Search Palette
- Ctrl+P opens command palette (VS Code style)
- Search across all loaded tables
- Search commands ("Deploy", "Restore", etc.)
- Recent items at top

## 6.5 Notes / Annotations
- Right-click entry → Add Note
- Per-entry note saved in mod JSON
- "Why I changed this" docs travel with mod
- Notes visible in field editor

## 6.6 Live Hot-Reload (Where Possible)
- After deploy, watch overlay PAZ for changes
- Detect game-loaded state via process inspection
- Auto-redeploy if mod updated while game running
- Soft warning if game won't pick up change without restart

## 6.7 Crash Recovery
- Auto-save state every 30s to `<config>/autosave.bin`
- On crash: detect dirty state on next launch
- Offer recovery: "Restore unsaved changes from <timestamp>?"

## 6.8 Tutorial / Help System
- First-run guided tour
- Click "?" on any field for explanation
- Searchable help panel (Ctrl+/)
- Links to community wiki

## 6.9 Update Checker
- Check GitHub releases on startup (configurable)
- Notify if newer version available
- One-click update button

---

# Implementation Order (For Agents)

Each agent gets a self-contained task. Tasks within a wave run in parallel; waves run sequentially.

## Wave 1 (Foundations)
- **A1.1** Config persistence module
- **A1.2** Steam detection module
- **A1.3** Catalog parser + indexes (loads game_map_complete_v4.json)
- **A1.4** Background worker infrastructure (channel + jobs)
- **A1.5** Toast/error system

## Wave 2 (Catalog Integration)
- **A2.1** Field name resolution in field_panel
- **A2.2** Cross-reference panel
- **A2.3** Universal search bar with catalog-aware matching
- **A2.4** Virtualization audit + perf tuning

## Wave 3 (Editor Power)
- **A3.1** Field diff highlighting + reset buttons
- **A3.2** Undo/redo + history panel
- **A3.3** Type-aware field editors
- **A3.4** Multi-select + bulk edit
- **A3.5** Copy/paste entries
- **A3.6** Tabs system

## Wave 4 (Special Files)
- **A4.1** PALOC editor
- **A4.2** PASEQ/PASTAGE editor
- **A4.3** iteminfo special integration

## Wave 5 (Validation)
- **A5.1** Lint rule framework + InfiniteLoadingRule
- **A5.2** Backup/snapshot system
- **A5.3** Diff viewer
- **A5.4** Conflict detection

## Wave 6 (Distribution)
- **A6.1** Mod metadata dialog
- **A6.2** Mod packaging (modpkg)
- **A6.3** Mod library browser
- **A6.4** Profile system
- **A6.5** Templates library
- **A6.6** Wizards

## Wave 7 (Polish)
- **A7.1** Theme system
- **A7.2** Keyboard shortcuts
- **A7.3** Item icons
- **A7.4** Command palette
- **A7.5** Notes/annotations
- **A7.6** Crash recovery
- **A7.7** Tutorial
- **A7.8** Update checker

After each wave: build verify, integration test, fix issues. Document at every step.
