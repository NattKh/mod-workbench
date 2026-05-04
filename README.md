# Crimson Desert Mod Workbench

A standalone Rust desktop tool (egui) for editing Crimson Desert game data.
Browses every parseable pabgb table, edits fields with type-aware widgets, and
deploys mods as PAZ overlays.

## Layout

```
mod-workbench/          The egui app (binary crate)
dmm-parser-rust-only/   Pure-Rust fork of dmm-parser (no PyO3, used as a
                        path dependency by mod-workbench)
```

## Build

Requires Rust 1.78+ (edition 2021).

```sh
cd mod-workbench
cargo build --release
# binary at: mod-workbench/target/release/mod-workbench.exe
```

Or use `mod-workbench/build_release.bat` on Windows for a guided build.

## Features

See `mod-workbench/STATUS.md` for the current feature list and architecture
inventory, and `mod-workbench/ROADMAP.md` for historical implementation
sprints.

Headlines:
- 122 pabgb tables (+ iteminfo via dedicated parser), full parse / serialize round-trip
- Async loading, virtualized 50K+ row tables, debounced search
- Catalog (`game_map_complete_v4.json`) integration: name resolution + cross-refs
- PALOC localization (EN + KR) with disk cache; CJK font loading for Korean rendering
- Field-level diff highlighting, undo/redo, type-aware editors
- DMM 1.3.3+ Field JSON v3 export (single self-contained `.json`, `modinfo + targets[]`)
- PAZ overlay mod folder export (`<name>/<group>/0.paz + 0.pamt + modinfo.json`)
- Quick-test loop: Apply to Game / Remove Overlay / Start Game from the bottom bar
- Lint rules (catches the infinite-loading equip-type bug)
- Backup / snapshot system, conflict detection, profiles, templates, wizards
- 3 themes, 15 keyboard shortcuts, command palette

## License

This project ships under two compatible licenses:

- **Mod Workbench** (everything under `mod-workbench/`) — Crimson Desert
  Mod Workbench License v1.0 (CDMWL v1.0). See
  [`mod-workbench/LICENSE.txt`](mod-workbench/LICENSE.txt). Copyright
  © 2026 NattKh.
- **dmm-parser-rust-only** (everything under `dmm-parser-rust-only/`)
  — Crimson Desert Modding Tools License v1.0 (CDMTL v1.0). See
  [`dmm-parser-rust-only/LICENSE.txt`](dmm-parser-rust-only/LICENSE.txt).
  Copyright © 2026 RicePaddySoftware.

Both licenses are copyleft, source-available, and non-commercial. CDMWL
v1.0 is structurally modeled on CDMTL v1.0 and is intended to operate
compatibly with it; the Workbench is designated as part of the
Authorized Software Suite under CDMTL v1.0 §1(g). Read both licenses
before redistributing, forking publicly, or building derivative tools.

The licenses include enforceable AI-mediated-access clauses (CDMWL §4.10
/ CDMTL §4.10): prompting an AI assistant or autonomous coding agent to
read, summarize, refactor, port, or replicate this work constitutes
acceptance of the License, and any knowledge so extracted is imputed to
the human user under §4.10.3.
