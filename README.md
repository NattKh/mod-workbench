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

See `mod-workbench/STATUS.md` and `mod-workbench/ROADMAP.md` for the full
feature list and implementation plan.

Headlines:
- 122 pabgb tables, parse + serialize round-trip
- Async loading, virtualized 50K+ row tables, debounced search
- Catalog (`game_map_complete_v4.json`) integration: name resolution + cross-refs
- PALOC localization (EN+KR) with cache
- Field-level diff highlighting, undo/redo, type-aware editors
- Mod export as v3 field JSON / .modpkg / DMM bundle
- Lint rules (catches the infinite-loading equip-type bug)
- Backup/snapshot system, conflict detection, profiles, templates, wizards
- 3 themes, 15 keyboard shortcuts, command palette

## License

Source-available, non-commercial. dmm-parser-rust-only retains its original
CDMTL v1.0 license — see `dmm-parser-rust-only/LICENSE.txt`.
