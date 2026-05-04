# `.paschedule` / `.paschedulepath` / `.paschedulectx` Format Research

Reverse engineered from the macOS retail binary
(`CrimsonDesert_Steam.app/Contents/MacOS/CrimsonDesert_Steam`) on
2026-05-04.

## File-type inventory

Live extension survey from `extractedpaz/0014_full/sequencer/`:

| Extension | Count | Description (inferred) |
|---|---|---|
| `.paschedule` | 3997 | Per-NPC schedule entry (one file per NPC) |
| `.paschedulepath` | 3997 | Companion path data (1:1 with paschedule) |
| `.paschedulectx` | 1 | Schedule context (single global file) |

In-game directory layout: `sequencer/binary__/` contains all three.
Loader globs `*.paschedule` first, then for each, looks up the matching
`%#.paschedulepath`. The `scheduleContext.paschedulectx` is a singleton
loaded once after all per-NPC schedules.

## Loader entry points (Mac, image base `0x100000000`)

| Function | Address | Role |
|---|---|---|
| `sub_10167AD30` | `0x10167AD30` | Top-level scheduler init. Globs `*.paschedule`, loads each, then loads `scheduleContext.paschedulectx`. |
| `sub_10167B2DC` | `0x10167B2DC` | Per-file paschedule loader. Allocates a 0xD0 (208-byte) object, calls deserializer. |
| `sub_10167E924` | `0x10167E924` | paschedulepath loader / merge function. Called from the paschedule loop after a paschedule file is parsed. |
| `sub_101677EEC` | `0x101677EEC` | **paschedule deserializer.** Reads the file into the 208-byte object. This is the schema. |

## paschedule object layout (208 bytes)

Captured from constructor + deserializer at
`sub_10167B2DC` / `sub_101677EEC`:

| Offset | Size | Type | Reader call | Notes |
|---|---|---|---|---|
| +0 | 8 | vtable ptr | const `off_107928B68` | identifies the class |
| +8 | 8 | weak-ref ptr | — | shared_ptr backing |
| +16 | 4 | refcount (u32) | — | atomic |
| +20 | 1 | kind (u8) | — | always 1 (atomic-refcount discriminator) |
| +21 | 1 | (padding) | — | |
| +22 | 1 | "loaded" flag (u8) | — | set to 1 after successful load |
| +24 | 4 | u32 | `sub_1006B907C` | id1 — generic u32 reader |
| +28 | 4 | u32 | `sub_1006B907C` | id2 |
| +32 | 4 | enum / hash | `sub_10137FE5C` | typed enum (positional reflect) |
| +36 | 4 | string-key (u32) | `sub_100F3BB18` | hashlittle-style string ref |
| +40 | 2 | u16 | (computed via CharacterInfo lookup from a deserialized u32 character key) | resolved CharacterKey index |
| +42 | 2 | (padding) | — | |
| +44 | 4 | u32 | `sub_1006B907C` | id3 |
| +48 | 16 | smart-pointer | `sub_1006B924C` | secondary object reference (`pa::SharedPtr<T>`-shape) |
| +56 | 2 | flags (u16) | `sub_101678428` | typed reader |
| +58 | 1 | bool | virtual `vtable[2]` | runtime-typed boolean |
| +64 | 16 | struct (Vec3 or similar) | `sub_1016825C4` | first inline struct |
| +80 | 16 | struct | `sub_101682964` | second inline struct |
| +96 | 16 | struct | `sub_101682E5C` | third inline struct |
| +112 | 16 | struct | `sub_101683218` | fourth inline struct |
| +128 | 48 | struct (large) | `sub_101683580` | quaternion+vec or transform-shape |
| +144 | 16 | array #1 (header) | inline loop of `sub_1016C2B08` | each element 0x28 (40 bytes) |
| +160 | 16 | array #2 (header) | inline loop of `sub_1016C2B08` | each element 0x28 (40 bytes) |
| +176 | 16 | struct | `sub_1006B909C` | small inline struct |
| +192 | 16 | struct | `sub_10168381C` | small inline struct |

### Array element format (`sub_1016C2B08`)

40 bytes each. Allocated via `sub_1005EA740(0x28)`. Schema not yet
walked — needs follow-up decompile of `sub_1016C2B08`. Refcounting
header at +16/+20 (kind, refcount). The user-visible payload is at
~+24..+40.

## Wire format (file bytes)

Sequential — fields written in object-layout order. No header
length prefix at the file level; the per-field readers know their
own widths.

Helper reader catalogue (from the deserializer call list):

| Helper | Reads |
|---|---|
| `sub_1006B907C` | u32 |
| `sub_1006B909C` | u64 / 16-byte struct |
| `sub_1006B924C` | shared_ptr (refcounted indirect) |
| `sub_10137FE5C` | enum / hash |
| `sub_100F3BB18` | string-key (4 bytes, looked up against a hash table) |
| `sub_101678428` | flags (typed) |
| `sub_1016825C4` | first inline struct (16B) |
| `sub_101682964` | second inline struct (16B) |
| `sub_101682E5C` | third inline struct (16B) |
| `sub_101683218` | fourth inline struct (16B) |
| `sub_101683580` | large inline struct (48B) |
| `sub_10168381C` | trailing inline struct (16B) |
| `sub_1016C2B08` | array element (40B) |

## paschedulepath / paschedulectx

- **`.paschedulepath`** loaded by `sub_10167E924` (size 0x3C0). Called
  AFTER the paschedule file finishes parsing. Likely a navmesh path
  graph (waypoints, segments). Schema not yet walked.
- **`.paschedulectx`** is a single global file loaded via
  `sub_101685210`, `sub_100C60704`, `sub_10168541C` (called from
  `sub_10167AD30` after the per-NPC loop). Three deserialization
  passes — likely three sections: contexts, links, transitions.
  Schema not yet walked.

## Realistic editor scope

A faithful structural Rust port of `sub_101677EEC` (and its 13+ inner
helpers) is a multi-week reverse-engineering project. For the workbench
the practical move is:

1. **Byte-level inspector + patcher** for all three extensions plus the
   adjacent unknowns (`.paseqh`, `.uianiminit`). Modeled on the existing
   PASEQ "Editor" tab — file picker, hex view, named find/replace
   patches, deploy as PAZ overlay, save/load patch JSON.
2. **Field-aware overlay** — for paschedule specifically, expose the
   first 9 fields (the simple u32/string/u16 ones at offsets +24..+44)
   as named scalars on top of the byte view. Users can edit those
   safely without understanding the rest.
3. **Format research** continues in parallel — each subsequent IDA
   session can decompile one of the inner deserializers and grow the
   field-aware view.

The "byte-level inspector" approach handles every unknown format in
the game with a single panel, scaling far better than per-format
structural editors. We already proved this pattern works in
`paseq_panel.rs::Editor`.

## Other unknown extensions surveyed

| Extension | Mac loader | Notes |
|---|---|---|
| `.paseqh` | `sub_10787DBB0` (`sequencerStageHeader.paseqh` string ref) | Stage-header file — single per-stage. Used for binding sequencer stages to scenes. |
| `.uianiminit` | `sub_102F7E858` (size 0x21CC) | UI animation init data. Heavy — schema decode would mirror animation bake state. |
| `.road` | `sub_1013ED79C` | Pathfinding data (out of scope per "no 3D" rule — flagged as 3D-adjacent). |
| `.pabg_b` / `.pabg_h` | (variant of pabgb — 16/15 files, same prefix) | Likely a debug or alt-build of pabgb. Existing pabgb pipeline should handle once we add the alt-extension to the scanner. |

## Suggested next move for the workbench

Add a single new panel `BinaryFileInspector` that handles `.paschedule`,
`.paschedulepath`, `.paschedulectx`, `.paseqh`, `.uianiminit`, and
treats anything else with a known PAZ home as opt-in via a config list.
Reuse the PASEQ "Editor" mode shape verbatim — the user already knows
that workflow.
