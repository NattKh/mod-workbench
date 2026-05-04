# Crimson Desert File-Format Catalog

Survey of every `.pa*`-extension file format the game loads, and the
workbench's status for each. Compiled from a string-table sweep of the
Mac retail binary (`CrimsonDesert_Steam`) on 2026-05-04, with loader
function addresses captured for future structural decode work.

## Coverage status legend

- ✅ **Full editor** — structural parser + dedicated UI panel.
- 🔧 **Byte-level editor** — Binary Inspector panel handles it (find/
  replace byte patches, deploy as PAZ overlay). Schema not decoded.
- ⛔ **Out of scope** — 3D, texture, audio, video, picture, shader, or
  deprecated debug-only. Not addressed by the workbench.
- ❓ **Not yet wired** — known to exist but not listed in any panel.

## Editable formats — covered

| Ext | Status | Panel | Notes |
|---|---|---|---|
| `pabgb` / `pabgh` | ✅ | PABGB Tables | 122 tables, full struct edit |
| `xml` | ✅ | XML Editor | Tree edit + patch builder |
| `paloc` | ✅ | PALOC Editor | 14 languages |
| `paseq` / `paseqc` / `pastage` | ✅ | PASEQ Editor | Presets + byte patcher |
| `paatt` | ✅ | PAATT Editor | Physics / projectile attrs |
| `paac` | ✅ | PAAC Editor | Action chart heuristic walk |
| `pappt` | ✅ | PAPPT Editor | Character part-prefab table |
| `pamhc` | ✅ | PAMHC Editor | Model property header collection (5-section, A as `u32` array) |
| `papgt` / `pamt` | ✅ | Archive Inspector | Read + revert overlays |
| `paschedule` | 🔧 | Binary Inspector | NPC schedule data, 3997 files |
| `paschedulepath` | 🔧 | Binary Inspector | Path companion to paschedule |
| `paschedulectx` | 🔧 | Binary Inspector | Singleton schedule context |
| `paseqh` | 🔧 | Binary Inspector | `sequencerStageHeader.paseqh` |
| `uianiminit` | 🔧 | Binary Inspector | UI animation init data, 866 files |
| `pai` | 🔧 | Binary Inspector | AI charts (`aichart.pai`, `PathFindTable.pai`) |
| `patag` | 🔧 | Binary Inspector | `tag.patag`, declarative tags |
| `padock` | 🔧 | Binary Inspector | NPC docking data |
| `pabc` / `paccd` / `pasg` / `parg` / `pati` | 🔧 | Binary Inspector | Unknown formats, byte-level only |
| `paem` | 🔧 | Binary Inspector | Effect emitter data (borderline 3D — opt-in) |
| `paver` | 🔧 | Binary Inspector | Build version metadata (`meta/0.paver`) |
| `pacpph` | 🔧 | Binary Inspector | Compiled-script header (`objectList.pacpph`) |
| `palevel` | 🔧 | Binary Inspector | Level / sector streaming data (companion `palevel_xml` covered by XML editor) |
| `pab` | 🔧 | Binary Inspector | Skeletal collision volumes (companion `pab.sockets.xml` covered by XML editor) |

## Out of scope (per user direction — no 3D / texture / audio / shader)

| Ext | Reason |
|---|---|
| `paa` | Animation data (3D) |
| `pam` / `pamlod` / `pampg` / `pami` | Mesh data (3D) |
| `pac` | Skinned mesh / animation curves (3D) |
| `pat` | Tree / vegetation mesh (3D) |
| `pati` | Mostly tree-related — but text says `.pati` so we kept it byte-editable |
| `pasound` | Audio (Wwise soundbanks) |
| `padxil` | DXIL shader bytecode (3D) |
| `pareflect` | Reflection probe baked data (graphics) |
| (paem moved to byte-level coverage above) | (was skipped — added opt-in 2026-05-04) |
| (palevel / pamhc / pab moved to byte-level coverage above 2026-05-04) | (companion XML files already covered by XML editor) |
| `palevel_xml` | Already covered by XML Tree Editor (dev-build companion) |
| `paasmt` | Animation matching table (3D) |
| `pathc` | Texture header collection |
| `pagputracer` | GPU debug tracer artefact |
| `pacpp.o` / `pacpph` | Native code object (script bytecode — skip; scripting layer) |

## Loader function catalogue

These are the functions to decompile when graduating a 🔧 entry to ✅.

| Loader | Address | Reads | Notes |
|---|---|---|---|
| Schedule top-level | `0x10167AD30` | `*.paschedule`, `scheduleContext.paschedulectx` | Globs schedule files, then loads context once |
| Schedule per-file | `0x10167B2DC` | `.paschedule` | Allocates 0xD0 (208-byte) object, calls deserializer |
| Schedule deserializer | `0x101677EEC` | `.paschedule` | **Full schema** — see `PASCHEDULE_FORMAT_RESEARCH.md` |
| Schedule path | `0x10167E924` | `.paschedulepath` | Companion to paschedule, schema not walked |
| Schedule ctx pass 1 | `0x101685210` | `.paschedulectx` | First section of context |
| Schedule ctx pass 2 | `0x100C60704` | `.paschedulectx` | Second section |
| Schedule ctx pass 3 | `0x10168541C` | `.paschedulectx` | Third section |
| Sequencer stage header | `0x10787DBB0` | `sequencerStageHeader.paseqh` | Single per-stage |
| UI anim init | `0x102F7E858` | `.uianiminit` (size 0x21CC) | Heavy loader |
| Road | `0x1013ED79C` | `*.road` | Pathfinding — out of scope (3D-adjacent) |
| Reflection probe | `0x103440FA4` | `.pareflect` | Out of scope (graphics) |
| Sentry message | (debug telemetry) | — | Skip |

## AI chart class hierarchy (for future `pai` structural editor)

The Mac binary RTTI strings show a deep AI behaviour-tree class system.
Each node type is registered as a `pa::CompressedObjectMemoryPool`
specialisation. Decompiling any of these gives you a slot in the
behaviour tree:

- **Packages** (top-level grouping):
  `AIPackage_Normal`, `AIPackage_PathFind`, `AIPackage_PathMove`,
  `AIPackage_Flow`.
- **States**: `AIState`, `AIState_TeleportDesc`, `AIState_DockingDesc`.
- **Branches** (decision nodes):
  `AIBranch_Normal`, `AIBranch_FindTarget`, `AIBranch_PathSegment`,
  `AIBranch_CheckPoint`, `AIBranch_PrevPathFind`, `AIBranch_OnArrived`,
  `AIBranch_Flow`, `AIBranch_FlowExit`, `AIBranch_HideBattleTable`,
  `AIBranch_Debug`.
- **Containers**: `AIBranchContainer`, `AIFunctionOrBranch`,
  `AIPackageAttribute`, `AIPackageAttributeContainer`.
- **Conditions**: `AIConditionStatement`.
- **PathFind descriptors**:
  `AIPathFindDesc_DestinationDesc`, `AIPathFindDesc_ETC`.
- **Function nodes** (action verbs — 20+ variants of `AIFunction_*`):
  `AIFunction_TryAppendPath`,
  `AIFunction_SetDestination_MoveToAiEvent`,
  `AIFunction_SetDestination_MoveToInteraction`,
  `AIFunction_SetDestination_MoveToLandingPosition`,
  `AIFunction_SetDestination_ToRandomAirPosition`,
  `AIFunction_SetDestination_MoveToSplinePatrol`, ...

A structural editor for `.pai` would mirror the paac panel's tree
view — a behaviour-tree visualiser with per-node typed editors. Not
attempted yet — graduate from byte-level when there's time.

## Plan — graduating byte-level to structural

Order of priority (by user-visible value × decode effort):

1. `pai` — AI charts modify enemy behaviour. High user value.
2. `paschedulectx` — singleton, three sections, smaller decode than
   per-NPC schedules.
3. `paschedule` — partial schema documented; fields +24..+44 are
   simple scalars and can be exposed first as a "header only" view
   while inner structs stay byte-level.
4. `paschedulepath` — companion; can wait.
5. `pappt` — single file, character-mod relevance. Decode after we
   land at least one character mod that needs it.

Each graduation is one IDA session + one Rust module + one panel
extension. None blocks the others.

## What's locked in

The Binary Inspector handles every 🔧 entry right now, so users can
already edit any of these formats at the byte level even before
structural decode. Schema research can land incrementally without
blocking shipping.
