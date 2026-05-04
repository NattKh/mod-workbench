# `.palevel` / `.pamhc` / `.pab` Format Research

Reverse-engineered from the Mac retail binary on 2026-05-04. All three
extensions are now byte-level editable via the Binary Inspector.
Structural editor planning is below per format.

## `.pamhc` — Model Property Header Collection (FULLY DECODED)

Single file: `miscellaneous/modelpropertyheadercollection.pamhc`.

**Loader**: `sub_102484E3C` (size `0x248`).

### File layout

```
Offset  Size  Field
+0x00   8     skip (read but discarded — likely a magic / version)
+0x08   4     u32  section_a_size  (must satisfy `(size & 3) == 0`)
+0x0C   4     u32  section_b_size
+0x10   4     u32  section_c_size
+0x14   4     u32  section_d_size
+0x18   4     u32  section_e_size  (or terminator)
+0x1C   var   payload — sections concatenated in order
```

In-memory bookkeeping (mirror of disk):

| Mem offset | Disk meaning |
|---|---|
| `+16` | 28 (section_a start) |
| `+20` | section_a_end (= 28 + size_a) |
| `+24` | section_b_end |
| `+28` | section_c_end |
| `+32` | section_d_end |
| `+36` | size_a / 4 = entry count of section A (so section A is u32 entries) |

### Structural editor notes

- 5 typed sections + 28-byte header, well-bounded.
- Section A is u32-entries (per `>>2` count). Other sections' element sizes need walking inner consumers.
- A structural editor would: parse 28-byte header → display per-section size + count → expose section A as a u32 array editor → other sections as hex view sub-panes.
- Round-trip is trivial — sections are just byte ranges, recompute the 5 sizes when editing.

**Effort**: small. This is graduable to a structural editor in one
focused agent session.

**Status (2026-05-04)**: structural editor SHIPPED. Parser at
`dmm-parser-rust-only/src/tables/pamhc/`, backend at
`mod-workbench/src/pamhc_editor.rs`, panel at
`mod-workbench/src/ui/pamhc_panel.rs`. 5-tab UI: Section A as `u32`
array editor + B/C/D/E paged hex viewers. Default overlay group `0072`.

## `.palevel` — Level / Sector Data (PARTIAL — discoverer mapped, deserializer pending)

Path patterns (from `sub_101A04078` path builder):
- `LevelData/<world>/<level>.palevel` (top-level)
- `LevelData/<world>/SectorLevel/<sector>.palevel` (sector / sub-level)
- `*.palevel_xml` (dev-build XML companion — already covered by the
  workbench's XML editor when the user has dev assets)

**Discoverer / loader**: `sub_101A0AEB0` (size `0xC58`).

This function:
1. Globs `*.palevel_xml` if `byte_10858E8A9 == 1` (dev mode), else
   globs `*.palevel` from the `bin__/` directory.
2. For each file found:
   - `sub_1006BF934` reads the file's path stem.
   - `sub_101A01E84(name)` parses the name into a 64-bit ID / coord
     (returns sentinel `0x7FFFFFFF` on failure).
   - Allocates a 0x1C8-byte (456-byte) `pa::SceneLevelData` via
     `sub_1005EA740`.
   - `sub_1019FEF3C` runs the constructor.
   - `sub_101A01FD4(scene_data, &id, 1)` populates the in-memory
     ID. This is the entry point to the file deserializer — its
     internals haven't been walked yet.
   - `sub_101A01A68` and `sub_101A0978C` install bounding-box +
     attach the loaded scene to the parent level container.

### What's editable today

- Byte-level via the Binary Inspector (added in this round).
- The XML companion path (`palevel_xml`) is already covered by the
  XML Tree Editor when you point at one.

### Structural editor effort — REVISED 2026-05-04

Walked `sub_101A01FD4` and `sub_101A0978C`:

- `sub_101A01FD4` is a **recursive ID-stamp** — walks a tree at
  `[ptr+216]` (children array, count at `[ptr+224]`), copies the
  ID into `[node+424]` of every node. Not the file deserializer.
- `sub_101A0978C` is a **parent-link / LOD-stack** function — walks
  `dword_10858E8F4` ancestors and appends a back-reference. Also
  not the deserializer.

**The discovery loop never reads file bytes.** It enumerates
`*.palevel` in PAZ, parses the filename into an ID, allocates a
`pa::SceneLevelData`, registers name + bbox + parent. The actual
**`.palevel` file content is loaded lazily** when the engine
streams a region in, not during this discovery pass.

To find the lazy-load deserializer we'd need to:
1. Identify the streaming trigger (probably a "load level by ID"
   call that bottoms out in PAZ extract → `sub_???_deserialize`).
2. Decompile that deserializer to capture the per-file schema.

**Revised effort**: large. Multi-session reverse-engineering
project. Defer until a specific mod use-case provides the streaming
trigger as a concrete entry point.

For now, byte-level via Binary Inspector remains the supported
path. The XML companion (`*.palevel_xml`) is already covered by
the XML editor.

## `.pab` — Skeletal Volume / Bone Container (3D-adjacent — not researched in depth)

Companion files: `*.pab` (binary) + `*.pab.sockets.xml` (XML
sidecar with named bone sockets).

Error strings the binary references:

- `"스켈레톤의 스켈레탈 볼륨 파일[%s] 로드를 실패했습니다. 다음 .pab/.pb 파일을 확인해 주세요"`
  ("Skeleton's skeletal-volume file load failed. Check the .pab/.pb file.")
- `"메쉬의 스켈레탈 볼륨 파일[%s] 로드를 실패했습니다. 다음 .pac/.pc 파일을 확인해 주세요"`

So `.pab` is the per-skeleton **collision-volume** definition file —
bone-attached capsules / boxes used for hit detection. Companion
`.pab.sockets.xml` carries named attachment sockets (handles, weapon
mount points, etc).

### What's editable today

- Byte-level via the Binary Inspector (added in this round). Modders
  with a known recipe (e.g. "shrink hit-volume on bone X by Y%") can
  apply byte patches.
- The `.pab.sockets.xml` companion is plain XML — already covered by
  the XML Tree Editor.

### Structural editor effort

- Format is the only real 3D-adjacent file in this batch — bone
  hierarchy + collision shape primitives. Low gameplay-modding value
  unless someone wants to tweak hit-volume sizes (which the byte-
  level editor handles).
- **Effort**: high. A real `.pab` editor would need a bone-tree UI +
  per-volume edit (capsule radius, box size, offset). Out of scope
  for byte-level tooling. Defer or use external 3D pipeline tools.

## Summary

| Format | Byte-level | Structural editor | Recommendation |
|---|---|---|---|
| `pamhc` | ✅ shipped | ✅ shipped (2026-05-04, default overlay `0072`) | done |
| `palevel` | ✅ shipped | ⏸ deferred — deserializer is buried in resource-manager indirection (vtable+64 lazy load), needs multi-session RE | graduate when a concrete mod use-case provides the streaming entry point |
| `pab` | ✅ shipped | ⏸ deferred — 3D bone-tree + shape primitives, low gameplay-modding value | leave at byte level |

Byte-level coverage in the Binary Inspector means modders with a
recipe can apply patches to any of the three today, even before the
structural decoders land.
