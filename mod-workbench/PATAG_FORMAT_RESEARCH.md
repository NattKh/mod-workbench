# .patag Format Research

`.patag` is a serialized `pa::TagManager` reflection object that the engine loads through PA's standard reflection framework. The class is registered by the global asset-system bootstrapper via `sub_102AFCB50(this, "tag.patag")`, which binds the ".patag" filename extension to the TagManager factory in the type registry. The class has a single reflected field `_tagElements`, declared as field type-code `10` (a polymorphic vector of object references). Therefore the on-disk file is a thin reflection wrapper around an array of refcounted Tag objects whose individual layouts are written and read by PA's generic object-marshalling code (the same mechanism used by `.pabgb`/`.pabgh` index files), not by any patag-specific deserializer.

## Loader entry point

- **Bootstrap site (asset registration):** `sub_102AFF208` at `0x102AFF208` (Mac retail, image base `0x100000000`). The string `"tag.patag"` lives at `0x1073FF38D` and is referenced from `0x102AFFA28`.
- **Allocation:** `sub_1005EA740(0x50)` allocates an 80-byte TagManager object.
- **Field metadata:** `sub_10055E114(this+64, "_tagElements", 1, 196607)` interns the field-name hash.
- **Extension bind:** `sub_102AFCB50(this, "tag.patag")` registers the extension with the type registry's vtable slot `+64`.
- **Class:** `pa::ReflectDerive<pa::TagManager, pa::ReflectObjectExtension>` — RTTI confirmed via `sub_102B0CD00` and `sub_102B0D2F8` (registers `"TagManager"` as the class name, default id `0x2FFFF`).
- **Class vtable:** `0x107B0FDF0` (16 slots, including dtor at `0x102AFCD90` which iterates the element array).
- **Factory:** `sub_102B0DD1C` — heap-allocates `0x50` and initializes the same layout as the bootstrap (vtable, empty array, self-pointer, hashed `_tagElements`).
- **Metaobject builder:** `sub_102AFC828` — registers the field, installs the getter/setter pair (`sub_102AFC818`, `sub_102AFC820` — both return `this+40`).
- **Field-extension vtable:** `0x107B10E68` (`pa::FieldExtension<pa::TagManager>`); slot 4 = `sub_100CD1218 -> 10` (field type-code = polymorphic ObjectList).

## File layout

`.patag` is not a custom binary — it is the standard PA reflection envelope around a single object. It uses the same generic loader path that PA reflection containers use everywhere (the framework opens the file, reads the schema/type table, then deserializes the registered root class).

Logical content (decoded view):

| Region | Field | Notes |
|--------|-------|-------|
| header | PA reflection magic + schema/type table | written by the framework, not by TagManager |
| body, root object | `pa::TagManager` | one reflected field below |
| body, field 0 | `_tagElements` | field-code `10` = ObjectList; written as `count : u32` followed by `count` typed object payloads |

Runtime layout of the live `pa::TagManager` instance (size 0x50 bytes):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 8 | vtable ptr | `0x107B0FDF0` |
| 0x08 | 32 | refcount / smart-ptr machinery | provided by `sub_100617010` (object base) |
| 0x28 | 8 | `_tagElements.data` | base pointer of element array; each entry is an 8-byte ObjectRef |
| 0x30 | 4 | `_tagElements.count` | u32 element count (verified by destructor loop bound) |
| 0x34 | 4 | padding / capacity tail | |
| 0x38 | 8 | self-pointer | written as `this`; used by reflect framework |
| 0x40 | 8 | interned-name slot for `_tagElements` | populated by `sub_10055E114` |
| 0x44 | 4 | id-cache (initially `-1`, then `0x2FFFF`) | |
| 0x48 | 8 | parent / owning module pointer | `*(a1 + 408)` from the bootstrap |

The destructor (`sub_102AFCD90`) confirms the array shape: it walks `count` entries at `data + 8*i`, refcount-decrements `entry+16`, and stores the global null sentinel `qword_108567EC0` back into the slot.

## Per-entry schema

Each `_tagElements` entry is an 8-byte **`ObjectRef`** to a refcounted polymorphic object. Element class is not pinned at the metaobject level — the getter/setter return raw `this+40` and the field type-code is `10` (ObjectList), so the framework writes/reads a per-element type-id and then the per-element field data through the same reflection machinery used elsewhere.

Layout of a single decoded element (in memory after load):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 8 | vtable | per-element class vtable; identifies the runtime type |
| 0x10 | 4 | atomic refcount | `entry+16`, zeroed on destruction (`qword_108567EC0` is the shared null) |
| 0x14+ | varies | per-class reflected fields | walked by the reflection deserializer using the element's metaobject |

On disk the framework writes per-element: `type_id : u32` (or interned class-name id), then the element's reflected fields back-to-back per its own metaobject. This is the same convention used by `.pabgb`/`.pabgh` containers, so a reusable PA-reflection reader will handle `.patag` once the root class is recognized as `pa::TagManager` with a single ObjectList field `_tagElements`.

## Open questions

- **Element class identity.** The Mac binary search did not surface a dedicated `pa::TagXxx` class registered alongside TagManager. The string `"[ContainerMemoryTag<false>]"` at `0x1072D28B2` is unrelated (it is a memory-tag identifier, not a TagManager element). The element class therefore needs to be identified empirically from a sample `.patag` file by reading the type-id of the first entry and looking it up against the engine's class registry.
- **File header framing.** The TagManager loader does not call any patag-specific magic check; the framework reads through `sub_1006E5550` and a vtable slot at `+64` of the type registry. The exact byte layout of the PA-reflection envelope (magic, version, schema/string-pool offsets) is shared with `.pabgb`/`.pabgh` and was not re-derived here. A real `.patag` sample would let us match the magic immediately.
- **Writeability.** TagManager has setters that return `this+40` but no special "validate before commit" hook was observed. If the count is zero or all elements are null sentinels, a freshly created file should round-trip cleanly.
- **Hot-reload / extension behavior.** No second factory site was found; the asset path appears single-instance per module (`*(a1 + 3880)`).

## Next steps for structural editor

- Locate at least one `.patag` file inside a PAZ archive (search e.g. `gamedata/binary__/client/bin/` and `tag/` subtrees) and dump the first 64 bytes — the framework header should match the existing PA-reflection magic the workbench already parses.
- Reuse the existing PA-reflection reader (the one used for `.pabgb` index parsing) to enumerate `_tagElements` entries; print each entry's class-id and field offsets.
- Cross-reference each observed class-id against `0x107B0FDF0`-style metaobject tables to name the element class (likely a thin `pa::Tag` value object with name+hash+flags).
- Build a structural editor on top of the existing reflection codepath: list TagManager.`_tagElements`, allow add/remove/reorder, and serialize back through the same writer used for `.pabgb`. No bespoke .patag binary code should be needed — once the root class is registered, the generic reflection writer handles the file end-to-end.
- Confirm refcount discipline on save: each entry must have a live ref or be replaced by `qword_108567EC0` (the global null sentinel) before the destructor runs, matching the pattern in `sub_102AFCD90`.
