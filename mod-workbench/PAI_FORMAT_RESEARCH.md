# .pai Format Research

Crimson Desert ships two `.pai` files (`aichart.pai` and `PathFindTable.pai`) under `aiscript/bin__` (or `aiscript/bindev__` if the dev flag at `byte_10857E419` is set). They contain the precompiled AI behaviour graph used by the engine: a slot-keyed tree of typed AI nodes (packages, states, branches, conditions, function verbs). The files are loaded into memory whole, wrapped in a streaming reader (`sub_1006B8DEC` / `sub_1006B8E2C` setting up `off_1077455A8` as the vtable), and consumed sequentially — there is **no outer file-level magic or version header**. Top-level shape is "730 typed slots in `aichart.pai`, plus a string-keyed entry table in `PathFindTable.pai`". All multi-byte values are little-endian.

## Loader entry points

| Function | Address | Reads | Body |
|---|---|---|---|
| `sub_10075C548` (PathFindTable loader) | `0x10075c690` calls it | `%#/PathFindTable.pai` | Resets per-slot state, opens stream, calls `sub_10075F498` (header) then `sub_10075F630` (body) |
| `sub_10075C88C` (aichart loader) | `0x10075c904` calls it | `%#/aichart.pai` | Resets pool state, opens stream, calls `sub_10075CC18` (per-slot init) then `sub_10075CD40` (read 730 slots) then `sub_10075F2F4` (read entry hashmap) |

Inside both loaders the file is opened via virtual call `(*(...)(*(_QWORD *)v_filesys + 64LL))(...)`. The buffer is then wrapped in the stream object at `sub_1006B8DEC`, which is what every `sub_1006B907C(stream, dst)` style call below consumes from. `sub_1006B907C` calls `vtable[2]` on the stream with `size = 4` — so reading a u32 is `read(stream, &dst, 4)`. `sub_1006B8FBC` / `sub_1006B8FFC` / `sub_1006B8FDC` all call the same vtable entry with `size = 1` (i.e. raw byte read used as bool / u8 / u8). `sub_1006B90DC` is also `size = 4` (alias for u32).

## Stream primitive vocabulary

| Helper | Function | Width | Notes |
|---|---|---|---|
| u32 | `sub_1006B907C` | 4 | core integer reader |
| u32 (try-then-write) | `sub_101A65EB0` | 4 | only writes destination on success |
| u8 / bool | `sub_1006B8FBC`, `sub_1006B8FFC`, `sub_1006B8FDC` | 1 | identical body, 3 aliases |
| pa::String | `sub_1006B924C` | u32 length + bytes | length-prefixed, zero-terminated, ref-counted; uses `sub_1006BA050` to install into a managed `pa::String` slot |
| u32 + u32 record (e.g. tag/value pair) | `sub_101869BF8`, `sub_101869450` | 5 raw u32s + 2-byte+u32 (20-byte struct) | used inside list entries — see Container shapes below |
| smart pointer (read header bool, alloc 0xA0, fill) | `sub_10075AF3C` | variable | this **is** the AIPackage reader |
| AI node ref by hash + sub-id | `sub_10169E44C`, `sub_100C61D78`, `sub_10189B3E0` | 8 | `(u16 type_index, u32 sub_id)` — sometimes followed by extra fields |

**There is no length field for the file.** The reader simply reads until it has consumed every slot.

## File header

There is no header. The first byte of the file is the first byte of the slot-0 count (a u32). The aichart loader iterates `for (slot = 0; slot < 730; ++slot) { u32 count = read_u32(); allocate_slot_pool_if(count > 0); for (i = 0; i < count; ++i) construct_then_deserialize_into_pool(slot, stream); }`. After the 730-slot loop it reads the string-keyed entry table (see "Aichart entry hashmap" below).

For `PathFindTable.pai` the loader at `sub_10075F498` first reads `u32 count` (total entries hint, used to pre-size a hashmap of capacity `(count + existing_count) / 31` rounded up to ≥ 2), then loops `count` times reading `(u32 key, deserialise(stream))` and inserting into the hashmap via `sub_10075FFFC`. After that, `sub_10075F630` reads a secondary `u32 count` followed by 24-byte records via `sub_101869A6C` (see PathFind entry struct below).

## Node-type dispatch

The aichart-side dispatch is the giant 730-case switch in `sub_10076104C` (factory function called with the slot index 0..729). The function:

1. Reads slot index `W21 = W0`.
2. Computes the slot's metadata pointer via the global memory-pool manager `pa::CompressedObjectMemoryPoolManager<pa::AIChartObjectType>::__memoryPool` plus offset `W0 * 8 + 0x17B0`.
3. Branches via a 730-entry jump table.
4. Each case: `alloc(0x280)` (the `AIChartObjectType` slot header is 640 bytes), then loads the class-name pointer from `off_107755A58[slot_index]` into x1, then calls the per-slot **constructor** (e.g. `sub_10076BF88` for slot 0). The constructor stores the vtable for that type at `+0` and sets up the per-pool buckets.
5. The actual deserialise is a separate vtable call later — `vtable[14]` (offset 112) on the constructed pool object, performed by the loader after every slot is constructed.

The slot-name table at `off_107755A58` is **730 pointer-to-string entries**, all into the contiguous string blob beginning at `0x1072e645c`. There are 352 unique class-name strings, so multiple slots share names (one class can occupy several slot indices because some class families register multiple variant slots with different per-slot deserializers). The full name list is in `Appendix A` below.

For `PathFindTable.pai`, dispatch is by hash: `(u32 path_key, u32 sub_index)` is read, then `sub_10075FFFC` (the open-addressing hashmap insert) does either lookup-and-merge or allocate-new-and-fill on the AIPackage struct (160 bytes — see below). PathFindTable's value type is **always** an `AIPackage_PathFind` (or compatible) — there's no per-entry class dispatch.

## AIPackage struct (96-byte payload, shipped via 160-byte refcounted block)

Decoded from `sub_10075AF3C`. The on-disk layout for a present (`u8 flag == 1`) AIPackage is:

| Offset | Width | Field | Reader | Notes |
|---:|---:|---|---|---|
| 0 | u32 | `key` (or `value_id`) | `sub_1006B907C` | populated indirectly by caller |
| 4 | u8 | `subKind` | `sub_1006B8FBC` | bool/enum |
| 8 | 8 | `_misc1` (struct) | `sub_10075DCB8` | optional 0x30-byte sub-block (only if its u8 flag == 1) — calls `sub_10177EC8C` constructor + `sub_10177EC18` reader |
| 16 | 32 | `_attributeContainer` | `sub_10075DD90` | hashmap-like list keyed by `u32 key`; element parser is `sub_10169E44C` (see Container shapes) |
| 48 | 16 | `_branchSegmentList` | `sub_10075DF3C` | flat array of `(u16 tag, u32 value)` 8-byte records read with two raw u32 reads |
| 64 | 32 | `_conditionList` | `sub_10075E144` | hashmap keyed by `u32 key`; element parser inline (u32+u32 → tag+value) — calls `sub_10075ED14` |
| 96 | 32 | `_targetList` | `sub_10075E2D4` | hashmap keyed by `u32 key`; element parser is `sub_1010AE4A4` (16-byte target struct) — calls `sub_10075EA48` |
| 128 | 32 | `_extraList` | `sub_10075E478` | hashmap keyed by `u32 key`; element parser inline (u32+u32) — calls `sub_1000D559C` |

Total reader-visible AIPackage bytes on disk are roughly 1 (`subKind`) + 1 (`_misc1.flag`) + (variable per sub-block) + 4 (`_attributeContainer.count`) + N entries + 4 + N + 4 + N + 4 + N + 4 + N. The leading `u8` "is this present" sentinel applies at the wrapping `sub_10075AF3C` level.

The four `sub_10075E144`-style readers all share the same *outer* shape: `u32 element_count` followed by the listed body. They grow via `(count + existing) / 31` capacity heuristic before reading the loop body — that's a hashmap-by-31-buckets convention, **not** a list.

## PathFind entry struct (88 bytes on the wire)

From `sub_101869CF8` (the PathFind entry deserializer):

| Offset | Width | Field | Reader |
|---:|---:|---|---|
| 0 | 4 | `pathKey` | `sub_1006B907C` (u32) |
| 8 | varlen | `name` | `sub_1006B924C` (pa::String) |
| 16 | 4 | `aux1` | `sub_101A65EB0` (u32 try-write) |
| 20 | 4 | `aux2` | `sub_101A65EB0` (u32 try-write) |
| 24 | 16 | `subA` | `sub_10189B7FC` (list of 16-byte records, each `u16 tag + u32 value + u32 keyHash + 8-byte ref`) |
| 40 | 16 | `subB` | `sub_10189BA88` (list of 20-byte records — `u32+u32+u32+u16+u32`) |
| 56 | 16 | `subC` | `sub_10189BD20` (list of 24-byte records) |
| 72 | 16 | `subD` | `sub_10189BF0C` (list of 24-byte records, first byte u8) |

The element parsers it calls are `sub_101869B10` (16B), `sub_101869BF8` (20B with 5 sub-fields), `sub_10189AC84` (24B keyed by 13-byte payload + 11-byte AIPackage tail), `sub_10189AF2C` (24B with leading `u8` byte then ref).

## Container shapes (the four list flavours)

Whenever the deserializer reads a list, it always follows one of four inner parsers. These are how an AI* node embeds children:

1. **Plain (key, ref) list** — `sub_10189B7FC`. Element = 16 bytes: `(u16 tag = 730 placeholder, u32 marker = 0xFFFFFFFF, u8 flag, u8 unused, u16 type_index, u32 sub_id)`. Used for hash-by-key references.
2. **(u32 key, u32 sub, u32 extra, u16 tag, u32 marker)** list — `sub_10189BA88`, 20 bytes. Used for action-with-parameter chains.
3. **(struct13B + AIPackage tail)** list — `sub_10189AC84`, 24 bytes. The 13-byte head is read by `sub_101869450` (u32 + u8 + u8 + u8 + u32 + u8 + ?). The remaining 11 bytes match an embedded AIPackage hash + tag.
4. **(u8 flag + ref + tag)** list — `sub_10189BF0C`, 24 bytes. First byte is `vtable[2](stream, size=1)`, then `sub_10189AF2C` reads the ref (a refcounted child), then the `(u16 tag, u32 marker)` tail.

All four list flavours share the same outer header: `u32 count` followed by `count` element bodies, with the container reusing capacity/realloc logic identical to `std::vector`.

## Aichart entry hashmap (after the 730-slot loop)

`sub_10075F2F4`:
1. `u32 entry_count`
2. for each entry:
   - `u32 entry_key` (the AI chart name hash)
   - `sub_10075AF3C(stream, &val_ptr)` → an AIPackage payload
   - `sub_100760448(...)` inserts `(key → AIPackage)` into the open-addressing hashmap at `a2`

Each AIPackage value is a 16-byte reference cell: `(u32 hash_pos, u32 sub_id, u64 payload_ptr)`. Multiple entries with the same `(entry_key, hash_pos)` collapse via `sub_10075B5E0` (refcount drop → free).

## Tree shape

```
aichart.pai
├── for slot in 0..730:
│   ├── u32 children_count
│   ├── for each child:
│   │   └── slot[slot].vtable[14](stream)   # per-class deserializer
│   └── (post-children u32 secondary list)
└── after-loop entry hashmap (sub_10075F2F4)
    └── for i in 0..entry_count:
        └── (u32 key, AIPackage payload, hashmap insert)

PathFindTable.pai
├── header (sub_10075F498)
│   ├── u32 entry_count
│   └── for each entry: (u32 path_key, AIPackage payload, hashmap insert via sub_10075FFFC)
└── body (sub_10075F630)
    ├── u32 record_count
    └── for each record: 24-byte struct via sub_101869A6C → sub_10189B588
```

Inside an AIPackage, the four child lists (`_attributeContainer`, `_conditionList`, `_targetList`, `_extraList`) and the 16-byte "branch segment" list together form the package's child graph. References across packages are by `(u16 type_index, u32 sub_id)` — these are foreign keys into the slot table, **not** offsets.

## Class-name table summary

The `off_107755A58` table is 730 pointers, all aimed inside a single 12 KB string blob at `0x1072e645c`. The blob holds **352 unique class-name strings** (UTF-8, NUL-terminated). The slot index is the binary tag — *not* a value chosen from the string table. Mappings (selected, by inspection of the 730 cases):

| Slot ID | Class name | Constructor body |
|---:|---|---|
| 0 | `AIPackage_Normal` | `sub_10076BF88` |
| 1 | `AIPackage_PathFind` | (next case in switch) |
| 2 | `AIPackage_PathMove` | "" |
| 3 | `AIPackage_Flow` | "" |
| 4 | `AIState_TeleportDesc` | "" |
| 5 | `AIState_DockingDesc` | "" |
| 6 | `AIState` | "" |
| 7 | `AIBranchContainer` | "" |
| 8 | `AIFunctionOrBranch` | "" |
| 9 | `AIConditionStatement` | "" |
| 10 | `AIPackageAttribute` | "" |
| 11 | `AIPackageAttributeContainer` | "" |
| 12 | `AIBranch_Normal` | "" |
| 13 | `AIBranch_FindTarget` | "" |
| 14 | `AIBranch_PathSegment` | "" |
| 15 | `AIBranch_CheckPoint` | "" |
| 16 | `AIBranch_PrevPathFind` | "" |
| 17 | `AIBranch_OnArrived` | "" |
| 18 | `AIBranch_Flow` | "" |
| 19 | `AIBranch_FlowExit` | "" |
| 20 | `AIBranch_HideBattleTable` | "" |
| 21 | `AIBranch_Debug` | "" |
| 22 | `AIPathFindDesc_DestinationDesc` | "" |
| 23 | `AIPathFindDesc_ETC` | "" |
| 24 | `AIFunction_TryAppendPath` | "" |
| 25..67 | `AIFunction_SetDestination_*` (43 slot IDs) | "" |
| 68..238 | other `AIFunction_*` verbs | "" |
| 239..351 | all `AICondition_*` predicates | "" |
| 352..729 | further variants — slot ID 352..729 reuses earlier strings via the pointer table | varies |

Slots 0..351 line up with the 352 string indices in the blob. Slots 352..729 are duplicates / variant deserializers that point back into the same string list. To enumerate the full mapping, walk the 5840-byte block at `off_107755A58` (730 little-endian u64 pointers) and resolve each pointer against the string blob.

## Schema for individual AI* node types

Each slot's deserializer (`vtable[14]` on the constructed object) reads a node-specific layout. I sampled `vtable[14]` for slot 0 (`AIPackage_Normal`) at `0x10076d40c`:

1. `u32 child_count` (stored at `+252` of the 640-byte slot header)
2. for each child:
   - `u32 child_id` (the child's own per-pool slot index)
   - allocate a child object via `sub_1002B9C48(memory_pool, 0)` then call `vtable[20](child, child_id)` to wire the pool slot
   - zero a 104-byte block, copy in vtable, recursively descend
3. `u32 secondary_count` followed by `u32` per element (each element copies into an internal flat list)

This means **every AI* node uses a shared envelope** of `{ u32 count_of_primary_children; child[]; u32 count_of_secondary_children; secondary[]; }` and the only variation is what each primary/secondary child is. For most "leaf" verbs (e.g. `AIFunction_*`), the per-class deserializer just reads a few u32s/strings into class-local fields, then chain-calls the base AI envelope.

**Schemas not yet walked** — the per-slot `vtable[14]` for ~728 of the 730 slots. Walking them would require ~700 single-address `decompile` calls. Instead the practical approach is:

- Treat every slot's payload as the standard AIPackage envelope plus zero-or-more class-specific u32/u8/string fields.
- For each leaf verb the user wants to edit, decompile its specific `vtable[14]` (look up via `off_107755A58 + slot*8`'s constructor → vtable → `[14]`) on demand.

## Open questions

1. **Per-class field schemas for the 728 unsampled slot types** — only `AIPackage_Normal` (slot 0) and the AIPackage envelope itself are decoded. Each of the 24 `AIFunction_TryAppendPath`-family verbs has its own vtable[14] with class-specific fields. Walk them lazily as needed.
2. **String hash convention used for `pathKey` / chart entry keys** — almost certainly Bob Jenkins lookup3 (per `project_jenkins_hash_universal.md` in user memory: every 4-byte hash in PA binaries is hashlittle). Confirm by hashing a known chart name and matching against a real `aichart.pai`.
3. **The `0x17B0` offset** added in the slot factory — that's where the vtable bucket array sits inside the global memory-pool struct. Not strictly needed for decoding, but useful when re-serialising.
4. **`subA`..`subD` element fields in the PathFind entry** — the 4-element record types are partially decoded. The third (`sub_10189AC84`) embeds an AIPackage; the field layout of the leading 13 bytes is partially understood (`sub_101869450` reads `u32 + u8 + u8 + u8 + u32 + u8 + ?` then continues into a `pa::String` and an AIPackage chain). Worth re-walking when implementing the PathFind half.
5. **How the engine writes these files** — the writer-side functions weren't searched. Expected to be symmetric with the readers (look for callers of `sub_1006B907C`'s writer counterpart `vtable[3]` on the stream).

## Next steps for structural editor

- **Rust port — read side**: encode the helpers (`u8`/`u32`/`pa::String`/`list-of-T`) as `nom`-style combinators or hand-rolled `Cursor<Bytes>` readers. Parse `aichart.pai` to a `Vec<Slot { class_name: &str, payloads: Vec<AIPackage> }>` and `PathFindTable.pai` to a `HashMap<u32, AIPackage>`.
- **Rust port — write side**: serialize back symmetrically. Because the format has no length-prefixes at the file level (only count-of-elements per node), edits are safe as long as you re-emit `count` values consistently with the children you write. Crucially: the slot index space is fixed at 730; **don't change slot indices**, only edit per-slot child counts and contents.
- **Workbench panel design**:
  1. **Tree view** rooted at "aichart" with 730 expandable slot nodes (named from `Appendix A`).
  2. Per slot, show `count` and a child list. Clicking a child opens its AIPackage envelope as four sub-tables (attributes / conditions / targets / extras / branches).
  3. **PathFindTable** view as a flat `(u32 key → AIPackage)` table, with the body's secondary 24-byte records in a separate panel.
  4. Class-specific field editors only need to be wired for the AI* types the user actually wants to mod. Keep everything else as raw hex with the envelope overlay.
- **Validation**: round-trip parse → re-emit → byte-diff. Because the file has no checksum, byte-equal output proves the parser is faithful.
- **First moddable target**: `AIPackage_PathFind` payloads in `PathFindTable.pai`. They drive NPC routes and are small / well-bounded relative to the giant `AIPackage_Normal` graph.

## Appendix A — class-name list (352 entries, in string-blob order)

```
0   AIPackage_Normal
1   AIPackage_PathFind
2   AIPackage_PathMove
3   AIPackage_Flow
4   AIState_TeleportDesc
5   AIState_DockingDesc
6   AIState
7   AIBranchContainer
8   AIFunctionOrBranch
9   AIConditionStatement
10  AIPackageAttribute
11  AIPackageAttributeContainer
12  AIBranch_Normal
13  AIBranch_FindTarget
14  AIBranch_PathSegment
15  AIBranch_CheckPoint
16  AIBranch_PrevPathFind
17  AIBranch_OnArrived
18  AIBranch_Flow
19  AIBranch_FlowExit
20  AIBranch_HideBattleTable
21  AIBranch_Debug
22  AIPathFindDesc_DestinationDesc
23  AIPathFindDesc_ETC
24..238  AIFunction_*  (215 verbs)
239..351 AICondition_* (113 predicates)
```

The full list (extracted from the string blob at `0x1072e645c`) is captured in the IDA project; resolve via `off_107755A58[slot] -> string`.
