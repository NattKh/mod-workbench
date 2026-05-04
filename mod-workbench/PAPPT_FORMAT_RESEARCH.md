# .pappt Format Research

`.pappt` (Part-Prefab Table) is a single global build-time registry that maps short part-prefab names + per-character variants to interned string IDs. The retail game loads exactly one of two paths at startup: `character/bin__/partprefabtable.pappt` (retail) or `character/bindev__/partprefabtable.pappt` (dev). The file is a flat little-endian byte stream with no magic and no entry alignment. It contains two arrays: a primary "part definition" array (each entry has 4 short-strings + a u8 flag + a count-prefixed list of inline children) and a secondary "alias / mapping" array of two-string pairs. There is no compression / no encryption — `sub_10058F658` is a raw bump-pointer reader.

## Loader entry point

| | |
|---|---|
| Function | `sub_101E47CB0` |
| Image base | `0x100000000` (Mac retail) |
| Function size | `0xebc` (3772 bytes) |
| Caller | `sub_101E490F0` (the table-class init/reload at `0x101E490F0` size `0x120`) |
| Path string at | `0x1073c5645` ("character/bin__/partprefabtable.pappt") and `0x1073c561c` ("character/bindev__/partprefabtable.pappt") |
| Path-string xref | `0x101e47d08` (inside `sub_101E47CB0`, selected by `a2` arg) |

The loader signature is `bool sub_101E47CB0(_QWORD *table, int dev_flag)`. It clears the embedded registries (`sub_101E48CC8(table+10)` and `sub_1006E1D04(table+14)`), opens the file via `vfs->open(table, file_io, mountpoint, "")` (vtable slot 64 from the engine VFS), and on success runs the deserializer. On open-failure it logs the localized Korean string `"%# 파일을 read 할 수 없습니다!"` (`"cannot read %# file!"`) and returns `false`.

The byte-stream reader is `sub_10058F658(stream_state, len)`. `stream_state` is a 24-byte struct on the stack (`v152`):

| Offset | Type | Meaning |
|---|---|---|
| `+0x00` | `void*` | vtable (set to `&off_10773BB70`) |
| `+0x08` | `void*` | file blob ptr |
| `+0x10` | `u32` | total size |
| `+0x14` | `u32` | cursor (advances on each read) |

Reads return `blob + cursor` and bump the cursor. When `cursor + len > size` the reader returns `NULL` — there is no error path beyond that nullable return, so a malformed file silently truncates.

## File layout

```
+0x00  u8[8]    skipped header / magic        (read but value never used)
+0x08  u32      primary_count        (N1)     ; number of part-prefab entries
+0x0C  primary_entry[N1]                       ; variable-stride, see below
       u32      secondary_count      (N2)     ; number of alias-pair entries
       secondary_entry[N2]                     ; variable-stride, see below
EOF
```

There is no version field, no checksum, no per-section size, and no padding. The 8-byte initial skip looks like a magic+version slot — the loader reads it (`sub_10058F658(v152, 8)`) but never inspects the bytes, so any 8-byte content is accepted.

### String encoding

Every string in this file is a length-prefixed Pascal string with a **u8 length** (max 255 bytes), **no NUL terminator written by the file** (the engine appends NUL when interning). Encoding is ASCII / engine-internal char (treat as bytes; the engine path-table later runs `sub_1006BB724` strlen on it).

```
pstr {
    u8   len;
    u8   data[len];
}
```

## Per-entry schema

### Primary entry (N1 records, packed back-to-back, no padding)

```
primary_entry {
    pstr  key_a;          // becomes table.registry1 key (a1+20, char/race-keyed map)
    pstr  key_b;          // becomes table.registry1 key (a1+28, second indexer)
    pstr  key_c;          // READ AND DISCARDED in deserializer
                          //   (purpose unknown — likely a legacy/source field
                          //    kept for forward-compat; see Open questions)
    pstr  asset_id;       // hashed via sub_10055E114 -> u32 interned-string ID,
                          //   stored at entry+16. This is the canonical part-prefab
                          //   asset key (input to the engine string-intern table,
                          //   ID range 0..0x2FFFE; 0x2FFFF = overflow sentinel).
    u8    flag;           // stored at entry+20 (purpose unknown — probably a
                          //   gender/tribe gating bit or "is_default" toggle)
    u8    child_count;    // M
    child_entry[M] {
        pstr   sub_key;   // hashed via sub_10055E114 -> u32 stored at child+0
        u8     sub_flag;  // stored at child+4
    }
}
```

The in-memory entry node (24 bytes, allocated by `sub_1005EA740(0x18)`):

| Offset | Type | Source field |
|---|---|---|
| `+0x00` | `child_entry*` | pointer to allocated child array (8B-stride) |
| `+0x08` | `u64` | (zeroed at construction; runtime back-pointer) |
| `+0x10` | `u32` | interned ID of `asset_id` |
| `+0x14` | `u8` | `flag` |
| `+0x15` | padding |
| `+0x18` | end |

Child array element (8 bytes):

| Offset | Type | Source field |
|---|---|---|
| `+0x00` | `u32` | interned ID of `sub_key` |
| `+0x04` | `u8` | `sub_flag` |
| `+0x05` | padding |

`key_a` and `key_b` are not hashed-to-ID; they are kept as engine `String<>` smart-pointer objects (refcounted via `qword_108567EC0` empty-string sentinel + `sub_1006BA9AC` release path). They are stored in `table.registry1` (`a1+10..14`) as the **lookup keys** that map *to* the entry.

### Secondary entry (N2 records, 16-byte stride after deserialization)

```
secondary_entry {
    pstr  alias_from;    // refcounted String, stored at v158[i*16 + 0]
    pstr  alias_to;      // refcounted String, stored at v158[i*16 + 8]
}
```

Both strings are kept as String<> objects (no hashing). They are inserted into `table.registry2` (`a1+36`), and `alias_to` is also indirectly inserted into a second sibling map keyed by `alias_to` itself (the duplicate insertion at `0x101e482e8` / `0x101e48590`). This is the standard pattern for a two-way alias table: lookup by either name returns the partner.

## Cross-references

- **`asset_id` (primary entry, field 4)** → `sub_10055E114` is the global string-intern table at `qword_108523388`. It produces a u32 ID in `[0, 0x2FFFE]` (cap = 196607). This same intern table is shared with the rest of the engine, so a `pappt` `asset_id` u32 can be directly compared against `_partPrefabKey` / `_partKey` u32 fields anywhere else in the runtime (e.g. `iteminfo.pabgb` equipment slots, character-load packages). **`asset_id` is the cross-cutting key that makes this file useful.**
- **`sub_key` (child entries)** → same intern table, same u32-namespace. These are likely auxiliary part variants (LOD names? slot names? tribe/gender variants?) that nest under one parent `asset_id`.
- **`key_a` / `key_b` (primary entry, fields 1-2)** → kept as raw refcounted Strings, used as the **map key** to look the entry up by character/tribe name. Likely shapes: `key_a = tribe/race name` (e.g. `"Kliff"`, `"Damiane"`, `"Common"`), `key_b = part-slot category` (e.g. `"hair"`, `"face"`, `"glove"`). Confirming this requires dumping a real file.
- **`alias_from` / `alias_to` (secondary array)** → kept as raw refcounted Strings, two-way alias map. Likely: legacy → new prefab name remapping, or character-mesh-set inheritance edges.
- **No PABGB cross-link is hard-coded in the loader.** The hashes flow into the global string-intern table only; downstream PABGB consumers compare interned-IDs, not the raw strings.

## Open questions

1. **`key_c` is read and discarded.** `sub_10058F658(v152, *v118); sub_10058F658(v152, *v119);` reads two pstrs but only the second one (`v120`) is used. The first (`v118`/`key_c`) is read solely to advance the cursor. It may be a legacy field kept for tooling round-trip, or a development-only annotation (description / source path) that the runtime intentionally ignores. **Real-file inspection needed** to know what's in there.
2. **`flag` (entry+0x14) and `sub_flag` (child+0x4) semantics.** Both are u8. Almost certainly enum / bitfield. Common candidates: gender (M/F/U), LOD index, attach-point group, "use as default" bit. Cannot tell from the loader alone — the runtime consumers of `table.registry1.entry+0x14` would need to be inspected.
3. **No version / no magic.** The leading 8 bytes are read but never compared. Treat as opaque header reserved for future use; on write, copy the input header verbatim to be safe.
4. **String charset.** The loader runs `sub_1006BB724` (strlen-style) on the bytes, treating them as C strings. Korean / Japanese / Chinese in the file would survive only if encoded as UTF-8 (which the engine path-tables typically use). UTF-16 would break path-hashing; assume UTF-8 until a real file proves otherwise.
5. **Entry uniqueness.** The deserializer does *not* dedupe primary entries on `(key_a, key_b)`. Duplicate keys are inserted twice into the registry map, which would normally be a hash-collision and is silently allowed by `sub_101E4EF58` (it just chains). Whether duplicates are legal in shipped files or always a build error is unknown.

## Next steps for structural editor

- **Build a parser first, not a hooker.** All field widths are static u8/u32/pstr — a Rust `nom` or manual cursor parser will round-trip perfectly. No symbol-table lookup, no LZ4, no encryption, nothing version-gated.
- **Schema for serializer:**
  ```
  Header   { magic_v: [u8; 8] }                  // copy through unchanged
  Primary  { count: u32, entries: [PrimaryEntry; count] }
  Secondary{ count: u32, entries: [SecondaryEntry; count] }
  PrimaryEntry { key_a: PStr, key_b: PStr, key_c: PStr, asset_id: PStr,
                  flag: u8, child_count: u8, children: [Child; child_count] }
  Child       { sub_key: PStr, sub_flag: u8 }
  Secondary   { alias_from: PStr, alias_to: PStr }
  PStr        { len: u8, data: [u8; len] }
  ```
- **Validation pass.** When emitting, assert every pstr length ≤ 255 and total file size matches sum-of-fields. The loader has zero tolerance for short reads (`sub_10058F658` returns NULL → next read derefs NULL).
- **Dump and label.** First Rust tool: `pappt-dump` printing `(key_a, key_b, key_c, asset_id, flag, [children...])` for every primary entry, plus `(from, to)` for every secondary. Categorise the unique values of `key_a` / `key_b` to confirm tribe vs. slot guesses above.
- **Cross-resolve `asset_id`.** Once dumped, look up each `asset_id` string in the bin/partprefabtable PAZ-side `.pappt`-dependent assets (mesh / skeleton bundles named after the same key). If 1:1 match — confirmed: `asset_id` is the canonical mesh-pack name.
- **Editor surface.** A structural editor needs to expose: (a) add/remove primary entry by `(key_a, key_b)`, (b) edit `asset_id` and `flag`, (c) add/remove children with `(sub_key, sub_flag)`, (d) add/remove secondary aliases. Re-emit byte-perfect (header passthrough + minimal-rewrite) so diffing against vanilla is trivial.
- **Don't build memory hooks.** `pappt` is loaded once at boot and lives in a refcounted in-memory map; modding it via memory-write would be racy and version-fragile. The PAZ overlay path (drop a modded `partprefabtable.pappt` into `character/bin__/`) is the supported route, mirroring the existing `iteminfo.pabgb` overlay flow.
