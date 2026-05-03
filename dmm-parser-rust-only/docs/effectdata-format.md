# EffectData Binary Format — effectinfo.pabgb

Empirically derived from effectinfo.pabgb dumps via Python hex analysis
(`tools/analyze_effectinfo[1-25].py`). Documents the **outer blob structure**
as seen from the wire; the IDA-derived field-level decoder for the inner
EffectDataElement record lives in `src/binary/variants/effect_data.rs` and
uses a different (non-empirical) analysis layer.

Field names are inferred from context; true names are unknown without IDA
symbol access.

> **Research artifact — partially reconciled with IDA analysis.**
> The empirical blob layout (fixed\_prefix, sub\_elements, inner\_map entries at
> 364 bytes each, real MeshEffectData at 50 bytes each) has been cross-checked
> against `effect_data.rs` / `effect_info/info.rs`. Key corrections applied:
> FP=300 (not 299), all blob sizes +1, 364-byte chunks = `inner_map` entries
> (not "MeshEffectData"), real MeshEffectData = 50 bytes per IDA `sub_1410DBD90`.
> Use the IDA-derived code as ground truth for parsing; use this doc for pattern
> observations and offset landmarks within a single element's bytes.

---

## Version History

Three inner sizes changed across patch versions:

| constant         | pre-4-11 | 4-11  | 4-23 / 4-24 |
|------------------|----------|-------|-------------|
| `fixed_prefix`   | 300      | 287   | 300         |
| `sub_element`    | 316      | 303   | 316         |
| `inner_map_elem` | 364      | 351   | 364         |
| baseline blob    | 324      | 311   | 324         |

The 4-11 patch shrank all three constants; the 4-23 patch reverted them.
The outer container layout is unchanged across all versions.

`fixed_prefix` (FP) = 300 bytes: `byte_a`(1) + `lookup_b`(4) + `EffectDataCoreBlock`(254) +
`lookups_c`(24) + `fields_d`(16) + `byte_e`(1). The last field `byte_e` is always 0 in
vanilla, which caused early empirical analysis (and Snow's doc) to count FP as 299 by
absorbing `byte_e` into the "15 trailing zeros" at the end of Region 5.

**Diff (4-11 → 4-24):** 12 zero bytes inserted at blob offset 172
(= fixed_prefix offset 168) for entries originally 312 bytes; 13 bytes
for entries originally 311 bytes. In both cases the -π/2 constant float
(`db 0f c9 bf`) moved from blob[172] to blob[184]. All common keys between
the two dumps diverge at exactly blob offset 172 (confirmed across 2035/2036
common entries).

---

## Outer pabgb/pabgh Container

`effectinfo.pabgb` uses the standard indexed blob format:

- **`.pabgh`**: u16 entry_count, then entry_count × (u32 key, u32 offset)
- **`.pabgb`**: concatenated entries; each entry spans `[offset .. next_offset)`

Each raw entry starts with:

```
u32_le   key
u32_le   string_len
u8[string_len]  string_key
u8       null          (CString null terminator)
u8       is_blocked
[blob]
u8       has_equip_type    ┐
u8       has_preset        ┤ TAIL_SIZE = 3 bytes, stripped before blob parsing
u8       target_color_lerp_type ┘
```

The "blob" extracted after stripping the outer wrapper and the 3-byte tail
is what the layout below describes.

---

## Blob Layout

```
Offset  Size    Field
──────────────────────────────────────────────────────────────
0       4       CArray<EffectDataElement> count — always 1 in vanilla
4       FP      fixed_prefix  (= EffectDataElement fixed fields; see § Fixed Prefix)
4+FP    4       named_item_count   u32_le  (0 for ~95% of entries)
8+FP    var     string_pairs       named_item_count × StringPair
X       var     struct_section     u32_le count + count × 144-byte NamedItemStruct
Y       var     sub_elements       K × SUB bytes  (K implicit: (mc_off − Y) ÷ SUB)
mc_off  4       inner_map_count    u32_le  (IDA: CArray<{u32 key, EffectDataInner}> count)
mc_off+4  n×364   inner_map_elems  n × 364-byte inner_map entry (key + EffectDataInner)
end−8   8       {0,0,0,0,0,0,0,0}  trailing zeros (= inner_map_count=0 + mesh_count=0
                                    when no mesh; see IDA note below)
```

> **IDA-reality note:** Per `info.rs`, the actual blob wire format is
> `[effect_count(4)][EffectDataElement(var)][mesh_count(4)][m×50 MeshEffectData]`.
> The empirical "8 trailing zeros" = the inner_map CArray count (last 4 bytes of
> EffectDataElement, = 0 when n=0) plus the outer mesh_count (= 0 when m=0). For
> entries with m>0 real mesh elements the trailing section is
> `[inner_map_count=0][mesh_count=m][m×50 bytes]` — not all zeros.
>
> **Naming note:** Early empirical analysis (and Snow's external doc) called the 364-byte
> chunks "MeshEffectData." Per IDA they are `inner_map` entries: `u32 key +
> EffectDataInner`. The 364-byte wire size holds when all of EffectDataInner's embedded
> CArrays are empty. Real `MeshEffectData` per IDA `sub_1410DBD90` is 50 bytes:
> `u8 + 8×u32 + u8 + 4×u32` (lookups).

Where per-version constants are:

| symbol   | 4-11 | 4-23/4-24 |
|----------|------|-----------|
| FP       | 287  | 300       |
| SUB      | 303  | 316       |
| MESH     | 351  | 364       |

And:

```
X      = (8+FP) + Σ(4 + len_i)  for i in 0..named_item_count
           ↑ 4 bytes = the length-prefix for each string pair
           ↑ len_i  = byte length of the i-th string (no null terminator)

Y      = X + 4 + named_item_count × 144
           ↑ 4 bytes = the struct_section count prefix
           ↑ struct count always equals named_item_count

mc_off = Y + K × SUB   (solve from blob_size: see mc_off detection below)
```

**mc_off detection** — two-step: (1) iterate candidate `n` (inner_map count) from
largest to smallest; for each, compute `mc_off = blob_size − 8 − n×364`; check
that `u32_le(blob, mc_off) == n`. (2) verify `(mc_off − Y) % SUB == 0`.
The divisibility check is required to avoid false positives: when inner_map data
happens to be zero at a candidate mc_off, step (1) alone gives wrong n.
For entries with real mesh (m>0) the blob is longer by `m×50` — `find_mesh_split`
in `info.rs` locates the mesh boundary first, then mc_off detection runs on the
effect-data sub-slice.

---

## Size Examples

### 2026-4-11 pabgb (2039 entries, FP=287, SUB=303, MESH=351)

General formula: `blob_size = 311 + named_items_extra + K×303 + inner_map×351 + mesh×50`

where `named_items_extra = Σ(4+len_i) + named_item_count×144`.

| blob_size | named_item_count | K (×303) | inner_map (×351) | mesh (×50) | notes |
|-----------|-----------------|----------|-----------------|------------|-------|
| 311       | 0               | 0        | 0               | 0          | baseline (1935 entries) |
| 463       | 1 ("leaf", 4)   | 0        | 0               | 0          | |
| 464       | 1 ("dist1", 5)  | 0        | 0               | 0          | |
| 465       | 1 ("smoke1", 6) | 0        | 0               | 0          | |
| 615       | 2               | 0        | 0               | 0          | |
| 616       | 2               | 0        | 0               | 0          | |
| 614       | 0               | 1        | 0               | 0          | |
| 917       | 0               | 2        | 0               | 0          | |
| 662       | 0               | 0        | 1               | 0          | |
| 1013      | 0               | 0        | 2               | 0          | |
| 1364      | 0               | 0        | 3               | 0          | |
| 1715      | 0               | 0        | 4               | 0          | |

### 2026-4-24 pabgb (2057 entries, FP=300, SUB=316, MESH=364)

General formula: `blob_size = 324 + named_items_extra + K×316 + inner_map×364 + mesh×50`

| blob_size | named_item_count | K (×316) | inner_map (×364) | mesh (×50) | notes |
|-----------|-----------------|----------|-----------------|------------|-------|
| 324       | 0               | 0        | 0               | 0          | baseline (1952 entries) |
| 476       | 1 ("leaf", 4)   | 0        | 0               | 0          | |
| 477       | 1 ("dist1", 5)  | 0        | 0               | 0          | |
| 478       | 1 ("smoke1", 6) | 0        | 0               | 0          | |
| 628       | 2               | 0        | 0               | 0          | |
| 629       | 2               | 0        | 0               | 0          | |
| 374       | 0               | 0        | 0               | 1          | one real MeshEffectData (50 bytes) |
| 640       | 0               | 1        | 0               | 0          | |
| 956       | 0               | 2        | 0               | 0          | |
| 688       | 0               | 0        | 1               | 0          | |
| 1052      | 0               | 0        | 2               | 0          | 26 entries |
| 1416      | 0               | 0        | 3               | 0          | |
| 1780      | 0               | 0        | 4               | 0          | |
| 2144      | 0               | 0        | 5               | 0          | |
| 2508      | 0               | 0        | 6               | 0          | |
| 2872      | 0               | 0        | 7               | 0          | 19 entries |
| 6148      | 0               | 0        | 16              | 0          | max observed |
| 832       | 0               | 0        | 1†              | 0          | irregular — bone-name inner_map body (+144 bytes) |
| 2536      | 0               | 7        | 0               | 0          | confirmed: 312 + 7×316 + 12 = 2536 (`Weapon_Fire_ing`) |
| 1788      | 0               | —        | —               | —          | irregular — split-reference (K=5, see Type C below) |
| 2152      | 0               | —        | —               | —          | irregular — split-reference (K=6, see Type C below) |

---

## StringPair

```
u32_le  len          (byte length of name, no null terminator in stream)
u8[len] name         (ASCII, e.g. "leaf", "core", "sub", "par1", "vector1")
```

All string pairs for an entry are stored consecutively (no structs between them).

---

## NamedItemStruct (144 bytes)

Immediately follows the struct_section count u32 (which equals named_item_count).
One struct per named item, same order as the string pairs. The struct_section
header is a single `u32=N` count (4 bytes only). The 12 zero bytes that appear
to follow the count in most entries are the first struct's colour field
(struct[0..12] = f32[3] default (0,0,0)) — not extra header padding. Blob size
examples confirm the 4-byte interpretation: a 1-named-item 475-byte blob gives
4+299+4+(4+4)+( **4** +144)+0+4+0+8 = 475, whereas a 16-byte header gives 487.

Internal layout from systematic byte scan across all 27 named item structs
(27 entries across 4-24 475–933 blobs):

| offset (within struct) | size | observation |
|------------------------|------|-------------|
| 0..12                  | 12   | f32[3]: **named-item colour** — independent of prefix color1/color2; default (0,0,0); e.g. (0.784, 0.392, 0.078) for one `leaf` component |
| 12..24                 | 12   | f32[3]: **named-item secondary colour** — default (0,0,0); not necessarily equal to prefix color2 |
| 24..36                 | 12   | f32[3]: mirrors prefix[40:52] — all three = 0.0f or all three = 0.05f (`cd cc 4c 3d`); only set when prefix[40:52] is set |
| 36..84                 | 48   | zeros (`vec_d`–`vec_g` all zero in all 27 vanilla entries) |
| 84..88                 | 4    | f32 `field_84`: per-stage intensity multiplier — same role as prefix[88:92]; 0.0 default, 0.3 for one `dist1` entry |
| 88..92                 | 4    | f32 `field_88`: 0.0 (`smoke1`), 0.3 (`smoke1` variant), or 1.0 (most components) |
| 92..96                 | 4    | u32 `field_92`: **{0, 2, 30}** — nonzero **only** for `par1` components (2 of 27 structs; values 2 and 30); likely particle emitter burst-count |
| 96..100                | 4    | always 0 |
| 100..104               | 4    | f32 = 1.0 (constant; 0.0 for `vector1`/`vector2` components) |
| 104..108               | 4    | f32 = 1.0 (constant; 0.0 for `vector1`/`vector2` components) |
| 108..112               | 4    | f32 = **−1.0** (constant sentinel — same role as prefix[112:116]) |
| 112..116               | 4    | f32 = 0.0 (constant) |
| 116..120               | 4    | f32 = 1.0 (constant) |
| 120..124               | 4    | f32 = 1.0 (constant) |
| 124..128               | 4    | f32 = 0.0 (constant) |
| 128..132               | 4    | f32 = 1.0 (constant) |
| 132..136               | 4    | f32 = 1.0 (constant) |
| 136..138               | 2    | `0a 05` (constant type marker — same as prefix[140:142]) |
| 138..140               | 2    | u16 bitmask flags (same role as prefix[142]); values: 0x0000, 0x0001, 0x0004, 0x0009, 0x0010, 0x0020, 0x0100, 0x0102 |
| 140..144               | 4    | zeros |

Total size confirmed: 144 bytes across all 27 entries.

**Field alignment:** NamedItemStruct IS a standalone D3Block (144 bytes). Within
EffectDataElement, the same D3Block sits at `core_block[0..144]`, which is at
prefix offset 4 (after `lookup_b`). So `struct[X] ≡ prefix[X+4]` for every
D3Block field. E.g. `field_92` at struct[92:96] ≡ prefix[96:100];
`byte_136/byte_137` type-marker at struct[136:138] ≡ prefix[140:142]. No TRS
or hash/ID region (the NamedItemStruct is a D3Block only, not a CoreBlock).

**EffectDataD3Block semantic labels** (Rust field name ↔ semantic meaning from cross-analysis):

| Rust field   | struct offset | semantic                                                  |
|-------------|--------------|-----------------------------------------------------------|
| `vec_a`     | 0..12        | named-item colour (RGB f32[3])                            |
| `vec_b`     | 12..24       | named-item secondary colour (RGB f32[3])                  |
| `vec_c`     | 24..36       | 0.0 or 0.05f triplet (mirrors prefix[40:52])              |
| `vec_d`–`vec_g` | 36..84  | all zero in vanilla (D3Block color/scale fields)          |
| `field_84`  | 84..88       | per-stage intensity multiplier — f32; 0.0 default; same role as prefix[88:92] |
| `field_88`  | 88..92       | type-dependent scale: 0.0, 0.3, or 1.0 across component types |
| `field_92`  | 92..96       | particle emitter parameter — u32 {0, 2, 30}; nonzero only for `par1` components |
| `byte_136`  | 136..137     | type marker byte 1 = 0x0a (same as prefix[140])          |
| `byte_137`  | 137..138     | type marker byte 2 = 0x05 (same as prefix[141])          |
| `word_138`  | 138..140     | bitmask flags — u16 (same role as prefix[142:144])        |

`field_96`–`field_132`, `vec4_a`, and `field_140` are IDA-derived anonymous names;
semantics follow the mirror relationship `struct[X] ≡ prefix[X+4]` (see above).

---

## Sub-Element (303 bytes in 4-11, 316 bytes in 4-24)

Present when `(mc_off − Y) > 0`. Count K is implicit (no count field stored).
Mapped from the 4-24 640-blob (K=1), sub-element at blob[312..628].

**Header (bytes 0..92 — all zeros except the header packet):**

| offset (within sub-element) | size | observation |
|-----------------------------|------|-------------|
| 0..8                        | 8    | zeros |
| 8                           | 1    | `0x01` (constant — version or type byte) |
| 9..13                       | 4    | **sub-element type ID** — 4 bytes identifying the sub-element class; shared across all blobs of the same class (e.g. `57 04 06 24` for 5 different 639-blobs, `79 1c a5 9a` for two 955-blobs and one sub within a 2535-blob). Not per-blob-unique. |
| 13..92                      | 79   | zeros |

**Body (bytes 9..316):**

The inner EffectData record begins at sub[9]. Its fields mirror
fixed_prefix[0..] with a +9 byte offset: sub[9+X] corresponds to prefix[X].
Byte-match sub[9+X] vs prefix[X] = 272/299 identical across available entries
(variable fields like TRS and IDs naturally differ).

| sub offset    | prefix equiv  | description |
|---------------|---------------|-------------|
| 9+92 = 101    | prefix[92]    | inner sub-struct float cluster begins |
| 9+140 = 149   | prefix[140]   | `0a 05` type marker |
| 9+200 = 209   | prefix[200]   | position XYZ (real values, e.g. (−0.020, 0, −0.237)) |
| 9+212 = 221   | prefix[212]   | scale XYZ (e.g. (0.5, 1, 1)) |
| 9+224 = 233   | prefix[224]   | rotation XYZ radians |

Sub-element TRS differs from the parent blob's TRS — each sub-element has
its own transform relative to the parent effect origin.

---

## InnerMapElement (351 bytes in 4-11, 364 bytes in 4-24)

> **Naming:** Snow's doc and early empirical analysis called these "MeshEffectData." Per IDA
> they are `inner_map` entries: `u32 key + EffectDataInner`. The 364-byte wire size applies
> when all of EffectDataInner's embedded CArrays are empty. This section retains the
> landmark offsets from empirical analysis; see `effect_data.rs` for the field-typed
> IDA-derived decoder.

Location: immediately after `inner_map_count` u32 at `mc_off + 4`.
In 4-24, confirmed up to n=16 (6148-byte blob).

**Activity flag:** mesh[0] = u8, either 0x01 (active) or 0x00 (null slot).
Only mesh[0] carries a full slot directory; trailing null slots carry only a
truncated self-reference and their own hash.

**Slot directory (mesh[0] only, variable size 20..68 bytes depending on M):**

mesh[0] encodes a linked "slot directory" covering all M active mesh slots.
The directory is `M×8 + 12` bytes (20 bytes minimum for M=1):

```
[0:4]         = 1 (active flag — slot 0)
[4:8]         = hash_A (slot 0's own hash/ID)

For k = 1 .. M-1:               ← (M-1) additional slots; empty range for M=1
  [8k:8k+4]   = 1 (active flag for slot k)
  [8k+4:8k+8] = hash_k (slot k's hash/ID)

[8M:8M+4]     = M  (total slot count)
[8M+4:8M+8]   = hash_A (repeated)
[8M+8:8M+12]  = hash_A (repeated again)
[8M+12 : 80]  = zeros (for standard entries; some complex entries override)
```

Concrete examples (from 70-sample scan — all M values confirmed):

| M | directory bytes | M field at | hash_A terminator at |
|---|-----------------|------------|----------------------|
| 1 | 20  | [8:12]  | [12:20] |
| 2 | 28  | [16:20] | [20:28] |
| 3 | 36  | [24:28] | [28:36] |
| 4 | 44  | [32:36] | [36:44] |
| 5 | 52  | [40:44] | [44:52] |
| 6 | 60  | [48:52] | [52:60] |
| 7 | 68  | [56:60] | [60:68] |

For M=1: no additional pairs (k range 1..0 is empty); directory = 20 bytes.
For M≥2: each pair k=1..M-1 references one of the other active mesh slots.

**Null/trailing mesh slots** contain only a compact back-reference (no directory):
zeros at [0:4] (inactive), hash at [4:8], zeros elsewhere in [0:80].

**Remaining mesh[0..108] fields:**

| mesh offset | size | description |
|-------------|------|-------------|
| 0..8M+12    | var  | slot directory (see above) |
| 8M+12..80   | var  | zeros for standard entries; one observed entry has f32=4.0 and RGB at [44:56] |
| 80..104     | 24   | zeros (confirmed across all 70 active mesh[0] samples) |
| 104..108    | 4    | f32: 0.0 or ~1.4 (1 of 70 active samples) |

**Shared inner sub-struct (mesh[M×8+100..364]):**

Starts at mesh[M×8+100] and mirrors fixed_prefix[92..300] (208 bytes) with the
alignment `mesh[M×8+100+X] ≅ prefix[92+X]`. The `0a 05` marker therefore lands
at mesh[M×8+148] for every M (confirmed for all M=1..16).

Landmarks below use M=1 base offsets (sub-struct start = mesh[108]); for M>1
add M×8 to each mesh offset:

| mesh offset (M=1) | prefix equiv     | landmark |
|-------------------|------------------|----------|
| 108               | prefix[92]       | float cluster start (f32 ≈ 1.0) |
| 156               | prefix[140]      | `0a 05` type marker |
| 196               | prefix[180]      | −π/2 constant |
| 216..252          | prefix[200..236] | TRS (position, scale, rotation) |
| 252               | prefix[236]      | constant `0x00000001` |
| 268               | prefix[252]      | constant `0x01000005` |
| 274..298          | prefix[258..282] | lookups_c (6×u32, null sentinel `0xeac5e173`) |
| 298..315          | prefix[282..299] | fields_d (16 bytes) + byte_e |

**Sub-struct boundary and mesh[316..364] content:**

The sub-struct occupies mesh[M×8+100 .. M×8+308]. For M=7 the sub-struct
exactly fills the mesh to byte 364. For M≤6 the sub-struct ends before 364
and the remainder is zeros. For M≥8 the sub-struct is truncated at byte 364
and the tail of Region 5 / Region 4 is absent from the mesh.

| M  | sub-struct end | mesh[316:364] content |
|----|----------------|-----------------------|
| 1  | mesh[316]      | all zeros (sub-struct ends at 316) |
| 2  | mesh[324]      | [316:324] = last 8 bytes of fields_d/byte_e (zeros); [324:364] zeros |
| 3  | mesh[332]      | [316:332] = last 16 bytes of fields_d region (zeros); [332:364] zeros |
| 4  | mesh[340]      | [316:340] = lookups_c[4..5] + fields_d; [340:364] zeros |
| 5  | mesh[348]      | [316:348] = lookups_c[3..5] + fields_d; [348:364] zeros |
| 6  | mesh[356]      | [316:356] = prefix[252..292] (`0x01000005` + lc[0..4]); [356:364] zeros |
| 7  | mesh[364]      | [316:364] = prefix[252..300] (`0x01000005` + lc[] + fields_d + byte_e) |
| 8  | mesh[372]†     | [316:364] = prefix[244..292] (Region 5 flags + lookups_c partial) |
| 16 | mesh[436]†     | [316:364] = prefix[180..228] (−π/2 + Region 3 zeros + TRS partial) |

† Truncated at mesh boundary; prefix bytes past the cutoff are absent.

---

## Fixed Prefix (blob[4 .. 4+FP])

Full field-level map from systematic byte and 4-byte-window scans across all
1952 baseline blobs in the 4-24 dump (FP=300, prefix offset = blob offset − 4).

### Region 1 — Colour parameters (prefix[0..92])

| prefix offset | size | type    | description |
|---------------|------|---------|-------------|
| 0..4          | 4    | zero    | always zero |
| 4..16         | 12   | f32[3]  | **grayscale tint** (all three always equal): default (0,0,0); 5 entries set value to 0.3/0.5/0.6/0.85. Mutually exclusive with color1/color2 — entries use one or the other. |
| 16..28        | 12   | f32[3]  | **color1** (start color, RGB normalised 0..1): default (0,0,0); 47 entries non-zero |
| 28..40        | 12   | f32[3]  | **color2** (end color, RGB normalised 0..1): default (0,0,0); 22 entries non-zero. When both color1 and color2 are non-zero they are usually equal (constant color). |
| 40..52        | 12   | f32[3]  | 3 floats, each 0.0 or 0.05f (`cd cc 4c 3d`); only 2 of 1952 entries use this |
| 52..88        | 36   | zero    | always zero |
| 88..92        | 4    | f32     | **per-stage intensity multiplier** (IDA: `d3.field_84`; Rust: `EffectDataD3Block.field_84`, typed u32 but semantically f32): default 0.0 (99.3% of entries). All 15 non-zero entries are `_switch_` or ribbon effects. Wolf-claw switch series: _01=0.3, _02=0.5, _03=1.0 — a 3-stage opacity ramp (30%→50%→100%). Ribbon entries: damian variants = 1.0, com (common player) variants = 1.5. Encodes per-switch-state brightness; 0.0 = inactive/no override. |

### Region 2 — Inner sub-struct (prefix[92..145])

This block mirrors the same inner structure found in NamedItemStruct[88..141]
and in sub-elements at sub[92..145]. Offset −4 shift in NamedItemStruct.

| prefix offset | size | type    | description |
|---------------|------|---------|-------------|
| 92..96        | 4    | f32     | ~99.7% = 1.0; 5 unique values, range 0.02..1.0 |
| 96..104       | 8    | f32[2]  | 0.0, 0.0 (constant) |
| 104..108      | 4    | f32     | ~98% = 1.0; 13 unique values, range 0.3..3.0 |
| 108..112      | 4    | f32     | ~98% = 1.0; 16 unique values, range 0.0..4.0 |
| 112..116      | 4    | f32     | default **−1.0** (sentinel); 6 unique values, can be positive |
| 116..120      | 4    | f32     | 0.0 (constant) |
| 120..128      | 8    | f32[2]  | 1.0, 1.0 (constant) |
| 128..132      | 4    | f32     | 0.0 (constant) |
| 132..140      | 8    | f32[2]  | 1.0, 1.0 (constant) |
| 140..142      | 2    | u8[2]   | `0x0a 0x05` — **constant type marker** |
| 142..143      | 1    | u8      | bitmask flags: 96% zero; nonzero values are powers of 2 {2,4,6,8,16,32,48} |
| 143..144      | 1    | u8      | bool: 0 (1950 entries) or 1 (2 entries) |
| 144..145      | 1    | u8      | enum 0..5: 73% zero, then 1(23%), 2(2%), 3(1%), 4(0.5%), 5(0.2%) |

### Region 3 — Zero padding (prefix[145..200])

All 55 bytes are constant zero in every entry. This includes the 12 zero
bytes inserted at prefix[168:180] in the 4-24 patch (absent in 4-11 where
the `−π/2` constant began at prefix[168]).

Exception embedded within the zero run:

| prefix offset | size | type | description |
|---------------|------|------|-------------|
| 180..184      | 4    | f32  | `db 0f c9 bf` = **−π/2 ≈ −1.5708** (constant) |

### Region 4 — Transform (prefix[200..236])

TRS (translation, scale, rotation) transform for this effect element,
confirmed from non-trivial entries (e.g., fire-effect entries with realistic
position, rotated turret effects with π/2 angles, etc.).

| prefix offset | size | type   | description |
|---------------|------|--------|-------------|
| 200..212      | 12   | f32[3] | **position** XYZ offset — default (0,0,0); range ~±40 |
| 212..224      | 12   | f32[3] | **scale** XYZ — default (1,1,1); **never zero**; range −1..10 |
| 224..236      | 12   | f32[3] | **rotation** XYZ in radians — default (0,0,0); range ±π |

Sample non-trivial entries:
- `pos=(0,0,0.75)  scale=(1,1,1)  rot=(0, π/2, 0)` — vertical offset, 90° yaw
- `pos=(−0.36,0,0) scale=(1.5,0.7,1.5)` — lateral shift, non-uniform scale
- `pos=(0,0,0.035) scale=(2.5,2.5,2.5)` — vertical offset, uniform upscale
- `scale=(0.05,0.05,0.01)` — tiny uniform scale

### Region 5 — Flags and IDs (prefix[236..299])

| prefix offset | size | type | description |
|---------------|------|------|-------------|
| 236..240      | 4    | u32  | constant `0x00000001` (single `0x01` byte) |
| 240..244      | 4    | —    | mostly zero; 2 of 1952 entries non-zero |
| 244..248      | 4    | u8[4]| `{0x00, 0x01, 0x00, 0x00}` for most entries (byte 245 = 1) |
| 248..252      | 4    | u8[4]| `{0x01, 0x00, 0x00, X}` where X ∈ {0,1,2,3,5} — byte 251 is an enum |
| 252..256      | 4    | u32  | constant `0x01000005` (bytes: `05 00 00 01`) |
| 256..258      | 2    | u8[2] | `0x00 0x00` — EffectDataCoreBlock byte_252/byte_253 (last two bytes of CoreBlock, always zero) |
| 258..282      | 24   | u32[6]| **`lookups_c[0..6]`** (Rust: `EffectDataElement.lookups_c`; IDA: `read_u32_lookup_DA30`): 6 × u32 effect hash. Null sentinel = `0xeac5e173` (bytes `73 e1 c5 ea`). See table below. |
| 282..298      | 16   | u32[4]| **`fields_d[0..4]`** (Rust: `EffectDataElement.fields_d`): all zero in vanilla |
| 298..299      | 1    | u8    | **`byte_e`** — always 0 in vanilla; IDA reads as named field (`EffectDataElement.byte_e`), making FP=300 not 299 |

**lookups_c detail (prefix[258..282], 6 × u32, null sentinel `0xeac5e173`):**

| slot  | prefix offset | unique values | null %  | notes |
|-------|---------------|---------------|---------|-------|
| lc[0] | 258..262      | ~250 groups   | 0%      | **effect group hash** — groups L/R mirror pairs, same-character body-part variants, and same-weapon-type variants; 1521 unique low-u16 / 1741 unique high-u16 across 2057 entries |
| lc[1] | 262..266      | 118 distinct  | ~50%    | secondary hash; role unknown |
| lc[2] | 266..270      | 2 distinct    | ~99%    | nearly always null |
| lc[3] | 270..274      | 3 distinct    | ~99%    | nearly always null |
| lc[4] | 274..278      | 22 distinct   | ~96%    | null except ~4%; non-null correlates with sub-element effects |
| lc[5] | 278..282      | 1 (null only) | 100%    | always null |

---

## Coverage

| dump      | entries | parsed | failures | failure sizes |
|-----------|---------|--------|----------|---------------|
| 2026-4-11 | 2039    | ~2035  | ~5       | 361×2, 806×1, 1356×2, 1723×1, 2074×1 (sizes +1 from original; not re-classified) |
| 2026-4-24 | 2057    | 2054   | 3        | 832×1 (TypeA), 1788×1 (TypeC), 2152×1 (TypeC) |

4-24 failure sizes are exactly 13 more than their 4-11 counterparts. Types B, D, and E
are standard after the FP=300 correction:
- Type B (374-byte) = standard mesh=1 (one 50-byte MeshEffectData)
- Type D (2536-byte) = standard K=7 sub-elements
- Type E (1416-byte) = standard inner_map=3

4-11 failure classification not re-verified after FP correction; some may also resolve.

---

## Irregular Blobs

The 3 irregular entries in 4-24 (after reconciliation; Types B, D, and E are now
standard). Byte offsets below use FP=300 boundaries:

### Type A — Bone-name inner_map body (832-byte blob)

One entry (`pafx_mc_rotationbash_lightning_gain_001a_switch_01`) has inner_map=1
but the entry body is variable-length because it embeds a bone name list and bone
weight array. The outer layout is identical to a standard inner_map blob
(blob[304:312]=8 zeros, blob[312:316]=inner_map_count=1, body, 8 trailing zeros),
but the body is 508 bytes instead of the standard 364.

The bone name list begins at **mesh offset 298**:

```
                                        ... (298 bytes standard mesh data)
07 00 00 00             ← bone_count = 7
0b 00 00 00  42 69 70 30 31 20 53 70 69 6e 65          "Bip01 Spine" (11)
0c 00 00 00  42 69 70 30 31 20 53 70 69 6e 65 31       "Bip01 Spine1" (12)
0c 00 00 00  42 69 70 30 31 20 53 70 69 6e 65 32       "Bip01 Spine2" (12)
10 00 00 00  42 69 70 30 31 20 52 20 43 6c 61 76 69 63 6c 65  "Bip01 R Clavicle" (16)
10 00 00 00  42 69 70 30 31 20 52 20 55 70 70 65 72 41 72 6d  "Bip01 R UpperArm" (16)
0d 00 00 00  42 69 70 30 31 20 52 20 45 6c 62 6f 77          "Bip01 R Elbow" (13)
0c 00 00 00  42 69 70 30 31 20 52 20 48 61 6e 64             "Bip01 R Hand" (12)
06 00 00 00             ← weight_count = 6
89 88 08 3e  ×6         ← 6 × f32 ≈ 0.1333 (bone weights per bone attachment?)
[58 trailing zeros]
```

Total body size: 508 bytes (298 standard + 4 count + 120 names + 4 count + 24 weights + 58 zeros).

### Type C — Split-reference mesh (1787, 2151-byte blobs)

Two entries use a "split header" format where K mesh headers are stored
separately from K−1 mesh bodies:

```
blob[304:312]         8 zeros (standard — named_item_count=0, struct_count=0)
blob[312:316]         K  (u32 reference count — NOT inner_map count)
blob[316:316+K×8]     K reference entries, each = (u32=1, u32=hash)
blob[316+K×8:end-8]   M = K−1  bodies, each 356 bytes
blob[end-8:end]       8 trailing zeros
```

Size formula: `316 + K×8 + (K−1)×356 + 8 = 364×K − 32`

| blob size | K | M=K-1 | entry name |
|-----------|---|-------|------------|
| 1788      | 5 | 4     | `pafx_Swim_Foot_Warmachine` |
| 2152      | 6 | 5     | `fx_smokeshell_out` |

The last two reference entries always share the same hash (a back-reference or
deduplication marker). Body layout (each 356 bytes):

| body offset | size | description |
|-------------|------|-------------|
| 0..4        | 4    | M (total body count) for body[0]; 0 for body[i>0] |
| 4..8        | 4    | hash — equals ref[i].hash for the corresponding reference entry |
| 8..12       | 4    | same hash repeated |
| 12..100     | 88   | zeros |
| 100..308    | 208  | **inner sub-struct** (≅ prefix[92..300]) — same layout as InnerMapElement[108..316]; `body[100+X] ≅ prefix[92+X]`; all landmarks confirmed |
| 308..356    | 48   | tail — all zeros (confirmed across all 9 bodies: 4×pafx_Swim + 5×fx_smokeshell_out) |

Key landmarks within the inner sub-struct (all confirmed):

| body offset | prefix equiv    | landmark |
|-------------|-----------------|----------|
| 100         | prefix[92]      | float cluster start (f32 = 1.0) |
| 148:150     | prefix[140:142] | `0a 05` type marker |
| 188:192     | prefix[180:184] | −π/2 constant |
| 208:244     | prefix[200:236] | TRS — per-body position/scale/rotation (e.g. pafx_Swim body 0: pos=(−0.36, 0.7, −0.4), scale=(1.8, 1.8, 1.8)) |
| 244:248     | prefix[236:240] | constant `0x00000001` |
| 260:264     | prefix[252:256] | constant `0x01000005` |
| 266:290     | prefix[258:282] | lookups_c (6×u32, null sentinel `0xeac5e173`) |

The body's inner sub-struct uses the same layout as InnerMapElement[108..316], with
the base offset 8 bytes earlier in the body's own coordinate space.

### Type D — Extended sub-element blob (2536-byte blob)

> **Reconciled:** this is a standard blob with K=7 sub-elements; not irregular.

One entry (`Weapon_Fire_ing`) has K=7 sub-elements, fitting the standard
sub-element formula `312 + K×316 + 12`:

```
312 + 7×316 + 12 = 2536  ✓
```

Each sub-element starts at blob[312 + i×316] with the standard header
`00 00 00 00 00 00 00 00 01` (8 zeros + 0x01). The trailing 12 zeros are
also standard. This blob fits the general formula — it was previously
miscounted because K=7 is larger than the K≤2 samples used to calibrate.

### Type E — Reconciled: standard inner_map=3 (1416-byte blobs)

> **Reconciled:** these entries are no longer classified as irregular. With FP=300
> the correct size for inner_map=3 is 324 + 3×364 = 1416, not 1407. The earlier
> "keyed-entry" analysis was derived from a wrong byte boundary (byte_e missed).
> Both entries fit the general formula with inner_map_count=3.

Two entries (`cdfx_mc_onguard_shield_fxpreset_01` and
`cdfx_mc_onguard_shield_fxpreset_01_applyAnimationSpeed`) — blob_size 1416 =
baseline(324) + 3×364(inner_map). Standard layout; no special handling required.

---

## Next Steps

1. ~~**prefix[88:92]**~~ **Resolved**: per-stage intensity multiplier (`d3.field_84`, f32).
   All 15 non-zero entries are `_switch_`/ribbon effects; wolf-claw switch stages step
   0.3→0.5→1.0 (_01/_02/_03). IDA types field as u32; actual wire values are clean f32.
   prefix[40:52] confirmed to mirror NamedItemStruct struct[24:36] (0.05f triplet).

2. ~~**Identify prefix[256:264] IDs**~~ **Resolved**: prefix[256:258] = CoreBlock byte_252/byte_253
   (always zero); prefix[258:282] = `lookups_c[0..6]` — 6 × u32 effect hashes.
   lc[0] is an **effect group hash** grouping visual variants (L/R mirrors, body parts,
   weapon-type variants); ~250 groups across 2057 entries. lc[1..5] are secondary hashes
   with decreasing cardinality; lc[5] is always null. Null sentinel = `0xeac5e173`. Earlier
   "unique per-entry ID" interpretation was an artefact of reading lc[0] as two u16s in
   isolation.

3. ~~**inner_map slot directory hashes**~~ **Resolved**: `InnerMapEntry.key` (the u32 map
   key stored at `mc_off+4 + n×364`) is a **Crimson Desert Jenkins hashlittle2 hash of a
   skeleton bone name** (init = `length + 0xDEBA1DCD`, returns `c`). The same value is
   redundantly stored as `EffectDataInner.field_0` (first u32 of the inner body). 9 of 168
   unique keys were cross-verified against `stringinfo.pabgb`: all decode to Biped
   skeleton bones (`Bip_Sphere_01`, `Bip_Spine_03/04/05`, `Bip_Spin_01..05` for the Kutum
   boss entry). The remaining 159 unique keys are almost certainly additional bone names
   not present in `stringinfo`. Confirmed NOT blob keys within effectinfo.pabgb (0 hits);
   the "different archive" hypothesis was wrong — these are inline skeleton attachments.

4. ~~**NamedItemStruct struct[80:84]**~~ **Resolved**: the field was at the wrong offset
   in the doc. Actual position is **struct[92:96]** (`field_92`); doc table rows 72:76
   through 128:144 were all wrong (cascading offset error). Corrected in full. `field_92`
   = u32 ∈ {0, 2, 30}, nonzero for exactly 2 of 27 par1 particle components
   (`fx_Soul_spear_On_Lv3` → 2, `fx_ancient_aura_a_aura1_custom1` → 30); likely a
   particle burst-count. Adjacent fixes: `field_84` = intensity multiplier (not zeros);
   `field_88` = type-dependent scale (not constant 1.0); byte_136/137/word_138 roles
   corrected (marker bytes are byte_136=0x0a, byte_137=0x05; word_138=bitmask, not
   the other way around); float-cluster alignment note corrected to `struct[X] ≡
   prefix[X+4]`.

5. ~~**Type C body remainder (body[152:356])**~~ **Resolved**: full mapping confirmed.
   body[100..308] = inner sub-struct ≅ prefix[92..300] (same structure as
   InnerMapElement[108..316]); body[308..356] = 48-byte tail, all zeros (verified
   across all 9 bodies: 4×pafx_Swim_Foot_Warmachine + 5×fx_smokeshell_out). All key
   landmarks confirmed: body[148:150]=`0a 05`, body[188:192]=−π/2, body[208:244]=TRS
   with per-body real values, body[244:248]=`0x01`, body[260:264]=`0x01000005`,
   body[266:290]=lookups_c with null sentinels. The 48-byte tail is entirely zeros —
   no hidden fields beyond the prefix-equivalent range.

6. ~~**InnerMapElement inner sub-struct tail (mesh[316..364], 48 bytes)**~~ **Resolved**:
   the sub-struct does not start at a fixed mesh[108]. It starts at mesh[M×8+100],
   shifting 8 bytes per active slot. The `0a 05` marker is at mesh[M×8+148] for every
   M=1..16. Sub-struct end = mesh[M×8+308]; for M=7 this is exactly mesh[364] (no
   tail). mesh[316:364] is NOT padding: for M≤6 it is the trailing fields_d/byte_e
   region of the sub-struct followed by zeros; for M≥7 it is an interior slice of
   Region 5 / Region 4 data (lookups_c, TRS, or −π/2 depending on M). For M≥8 the
   sub-struct is truncated at the 364-byte mesh boundary. Slot directory formula
   also corrected: M×8+12 bytes (not max(M,2)×8+12); M=1 directory = 20 bytes with
   no self-reference pair.
