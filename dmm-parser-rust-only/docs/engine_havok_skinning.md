# Crimson Desert Engine — Havok Integration Research

Research notes from binary analysis of `CrimsonDesert.exe` (Win retail build).
Triggered by community question about whether the engine uses Havok rigid
bodies for skin proxies.

**Status:** Research notes only. Capturing findings for future work on
mesh/skel/animation parsing (currently Layer 5 — binary asset content
inside PAZ archives, not yet field-level parsed).

## TL;DR

The engine is built on **Havok 2024.2 SDK**, fully statically linked.
- Vertex weights / skinning live in **`hkaMeshBinding` + `hkxMesh::Section`**
  (the canonical Havok skinned-mesh classes).
- Rigid bodies / ragdoll live in a **parallel `hknpRagdoll` hierarchy** that
  shares the same `hkaSkeleton` as the skinned mesh.
- During normal animation: rigid bodies are keyframe-driven by the same pose
  that skins the mesh (effectively skin-following physics proxies).
- During physics events (hits, death, etc): `hknpRagdollStatePoweredDynamicAnimation`
  blends physics into the bones; the skinned mesh follows because it's still
  bound to the skeleton, which is now driven by physics.

## Confirmed via IDA Pro string + RTTI scan

### Build path (proves Havok 2024.2 statically linked)

```
d:\bs\mainline\code\trunk\External\Havok_2024_2\Public\HavokSDK\
    Common\Base\Container\RelArray\hkRelArray.inl
    Common\Base\Container\Array\hkArray.inl
    Common\Base\Reflect\Impl\hkBuiltinImpl.cpp
    Common\Base\Reflect\Impl\hkHavokImpl.cpp
    Common\Base\Thread\Pool\hkCpuThreadPool.cpp
    Common\Base\Memory\Debug\hkMemorySnapshot.cpp
    Common\Visualize\hkVisualDebugger.cpp
    Platform\Windows\Common\Base\hkWin32FileSystem.cxx
    ...
```

Plus thread names: `Havok Worker`, `Havok Async`.

### Animation module (`hka*`) — drives skinning

| Class | Purpose |
|---|---|
| `hkaSkeleton` | Bone hierarchy |
| `hkaBone` | Single bone |
| `hkaSkeletonMapperData` | Skeleton remapping |
| `hkaAnimationBinding` | Animation → skeleton binding |
| `hkaBoneAttachment` | Attachment point on a bone |
| **`hkaMeshBinding`** | **Skinned mesh ↔ skeleton binding (vertex weights)** |
| `hkaAnimation` / `hkaQuantizedAnimation` | Animation data |
| `hkaAnimationContainer` | Top-level container |
| `hkaFootstepAnalysisInfo` | Locomotion metadata |

**`hkaMeshBinding` is the canonical vertex-skinning class.** Its known field
layout (per Havok 2024.2 SDK + confirmed by string `boneFromSkinMeshTransforms`
in the exe):

```cpp
class hkaMeshBinding {
    hkRefPtr<hkxMesh>          m_mesh;
    hkStringPtr                m_originalSkeletonName;
    hkRefPtr<hkaSkeleton>      m_skeleton;
    hkArray<Mapping>           m_boneFromSkinMeshMappings;
    hkArray<hkInt16>           m_boneFromSkinMeshMappings;  // per-section indices
    hkArray<hkMatrix4>         m_boneFromSkinMeshTransforms;  // bind pose
};

class hkxMesh {
    hkArray<hkRefPtr<hkxMeshSection>> m_sections;
    hkArray<UserChannelInfo>          m_userChannelInfos;
};

class hkxMeshSection {
    hkRefPtr<hkxVertexBuffer>  m_vertexBuffer;  // pos + normal + uv + bone_weights + bone_indices
    hkRefPtr<hkxIndexBuffer>   m_indexBuffer;   // triangles
    hkRefPtr<hkxMaterial>      m_material;
    // ...
};
```

Vertex weights live inside `hkxVertexBuffer` as per-vertex `(weight×4,
boneIndex×4)` pairs (standard 4-bone skinning).

### Physics module (`hknp*`) — modern HKNP API

| Class | Purpose |
|---|---|
| `hknpBody` | Single rigid body (replaces legacy `hkpRigidBody`) |
| `hknpBodyCinfo` | Body construction info |
| `hknpBodyQuality` | Quality / LOD presets |
| `hknpCompoundShape` | Compound collision shape |
| `hknpMeshShape` | Mesh-based collision (read-only triangle mesh) |
| `hknpCharacterProxy` | Character physics proxy (movement-controller-style) |
| `hknpCharacterProxyManager` | Manages character proxies |
| **`hknpRagdoll`** | **Hierarchy of rigid bodies matching a skeleton** |
| **`hknpRagdollController`** | **Drives the rigid body hierarchy** |
| **`hknpRagdollKeyFrameHierarchyController`** | **Keyframes drive bodies (animation-following)** |
| **`hknpRagdollStatePoweredDynamicAnimation`** | **Animation-driven physics state** |
| `hkaRagdollInstance` | Animation-side ragdoll instance (binds anim ↔ physics) |

Multiple version-migration suffixes (`_0_to_1`, `_1_to_2`, etc.) confirm
HKNP is the actively-used API, with serialized data going through
version-upgrade paths.

### Cloth module (`hcl*`/`hct*`)

| Class | Purpose |
|---|---|
| `hclSimClothData` | Simulated cloth state |
| `hclClothContainer` | Top-level container |
| `hclClothState` / `hclClothStateBuffer` | Per-frame cloth state |
| `hclSimClothPose` | Pose at frame |
| `hctClothSetup20151` | Cloth tool import (Havok Cloth Tool) |

So the engine ALSO has Havok Cloth in use — relevant to cape/hair/garment
deformation that follows skeleton motion.

## Skin-proxy / vertex-weight pipeline as understood from binary

```
┌─────────────────────────────────────────────────────────────────┐
│                       hkaSkeleton (bones)                        │
│       Single source of truth for bone transforms at runtime.     │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
    ┌──────────────────┐ ┌──────────┐ ┌────────────────┐
    │  hkaMeshBinding  │ │ hknpRag- │ │ hclSimCloth   │
    │  + hkxMesh       │ │  doll    │ │  Data         │
    │  (vertex weights │ │ (rigid   │ │  (cloth      │
    │   GPU-skinned to │ │  bodies  │ │   proxies)   │
    │   bones)         │ │  matching│ │              │
    └──────────────────┘ │  bones)  │ └────────────────┘
                         └──────────┘
                              │
                              ▼
                   hknpRagdollKeyFrameHierarchyController
                   (animation pose → rigid body transforms)
                              │
                              ▼
                   On hit/death event:
                   hknpRagdollStatePoweredDynamicAnimation
                   (physics blends in, drives skeleton,
                    skin follows because still bound to it)
```

## Implications for mod work

### What "import/export character stuff kinda works"

The skinned mesh format is standard Havok (`hkxMesh` + `hkaMeshBinding` +
`hkaSkeleton`). Any DCC plugin that ingests Havok packfiles (`.hkt`, `.hkx`,
or the binary serialization of the same classes via `hkSerializeUtil`) will
recognize the bone hierarchy + vertex weights. That's why partial roundtrip
works: it's the canonical Havok class set.

The thing that probably feels janky:
- The PAZ archive layer (game-specific encryption + container format)
  wraps the Havok data and isn't a standard Havok packfile.
- The ragdoll/physics layer (`hknpRagdoll` + constraints) is HKNP, which
  is newer and has fewer DCC plugins than the legacy `hkp*` API.
- Cloth setup (`hctClothSetup20151`) is the 2015.1 cloth tool format
  embedded in 2024.2 — older toolchains might not match.

### Path forward for full mesh/skel mod authoring

When this layer becomes a parsing target (Layer 5 — currently binary
pass-through), the deserialization order would be:

1. Identify the PAZ asset that holds skel + mesh (likely `*.skel`/`*.mesh`
   inside character PAZ archives).
2. Decrypt PAZ wrapper to raw bytes.
3. Detect Havok packfile signature (`\x57\xE0\xE0\x57\x10\xC0\xC0\x10` for
   binary tagfiles or `<hktagfile` for XML).
4. Use Havok `hkSerializeUtil::load()`-equivalent reader (or roll our own,
   since the schemas are stable per SDK version 2024.2).
5. Walk the loaded `hkRootLevelContainer` for `hkaAnimationContainer`,
   `hkaMeshBinding`, `hknpRagdoll`, `hclClothContainer`.
6. Emit JSON v3.1 schema with field-level intents per Havok class.

### Quick wins available now

- Search the exe for the function that ingests skel+mesh from PAZ to
  identify the loader entry point and which PAZ asset type it consumes.
- Cross-reference `hkaMeshBinding::staticClass()` to find serializer
  registrations.
- Identify which PAZ class hash maps to skel/mesh assets via PAPGT
  type-table.

Tracked under future work: this isn't a Tier 1 priority since current
mod authoring (DDS texture replacement + pabgb table editing) doesn't
touch the skin pipeline. Document captured here so when the time comes,
we have the receipts.

## Source

All findings pulled via IDA Pro MCP (ida-pro-mcp 1.4.0) string + global
filter scans against CrimsonDesert.exe (retail Windows build).
