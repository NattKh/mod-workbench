# Crimson Desert pa::*Info Table Catalog

Comprehensive catalog of every `pa::*Info` C++ class found in the
Crimson Desert Mac binary symbol dump (449 classes total).
Generated from `mac_extract/mac_table_fields.json` cross-referenced
with the current dmm-parser table coverage and the on-disk pabgb
file set.

Regenerate with: `python dmm-pabgb-aio/generate_449_catalog.py`

## Summary

| Status | Count |
|---|---|
| **On-disk + Tier 1 (fully field-decoded)** | 118 |
| **On-disk + Tier 1.5 (typed + polymorphic blob field)** | 0 |
| **On-disk + Tier 2 (blob-tail, partial decode)** | 0 |
| **Parser exists but not in current dump** | 2 |
| **In-memory only (C++ struct, no pabgb file)** | 327 |
| **TOTAL** | 449 |

## Status legend

| Glyph | Meaning |
|---|---|
| ✅ T1 | On disk, fully field-decoded — every field individually addressable by v3 mods |
| 🟢 T1.5 | On disk, mostly typed — one polymorphic field exposed as opaque-but-clonable blob |
| 🟡 T2 | On disk, blob-tail decoded — `key`/`string_key`/`is_blocked` editable; rest opaque |
| 📚 P  | Parser exists but no matching .pabgb in this game dump (older version or other region) |
| 🧠 — | In-memory C++ struct only; never serialized to disk; no parser needed |

## Categories

- [AI](#ai) — 8
- [Buff/Effect/Condition](#buffeffectcondition) — 26
- [Character/NPC](#characternpc) — 30
- [Crafting/Material](#craftingmaterial) — 17
- [Faction/Field/World](#factionfieldworld) — 112
- [Gimmick/Trigger](#gimmicktrigger) — 53
- [Item/Inventory](#iteminventory) — 34
- [Mini-game / Special](#mini-game--special) — 7
- [Misc](#misc) — 75
- [Platform/System](#platformsystem) — 6
- [Quest/Mission/Knowledge](#questmissionknowledge) — 26
- [Skill/Action](#skillaction) — 35
- [UI/Audio/Localization](#uiaudiolocalization) — 20

## AI

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `AIActionAttributeInfo` | 4 | records for ai action attribute (records can be individually blocked via is_blocked) |
| ✅ T1 | `AIDialogStringInfo` | 11 | records for ai dialog string (records can be individually blocked via is_blocked) |
| ✅ T1 | `AIDialogTypeInfo` | 7 | type/enum definitions for ai dialog (records can be individually blocked via is_blocked) |
| ✅ T1 | `AIEventTableInfo` | 12 | lookup table for ai event (records can be individually blocked via is_blocked) |
| ✅ T1 | `AIMemoryInfo` | 3 | records for ai memory (records can be individually blocked via is_blocked) |
| 🧠 — | `AIMemoryOfTarget` | 2 | records for ai memory of target |
| 🧠 — | `AIMoveSpeedData` | 20 | records for ai move speed data |
| ✅ T1 | `AIMoveSpeedInfo` | 4 | records for ai move speed (records can be individually blocked via is_blocked) |

## Buff/Effect/Condition

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `ActionChartFrameEvent_EffectDataDesc` | 26 | records for action chart frame event effect data desc |
| 🧠 — | `ActionChartFrameEvent_EffectVariationParameter` | 21 | records for action chart frame event effect variation parameter |
| ✅ T1 | `BuffInfo` | 13 | records for buff (records can be individually blocked via is_blocked; carries buff data) |
| 🧠 — | `BuffLevelData` | 1 | records for buff level data (carries buff data) |
| ✅ T1 | `ConditionInfo` | 6 | records for condition (records can be individually blocked via is_blocked) |
| 🧠 — | `ConditionOptionData` | 4 | records for condition option data |
| 🧠 — | `ConditionTargetData` | 5 | records for condition target data |
| ✅ T1 | `EffectInfo` | 8 | records for effect (records can be individually blocked via is_blocked) |
| 🧠 — | `EffectInfoData` | 18 | records for effect info data (spawn-related) |
| 🧠 — | `EffectPlayInfo` | 1 | records for effect play |
| 🧠 — | `EffectPresetElement` | 18 | records for effect preset element (positional; spawn-related) |
| 🧠 — | `FactionEventData_ExecuteCondition` | 10 | records for faction event data execute condition (quest references) |
| 🧠 — | `GameConditionInfo` | 4 | records for game condition (records can be individually blocked via is_blocked) |
| ✅ T1 | `GameGlobalEffectInfo` | 17 | records for game global effect (records can be individually blocked via is_blocked) |
| 🧠 — | `GameGlobalEffectInfo_Effect` | 7 | records for game global effect info effect (spawn-related) |
| 🧠 — | `GameGlobalEffectInfo_PostProcess` | 22 | records for game global effect info post process |
| 🧠 — | `GameGlobalEffectInfo_Weather` | 46 | records for game global effect info weather |
| 🧠 — | `GimmickSceneObjectControl_GenerateEffectData` | 3 | records for gimmick scene object control generate effect data |
| 🧠 — | `InteractionConditionData` | 7 | records for interaction condition data |
| 🧠 — | `MeshEffectInfoData` | 14 | records for mesh effect info data |
| 🧠 — | `NighScheduleConvertingConditionData` | 8 | records for nigh schedule converting condition data |
| 🧠 — | `StageInfo_GlobalEffect` | 4 | records for stage info global effect |
| ✅ T1 | `StatusGroupInfo` | 8 | grouping/categorization for status (records can be individually blocked via is_blocked) |
| ✅ T1 | `StatusInfo` | 34 | records for status (records can be individually blocked via is_blocked; carries buff data) |
| 🧠 — | `SubInnerGuideEffectData` | 3 | records for sub inner guide effect data |
| 🧠 — | `UpgradeActiveConditionData` | 2 | records for upgrade active condition data |

## Character/NPC

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `AutoSpawnCharacterData` | 6 | records for auto spawn character data (NPC/character references) |
| 🧠 — | `CharacterAdditionalPartsData` | 3 | records for character additional parts data |
| ✅ T1 | `CharacterAppearanceIndexInfo` | 7 | records for character appearance index (records can be individually blocked via is_blocked; NPC/character references) |
| ✅ T1 | `CharacterChangeInfo` | 4 | records for character change (records can be individually blocked via is_blocked) |
| 🧠 — | `CharacterCloneInfo` | 1 | records for character clone |
| 🧠 — | `CharacterDialogGroupData` | 1 | records for character dialog group data |
| 🧠 — | `CharacterEquipmentData` | 9 | records for character equipment data |
| 🧠 — | `CharacterFriendlyItemData` | 5 | records for character friendly item data |
| ✅ T1 | `CharacterGroupInfo` | 15 | grouping/categorization for character (records can be individually blocked via is_blocked; NPC/character references) |
| ✅ T1 | `CharacterInfo` | 174 | records for character (records can be individually blocked via is_blocked; skill references; NPC/character references; spawn-related) |
| 🧠 — | `CharacterLevelData` | 10 | records for character level data |
| 🧠 — | `CharacterMoveSpeedInfo` | 12 | records for character move speed (records can be individually blocked via is_blocked) |
| 🧠 — | `CharacterRewardData` | 3 | records for character reward data |
| 🧠 — | `CharacterThreatData` | 3 | records for character threat data |
| 🧠 — | `CommonMiniGamePlayCharacterParameter` | 1 | records for common mini game play character parameter |
| 🧠 — | `FactionPatrolCharacterData` | 6 | records for faction patrol character data (NPC/character references) |
| 🧠 — | `InventoryNpcUsableData` | 2 | records for inventory npc usable data |
| ✅ T1 | `JobInfo` | 7 | records for job (records can be individually blocked via is_blocked) |
| 📚 P | `MercenaryGroupInfo` | 6 | grouping/categorization for mercenary (records can be individually blocked via is_blocked) |
| ✅ T1 | `MercenaryInfo` | 19 | records for mercenary (records can be individually blocked via is_blocked; spawn-related) |
| 🧠 — | `MiniGameCharacterData` | 6 | records for mini game character data |
| 🧠 — | `NpcFriendlyInfo` | 4 | records for npc friendly (records can be individually blocked via is_blocked) |
| ✅ T1 | `NpcInfo` | 15 | records for npc (records can be individually blocked via is_blocked; UI icon) |
| 🧠 — | `SequencerStageTrackChangeData_Character` | 4 | records for sequencer stage track change data character (NPC/character references) |
| 🧠 — | `StageChart_Function_HireMercenary` | 5 | records for stage chart function hire mercenary |
| 🧠 — | `StageChart_Function_RecoveryMercenary` | 3 | records for stage chart function recovery mercenary |
| 🧠 — | `SummonCharacterData` | 41 | records for summon character data (positional; spawn-related) |
| 🧠 — | `SummonCharacterData_SelectData` | 2 | records for summon character data select data |
| 🧠 — | `SummonCharacterData_TerrainRegionAutoSpawn` | 5 | records for summon character data terrain region auto spawn (spawn-related) |
| ✅ T1 | `TribeInfo` | 29 | records for tribe (records can be individually blocked via is_blocked) |

## Crafting/Material

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `CraftToolGroupInfo` | 7 | grouping/categorization for craft tool (records can be individually blocked via is_blocked) |
| ✅ T1 | `CraftToolInfo` | 6 | records for craft tool (records can be individually blocked via is_blocked) |
| 🧠 — | `DropDefaultData` | 6 | records for drop default data |
| 🧠 — | `DropFriendlyData` | 8 | records for drop friendly data (NPC/character references) |
| 🧠 — | `DropInfoData` | 11 | records for drop info data |
| ✅ T1 | `DropSetInfo` | 12 | records for drop set (records can be individually blocked via is_blocked) |
| ✅ T1 | `ElementalMaterialInfo` | 20 | records for elemental material (records can be individually blocked via is_blocked) |
| 🧠 — | `ElementalMaterialSceneObjectSoundData` | 3 | records for elemental material scene object sound data |
| 🧠 — | `ElementalMaterialStatData` | 4 | records for elemental material stat data |
| 🧠 — | `ElementalMaterialStateData` | 14 | records for elemental material state data (UI icon) |
| 🧠 — | `ElementalMaterialStateDataList` | 1 | records for elemental material state data list |
| 🧠 — | `FixedMaterialData` | 6 | records for fixed material data (NPC/character references) |
| 🧠 — | `GroupMaterialData` | 3 | records for group material data |
| ✅ T1 | `MaterialBloodDecalInfo` | 5 | records for material blood decal (records can be individually blocked via is_blocked; skill references) |
| ✅ T1 | `MaterialMatchInfo` | 8 | records for material match (records can be individually blocked via is_blocked) |
| ✅ T1 | `MaterialRelationInfo` | 4 | relations between material (records can be individually blocked via is_blocked) |
| 🧠 — | `MaterialRelationMatchUpData` | 2 | records for material relation match up data |

## Faction/Field/World

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `AutoSpawnFilterInfo` | 4 | records for auto spawn filter (records can be individually blocked via is_blocked) |
| 🧠 — | `AutoSpawnPartyData` | 15 | records for auto spawn party data (spawn-related) |
| 🧠 — | `AutoSpawnTargetData` | 17 | records for auto spawn target data (spawn-related) |
| 🧠 — | `FactionBlockadingData` | 8 | records for faction blockading data |
| 🧠 — | `FactionEventData` | 36 | records for faction event data (spawn-related) |
| 🧠 — | `FactionEventProcessInfo` | 5 | records for faction event process (records can be individually blocked via is_blocked) |
| 🧠 — | `FactionGimmickActorSpawnInfo` | 3 | spawn rules for faction gimmick actor |
| ✅ T1 | `FactionGroupInfo` | 8 | grouping/categorization for faction (records can be individually blocked via is_blocked) |
| ✅ T1 | `FactionInfo` | 19 | records for faction (records can be individually blocked via is_blocked) |
| ✅ T1 | `FactionNodeInfo` | 31 | records for faction node (records can be individually blocked via is_blocked; skill references) |
| 🧠 — | `FactionNodeInfo_ObserveData` | 5 | records for faction node info observe data |
| ✅ T1 | `FactionNodeSpawnInfo` | 6 | spawn rules for faction node (records can be individually blocked via is_blocked) |
| 🧠 — | `FactionNodeSpawnPatrolSplineData` | 2 | records for faction node spawn patrol spline data |
| 🧠 — | `FactionPatrolData` | 2 | records for faction patrol data (spawn-related) |
| ✅ T1 | `FactionRelationGroupInfo` | 4 | grouping/categorization for faction relation (records can be individually blocked via is_blocked) |
| 🧠 — | `FactionResearchData` | 10 | records for faction research data |
| 🧠 — | `FactionResearchProgressData` | 2 | records for faction research progress data |
| 🧠 — | `FactionResourceData` | 5 | records for faction resource data |
| 🧠 — | `FactionScheduleInfo` | 29 | records for faction schedule |
| 🧠 — | `FactionScheduleInfo_StatData` | 3 | records for faction schedule info stat data |
| 🧠 — | `FactionSchedulePlayInfo` | 6 | records for faction schedule play (spawn-related) |
| 🧠 — | `FactionScheduleSpawnInfo` | 1 | spawn rules for faction schedule |
| 🧠 — | `FactionSequencerSpawnInfo` | 1 | spawn rules for faction sequencer |
| ✅ T1 | `FactionSpawnDataInfo` | 7 | data records for faction spawn (records can be individually blocked via is_blocked) |
| 🧠 — | `FactionStateData` | 4 | records for faction state data |
| 🧠 — | `FactionStealthOptionData` | 3 | records for faction stealth option data |
| 🧠 — | `FactionUICardData` | 2 | records for faction ui card data |
| 🧠 — | `FactionWayPointData` | 3 | records for faction way point data |
| 🧠 — | `FactionWayPointInfo` | 4 | records for faction way point (records can be individually blocked via is_blocked) |
| ✅ T1 | `FieldInfo` | 24 | records for field (records can be individually blocked via is_blocked; spawn-related) |
| ✅ T1 | `FieldLevelNameTableInfo` | 5 | lookup table for field level name (records can be individually blocked via is_blocked) |
| ✅ T1 | `FieldReviveInfo` | 10 | records for field revive (records can be individually blocked via is_blocked; positional) |
| ✅ T1 | `GameEventHandlerInfo` | 9 | records for game event handler (records can be individually blocked via is_blocked) |
| ✅ T1 | `GameLevelInfo` | 6 | records for game level (records can be individually blocked via is_blocked) |
| ✅ T1 | `GamePlayTriggerInfo` | 13 | records for game play trigger (records can be individually blocked via is_blocked; positional) |
| ✅ T1 | `GamePlayVariableInfo` | 5 | records for game play variable (records can be individually blocked via is_blocked) |
| 🧠 — | `GimmickGameEventHandlerData` | 3 | records for gimmick game event handler data |
| 🧠 — | `GimmickInfo_FactionStructure` | 5 | records for gimmick info faction structure |
| 🧠 — | `GimmickInfo_FactionStructureEvent` | 2 | records for gimmick info faction structure event |
| ✅ T1 | `GlobalGameEventGroupInfo` | 5 | grouping/categorization for global game event (records can be individually blocked via is_blocked) |
| ✅ T1 | `GlobalGameEventInfo` | 5 | records for global game event (records can be individually blocked via is_blocked) |
| ✅ T1 | `GlobalStageSequencerInfo` | 14 | records for global stage sequencer (records can be individually blocked via is_blocked) |
| ✅ T1 | `HouseInfo` | 6 | records for house (records can be individually blocked via is_blocked) |
| 🧠 — | `HouseRegionData` | 3 | records for house region data |
| 🧠 — | `RegionDomainFactionData` | 3 | records for region domain faction data |
| ✅ T1 | `RegionInfo` | 23 | records for region (records can be individually blocked via is_blocked) |
| ✅ T1 | `ReserveSlotInfo` | 17 | records for reserve slot (records can be individually blocked via is_blocked) |
| 🧠 — | `ReserveSlotTargetData` | 2 | records for reserve slot target data |
| ✅ T1 | `RoyalSupplyInfo` | 7 | records for royal supply (records can be individually blocked via is_blocked) |
| 🧠 — | `RoyalSupplyRandomData` | 4 | records for royal supply random data |
| 🧠 — | `ScheduleStageCompleteAIEventDesc` | 2 | records for schedule stage complete ai event desc |
| 🧠 — | `SequencerStageBoundaryData` | 13 | records for sequencer stage boundary data (spawn-related) |
| 🧠 — | `SequencerStageSpawnData` | 9 | records for sequencer stage spawn data (spawn-related) |
| 🧠 — | `SequencerStageSpawnDataList` | 1 | records for sequencer stage spawn data list |
| 🧠 — | `SequencerStageTrackChangeData` | 2 | records for sequencer stage track change data (spawn-related) |
| 🧠 — | `SequencerStageTrackChangeDataList` | 4 | records for sequencer stage track change data list |
| 🧠 — | `SequencerStageTrackChangeData_Gimmick` | 2 | records for sequencer stage track change data gimmick |
| ✅ T1 | `SpawningPoolAutoSpawnInfo` | 16 | spawn rules for spawning pool auto (records can be individually blocked via is_blocked; spawn-related) |
| 🧠 — | `StageBranchData` | 7 | records for stage branch data |
| 🧠 — | `StageChart_Function` | 4 | records for stage chart function |
| 🧠 — | `StageChart_Function_CameraPreset` | 5 | records for stage chart function camera preset |
| 🧠 — | `StageChart_Function_ChangePhasePanelTag` | 2 | records for stage chart function change phase panel tag |
| 🧠 — | `StageChart_Function_ChangePivot` | 1 | records for stage chart function change pivot |
| 🧠 — | `StageChart_Function_ClearWanted` | 2 | records for stage chart function clear wanted |
| 🧠 — | `StageChart_Function_ConnectActor` | 5 | records for stage chart function connect actor |
| 🧠 — | `StageChart_Function_DeactivateMiniGame` | 4 | records for stage chart function deactivate mini game |
| 🧠 — | `StageChart_Function_DisconnectActor` | 1 | records for stage chart function disconnect actor |
| 🧠 — | `StageChart_Function_DropGroup` | 3 | records for stage chart function drop group |
| 🧠 — | `StageChart_Function_EvadeTrigger` | 1 | records for stage chart function evade trigger |
| 🧠 — | `StageChart_Function_ExecuteMiniGameEvent` | 1 | records for stage chart function execute mini game event |
| 🧠 — | `StageChart_Function_FadeInOut` | 2 | records for stage chart function fade in out |
| 🧠 — | `StageChart_Function_ForceLockOn` | 5 | records for stage chart function force lock on |
| 🧠 — | `StageChart_Function_GameTrigger` | 12 | records for stage chart function game trigger (skill references) |
| 🧠 — | `StageChart_Function_InputBlock` | 2 | records for stage chart function input block |
| 🧠 — | `StageChart_Function_KeepAggro` | 1 | records for stage chart function keep aggro |
| 🧠 — | `StageChart_Function_LetterBox` | 1 | records for stage chart function letter box |
| 🧠 — | `StageChart_Function_Loading` | 9 | records for stage chart function loading |
| 🧠 — | `StageChart_Function_LookAt` | 3 | records for stage chart function look at |
| 🧠 — | `StageChart_Function_MaterialParameter` | 3 | records for stage chart function material parameter |
| 🧠 — | `StageChart_Function_MultiChange` | 1 | records for stage chart function multi change |
| 🧠 — | `StageChart_Function_PushReward` | 1 | records for stage chart function push reward |
| 🧠 — | `StageChart_Function_Reward` | 3 | records for stage chart function reward |
| 🧠 — | `StageChart_Function_Sell` | 3 | records for stage chart function sell |
| 🧠 — | `StageChart_Function_SequencerCamera` | 3 | records for stage chart function sequencer camera |
| 🧠 — | `StageChart_Function_SetAggro` | 1 | records for stage chart function set aggro |
| 🧠 — | `StageChart_Function_SetBattleTarget` | 1 | records for stage chart function set battle target |
| 🧠 — | `StageChart_Function_SetCustomMesh` | 3 | records for stage chart function set custom mesh |
| 🧠 — | `StageChart_Function_SetInteraction` | 5 | records for stage chart function set interaction |
| 🧠 — | `StageChart_Function_SetPhase` | 4 | records for stage chart function set phase |
| 🧠 — | `StageChart_Function_SetPreviewTarget` | 4 | records for stage chart function set preview target |
| 🧠 — | `StageChart_Function_SetTimer` | 1 | records for stage chart function set timer |
| 🧠 — | `StageChart_Function_SetWanted` | 4 | records for stage chart function set wanted |
| 🧠 — | `StageChart_Function_SpecialMode` | 2 | records for stage chart function special mode |
| 🧠 — | `StageChart_Function_SummonActor` | 7 | records for stage chart function summon actor |
| 🧠 — | `StageChart_Function_UIControl` | 4 | records for stage chart function ui control |
| 🧠 — | `StageChart_Function_UIControl_Parameter` | 3 | records for stage chart function ui control parameter |
| 🧠 — | `StageChart_Function_UIControl_ParameterAttribute` | 3 | records for stage chart function ui control parameter attribute |
| 🧠 — | `StageChart_Function_UIFindPath` | 3 | records for stage chart function ui find path |
| 🧠 — | `StageChart_Function_UIHint` | 2 | records for stage chart function ui hint |
| 🧠 — | `StageChart_Function_UIShowMinimap` | 6 | records for stage chart function ui show minimap |
| 🧠 — | `StageChart_Function_UIStageGuide` | 5 | records for stage chart function ui stage guide |
| 🧠 — | `StageChart_Function_UIStageIcon` | 1 | records for stage chart function ui stage icon |
| 🧠 — | `StageChart_Function_UnsummonActor` | 4 | records for stage chart function unsummon actor |
| 🧠 — | `StageChart_Function_VarySharpness` | 3 | records for stage chart function vary sharpness |
| 🧠 — | `StageChart_Function_WithActor` | 2 | records for stage chart function with actor |
| ✅ T1 | `StageInfo` | 85 | records for stage (records can be individually blocked via is_blocked; spawn-related) |
| 🧠 — | `SubLevelExpData` | 4 | records for sub level exp data |
| ✅ T1 | `SubLevelInfo` | 23 | records for sub level (records can be individually blocked via is_blocked; carries buff data) |
| ✅ T1 | `TerrainRegionAutoSpawnInfo` | 24 | spawn rules for terrain region auto (records can be individually blocked via is_blocked; spawn-related) |
| ✅ T1 | `TerrainRegionNaviInfo` | 4 | records for terrain region navi (records can be individually blocked via is_blocked) |
| ✅ T1 | `TriggerRegionInfo` | 4 | records for trigger region (records can be individually blocked via is_blocked) |
| ✅ T1 | `WantedInfo` | 5 | records for wanted (records can be individually blocked via is_blocked) |

## Gimmick/Trigger

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `BreakableObjectInfo` | 8 | records for breakable object (records can be individually blocked via is_blocked) |
| 🧠 — | `ChildVehicleData` | 2 | records for child vehicle data (NPC/character references) |
| ✅ T1 | `DetectDetailInfo` | 4 | records for detect detail (records can be individually blocked via is_blocked) |
| ✅ T1 | `DetectInfo` | 7 | records for detect (records can be individually blocked via is_blocked) |
| 🧠 — | `DetectModeAreaData` | 8 | records for detect mode area data |
| ✅ T1 | `DetectReactionInfo` | 7 | records for detect reaction (records can be individually blocked via is_blocked; carries buff data) |
| 🧠 — | `DetectSenseData` | 11 | records for detect sense data |
| 🧠 — | `GimmickAliasData` | 7 | records for gimmick alias data |
| 🧠 — | `GimmickAttachedData` | 6 | records for gimmick attached data |
| 🧠 — | `GimmickAttackImpulseCompleteData` | 2 | records for gimmick attack impulse complete data |
| 🧠 — | `GimmickChartCachedData` | 2 | records for gimmick chart cached data (spawn-related) |
| 🧠 — | `GimmickChartStateCachedData` | 3 | records for gimmick chart state cached data |
| 🧠 — | `GimmickCombinationAliasData` | 4 | records for gimmick combination alias data |
| 🧠 — | `GimmickConstraintData` | 7 | records for gimmick constraint data |
| 🧠 — | `GimmickEventHandlerEventTargetData` | 4 | records for gimmick event handler event target data |
| ✅ T1 | `GimmickEventTableInfo` | 7 | lookup table for gimmick event (records can be individually blocked via is_blocked; spawn-related) |
| ✅ T1 | `GimmickGateConnectionInfo` | 9 | records for gimmick gate connection (records can be individually blocked via is_blocked) |
| ✅ T1 | `GimmickGateInfo` | 6 | records for gimmick gate (records can be individually blocked via is_blocked; positional) |
| ✅ T1 | `GimmickGroupInfo` | 70 | grouping/categorization for gimmick (records can be individually blocked via is_blocked; spawn-related) |
| ✅ T1 | `GimmickInfo` | 162 | records for gimmick (records can be individually blocked via is_blocked; spawn-related) |
| 🧠 — | `GimmickInfo_CombinationLinkData` | 10 | records for gimmick info combination link data |
| 🧠 — | `GimmickInfo_ConstraintData` | 11 | records for gimmick info constraint data |
| 🧠 — | `GimmickInfo_CraftToolData` | 3 | records for gimmick info craft tool data |
| 🧠 — | `GimmickInfo_DefaultSpawnReason` | 3 | records for gimmick info default spawn reason |
| 🧠 — | `GimmickInfo_DialogData` | 2 | records for gimmick info dialog data |
| 🧠 — | `GimmickInfo_ElmentalAreaData` | 17 | records for gimmick info elmental area data |
| 🧠 — | `GimmickInfo_HousingData` | 3 | records for gimmick info housing data |
| 🧠 — | `GimmickInfo_PhysicsTriggerData` | 4 | records for gimmick info physics trigger data |
| 🧠 — | `GimmickInfo_SealData` | 3 | records for gimmick info seal data (UI icon) |
| 🧠 — | `GimmickInfo_TrafficBoxData` | 3 | records for gimmick info traffic box data |
| 🧠 — | `GimmickLinkSignalGroup` | 8 | records for gimmick link signal group |
| 🧠 — | `GimmickMiniGameData` | 6 | records for gimmick mini game data (spawn-related) |
| 🧠 — | `GimmickOnTimeData` | 4 | records for gimmick on time data |
| 🧠 — | `GimmickOnTimeGroupData` | 3 | records for gimmick on time group data (spawn-related) |
| 🧠 — | `GimmickRandomSpawnParam` | 6 | records for gimmick random spawn param (spawn-related) |
| 🧠 — | `GimmickRemoteCatchableData` | 3 | records for gimmick remote catchable data |
| 🧠 — | `GimmickSceneObjectControl_SetMaterialParameterValue` | 7 | records for gimmick scene object control set material parameter value |
| 🧠 — | `GimmickSummonRandomData` | 7 | records for gimmick summon random data (spawn-related) |
| 🧠 — | `GimmickTransformSet` | 2 | records for gimmick transform set (spawn-related) |
| 🧠 — | `GimmickTransformSetData` | 2 | records for gimmick transform set data |
| 🧠 — | `GimmickUnlockableData` | 3 | records for gimmick unlockable data |
| 🧠 — | `GimmickVisualPrefabData` | 5 | records for gimmick visual prefab data |
| ✅ T1 | `InteractionInfo` | 38 | records for interaction (records can be individually blocked via is_blocked) |
| 🧠 — | `InteractionOverrideData` | 15 | records for interaction override data |
| 🧠 — | `InteractionPivotOverrideData` | 8 | records for interaction pivot override data |
| 🧠 — | `LevelGimmickSceneObjectData` | 13 | records for level gimmick scene object data (spawn-related) |
| ✅ T1 | `LevelGimmickSceneObjectInfo` | 25 | records for level gimmick scene object (records can be individually blocked via is_blocked) |
| 🧠 — | `RelationInfoGimmickTagData` | 3 | records for relation info gimmick tag data (spawn-related) |
| 🧠 — | `SummonGimmickData` | 21 | records for summon gimmick data (spawn-related) |
| 🧠 — | `SummonGimmickData_SpawnRate` | 3 | records for summon gimmick data spawn rate |
| ✅ T1 | `VehicleInfo` | 22 | records for vehicle (records can be individually blocked via is_blocked; UI icon) |
| ✅ T1 | `VibratePatternInfo` | 6 | records for vibrate pattern (records can be individually blocked via is_blocked) |
| 🧠 — | `VibratePatternInfoData` | 4 | records for vibrate pattern info data |

## Item/Inventory

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `DockingItemEventKeyGuide` | 5 | records for docking item event key guide |
| 🧠 — | `EquipCategoryData` | 3 | records for equip category data (UI icon) |
| 📚 P | `EquipInfo` | 7 | records for equip (records can be individually blocked via is_blocked) |
| 🧠 — | `EquipInfoData` | 18 | records for equip info data |
| ✅ T1 | `EquipTypeInfo` | 20 | type/enum definitions for equip (records can be individually blocked via is_blocked) |
| 🧠 — | `GimmickAttachTargetSocketData` | 10 | records for gimmick attach target socket data |
| 🧠 — | `InventoryChangeData` | 2 | records for inventory change data |
| ✅ T1 | `InventoryInfo` | 17 | records for inventory (records can be individually blocked via is_blocked) |
| 🧠 — | `InventoryMoveData` | 10 | records for inventory move data |
| 🧠 — | `InventoryPushableData` | 2 | records for inventory pushable data |
| ✅ T1 | `ItemGroupInfo` | 14 | grouping/categorization for item (records can be individually blocked via is_blocked; UI icon) |
| 🧠 — | `ItemIconData` | 3 | records for item icon data (UI icon) |
| 🧠 — | `ItemInfo` | 111 | records for item (records can be individually blocked via is_blocked) |
| 🧠 — | `ItemInfo_PatternDescriptionData` | 2 | records for item info pattern description data |
| 🧠 — | `ItemInfo_SharpnessData` | 3 | records for item info sharpness data |
| 🧠 — | `ItemMeshGroupData` | 1 | records for item mesh group data |
| 🧠 — | `ItemMeshGroupInfo` | 4 | grouping/categorization for item mesh (records can be individually blocked via is_blocked) |
| 🧠 — | `ItemMoveData` | 4 | records for item move data |
| ✅ T1 | `ItemUseInfo` | 4 | records for item use (records can be individually blocked via is_blocked) |
| 🧠 — | `LootDropSubItemData` | 2 | records for loot drop sub item data |
| 🧠 — | `OccupiedEquipSlotData` | 2 | records for occupied equip slot data |
| 🧠 — | `RagdollEquipTableData` | 3 | records for ragdoll equip table data |
| 🧠 — | `RagdollEquipTableGroupData` | 2 | records for ragdoll equip table group data |
| 🧠 — | `SequencerStageTrackChangeData_Item` | 2 | records for sequencer stage track change data item |
| 🧠 — | `SocketGroupData` | 2 | records for socket group data |
| ✅ T1 | `SocketGroupInfo` | 4 | grouping/categorization for socket (records can be individually blocked via is_blocked) |
| ✅ T1 | `SocketInfo` | 5 | records for socket (records can be individually blocked via is_blocked; UI icon) |
| 🧠 — | `StageChart_Function_CreateItem` | 4 | records for stage chart function create item |
| 🧠 — | `StageChart_Function_DeleteItem` | 4 | records for stage chart function delete item |
| 🧠 — | `StageChart_Function_ExchangeTradeItem` | 2 | records for stage chart function exchange trade item |
| 🧠 — | `SummonItemData` | 13 | records for summon item data (spawn-related) |
| 🧠 — | `TradeMarketItemInfo` | 20 | records for trade market item (records can be individually blocked via is_blocked) |
| 🧠 — | `UseResourceItem` | 2 | records for use resource item |
| 🧠 — | `VaryTradeItemPriceData` | 3 | records for vary trade item price data |

## Mini-game / Special

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `FormationInfo` | 6 | records for formation (records can be individually blocked via is_blocked) |
| ✅ T1 | `MiniGameDataInfo` | 16 | data records for mini game (records can be individually blocked via is_blocked; spawn-related) |
| 🧠 — | `MiniGameParam` | 1 | records for mini game param |
| 🧠 — | `MiniGameSpawnDesc` | 2 | records for mini game spawn desc |
| ✅ T1 | `MultiChangeInfo` | 26 | records for multi change (records can be individually blocked via is_blocked) |
| ✅ T1 | `SpecialModeInfo` | 24 | records for special mode (records can be individually blocked via is_blocked; skill references) |
| 🧠 — | `SpecialModeOptionData` | 32 | records for special mode option data |

## Misc

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `ActorPossessionData` | 4 | records for actor possession data |
| ✅ T1 | `AllyGroupInfo` | 12 | grouping/categorization for ally (records can be individually blocked via is_blocked) |
| 🧠 — | `BloodDecalData` | 3 | records for blood decal data |
| 🧠 — | `BoardData` | 3 | records for board data (spawn-related) |
| 🧠 — | `BoardDataGroup` | 7 | records for board data group (spawn-related) |
| ✅ T1 | `BoardInfo` | 5 | records for board (records can be individually blocked via is_blocked) |
| 🧠 — | `CampGuestData` | 1 | records for camp guest data |
| 🧠 — | `CatchSpawnData` | 3 | records for catch spawn data |
| ✅ T1 | `CategoryGroupInfo` | 4 | grouping/categorization for category (records can be individually blocked via is_blocked) |
| ✅ T1 | `CategoryInfo` | 6 | records for category (records can be individually blocked via is_blocked) |
| 🧠 — | `ChallengeEventData` | 6 | records for challenge event data (spawn-related) |
| 🧠 — | `CogWheelConstraintData` | 2 | records for cog wheel constraint data |
| 🧠 — | `ConstraintData` | 10 | records for constraint data |
| 🧠 — | `ConstraintMotor` | 1 | records for constraint motor |
| 🧠 — | `CustomVolumeGroupData` | 1 | records for custom volume group data |
| 🧠 — | `DataDefinedDefaultStatData` | 5 | records for data defined default stat data |
| 🧠 — | `DockingChildData` | 24 | records for docking child data (spawn-related) |
| 🧠 — | `DyeTextureSetData` | 2 | records for dye texture set data |
| 🧠 — | `EnchantData` | 4 | records for enchant data |
| 🧠 — | `EnchantStatData` | 4 | records for enchant stat data |
| 🧠 — | `ExperienceLevelData` | 5 | records for experience level data |
| 🧠 — | `FriendlyDailyCountData` | 2 | records for friendly daily count data |
| 🧠 — | `GameEventExecuteData` | 4 | records for game event execute data |
| 🧠 — | `GamePlayObjectShareData` | 5 | records for game play object share data |
| 🧠 — | `GraphData` | 4 | records for graph data |
| 🧠 — | `GrowthData` | 7 | records for growth data (NPC/character references) |
| 🧠 — | `InspectData` | 20 | records for inspect data (NPC/character references; spawn-related) |
| 🧠 — | `KeySetting` | 3 | records for key setting |
| 🧠 — | `LevelNameInfo` | 4 | records for level name |
| 🧠 — | `LightDataInfo` | 4 | data records for light (records can be individually blocked via is_blocked) |
| 🧠 — | `LimitedHingeConstraintData` | 10 | records for limited hinge constraint data |
| 🧠 — | `LoadingTargetInfo` | 2 | records for loading target |
| 🧠 — | `LocalVelocity_DEV` | 3 | records for local velocity dev |
| 🧠 — | `MoneyTypeDefine` | 2 | records for money type define |
| 🧠 — | `OperationAdditionalData` | 3 | records for operation additional data |
| 🧠 — | `PageData` | 4 | records for page data |
| 🧠 — | `PartSubMeshDyeData` | 4 | records for part sub mesh dye data |
| 🧠 — | `PathFindTable_BaseData` | 8 | records for path find table base data |
| 🧠 — | `PathFindTable_Hurdle_BaseData` | 7 | records for path find table hurdle base data |
| 🧠 — | `PathFindTable_MoveState_BaseData` | 3 | records for path find table move state base data |
| 🧠 — | `PathFindTable_OptimizePitchJump` | 4 | records for path find table optimize pitch jump |
| 🧠 — | `PathFindTable_RoadBranch` | 3 | records for path find table road branch |
| 🧠 — | `PathFindTable_RoadHurdle` | 3 | records for path find table road hurdle |
| 🧠 — | `PathFindTable_RoadState_BaseData` | 2 | records for path find table road state base data |
| 🧠 — | `PathFindTable_SplineCurveLimitAngle` | 3 | records for path find table spline curve limit angle |
| 🧠 — | `PatrolPartyData` | 8 | records for patrol party data (spawn-related) |
| 🧠 — | `PlaneConstraintData` | 1 | records for plane constraint data |
| 🧠 — | `PositionConstraintMotor` | 4 | records for position constraint motor |
| 🧠 — | `PrefabData` | 4 | records for prefab data |
| 🧠 — | `PriceFloor` | 3 | records for price floor |
| 🧠 — | `PrismaticConstraintData` | 10 | records for prismatic constraint data |
| 🧠 — | `PulleyConstraintData` | 3 | records for pulley constraint data |
| 🧠 — | `RackAndPinionConstraintData` | 2 | records for rack and pinion constraint data |
| 🧠 — | `RagdollConstraintData` | 12 | records for ragdoll constraint data |
| ✅ T1 | `RelationInfo` | 11 | relations between (records can be individually blocked via is_blocked) |
| 🧠 — | `RepairData` | 4 | records for repair data |
| ✅ T1 | `SequencerSpawnInfo` | 8 | spawn rules for sequencer (records can be individually blocked via is_blocked) |
| 🧠 — | `SheetMusicInfo` | 18 | records for sheet music (records can be individually blocked via is_blocked) |
| 🧠 — | `SheetMusicPlayData` | 2 | records for sheet music play data |
| 🧠 — | `StatNode` | 8 | records for stat node |
| 🧠 — | `StiffSpringConstraintData` | 2 | records for stiff spring constraint data |
| 🧠 — | `StockData` | 13 | records for stock data |
| 🧠 — | `StockOrderCountData` | 2 | records for stock order count data |
| 🧠 — | `SubTimelineBreakDesc` | 4 | records for sub timeline break desc |
| 🧠 — | `TerritoryInfo` | 4 | records for territory (records can be individually blocked via is_blocked) |
| 🧠 — | `TextGuideInfo` | 8 | records for text guide (records can be individually blocked via is_blocked) |
| 🧠 — | `TrapFoodData` | 3 | records for trap food data |
| 🧠 — | `UnitData` | 5 | records for unit data (UI icon) |
| 🧠 — | `UseResourceStat` | 6 | records for use resource stat |
| 🧠 — | `VaryExpPerDonationData` | 3 | records for vary exp per donation data |
| 🧠 — | `VelocityConstraintMotor` | 3 | records for velocity constraint motor |
| 🧠 — | `VelocityInfo_DEV` | 3 | records for velocity info dev |
| 🧠 — | `VerticalPlaneConstraintData` | 5 | records for vertical plane constraint data |
| 🧠 — | `VisioningData` | 2 | records for visioning data |
| 🧠 — | `YOnlyConstraintData` | 3 | records for y only constraint data |

## Platform/System

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `KeyMapSettingListInfo` | 4 | records for key map setting list (records can be individually blocked via is_blocked) |
| ✅ T1 | `PartPrefabDyeSlotInfo` | 5 | records for part prefab dye slot (records can be individually blocked via is_blocked) |
| ✅ T1 | `PartPrefabDyeTexturePalleteInfo` | 5 | records for part prefab dye texture pallete (records can be individually blocked via is_blocked) |
| 🧠 — | `PartPrefabDyeTextureSet` | 5 | records for part prefab dye texture set (UI icon) |
| ✅ T1 | `PlatformAchievementInfo` | 10 | records for platform achievement (records can be individually blocked via is_blocked; quest references) |
| ✅ T1 | `PlatformEntitlementInfo` | 9 | records for platform entitlement (records can be individually blocked via is_blocked; UI icon) |

## Quest/Mission/Knowledge

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| ✅ T1 | `GameAdviceGroupInfo` | 8 | grouping/categorization for game advice (records can be individually blocked via is_blocked) |
| ✅ T1 | `GameAdviceInfo` | 15 | records for game advice (records can be individually blocked via is_blocked) |
| 🧠 — | `KnowledgeDescriptionData` | 6 | records for knowledge description data |
| ✅ T1 | `KnowledgeGroupInfo` | 15 | grouping/categorization for knowledge (records can be individually blocked via is_blocked) |
| ✅ T1 | `KnowledgeInfo` | 29 | records for knowledge (records can be individually blocked via is_blocked; skill references; NPC/character references) |
| 🧠 — | `KnowledgeLearnableData` | 10 | records for knowledge learnable data |
| 🧠 — | `KnowledgeLevelData` | 12 | records for knowledge level data |
| 🧠 — | `MissionBranchData` | 6 | records for mission branch data |
| 🧠 — | `MissionFunctionData` | 12 | records for mission function data (quest references) |
| ✅ T1 | `MissionInfo` | 40 | records for mission (records can be individually blocked via is_blocked) |
| 🧠 — | `MissionResultData` | 11 | records for mission result data |
| 🧠 — | `MissionUIDesc` | 18 | records for mission ui desc |
| 🧠 — | `QuestDialogData` | 1 | records for quest dialog data |
| 🧠 — | `QuestDialog_DialogFlow` | 6 | records for quest dialog dialog flow |
| 🧠 — | `QuestDialog_FilterData` | 18 | records for quest dialog filter data |
| 🧠 — | `QuestDialog_RewardData` | 6 | records for quest dialog reward data |
| 🧠 — | `QuestDialog_SelectDialogSet` | 7 | records for quest dialog select dialog set |
| 🧠 — | `QuestDialog_TextData` | 8 | records for quest dialog text data |
| 🧠 — | `QuestGaugeCountData` | 3 | records for quest gauge count data |
| 🧠 — | `QuestGaugeCountData_Stage` | 5 | records for quest gauge count data stage |
| ✅ T1 | `QuestGaugeInfo` | 12 | records for quest gauge (records can be individually blocked via is_blocked; quest references) |
| ✅ T1 | `QuestGroupInfo` | 15 | grouping/categorization for quest (records can be individually blocked via is_blocked; quest references) |
| ✅ T1 | `QuestInfo` | 35 | records for quest (records can be individually blocked via is_blocked; quest references) |
| 🧠 — | `QuestPlatformInfoLInker` | 2 | records for quest platform info l inker |
| 🧠 — | `StageChart_Function_SetQuestDialogAICategory` | 2 | records for stage chart function set quest dialog ai category |
| ✅ T1 | `StoreInfo` | 21 | records for store (records can be individually blocked via is_blocked) |

## Skill/Action

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `ActionCameraShakeDesc` | 9 | records for action camera shake desc |
| 🧠 — | `ActionPoint` | 7 | records for action point |
| 🧠 — | `ActionPointAccessor` | 6 | records for action point accessor |
| ✅ T1 | `ActionPointInfo` | 5 | records for action point (records can be individually blocked via is_blocked) |
| ✅ T1 | `ActionRestrictionOrderInfo` | 18 | records for action restriction order (records can be individually blocked via is_blocked; skill references; spawn-related) |
| 🧠 — | `CombatTargetingFlags` | 4 | records for combat targeting flags |
| 🧠 — | `ElementalMaterialSkillData` | 9 | records for elemental material skill data |
| 🧠 — | `FactionPassiveSkillData` | 3 | records for faction passive skill data |
| ✅ T1 | `FrameEventAttrGroupInfo` | 4 | grouping/categorization for frame event attr (records can be individually blocked via is_blocked) |
| 🧠 — | `FrameEventAttribute` | 5 | records for frame event attribute |
| 🧠 — | `FrameEventAttribute_Acc` | 9 | records for frame event attribute acc |
| 🧠 — | `FrameEventAttribute_Jump` | 2 | records for frame event attribute jump |
| 🧠 — | `FrameEventAttribute_Move` | 3 | records for frame event attribute move |
| 🧠 — | `FrameEventAttribute_Rotate` | 5 | records for frame event attribute rotate |
| 🧠 — | `InspectAction` | 4 | records for inspect action |
| 🧠 — | `InteractionActionOverrideData` | 2 | records for interaction action override data |
| 🧠 — | `LevelActionPointActionSet` | 3 | records for level action point action set |
| 🧠 — | `LevelActionPointGroup` | 2 | records for level action point group |
| ✅ T1 | `LevelActionPointInfo` | 5 | records for level action point (records can be individually blocked via is_blocked) |
| 🧠 — | `PathMoveAction` | 5 | records for path move action |
| 🧠 — | `PathMoveActionSet` | 3 | records for path move action set |
| 🧠 — | `PathMoveActionSetGroup` | 2 | records for path move action set group |
| 🧠 — | `PathMoveActionSetOfMoveType` | 10 | records for path move action set of move type |
| 🧠 — | `PlayerActionLimitDesc` | 8 | records for player action limit desc (skill references) |
| ✅ T1 | `QuickTimeEventInfo` | 4 | records for quick time event (records can be individually blocked via is_blocked) |
| 🧠 — | `QuickTimeEventInfoData` | 12 | records for quick time event info data (positional) |
| ✅ T1 | `SkillGroupInfo` | 5 | grouping/categorization for skill (records can be individually blocked via is_blocked; skill references) |
| ✅ T1 | `SkillInfo` | 34 | records for skill (records can be individually blocked via is_blocked; carries buff data; skill references; UI icon) |
| 🧠 — | `SkillNode` | 17 | records for skill node (skill references) |
| ✅ T1 | `SkillTreeGroupInfo` | 9 | grouping/categorization for skill tree (records can be individually blocked via is_blocked; skill references; NPC/character references) |
| ✅ T1 | `SkillTreeInfo` | 16 | records for skill tree (records can be individually blocked via is_blocked; skill references; NPC/character references) |
| 🧠 — | `StageChart_Function_PassiveSkill` | 2 | records for stage chart function passive skill (skill references) |
| 🧠 — | `StageChart_PassiveSkill` | 3 | records for stage chart passive skill (skill references) |
| ✅ T1 | `UISocialActionInfo` | 7 | records for ui social action (records can be individually blocked via is_blocked) |
| ✅ T1 | `ValidScheduleActionInfo` | 7 | records for valid schedule action (records can be individually blocked via is_blocked) |

## UI/Audio/Localization

| Status | Class | Fields | Purpose |
|---|---|---:|---|
| 🧠 — | `AiDialogTextData` | 5 | records for ai dialog text data |
| 🧠 — | `BitmapColorKey` | 2 | records for bitmap color key |
| ✅ T1 | `BitmapPositionInfo` | 11 | records for bitmap position (records can be individually blocked via is_blocked) |
| 🧠 — | `DialogSetInfo` | 4 | records for dialog set (records can be individually blocked via is_blocked) |
| 🧠 — | `DialogSpeaker` | 4 | records for dialog speaker |
| 🧠 — | `DialogTextData` | 2 | records for dialog text data |
| ✅ T1 | `DialogVoiceInfo` | 15 | records for dialog voice (records can be individually blocked via is_blocked) |
| 🧠 — | `DyeColorData` | 2 | records for dye color data |
| 🧠 — | `DyeColorGroupData` | 2 | records for dye color group data |
| ✅ T1 | `DyeColorGroupInfo` | 6 | grouping/categorization for dye color (records can be individually blocked via is_blocked; UI icon) |
| ✅ T1 | `FailMessageInfo` | 4 | records for fail message (records can be individually blocked via is_blocked) |
| 🧠 — | `FailMessageInfoData` | 2 | records for fail message info data |
| ✅ T1 | `LocalStringInfo` | 5 | records for local string (records can be individually blocked via is_blocked) |
| ✅ T1 | `PatternDescriptionInfo` | 10 | records for pattern description (records can be individually blocked via is_blocked) |
| 🧠 — | `PatternDescriptionParam` | 2 | records for pattern description param |
| ✅ T1 | `StringInfo` | 4 | records for string (records can be individually blocked via is_blocked; carries buff data) |
| 🧠 — | `UIFilterData` | 5 | records for ui filter data |
| ✅ T1 | `UIFilterGroupInfo` | 7 | grouping/categorization for ui filter (records can be individually blocked via is_blocked) |
| 🧠 — | `UIFilterIconData` | 3 | records for ui filter icon data |
| ✅ T1 | `UIMapTextureInfo` | 50 | records for ui map texture (records can be individually blocked via is_blocked) |

## Full alphabetical reference (with field lists)

### AIActionAttributeInfo ✅ T1

**Category**: AI  
**Purpose**: records for ai action attribute (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/aiaction_attribute_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_passiveSkillKeyList`

### AIDialogStringInfo ✅ T1

**Category**: AI  
**Purpose**: records for ai dialog string (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/ai_dialog_string_info/`
**Fields (11)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_aiDialogStringInfoType`
- `_isOverrideData`
- `_characterGroupInfoList`
- `_regionInfo`
- `_aiDialogTypeInfo`
- `_aiDialogTextList`
- `_isOnce`
- `_characterThreatData`

### AIDialogTypeInfo ✅ T1

**Category**: AI  
**Purpose**: type/enum definitions for ai dialog (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/aidialog_type_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_limitDistance`
- `_isPlayerSubtitle`
- `_isShowSubtitle`
- `_blockByQuestDialogMust`

### AIEventTableInfo ✅ T1

**Category**: AI  
**Purpose**: lookup table for ai event (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/aievent_table_info/`
**Fields (12)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_showName`
- `_delegateEventHandler`
- `_reactionLevel`
- `_allowTypeFlag`
- `_eventType`
- `_eventDelayType`
- `_isSequencerInterruptEvent`
- `_isTargetMustExist`
- `_isMustHandled`

### AIMemoryInfo ✅ T1

**Category**: AI  
**Purpose**: records for ai memory (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/aimemory_info/`
**Fields (3)**:

- `_key`
- `_stringKey`
- `_isBlocked`

### AIMemoryOfTarget 🧠 —

**Category**: AI  
**Purpose**: records for ai memory of target  
**Parser**: not present
**Fields (2)**:

- `_fieldNpcSaveDataKey`
- `_memoryInfoAndLimitFieldTimeList`

### AIMoveSpeedData 🧠 —

**Category**: AI  
**Purpose**: records for ai move speed data  
**Parser**: not present
**Fields (20)**:

- `_targetMoveSpeed`
- `_minMoveSpeed`
- `_moveAcc`
- `_moveDcc`
- `_lookForwardSec`
- `_lookForwardTurnSec`
- `_minDegreeDiff`
- `_maxDegreeDiff`
- `_rotationDamping`
- `_maxRotationSpeed`
- `_accPreventDistanceAfterCurve`
- `_minDegreeDiffStride`
- `_maxDegreeDiffStride`
- `_minMoveSpeedStride`
- `_minDistanceRotateToTarget`
- `_maxDistanceRotateToTarget`
- `_speedDownDistanceBeforeCurveLimit`
- `_accCount`
- `_dccCount`
- `_rotateToTargetSyncWithIK`

### AIMoveSpeedInfo ✅ T1

**Category**: AI  
**Purpose**: records for ai move speed (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/aimove_speed_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_aiMoveSpeedDataList`

### ActionCameraShakeDesc 🧠 —

**Category**: Skill/Action  
**Purpose**: records for action camera shake desc  
**Parser**: not present
**Fields (9)**:

- `_blendInTime`
- `_blendOutTime`
- `_shakeTime`
- `_shakeSpeed`
- `_shakeRadius`
- `_shakeDirection`
- `_shakeRotation`
- `_shakeDirType`
- `_fallOffType`

### ActionChartFrameEvent_EffectDataDesc 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for action chart frame event effect data desc  
**Parser**: not present
**Fields (26)**:

- `_effectVariationParameter`
- `_weaponKey`
- `_rayCastStartSocketOffset`
- `_raycastStartPosition`
- `_raycastYawPitchDirection`
- `_raycastDistance`
- `_attachPositionOffset`
- `_effectPosition`
- `_effectScale`
- `_effectRotation`
- `_partLOD`
- `_barrierHitEffectKey`
- `_isBarrierEffect`
- `_applyBoneRotation`
- `_keepAttachParent`
- `_applyOwnerAnimationSpeed`
- `_syncParentVisibility`
- `_applyParentScale`
- `_isAttackEffectRotateToDir`
- `_effectRotationType`
- `_effectDir`
- `_effectVariation`
- `_random`
- `_effectPower`
- `_raycastAttach`
- `_ignorePlatformOption`

### ActionChartFrameEvent_EffectVariationParameter 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for action chart frame event effect variation parameter  
**Parser**: not present
**Fields (21)**:

- `_particleSpawnVolumeScale`
- `_color`
- `_emissiveColor`
- `_particleScale`
- `_velocity`
- `_velocityMin`
- `_velocityMax`
- `_particleLifeTime`
- `_opacity`
- `_effectSpawnCount`
- `_randomSeed`
- `_initialSimulationSpeed`
- `_initialSpawnRatio`
- `_effectLifeTime`
- `_particleSpawnVolumeData`
- `_particleScaleMinRatio`
- `_particleScaleMaxRatio`
- `_particleSpawnVolumeType`
- `_particleVelocityType`
- `_variationParameterFlag`
- `_overideParameterFlag`

### ActionPoint 🧠 —

**Category**: Skill/Action  
**Purpose**: records for action point  
**Parser**: not present
**Fields (7)**:

- `_actionPointAccessor`
- `_levelActionPointInfo`
- `_platformDockingTagNameHash`
- `_platformCharacterKey`
- `_levelName`
- `_actionPosition`
- `_actionYaw`

### ActionPointAccessor 🧠 —

**Category**: Skill/Action  
**Purpose**: records for action point accessor  
**Parser**: not present
**Fields (6)**:

- `_actionPointKey`
- `_autoSpawnKey`
- `_socketNameHash`
- `_sceneObjectUuid`
- `_gimmickActorKey`
- `_objectActionPointIndex`

### ActionPointInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for action point (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/action_point_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_actionPoint`
- `_levelActionPointInfo`

### ActionRestrictionOrderInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for action restriction order (records can be individually blocked via is_blocked; skill references; spawn-related)  
**Parser**: `dmm-parser/src/tables/action_restriction_order_info/`
**Fields (18)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_startAiEventHash`
- `_endAiEventHash`
- `_order`
- `_actionRestrictionType`
- `_registTypeStatus`
- `_skillInfo`
- `_spawnActionList`
- `_aiEventTagNameHash`
- `_ignoreCatch`
- `_ignoreThrow`
- `_delayDeadFatal`
- `_delayKnockOut`
- `_useRandomHitDir`
- `_useAutoAttackThrow`
- `_additiveSkill`

### ActorPossessionData 🧠 —

**Category**: Misc  
**Purpose**: records for actor possession data  
**Parser**: not present
**Fields (4)**:

- `_factionNode`
- `_possessionTriggerList`
- `_possessionActorKey`
- `_isInPossessionBoundary`

### AiDialogTextData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for ai dialog text data  
**Parser**: not present
**Fields (5)**:

- `_dialogVoiceInfo`
- `_tagList`
- `_isPlayer`
- `_sharedDialogText`
- `_externDialogText`

### AllyGroupInfo ✅ T1

**Category**: Misc  
**Purpose**: grouping/categorization for ally (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/ally_group_info/`
**Fields (12)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_relationTypeList`
- `_killerDetectionTime`
- `_applyReporting`
- `_isWild`
- `_isMainAllyGroup`
- `_isIntruder`
- `_interestingCondition`
- `_addOnAllyGroupList`
- `_interestingOrderList`

### AutoSpawnCharacterData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for auto spawn character data (NPC/character references)  
**Parser**: not present
**Fields (6)**:

- `_characterInfo`
- `_characterGroupInfo`
- `_subCharacterInfo`
- `_subCharacterGroupInfo`
- `_characterCount`
- `_subCharacterCount`

### AutoSpawnFilterInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for auto spawn filter (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/auto_spawn_filter_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_shareValueIndex`

### AutoSpawnPartyData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for auto spawn party data (spawn-related)  
**Parser**: not present
**Fields (15)**:

- `_characterSpawnList`
- `_sequencerSpawnInfo`
- `_gimmickInfo`
- `_itemInfo`
- `_spawnDataName`
- `_formationInfo`
- `_spawnReason`
- `_spawnRate`
- `_minWaterDepth`
- `_maxWaterDepth`
- `_color`
- `_isDuplicatable`
- `_isPartySameTeam`
- `_isFactionSequencerSpawn`
- `_spawnPercent`

### AutoSpawnTargetData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for auto spawn target data (spawn-related)  
**Parser**: not present
**Fields (17)**:

- `_partySpawnList`
- `_regionInfoList`
- `_notSpawnRegionInfoList`
- `_spawnRegionTagList`
- `_notSpawnRegionTagList`
- `_weatherStateFlag`
- `_blockedWeatherStateFlag`
- `_temperatureRange`
- `_metersPerSpawn`
- `_spawnSafetyDistance`
- `_timeBegin`
- `_timeEnd`
- `_stageCategory`
- `_spawnDistance`
- `_spawnDistanceOption`
- `_indoorType`
- `_spawnLimitCount`

### BitmapColorKey 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for bitmap color key  
**Parser**: not present
**Fields (2)**:

- `_r`
- `_g`

### BitmapPositionInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for bitmap position (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/bitmap_position_info/`
**Fields (11)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_scaleType`
- `_values`
- `_boundaryPositionMin`
- `_boundaryPositionMax`
- `_centerPosition`
- `_scalePerPixel`
- `_maxUsingHeight`
- `_exportTextureOnEditing`

### BloodDecalData 🧠 —

**Category**: Misc  
**Purpose**: records for blood decal data  
**Parser**: not present
**Fields (3)**:

- `_variationName`
- `_bloodDecalName`
- `_scale`

### BoardData 🧠 —

**Category**: Misc  
**Purpose**: records for board data (spawn-related)  
**Parser**: not present
**Fields (3)**:

- `_spawnRate`
- `_itemInfo`
- `_playerCondition`

### BoardDataGroup 🧠 —

**Category**: Misc  
**Purpose**: records for board data group (spawn-related)  
**Parser**: not present
**Fields (7)**:

- `_spawnPercent`
- `_totalRate`
- `_category`
- `_name`
- `_condition`
- `_playerCondition`
- `_boardDataList`

### BoardInfo ✅ T1

**Category**: Misc  
**Purpose**: records for board (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/board_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_boardDataList`
- `_boardDataGroupList`

### BreakableObjectInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for breakable object (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/breakable_object_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_breakingImpulseDamage`
- `_minImpulseDamage`
- `_breakableHp`
- `_isBreakToVandalism`
- `_useGroupSpawnByImpulse`

### BuffInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: records for buff (records can be individually blocked via is_blocked; carries buff data)  
**Parser**: `dmm-parser/src/tables/buff_info/`
**Fields (13)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_buffDataList`
- `_minLevel`
- `_maxLevel`
- `_sequencerFileName`
- `_buffLevelCalculateType`
- `_uiTemplateName`
- `_uiComponentName`
- `_elementalStatusInfo`
- `_isUseSkillInfoPatternDescription`
- `_useCountingByGlobalTimer`

### BuffLevelData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for buff level data (carries buff data)  
**Parser**: not present
**Fields (1)**:

- `_buffDataList`

### CampGuestData 🧠 —

**Category**: Misc  
**Purpose**: records for camp guest data  
**Parser**: not present
**Fields (1)**:

- `_isValid`

### CatchSpawnData 🧠 —

**Category**: Misc  
**Purpose**: records for catch spawn data  
**Parser**: not present
**Fields (3)**:

- `_catchPresetNameHash`
- `_gimmickInfo`
- `_catchDropSetInfo`

### CategoryGroupInfo ✅ T1

**Category**: Misc  
**Purpose**: grouping/categorization for category (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/category_group_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_list`

### CategoryInfo ✅ T1

**Category**: Misc  
**Purpose**: records for category (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/category_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_mainCategoryIndex`
- `_middleCategoryIndex`
- `_subCategoryIndex`

### ChallengeEventData 🧠 —

**Category**: Misc  
**Purpose**: records for challenge event data (spawn-related)  
**Parser**: not present
**Fields (6)**:

- `_gameEventExecuteData`
- `_spawnStageInfoList`
- `_haveCountItemInfo`
- `_haveCountItemGroupInfo`
- `_challengeFunctionType`
- `_preCheck`

### CharacterAdditionalPartsData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character additional parts data  
**Parser**: not present
**Fields (3)**:

- `_partsCondition`
- `_partsFileName`
- `_randomPartsNameList`

### CharacterAppearanceIndexInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for character appearance index (records can be individually blocked via is_blocked; NPC/character references)  
**Parser**: `dmm-parser/src/tables/character_appearance_index_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_characterEditName`
- `_appearanceName`
- `_characterScale`
- `_characterInfo`

### CharacterChangeInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for character change (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/character_change_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_characterChangeFilter`

### CharacterCloneInfo 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character clone  
**Parser**: not present
**Fields (1)**:

- `_flags`

### CharacterDialogGroupData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character dialog group data  
**Parser**: not present
**Fields (1)**:

- `_dialogList`

### CharacterEquipmentData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character equipment data  
**Parser**: not present
**Fields (9)**:

- `_equipItemInfo`
- `_equipDropSetInfo`
- `_deadDropPercent`
- `_throwDropPercent`
- `_minEndurancePercent`
- `_maxEndurancePercent`
- `_enhancedPercent`
- `_minEnhancedEndurancePercent`
- `_maxEnhancedEndurancePercent`

### CharacterFriendlyItemData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character friendly item data  
**Parser**: not present
**Fields (5)**:

- `_friendlyItemRewardDropSetInfoList`
- `_itemInfoToDeliver`
- `_itemGroupInfoToDeliver`
- `_knowledgeInfo`
- `_rewardFriendly`

### CharacterGroupInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: grouping/categorization for character (records can be individually blocked via is_blocked; NPC/character references)  
**Parser**: `dmm-parser/src/tables/character_group_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_groupName`
- `_characterInfoList`
- `_groupGenderList`
- `_groupTribeList`
- `_groupRegionInfoList`
- `_groupAgeList`
- `_groupWeaponTypeList`
- `_groupTierList`
- `_groupAllyGroupList`
- `_groupFactionList`
- `_groupJobInfoList`
- `_stopAnimConstraintDead`

### CharacterInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for character (records can be individually blocked via is_blocked; skill references; NPC/character references; spawn-related)  
**Parser**: `dmm-parser/src/tables/character_info/`
**Fields (174)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_characterName`
- `_characterDesc`
- `_uiIconPath`
- `_category`
- `_characterEditName`
- `_spawnActorType`
- `_nonePlayerSubType`
- `_equipInfo`
- `_npcInfo`
- `_vehicleInfo`
- `_callMercenaryCoolTime`
- `_callMercenarySpawnDuration`
- `_mercenaryCoolTimeType`
- `_childVehicleList`
- `_factionInfo`
- `_upperActionChartPackageGroupName`
- `_lowerActionChartPackageGroupName`
- `_characterGamePlayDataName`
- `_appearanceName`
- `_characterPrefabPath`
- `_skeletonName`
- `_skeletonVariationName`
- `_shareValueNameHash`
- `_projectileInfoPackage`
- `_memo`
- `_tribeInfoWrapper`
- `_tribeEffectHash`
- `_characterTribeAndGenderString`
- `_aiScriptPathHash`
- `_aiScriptPathFocusHash`
- `_playerTargetableType`
- `_playerLockOnType`
- `_gender`
- `_mercenaryInfo`
- `_mercenaryHireMessage`
- `_ownedMercenaryCharacterInfo`
- `_spawnFixType`
- `_playerIndex`
- `_commbatTargetingFlags`
- `_isCatchable`
- `_isRemoteCatchable`
- `_isAttackThrowable`
- `_isUnique`
- `_isPushable`
- `_isLookable`
- `_isLogoutAtLooted`
- `_isUseScheduleInfo_Dev`
- `_isGlobalSchedule`
- `_isSealable`
- `_isRandomAppearance`
- `_isRandomAppearance_IgnoreScale`
- `_isRandomCharacter`
- `_isRandomCharacter_IgnoreScale`
- `_isHirable`
- `_useLargeSplineCurve`
- `_sendKillEventOnDead`
- `_isShowHpWhenFocusActor`
- `_isHudHpEnabled`
- `_isEquipDropable`
- `_isEditorUsable`
- `_isEditorUsableAppearance`
- `_disableFootStepOptimize`
- `_isVisibleWhenDetectModeOnly`
- `_obstacleDisableByDead`
- `_isGhost`
- `_ignoreTriggerRegion`
- `_isTerrainCharacter`
- `_isMapIconAlwaysShow`
- `_isWallSwingable`
- `_isItemSocketContents`
- `_isClimbable`
- `_isEnableFriendly`
- `_allowFarAttackTarget`
- `_refillHPWhenCooltimeEnd`
- `_ignoreWaterFall`
- `_isCreatableDetectIcon`
- `_enableDockingGimmickAutoWallUp`
- `_isFireable`
- `_vanishTickCount`
- `_uiPortraitPath`
- `_symbolImage`
- `_skillInfoBySpawnList`
- `_skillInfoByReviveList`
- `_aliveSkillInfoList`
- `_playerSkillInfoList`
- `_interactionInfoList`
- `_interactionDistance`
- `_defaultActionActionIndex`
- `_defaultShareValueIndex`
- `_characterWeight`
- `_battleOrderType`
- `_characterType`
- `_uiMapTextureInfo`
- `_mapIconDisplayType`
- `_knowledgeInfo`
- `_knowledgeObtainType`
- `_inspectDataList`
- `_characterGroupInfoList`
- `_visioningData`
- `_detectInfo`
- `_maxAggroCount`
- `_personalityType`
- `_characterTier`
- `_characterRegionInfoList`
- `_characterAge`
- `_characterWeaponType`
- `_dialogVoiceInfo`
- `_interactionCategoryGroupInfo`
- `_detectReactionInfo`
- `_allyGroupInfo`
- `_characterPauseType`
- `_ownerFollowType`
- `_farmDropInfoList`
- `_farmBreedingTargetList`
- `_farmBreedingResultList`
- `_farmBreedingCoolTime`
- `_characterRewardDataList`
- `_isRewardDropRollByCreateActor`
- `_mercenaryDropInfoList`
- `_equipItemInfoList`
- `_minigameSeedList`
- `_priceList`
- `_wantedPriceList`
- `_terrainRegionAutoSpawnInfo`
- `_terrainRegionSpawnPerCount`
- `_convertItemInfo`
- `_pathTrailType`
- `_inventoryInfoList`
- `_pathFindTableName`
- `_dockingChildDataList`
- `_dockingChildEventList`
- `_characterInteractionOverrideDataList`
- `_characterCollisionType`
- `_bumpTypeHash`
- `_characterFriendlyItemDataList`
- `_characterThreatDialogInfo`
- `_aiDialogOverrideList`
- `_trapFoodData`
- `_weatherWeight`
- `_useHideCameraOverlap`
- `_forceFieldTargetType`
- `_additionalPartsDataList`
- `_attackByCollisionInfoListKey`
- `_interactionUIDistanceLv`
- `_detectReactionOverrideList`
- `_stageInfoForNpcShopList`
- `_gamePlayObjectShareData`
- `_characterScale`
- `_breakableObjectInfo`
- `_weakPointEffectDataList`
- `_miniGameParam`
- `_bulletItem`
- `_jobInfo`
- `_callVehicleGimmickInfo`
- `_campGuestData`
- `_baseMaterialKeyOverride`
- `_isFarmAnimal`
- `_catchSpawnData`
- `_grownTargetKeyList`
- `_grownLevel`
- `_defaultFriendlyValue`
- `_gameDifficultyBuffLevelList`
- `_gameDifficultyBuffInfo`
- `_balanceDifficultyLevel`
- `_isApplyStatControlData`
- `_applyStatBalaceData`
- `_statusGroupInfo`
- `_characterLevelDataList`
- `_detectableGimmickTagNameHashList`
- `_mercenaryDetectableGimmickTagHashList`
- `_elementalMaterialInfoList`

### CharacterLevelData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character level data  
**Parser**: not present
**Fields (10)**:

- `_level`
- `_experience`
- `_dropExperience`
- `_statDataLevel`
- `_frameEventAttrGroupInfoName`
- `_learnSkillList`
- `_hiddenSkillList`
- `_statList_DataDefinedStatic`
- `_statList_DataDefinedRegenarate`
- `_statList_StaticStatLevel`

### CharacterMoveSpeedInfo 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character move speed (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (12)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_minMoveSpeed`
- `_moveSpeed`
- `_moveAcc`
- `_moveDeacc`
- `_moveAccAuto`
- `_moveDirectionLimit`
- `_inertiaBrakeMinThreshold`
- `_inertiaBrakeMaxThreshold`
- `_inertiaBrakeStrength`

### CharacterRewardData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character reward data  
**Parser**: not present
**Fields (3)**:

- `_dropSetInfo`
- `_rewardTagTypeFlag`
- `_repeatCount`

### CharacterThreatData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for character threat data  
**Parser**: not present
**Fields (3)**:

- `_threatDialogGroupList`
- `_endIndex`
- `_ignoreReward`

### ChildVehicleData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for child vehicle data (NPC/character references)  
**Parser**: not present
**Fields (2)**:

- `_characterInfo`
- `_characterGroupInfo`

### CogWheelConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for cog wheel constraint data  
**Parser**: not present
**Fields (2)**:

- `_selfCogWheelRadius`
- `_targetCogWheelRadius`

### CombatTargetingFlags 🧠 —

**Category**: Skill/Action  
**Purpose**: records for combat targeting flags  
**Parser**: not present
**Fields (4)**:

- `_invincibility`
- `_isAttackable`
- `_isAggroTargetable`
- `_isValid`

### CommonMiniGamePlayCharacterParameter 🧠 —

**Category**: Character/NPC  
**Purpose**: records for common mini game play character parameter  
**Parser**: not present
**Fields (1)**:

- `_aiIntelligence`

### ConditionInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: records for condition (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/condition_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_gameCondition`
- `_originalString`
- `_parserType`

### ConditionOptionData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for condition option data  
**Parser**: not present
**Fields (4)**:

- `_condition`
- `_failType`
- `_message`
- `_summaryMessage`

### ConditionTargetData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for condition target data  
**Parser**: not present
**Fields (5)**:

- `_targetName`
- `_matchTargetCount`
- `_matchTargetOperationType`
- `_matchAllTarget`
- `_matchPercent`

### ConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for constraint data  
**Parser**: not present
**Fields (10)**:

- `_pivotTransform`
- `_useTargetPivotTransformForEachBodySpace`
- `_targetPivotTransform`
- `_overrideDummyBodyTransform`
- `_dummyBodyTransformInWorld`
- `_targetMeshNodeIndex`
- `_targetSocketName`
- `_selfSocketName`
- `_breakingThreshold`
- `_disableCollisionWithTarget`

### ConstraintMotor 🧠 —

**Category**: Misc  
**Purpose**: records for constraint motor  
**Parser**: not present
**Fields (1)**:

- `_maxForce`

### CraftToolGroupInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: grouping/categorization for craft tool (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/craft_tool_group_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_craftToolInfoList`
- `_craftToolType`
- `_ignoreReduceMaterialCountBuff`
- `_materialInventoryInfoList`

### CraftToolInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: records for craft tool (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/craft_tool_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_craftToolGroupInfo`
- `_failItem`
- `_ingredientsItemGroupInfo`

### CustomVolumeGroupData 🧠 —

**Category**: Misc  
**Purpose**: records for custom volume group data  
**Parser**: not present
**Fields (1)**:

- `_customVolumeDataList`

### DataDefinedDefaultStatData 🧠 —

**Category**: Misc  
**Purpose**: records for data defined default stat data  
**Parser**: not present
**Fields (5)**:

- `_maxStat`
- `_minStat`
- `_regenStat`
- `_initialStat`
- `_redZoneStat`

### DetectDetailInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for detect detail (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/detect_detail_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_detectDetailDataListNew`

### DetectInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for detect (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/detect_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_decreaseValuePerSec`
- `_isDetectableAttachedDocking`
- `_targetLostDistance`
- `_detectSenseData`

### DetectModeAreaData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for detect mode area data  
**Parser**: not present
**Fields (8)**:

- `_detectModeAreaDataType`
- `_equipSlotName`
- `_socketName`
- `_upAxis`
- `_forwardAxis`
- `_coneAngle`
- `_distance`
- `_useCameraDirection`

### DetectReactionInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for detect reaction (records can be individually blocked via is_blocked; carries buff data)  
**Parser**: `dmm-parser/src/tables/detect_reaction_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_reactionTable`
- `_buffReactionType`
- `_strongBuffReactionType`
- `_playerSensibleReactionType`

### DetectSenseData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for detect sense data  
**Parser**: not present
**Fields (11)**:

- `_frontDistance`
- `_frontBeginAngle`
- `_frontEndAngle`
- `_surroundingDistance`
- `_sensitiveDistance`
- `_eventDistance`
- `_heightFloor`
- `_heightCeiling`
- `_doRayCheck`
- `_checkPitch`
- `_subDetectSenseData`

### DialogSetInfo 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for dialog set (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_dialogList`

### DialogSpeaker 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for dialog speaker  
**Parser**: not present
**Fields (4)**:

- `_uniqueCharacterInfo`
- `_speakerScheduleNPCAliasName`
- `_speakerIndex`
- `_isPlayer`

### DialogTextData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for dialog text data  
**Parser**: not present
**Fields (2)**:

- `_dialogText`
- `_isPlayer`

### DialogVoiceInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for dialog voice (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/dialog_voice_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_soundEvent`
- `_footStepSoundEvent`
- `_footStepCrouchSoundEvent`
- `_footStepLandSoundEvent`
- `_footStepGroundSoundEvent`
- `_footStepSoundOffset`
- `_footStepCrouchSoundOffset`
- `_footStepLandSoundOffset`
- `_footStepGroundSoundOffset`
- `_gender`
- `_characterAge`
- `_jobInfoList`

### DockingChildData 🧠 —

**Category**: Misc  
**Purpose**: records for docking child data (spawn-related)  
**Parser**: not present
**Fields (24)**:

- `_gimmickInfoKey`
- `_charcaterKey`
- `_itemKey`
- `_attachParentSocketName`
- `_attachChildSocketName`
- `_dockingTagNameHash`
- `_dockingEquipSlotNo`
- `_spawnDistanceLevel`
- `_isItemEquipDockingGimmick`
- `_sendDamageToParent`
- `_isBodyPart`
- `_dockingType`
- `_isSummonerTeam`
- `_isPlayerOnly`
- `_isNpcOnly`
- `_isSyncBreakParent`
- `_hitPart`
- `_detectedByNPC`
- `_isBagDocking`
- `_enableCollision`
- `_disableCollisionWithOtherGimmick`
- `_dockingSlotKey`
- `_inheritSummoner`
- `_summonTagNameHash`

### DockingItemEventKeyGuide 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for docking item event key guide  
**Parser**: not present
**Fields (5)**:

- `_gimmickEventKey`
- `_localStringKey`
- `_actionNameHash`
- `_deactiveGimmickStateList`
- `_activateCondition`

### DropDefaultData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for drop default data  
**Parser**: not present
**Fields (6)**:

- `_dropEnchantLevel`
- `_socketItemList`
- `_addSocketMaterialItemList`
- `_defaultSubItem`
- `_socketValidCount`
- `_useSocket`

### DropFriendlyData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for drop friendly data (NPC/character references)  
**Parser**: not present
**Fields (8)**:

- `_toMercenaryNoRaw`
- `_factionInfo`
- `_characterInfo`
- `_toTargetActor`
- `_interactionInfo`
- `_varyFriendly`
- `_varyReason`
- `_npcRewardType`

### DropInfoData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for drop info data  
**Parser**: not present
**Fields (11)**:

- `_keyRaw`
- `_dropResultType`
- `_ownerConditionInfo`
- `_playerConditionInfo`
- `_gimmickCachedTargetConditionInfo`
- `_dropTagNameHash`
- `_percent`
- `_subPercent`
- `_minValue`
- `_maxValue`
- `_enchantLevel`

### DropSetInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: records for drop set (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/drop_set_info/`
**Fields (12)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_dropRollType`
- `_dropRollCount`
- `_dropConditionString`
- `_dropTagNameHash`
- `_list`
- `_neeSlotCount`
- `_needWeight`
- `_totalDropRate`
- `_originalString`

### DyeColorData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for dye color data  
**Parser**: not present
**Fields (2)**:

- `_color`
- `_condition`

### DyeColorGroupData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for dye color group data  
**Parser**: not present
**Fields (2)**:

- `_dyeColorGroupInfo`
- `_condition`

### DyeColorGroupInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: grouping/categorization for dye color (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/dye_color_group_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_dyeColorDataList`
- `_dyeColorGroupName`
- `_iconPath`

### DyeTextureSetData 🧠 —

**Category**: Misc  
**Purpose**: records for dye texture set data  
**Parser**: not present
**Fields (2)**:

- `_dyeTextureSetKey`
- `_condition`

### EffectInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: records for effect (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/effect_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_effectDataList`
- `_meshEffectDataList`
- `_hasEquipType`
- `_hasPreset`
- `_targetColorLerpType`

### EffectInfoData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for effect info data (spawn-related)  
**Parser**: not present
**Fields (18)**:

- `_isValid`
- `_equipTypeInfo`
- `_effectData`
- `_effectNameString`
- `_socketNameString`
- `_targetSocketNameString`
- `_spawnPartNameString`
- `_attachingPartNameString`
- `_effectVariationNameString`
- `_soundSwitchGroup`
- `_soundSwitchInfo`
- `_soundEventName`
- `_soundFadeOutTime`
- `_ignoreAttachedObjectVisibility`
- `_aliasList`
- `_aliasParameterList`
- `_effectPlayList`
- `_effectPresetElementList`

### EffectPlayInfo 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for effect play  
**Parser**: not present
**Fields (1)**:

- `_randomPlayList`

### EffectPresetElement 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for effect preset element (positional; spawn-related)  
**Parser**: not present
**Fields (18)**:

- `_elementNameHash`
- `_effectData`
- `_effectNameString`
- `_socketNameString`
- `_targetSocketNameString`
- `_spawnPartNameString`
- `_attachingPartNameString`
- `_effectVariationNameString`
- `_moveBoneList`
- `_boneMoveTimeList`
- `_scaleRandom`
- `_positionRandom`
- `_rotationRandom`
- `_attachPositionRandom`
- `_effectSpeedRandom`
- `_aliasList`
- `_aliasParameterList`
- `_flagXXX`

### ElementalMaterialInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: records for elemental material (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/elemental_material_info/`
**Fields (20)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_elementalMaterialSystemType`
- `_elementalMaterialKey`
- `_totalFuelAmount`
- `_fuelStandardObbSize`
- `_fuelEndPassiveSkillKey`
- `_fuelEndPassiveSkillLevel`
- `_fuelEndActiveSkillKey`
- `_fuelEndActiveSkillLevel`
- `_useTemperatureTransferMargin`
- `_elementalMaterialStateDataList`
- `_minStatList`
- `_maxStatList`
- `_parentMaterialKeyListDeprecatedXXX`
- `_flag`
- `_isSystemType`
- `_elementalMaterialStatDataList`
- `_sceneObjectSpawnableType`

### ElementalMaterialSceneObjectSoundData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for elemental material scene object sound data  
**Parser**: not present
**Fields (3)**:

- `_audioParameterName`
- `_elementalMaterialStateName`
- `_elementalMaterialSoundEventName`

### ElementalMaterialSkillData 🧠 —

**Category**: Skill/Action  
**Purpose**: records for elemental material skill data  
**Parser**: not present
**Fields (9)**:

- `_passiveSkillInfo`
- `_passiveSkillLevel`
- `_increaseActiveSkillInfo`
- `_increaseActiveSkillLevel`
- `_decreaseActiveSkillInfo`
- `_decreaseActiveSkillLevel`
- `_leaveActiveSkillInfo`
- `_leaveActiveSkillLevel`
- `_elementalMaterialBuffLevel`

### ElementalMaterialStatData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for elemental material stat data  
**Parser**: not present
**Fields (4)**:

- `_statusKey`
- `_parentElementalMaterialKey`
- `_elementalMaterialBuffKeyForCharacter`
- `_isActivatedInSafeZone`

### ElementalMaterialStateData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for elemental material state data (UI icon)  
**Parser**: not present
**Fields (14)**:

- `_statusInfo`
- `_ceilStat`
- `_floorStat`
- `_iconPath`
- `_elementalMaterialStateName`
- `_elementalMaterialResistType`
- `_elementalMaterialGimmickSoundData`
- `_elementalMaterialSkillDataList`
- `_increasePerSecond`
- `_decreasePerSecond`
- `_isImmediately`
- `_isInitialStat`
- `_evadeElementalObstacle`
- `_isEndState`

### ElementalMaterialStateDataList 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for elemental material state data list  
**Parser**: not present
**Fields (1)**:

- `_list`

### EnchantData 🧠 —

**Category**: Misc  
**Purpose**: records for enchant data  
**Parser**: not present
**Fields (4)**:

- `_level`
- `_enchantStatData`
- `_buyPriceList`
- `_equipBuffs`

### EnchantStatData 🧠 —

**Category**: Misc  
**Purpose**: records for enchant stat data  
**Parser**: not present
**Fields (4)**:

- `_maxStatList_DataDefinedRegenerate`
- `_regenStatList_DataDefinedRegenerate`
- `_statList_DataDefinedStatic`
- `_statList_DataDefinedStaticLevel`

### EquipCategoryData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for equip category data (UI icon)  
**Parser**: not present
**Fields (3)**:

- `_uiEquipPositionX`
- `_uiEquipPositionY`
- `_iconPath`

### EquipInfo 📚 P

**Category**: Item/Inventory  
**Purpose**: records for equip (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/equip_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_attackedMaterialSlotNo`
- `_list`
- `_radgollEquipTableGroupDataList`
- `_uiComponentName`

### EquipInfoData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for equip info data  
**Parser**: not present
**Fields (18)**:

- `_equipTypeList`
- `_equipCategoryData`
- `_equipSlotNo`
- `_decreaseEndurancePercent`
- `_sequencer`
- `_idleActionHash`
- `_changeActionHash`
- `_socketCombinationHash`
- `_equipSlotName`
- `_equipSlotMemo`
- `_equipQuickSlotUiTabIndex`
- `_equipQuickSlotUiIndex`
- `_mustEquipTypeInfo`
- `_isMustEquipSlot`
- `_isShowEquipMesh`
- `_isHideEquipInDyeingProcess`
- `_isWeaponSlot`
- `_isSpawnCustomMesh`

### EquipTypeInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: type/enum definitions for equip (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/equip_type_info/`
**Fields (20)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_destroyedAiEvent`
- `_useResourceItemType`
- `_fakeEquipReserveSlotData`
- `_applyStatusGroupInfoOnActivate`
- `_applyPassiveSkillOnActivate`
- `_isShowStamina`
- `_decreaseEndurancePercent`
- `_onGuardDamageReductionPercent`
- `_isCriticalCollidable`
- `_enableTransfer`
- `_enableEnchant`
- `_useActionOnQuickSlot`
- `_cameraPresetHash`
- `_dyeRotationValue`
- `_equipAbleHashList`
- `_equipTypeName`
- `_showHelmOnBattleStance`

### ExperienceLevelData 🧠 —

**Category**: Misc  
**Purpose**: records for experience level data  
**Parser**: not present
**Fields (5)**:

- `_level`
- `_expValue`
- `_gimmickEventDailyCountData`
- `_actionFrameEventDailyCountData`
- `_talkEventDailyCountData`

### FactionBlockadingData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction blockading data  
**Parser**: not present
**Fields (8)**:

- `_blockadingFactionInfo`
- `_blockadingLineStartNodeInfo`
- `_useBlockDay`
- `_isBlockByPlayer`
- `_blockSubType`
- `_blockEndDay`
- `_blockEventKey`
- `_subBlockadingFactionInfoList`

### FactionEventData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction event data (spawn-related)  
**Parser**: not present
**Fields (36)**:

- `_eventDataType`
- `_factionInfo`
- `_factionNodeInfo`
- `_leaderCharacterInfo`
- `_targetFactionNodeInfo`
- `_targetFactionInfo`
- `_factionRelation`
- `_dueDateInSeconds`
- `_relationGroupInfo`
- `_conqueredNodeInfo`
- `_isConquerEnable`
- `_isCapital`
- `_blockData`
- `_isBlockEnable`
- `_dailyDeliveryItemPair`
- `_rangeValue`
- `_spawnRate`
- `_targetQuestList`
- `_targetStage`
- `_targetFactionList`
- `_applySkillData`
- `_targetFactionNodeList`
- `_targetRegionList`
- `_targetPosition`
- `_isSkillEnable`
- `_isReviveEnable`
- `_isSaveEnable`
- `_isSubInnerEnable`
- `_isNodeEnable`
- `_fireArmRangeType`
- `_targetFactionType`
- `_levelName`
- `_aliasName`
- `_desc`
- `_eventDataFileName`
- `_eventDataFileLineNumber`

### FactionEventData_ExecuteCondition 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for faction event data execute condition (quest references)  
**Parser**: not present
**Fields (10)**:

- `_eventType`
- `_playerCondition`
- `_questInfo`
- `_stageInfo`
- `_missionInfo`
- `_factionNodeInfo`
- `_factionInfo`
- `_gameVariableInfo`
- `_closeStageOnEndType`
- `_subInnerComplete`

### FactionEventProcessInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction event process (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_factionEventExecuteCondition`
- `_factionEventDataList`

### FactionGimmickActorSpawnInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: spawn rules for faction gimmick actor  
**Parser**: not present
**Fields (3)**:

- `_gimmickSpawnTag`
- `_characterGroupInfo`
- `_condition`

### FactionGroupInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: grouping/categorization for faction (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/faction_group_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_factionGroupName`
- `_factionInfoList`
- `_knowledgeInfo`
- `_uiIconPath`
- `_uiDailyQuestImagePath`

### FactionInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for faction (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/faction_info/`
**Fields (19)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_memo`
- `_categoryType`
- `_flagComponentName`
- `_knowledgeInfo`
- `_contributionSubLevelInfo`
- `_contributionWorkerInfo`
- `_tradeRewardDropsetInfo`
- `_factionRelationGroupInfo`
- `_factionGroupInfo`
- `_representFactionInfo`
- `_stageIconPath`
- `_factionUiCardList`
- `_stealthOptionList`
- `_factionEventDataList`
- `_isEmptyMisc`
- `_factionColor`

### FactionNodeInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for faction node (records can be individually blocked via is_blocked; skill references)  
**Parser**: `dmm-parser/src/tables/faction_node_info/`
**Fields (31)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_knowledgeInfo`
- `_skillTreeInfo`
- `_connectResearchNodeInfo`
- `_storeInfo`
- `_royalSupplyInfo`
- `_memo`
- `_childFactionInfoList`
- `_nodeLineMainFactionInfoList`
- `_worldPosition`
- `_nodeRadius`
- `_applySkillDataList`
- `_resourceItemList`
- `_revivalStageInfoList`
- `_wayPointDataList_deprecated`
- `_factionScheduleInfoList`
- `_factionType`
- `_subInnerTypeString`
- `_workerCount`
- `_knockDownCondition`
- `_bitMapColorKey`
- `_researchDataList`
- `_factionEventDataList`
- `_useCustomWayPointforDev`
- `_observeData`
- `_religionMaxBlockDay`
- `_religionBlockCostList`
- `_religionEffectRegionInfoList`
- `_religionSubLevelInfo`

### FactionNodeInfo_ObserveData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction node info observe data  
**Parser**: not present
**Fields (5)**:

- `_observePosition`
- `_startYaw`
- `_yawMin`
- `_yawMax`
- `_observeCameraPresetHash`

### FactionNodeSpawnInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: spawn rules for faction node (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/faction_node_spawn_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_factionNodeInfo`
- `_boundaryBox`
- `_patrolAISplineDataList`

### FactionNodeSpawnPatrolSplineData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction node spawn patrol spline data  
**Parser**: not present
**Fields (2)**:

- `_splineObjectUUID`
- `_aiSpline`

### FactionPassiveSkillData 🧠 —

**Category**: Skill/Action  
**Purpose**: records for faction passive skill data  
**Parser**: not present
**Fields (3)**:

- `_deliveredFromFactionInfo`
- `_applySkillData`
- `_factionStateData`

### FactionPatrolCharacterData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for faction patrol character data (NPC/character references)  
**Parser**: not present
**Fields (6)**:

- `_characterInfo`
- `_characterGroupInfo`
- `_subCharacterInfo`
- `_subCharacterGroupInfo`
- `_characterCount`
- `_subCharacterCount`

### FactionPatrolData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction patrol data (spawn-related)  
**Parser**: not present
**Fields (2)**:

- `_spawnOptionTagList`
- `_patrolPartyDataList`

### FactionRelationGroupInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: grouping/categorization for faction relation (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/faction_relation_group_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_relationGroupList`

### FactionResearchData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction research data  
**Parser**: not present
**Fields (10)**:

- `_key`
- `_researchName`
- `_researchDesc`
- `_uiTextureName`
- `_dropSetInfo`
- `_connectFactionNodeInfo`
- `_conditionOptionList`
- `_progressDataList`
- `_costItemList`
- `_researchTotalProgress`

### FactionResearchProgressData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction research progress data  
**Parser**: not present
**Fields (2)**:

- `_condition`
- `_onFailMaxValue`

### FactionResourceData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction resource data  
**Parser**: not present
**Fields (5)**:

- `_deliveredFromFactionInfo`
- `_resourceItemInfo`
- `_initialCount`
- `_resourceCountPerDay`
- `_factionStateData`

### FactionScheduleInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction schedule  
**Parser**: not present
**Fields (29)**:

- `_scheduleType`
- `_schedulePlayList`
- `_activeStateData`
- `_deliveringItemList`
- `_deliveryCharacterInfoList`
- `_periodTimeInSecond`
- `_moveStartTimeHour`
- `_moveStartTimeMinute`
- `_uiSpecialIcon`
- `_isRewardToLevel`
- `_operationKey`
- `_operationStringKey`
- `_operationName`
- `_resourceDataList`
- `_rewardDropSetInfo`
- `_rewardDropMoney`
- `_equipItemInfo`
- `_targetLevelInfo`
- `_gimmickAliasName`
- `_operationDay`
- `_needOperatorMinCount`
- `_needOperatorMaxCount`
- `_maxCombatPower`
- `_operationTypeString`
- `_factionScheduleInfo_StatData`
- `_scheduleSpawnPivot`
- `_conditionOptionList`
- `_operationAdditionalDataList`
- `_isRepeatable`

### FactionScheduleInfo_StatData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction schedule info stat data  
**Parser**: not present
**Fields (3)**:

- `_statusInfo`
- `_needSkillInfo`
- `_addRewardPercentByStat`

### FactionSchedulePlayInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction schedule play (spawn-related)  
**Parser**: not present
**Fields (6)**:

- `_scheduleCompleteType`
- `_scheduleFileNameHash`
- `_operationProgress`
- `_spawnPosition`
- `_skipSchedule`
- `_additionalSpawnCharacterInfoList`

### FactionScheduleSpawnInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: spawn rules for faction schedule  
**Parser**: not present
**Fields (1)**:

- `_characterGroupInfoList`

### FactionSequencerSpawnInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: spawn rules for faction sequencer  
**Parser**: not present
**Fields (1)**:

- `_sequencerSpawnInfoList`

### FactionSpawnDataInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: data records for faction spawn (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/faction_spawn_data_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_patrolSpawnData`
- `_gimmickSpawnDataList`
- `_scheduleSpawnInfo`
- `_sequencerSpawnInfo`

### FactionStateData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction state data  
**Parser**: not present
**Fields (4)**:

- `_activateFactionStateList`
- `_playerConditionInfo`
- `_relationTargetFactionInfo`
- `_relationType`

### FactionStealthOptionData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction stealth option data  
**Parser**: not present
**Fields (3)**:

- `_optionName`
- `_playerCondition`
- `_useDetectEye`

### FactionUICardData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction ui card data  
**Parser**: not present
**Fields (2)**:

- `_knowledgeInfo`
- `_questKeyList`

### FactionWayPointData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction way point data  
**Parser**: not present
**Fields (3)**:

- `_fromNodeInfo`
- `_toNodeInfo`
- `_wayPointList`

### FactionWayPointInfo 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for faction way point (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_wayPointData`

### FailMessageInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for fail message (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/fail_message_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_failMessageInfoList`

### FailMessageInfoData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for fail message info data  
**Parser**: not present
**Fields (2)**:

- `_conditionInfo`
- `_nakMessage`

### FieldInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for field (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/field_info/`
**Fields (24)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_spawnPath`
- `_levelName`
- `_sequencerSpawnKey`
- `_maxPlayerCount`
- `_addFieldStyle`
- `_readOnly`
- `_fieldRegistType`
- `_sceneLevelPath`
- `_returnPosition`
- `_boundaryPositionMin`
- `_boundaryPositionMax`
- `_startSectorIndex`
- `_endSectorIndex`
- `_detectInfo`
- `_useFixedFieldTime`
- `_isEnableAutoSave`
- `_fixedFieldTime`
- `_regionBitmapPositionInfo`
- `_natureRegionBitmapPositionInfo`
- `_crimeRegionBitmapPositionInfo`
- `_alwaysCallVehicle_dev`

### FieldLevelNameTableInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: lookup table for field level name (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/field_level_name_table_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_fieldLevelName`
- `_levelNameInfoDataList`

### FieldReviveInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for field revive (records can be individually blocked via is_blocked; positional)  
**Parser**: `dmm-parser/src/tables/field_revive_info/`
**Fields (10)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_position`
- `_rotationY`
- `_sequencerStageChartDesc`
- `_fieldInfoKey`
- `_knowledgeInfo`
- `_knowledgeLevel`
- `_useDefaultRevive`

### FixedMaterialData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for fixed material data (NPC/character references)  
**Parser**: not present
**Fields (6)**:

- `_itemInfo`
- `_gimmickInfo`
- `_characterInfo`
- `_count`
- `_couponCount`
- `_enchantLevel`

### FormationInfo ✅ T1

**Category**: Mini-game / Special  
**Purpose**: records for formation (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/formation_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_memberDataList`
- `_absoluteOffset`
- `_isSuperStrict`

### FrameEventAttrGroupInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: grouping/categorization for frame event attr (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/frame_event_attr_group_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_frameEventAttributeArr`

### FrameEventAttribute 🧠 —

**Category**: Skill/Action  
**Purpose**: records for frame event attribute  
**Parser**: not present
**Fields (5)**:

- `_type`
- `_moveInfo`
- `_accInfo`
- `_rotateInfo`
- `_jumpInfo`

### FrameEventAttribute_Acc 🧠 —

**Category**: Skill/Action  
**Purpose**: records for frame event attribute acc  
**Parser**: not present
**Fields (9)**:

- `_name`
- `_moveAcc`
- `_moveDeacc`
- `_inertiaBrakeMinThreshold`
- `_inertiaBrakeMaxThreshold`
- `_inertiaBrakeStrength`
- `_inputAccAddSpeed`
- `_inputAccDecreaseSpeed`
- `_inputAccDecreaseCoolTime`

### FrameEventAttribute_Jump 🧠 —

**Category**: Skill/Action  
**Purpose**: records for frame event attribute jump  
**Parser**: not present
**Fields (2)**:

- `_name`
- `_jumpHeight`

### FrameEventAttribute_Move 🧠 —

**Category**: Skill/Action  
**Purpose**: records for frame event attribute move  
**Parser**: not present
**Fields (3)**:

- `_name`
- `_moveSpeed`
- `_inputAccMaxSpeed`

### FrameEventAttribute_Rotate 🧠 —

**Category**: Skill/Action  
**Purpose**: records for frame event attribute rotate  
**Parser**: not present
**Fields (5)**:

- `_name`
- `_characterRotationSpeed`
- `_changingRotationSpeed`
- `_characterRotationAcc`
- `_characterRotationDcc`

### FriendlyDailyCountData 🧠 —

**Category**: Misc  
**Purpose**: records for friendly daily count data  
**Parser**: not present
**Fields (2)**:

- `_lastUpdateTime`
- `_dailyCount`

### GameAdviceGroupInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: grouping/categorization for game advice (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_advice_group_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_gameAdviceGroupName`
- `_gameAdviceGroupUnknownName`
- `_gameAdviceGroupIconPath`
- `_gameAdviceInfoList`
- `_gameAdviceStartIndex`

### GameAdviceInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for game advice (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_advice_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_titleLocalStringInfo`
- `_descLocalStringInfo`
- `_keyMouseInputDescLocalStringInfo`
- `_gameAdviceUnknownName`
- `_uiTextureNameStringInfo`
- `_uiVideoPathStringInfo`
- `_widgetIdStringInfo`
- `_isOnce`
- `_isShowGuideList`
- `_gameAdviceGroupInfo`
- `_isDefault`
- `_isUseLoadingView`

### GameConditionInfo 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for game condition (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_expression`

### GameEventExecuteData 🧠 —

**Category**: Misc  
**Purpose**: records for game event execute data  
**Parser**: not present
**Fields (4)**:

- `_gameEventType`
- `_playerCondition`
- `_targetCondition`
- `_eventCondition`

### GameEventHandlerInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for game event handler (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_event_handler_info/`
**Fields (9)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_gameEventType`
- `_playerCondition`
- `_eventCondition`
- `_targetCondition`
- `_gameEventHandlerData`
- `_isPendOnBattleState`

### GameGlobalEffectInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: records for game global effect (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_global_effect_info/`
**Fields (17)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_condition`
- `_projectileKey`
- `_projectileShotKey`
- `_projectileChasePhysicsMaterialHash`
- `_projectileShotSpread`
- `_projectileShotInterval`
- `_projectileHeightOffset`
- `_projectileCreateDelayTime`
- `_projectileHitRate`
- `_projectileShotCount`
- `_effectData`
- `_weatherData`
- `_postProcessData`
- `_isAdvanced`

### GameGlobalEffectInfo_Effect 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for game global effect info effect (spawn-related)  
**Parser**: not present
**Fields (7)**:

- `_effectFileName`
- `_spawnInterval`
- `_spawnRatioCheckValue`
- `_spawnRatio`
- `_spawnType`
- `_spawnRatioType`
- `_indoorType`

### GameGlobalEffectInfo_PostProcess 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for game global effect info post process  
**Parser**: not present
**Fields (22)**:

- `_exposureCompensation`
- `_exposureLowPercent`
- `_exposureHighPercent`
- `_minLuminance`
- `_maxLuminance`
- `_fixedExposureValue`
- `_localToneMappingShadows`
- `_localToneMappingHighlights`
- `_localToneMappingSigma`
- `_chromaticAberrationRatio`
- `_vignettingRatio`
- `_slopeRed`
- `_slopeGreen`
- `_slopeBlue`
- `_powerRed`
- `_powerGreen`
- `_powerBlue`
- `_whiteBalance`
- `_saturation`
- `_brightness`
- `_contrast`
- `_autoWhiteBalanceRatio`

### GameGlobalEffectInfo_Weather 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for game global effect info weather  
**Parser**: not present
**Fields (46)**:

- `_precipitation`
- `_cloudiness`
- `_humidity`
- `_windSpeed`
- `_puddleRate`
- `_snowPuddleRate`
- `_snowAmount`
- `_snowRate`
- `_iceRatio`
- `_windDegree`
- `_altitudeWindRatio`
- `_sunDirX`
- `_sunDirY`
- `_moonSizeAngle`
- `_moonDirX`
- `_moonDirY`
- `_mieScaledHeight`
- `_mieAerosolDensity`
- `_mieAerosolDensityMultiRatio`
- `_mieAerosolAbsorption`
- `_mieScatterColor`
- `_ozoneRatio`
- `_directionalLightLuminanceScale`
- `_heightFogDensity`
- `_heightFogBaseline`
- `_heightFogFalloff`
- `_volumeFogScatterColor`
- `_cloudBaseDensity`
- `_cloudBaseContrast`
- `_cloudAlpha`
- `_cloudScrollMultiplier`
- `_cloudAltitude`
- `_cloudThickness`
- `_cloudNear`
- `_cloudFadeRange`
- `_cloudDetailRatio`
- `_cloudDetailScale`
- `_cloudCirrusAltitude`
- `_cloudCirrusDensity`
- `_cloudCirrusWeightR`
- `_cloudCirrusWeightG`
- `_cloudCirrusWeightB`
- `_cloudFlow`
- `_cloudSeed`
- `_rayleighScatteringColor`
- `_enableClimateTexture`

### GameLevelInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for game level (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_level_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_defaultLevelDataName`
- `_updateRegionInfo`
- `_levelDataList`

### GamePlayObjectShareData 🧠 —

**Category**: Misc  
**Purpose**: records for game play object share data  
**Parser**: not present
**Fields (5)**:

- `_mainKeyColor`
- `_projectileKeyColor`
- `_summonKeyColor`
- `_useKeyColor`
- `_isKillJammedTarget`

### GamePlayTriggerInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for game play trigger (records can be individually blocked via is_blocked; positional)  
**Parser**: `dmm-parser/src/tables/game_play_trigger_info/`
**Fields (13)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_triggerType`
- `_isEnable`
- `_safeZoneType`
- `_playerConditionInfo`
- `_uiMapTextureInfo`
- `_position`
- `_rotationY`
- `_worldMapColorR`
- `_fieldReviveInfo`
- `_targetDataList`

### GamePlayVariableInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for game play variable (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/game_play_variable_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_initialVariable`
- `_devMemo`

### GimmickAliasData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick alias data  
**Parser**: not present
**Fields (7)**:

- `_selfSpawnReason`
- `_targetSpawnReason`
- `_needKnowledgeInfo`
- `_conditionInfo`
- `_needKnowledgeLevel`
- `_targetRegionInfo`
- `_uiMapTextureEnableDataList`

### GimmickAttachTargetSocketData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for gimmick attach target socket data  
**Parser**: not present
**Fields (10)**:

- `_socketNameList`
- `_targetSocketNameList`
- `_socketGroupName`
- `_targetSocketGroupName`
- `_rotationSnapType`
- `_rotationPieces`
- `_snapRotationOffset`
- `_snapPositionOffset`
- `_needSnapPosition`
- `_findClosestPoint`

### GimmickAttachedData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick attached data  
**Parser**: not present
**Fields (6)**:

- `_selfSocketNameHash`
- `_targetSocketNameHash`
- `_gimmickAttachMethod`
- `_targetActorKey`
- `_fieldGimmickSaveDataKey`
- `_isChild`

### GimmickAttackImpulseCompleteData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick attack impulse complete data  
**Parser**: not present
**Fields (2)**:

- `_minLevel`
- `_attackFilterList`

### GimmickChartCachedData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick chart cached data (spawn-related)  
**Parser**: not present
**Fields (2)**:

- `_spawnReasonList`
- `_gimmickStateList`

### GimmickChartStateCachedData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick chart state cached data  
**Parser**: not present
**Fields (3)**:

- `_stateNameHash`
- `_localStringInfo`
- `_isSaveState`

### GimmickCombinationAliasData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick combination alias data  
**Parser**: not present
**Fields (4)**:

- `_combinationAliasName`
- `_collideWithParent`
- `_parentSocketName`
- `_childSocketName`

### GimmickConstraintData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick constraint data  
**Parser**: not present
**Fields (7)**:

- `_fieldGimmickSaveDataKey`
- `_gimmickTargetType`
- `_targetActorKey`
- `_isChild`
- `_gimmickEventHandlerId`
- `_constraintData`
- `_constraintMotor`

### GimmickEventHandlerEventTargetData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick event handler event target data  
**Parser**: not present
**Fields (4)**:

- `_targetCombinationAliasName`
- `_targetGimmickInfo`
- `_targetGimmickGroupInfo`
- `_targetGimmickInfoIndex`

### GimmickEventTableInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: lookup table for gimmick event (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/gimmick_event_table_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_usingTypeFlag`
- `_descriptionText`
- `_gimmickIndexMatchingType`
- `_spawnLevelGroupGimmickOnStage`

### GimmickGameEventHandlerData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for gimmick game event handler data  
**Parser**: not present
**Fields (3)**:

- `_gameEventType`
- `_conditionInfo`
- `_gimmickEventKey`

### GimmickGateConnectionInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick gate connection (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/gimmick_gate_connection_info/`
**Fields (9)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_materialItemInfo`
- `_resultItemInfo`
- `_knowledgeInfo`
- `_srcGateInfo`
- `_destGateInfo`
- `_pushKnowledgeToGimmick`

### GimmickGateInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick gate (records can be individually blocked via is_blocked; positional)  
**Parser**: `dmm-parser/src/tables/gimmick_gate_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_position`
- `_rotation`
- `_fieldInfo`

### GimmickGroupInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: grouping/categorization for gimmick (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/gimmick_group_info/`
**Fields (70)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_mainGimmickGroupInfoOfCombination`
- `_batteryInitCapacity`
- `_batteryTotalCapacity`
- `_linkSignalGroupList`
- `_propertyList`
- `_gimmickTagList`
- `_gimmickChartPath`
- `_gimmickType`
- `_gimmickPlacementStyle`
- `_gimmickInterfaceType`
- `_gimmickRemoteCatchableData`
- `_autoTargetingConstraintDataList`
- `_gimmickConstraintDataList`
- `_gimmickInfoList`
- `_gameEventHandlerList`
- `_unlockableIDataList`
- `_defaultSpawnReasonHash`
- `_initialBodyMotionType`
- `_sequencerLevelAllowGimmickEventKeyList`
- `_sequencerLevelConnectAliasNameList`
- `_gimmickAliasDataList`
- `_logoutTimeAfterBreak`
- `_attackByCollisionInfoListKey`
- `_useSlidingMotionProperty`
- `_isEditorUseable`
- `_isGetKnowledgeWhenGetItem`
- `_isUseConstrainSound`
- `_isTargetable`
- `_isAutoPartialBreak`
- `_isAnchorEdgeDisable`
- `_isKeepAnchor`
- `_isIsolatedAnchorBreakable`
- `_useConstraintAchorEdge`
- `_isSubPart`
- `_isBreakMainPartOnBreak`
- `_isAttackByCollisionKeyFrame`
- `_isAttackByCollisionDynamic`
- `_isAttackByCollisionDocking`
- `_isSpreadBreakInCombination`
- `_remoteCatchPullOutUseAction`
- `_saveLevelData`
- `_isScaleable`
- `_gimmickNodeData`
- `_isMacroGimmick`
- `_spawnDistanceLevel`
- `_isDefaultSpawnDistanceLevel`
- `_isPiercedAllyProjectile`
- `_isSpawnComponentInLevel`
- `_useParentGimmickPoint`
- `_isDockingCombinationKeyFrame`
- `_isSpawnedOnPlatformKeyFrame`
- `_useBuoyancyRestoringCenterOfMass`
- `_useRemoteCatchFishing`
- `_isHousingGimmick`
- `_isLinkDecoGimmick`
- `_isWild`
- `_isBuyable`
- `_excludeSequencerBoundary`
- `_stickToObjectSocketList`
- `_pushObjectSocketList`
- `_combinationAliasDataList`
- `_combinationLinkDataList`
- `_stickToObjectType`
- `_interactionUIDistanceLv`
- `_targetableRange`
- `_elementalMaterialInfoList`
- `_elementalStatusInitialStatList`

### GimmickInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/gimmick_info/`
**Fields (162)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_prefabPath`
- `_gimmickGroupInfo`
- `_breakableObjectInfo`
- `_gimmickInteractionOverrideDataList`
- `_useInteractionUISocket`
- `_useSubPartForInteraction`
- `_propertyList`
- `_gimmickNameHash`
- `_gimmickName`
- `_emojiTextureID`
- `_devMemo`
- `_gimmickChartParameterList`
- `_gimmickTagList`
- `_triggerVolumeGroupDataList`
- `_triggerCheckTargetDataList`
- `_elementalReceiverColliderGroupDataList`
- `_gimmickOnTimeGroupDataList`
- `_canDisassemble`
- `_transmutationMaterialGimmickList`
- `_transmutationMaterialItemList`
- `_transmutationMaterialItemGroupList`
- `_timerRandomInterval`
- `_gimmickInfo_NavigationType`
- `_movableNavigation`
- `_motionTypeAsPlatform`
- `_registerAsPlatformOfSummonee`
- `_checkAllyToBreak`
- `_checkAllyToBreakUseGimmickInfo`
- `_isBlockRoadSpawnStageObstacle`
- `_generateEffectData`
- `_controlMaterialParamValueList`
- `_growthDataList`
- `_isInstallable`
- `_convertItemInfo`
- `_uiMapTextureInfo`
- `_allyGroupInfo`
- `_isTargetable`
- `_detectCustomRenderIndex`
- `_boardKey`
- `_attackImpulseCompleteData`
- `_batteryInitCapacity`
- `_batteryTotalCapacity`
- `_collisionBodyData`
- `_centerOfMass`
- `_physicsBreakingDeltaVelocityThreashold`
- `_physicsContactEventDeltaVelocityThreashold`
- `_sealCompleteCount`
- `_pushableDirection`
- `_pendulumData`
- `_snapDialData`
- `_forceFieldTargetType`
- `_hoveringData`
- `_keepClimbPointWhenBroken`
- `_triggerCheckTargetType`
- `_constraintSpeedLevel`
- `_cogWheelSawToothCount`
- `_cogWheelTriggerScale`
- `_dropRollCount`
- `_dropOffsetSocketName`
- `_dropSetInfoList`
- `_dropInfoDataList`
- `_buyableDropItem`
- `_transformSetList`
- `_gimmickAttachTargetDataList`
- `_targetSealPartGimmickInfoList`
- `_eventKeyGuideList`
- `_remoteCatchPullInDurationTime`
- `_bodyMass`
- `_isTwoHandsRemoteCatch`
- `_isLevelGimmickQuickRespawn`
- `_gimmickNodeData`
- `_summonGimmickDataList`
- `_summonCharacterDataList`
- `_summonItemDataList`
- `_summonRandomDataList`
- `_impulseSurroundingDistance`
- `_inspectDataList`
- `_pageGimmickInfo`
- `_installOriginGimmickInfo`
- `_maxFertilizerAmount`
- `_fertilizerIntakeAmount`
- `_propertyConditionStringListForDebug`
- `_stickToObjectType`
- `_pushObjectSpeedRate`
- `_stickToObjectSocketList`
- `_pushObjectSocketList`
- `_interactionUIDistanceLv`
- `_targetableRange`
- `_vehicleInfo`
- `_hasInventoryInfo`
- `_isUnique`
- `_hasObstacleUseType`
- `_isHandCatchable`
- `_isHousingGimmick`
- `_isPuzzleGimmick`
- `_isSavePresetTarget`
- `_isCollectOnlyGimmick`
- `_isBlockSpawnOnAwayFromOriginTransform`
- `_useGroupingRemoteCatch`
- `_applyGimmickStateToItem`
- `_snowRatio`
- `_sealData`
- `_massLevel`
- `_dialogDataList`
- `_buoyancySubmersionRatio`
- `_breakDropOffsetDistance`
- `_characterStepHeight`
- `_breakTypeFromParent`
- `_defaultAliasName`
- `_weakPointEffectDataList`
- `_elementalAreaDataList`
- `_elementalAreaWithMaterial`
- `_physicsTriggerDataList`
- `_trafficBoxDataList`
- `_miniGameDataList`
- `_housingItemPlacementTypeFlag`
- `_factionStructure`
- `_housingStackableTypeFlag`
- `_housingGimmickSpecialType`
- `_housingSupportPlaneScale`
- `_collectFilter_Dev`
- `_knowledgeExtractType`
- `_physicsQualityPreset`
- `_spawnDistanceLevel`
- `_equipDockingSpawnDistanceLevel`
- `_collisionGroupLayer`
- `_useOnDemandCombination`
- `_spawnableVisibleOnly`
- `_applyOffsetByScreenSpaceCasting`
- `_initScale`
- `_gamePlayObjectShareData`
- `_craftToolData`
- `_housingData`
- `_shaderMaterialEffectType`
- `_jammedLogoutEffectName`
- `_jamReactionType`
- `_autoSpawnEnviornmentDetailEffect`
- `_forceCursorAimTargetable`
- `_isAttachTargetOfOtherGimmick`
- `_gimmickFactionInoMode`
- `_isShowInteractionByTrigger`
- `_propagateSkillFromParentActor`
- `_releaseCatchStyle`
- `_initialBodyMotionType`
- `_setObstacleType`
- `_respawnTimeSeconds`
- `_elementalMaterialInfoList`
- `_elementalStatusInitialStatList`
- `_customVolumeGroupDataList`
- `_defaultSpawnReasonData`
- `_defaultSpawnReasonHash`
- `_isWild`
- `_isBuyable`
- `_excludeSequencerBoundary`
- `_useRemoteCatchFishing`
- `_additionalHeightOnCatched`
- `_saveLevelData`
- `_saveOption`
- `_knowledgeInfo`

### GimmickInfo_CombinationLinkData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info combination link data  
**Parser**: not present
**Fields (10)**:

- `_fromGimmickGroupInfo`
- `_fromGimmickGroupIndex`
- `_fromGimmickAliasName`
- `_isFromSelf`
- `_toGimmickGroupInfo`
- `_toGimmickGroupIndex`
- `_toGimmickAliasName`
- `_isToSelf`
- `_linkSignalGroupName`
- `_fromStateHash`

### GimmickInfo_ConstraintData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info constraint data  
**Parser**: not present
**Fields (11)**:

- `_constraintName`
- `_constraintType`
- `_targetType`
- `_useTriggerAutoTarget`
- `_disableCollideWithTarget`
- `_failable`
- `_breakingThreshold`
- `_pivotPosition`
- `_pivotRotation`
- `_selfSocketName`
- `_targetSocketNameList`

### GimmickInfo_CraftToolData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info craft tool data  
**Parser**: not present
**Fields (3)**:

- `_showCraftToolGroupInfo`
- `_enableCraftToolInfoList`
- `_enableFreeMode`

### GimmickInfo_DefaultSpawnReason 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info default spawn reason  
**Parser**: not present
**Fields (3)**:

- `_fixedSpawnReason`
- `_emptyRate`
- `_randomSpawnReasonList`

### GimmickInfo_DialogData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info dialog data  
**Parser**: not present
**Fields (2)**:

- `_dialogList`
- `_index`

### GimmickInfo_ElmentalAreaData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info elmental area data  
**Parser**: not present
**Fields (17)**:

- `_elmentalStatusInfo`
- `_conductionSpeedType`
- `_shapeType`
- `_areaType`
- `_priorityLayer`
- `_transform`
- `_elementalAreaValue`
- `_additionalTransferLength`
- `_enableEvadeObstacle`
- `_enableElementalArea`
- `_useAttackRayCast`
- `_useActorShape`
- `_checkPhysicsCollision`
- `_fireArrowDistance`
- `_warmDistance`
- `_warmDistanceParsed`
- `_parsedFlag`

### GimmickInfo_FactionStructure 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for gimmick info faction structure  
**Parser**: not present
**Fields (5)**:

- `_nodeName`
- `_nodeDesc`
- `_subInnerType`
- `_nodeKnowledgeInfo`
- `_eventDataList`

### GimmickInfo_FactionStructureEvent 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for gimmick info faction structure event  
**Parser**: not present
**Fields (2)**:

- `_stateNameHashList`
- `_factionEventDataList`

### GimmickInfo_HousingData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info housing data  
**Parser**: not present
**Fields (3)**:

- `_varyInventoryInfo`
- `_varyInventorySlot`
- `_isValid`

### GimmickInfo_PhysicsTriggerData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info physics trigger data  
**Parser**: not present
**Fields (4)**:

- `_meshPath`
- `_physicsTriggerAliasName`
- `_enterGimmickEventKey`
- `_exitGimmickEventKey`

### GimmickInfo_SealData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info seal data (UI icon)  
**Parser**: not present
**Fields (3)**:

- `_priceList`
- `_description`
- `_iconPath`

### GimmickInfo_TrafficBoxData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick info traffic box data  
**Parser**: not present
**Fields (3)**:

- `_trafficBoxNameHash`
- `_trafficPauseType`
- `_transform`

### GimmickLinkSignalGroup 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick link signal group  
**Parser**: not present
**Fields (8)**:

- `_linkSignalGroupName`
- `_type`
- `_completeCount`
- `_counterFilterType`
- `_linkSignalOnEventKey`
- `_linkSignalOffEventKey`
- `_randomDelayMin`
- `_randomDelayMax`

### GimmickMiniGameData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick mini game data (spawn-related)  
**Parser**: not present
**Fields (6)**:

- `_miniGameInfo`
- `_entranceFeeItemDataList`
- `_entrancePotItemDataList`
- `_spawnReason`
- `_overrideActorListData`
- `_caseCount`

### GimmickOnTimeData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick on time data  
**Parser**: not present
**Fields (4)**:

- `_gimmickOnTimeHour`
- `_gimmickOnTimeMinute`
- `_gimmickOffTimeHour`
- `_gimmickOffTimeMinute`

### GimmickOnTimeGroupData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick on time group data (spawn-related)  
**Parser**: not present
**Fields (3)**:

- `_spawnReasonHash`
- `_gimmickOnTimeDataList`
- `_switchModeType`

### GimmickRandomSpawnParam 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick random spawn param (spawn-related)  
**Parser**: not present
**Fields (6)**:

- `_itemInfoWrapper`
- `_itemGroupInfoWrapper`
- `_gimmickInfoWrapper`
- `_spawnPercent`
- `_isRandomYaw`
- `_spawnOffsetSocketName`

### GimmickRemoteCatchableData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick remote catchable data  
**Parser**: not present
**Fields (3)**:

- `_controlBaseDirection`
- `_gimmickRemoteCatchType`
- `_useCrossHairPosition`

### GimmickSceneObjectControl_GenerateEffectData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for gimmick scene object control generate effect data  
**Parser**: not present
**Fields (3)**:

- `_switchOnStateNameHash`
- `_useGenerateEffect`
- `_generatedEffectShowConditionType`

### GimmickSceneObjectControl_SetMaterialParameterValue 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick scene object control set material parameter value  
**Parser**: not present
**Fields (7)**:

- `_isSwitchOn`
- `_conditionType`
- `_durationTime`
- `_easeFunctionsType`
- `_materialParamName`
- `_parameterType`
- `_paramFloat4`

### GimmickSummonRandomData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick summon random data (spawn-related)  
**Parser**: not present
**Fields (7)**:

- `_summonRandom_PrefixSocketName`
- `_summonRandom_SummonList`
- `_summonRandom_EmptyPercent`
- `_summonRandom_IsUsePercent`
- `_summonRandom_withAttach`
- `_spawnReason`
- `_condition`

### GimmickTransformSet 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick transform set (spawn-related)  
**Parser**: not present
**Fields (2)**:

- `_spawnReason`
- `_transformDataList`

### GimmickTransformSetData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick transform set data  
**Parser**: not present
**Fields (2)**:

- `_knowledgeInfo`
- `_gimmickInfo`

### GimmickUnlockableData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick unlockable data  
**Parser**: not present
**Fields (3)**:

- `_unlockableItemInfoList`
- `_unlockableMissionInfoList`
- `_defaultLocked`

### GimmickVisualPrefabData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for gimmick visual prefab data  
**Parser**: not present
**Fields (5)**:

- `_tagNameHash`
- `_scale`
- `_prefabNames`
- `_animationPathList`
- `_useGimmickPrefab`

### GlobalGameEventGroupInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: grouping/categorization for global game event (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/global_game_event_group_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_globalGameEventInfoList`
- `_executePercent`

### GlobalGameEventInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for global game event (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/global_game_event_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_globalGameEventGroupInfo`
- `_executeData`

### GlobalStageSequencerInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for global stage sequencer (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/global_stage_sequencer_info/`
**Fields (14)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_groupName`
- `_groupLeaderInfo`
- `_loadingTargetInfo`
- `_gameEventExecuteData`
- `_useReserve`
- `_ignorePlayerState`
- `_playerBehaviorSpaceRadius`
- `_playerBehaviorFloorCheckDistance`
- `_playerBehaviorSpaceCheckOffsetY`
- `_playerBehaviorPlayCondition`
- `_sequencerDescList`

### GraphData 🧠 —

**Category**: Misc  
**Purpose**: records for graph data  
**Parser**: not present
**Fields (4)**:

- `_minValue`
- `_maxValue`
- `_valuePerLevel`
- `_maxLevel`

### GroupMaterialData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for group material data  
**Parser**: not present
**Fields (3)**:

- `_itemGroupInfo`
- `_count`
- `_enchantLevel`

### GrowthData 🧠 —

**Category**: Misc  
**Purpose**: records for growth data (NPC/character references)  
**Parser**: not present
**Fields (7)**:

- `_needGrowthSeconds`
- `_maxAccelateSeconds`
- `_gimmickInfo`
- `_characterInfo`
- `_sendGimmickEventKey`
- `_waitInteraction`
- `_setMercenary`

### HouseInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for house (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/house_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_houseName`
- `_unlockConditionInfo`
- `_houseRegionDataList`

### HouseRegionData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for house region data  
**Parser**: not present
**Fields (3)**:

- `_regionInfo`
- `_houseIconPath`
- `_houseLevelName`

### InspectAction 🧠 —

**Category**: Skill/Action  
**Purpose**: records for inspect action  
**Parser**: not present
**Fields (4)**:

- `_actionNameHash`
- `_catchTagNameHash`
- `_catcherSocketName`
- `_catchTargetSocketName`

### InspectData 🧠 —

**Category**: Misc  
**Purpose**: records for inspect data (NPC/character references; spawn-related)  
**Parser**: not present
**Fields (20)**:

- `_itemInfo`
- `_gimmickInfo`
- `_characterInfo`
- `_spawnReaseonHash`
- `_socketName`
- `_speakCharacterInfo`
- `_inspectTargetTag`
- `_rewardOwnKnowledge`
- `_rewardKnowledgeInfo`
- `_itemDesc`
- `_boardKey`
- `_inspectActionType`
- `_gimmickStateNameHash`
- `_targetPageIndex`
- `_isLeftPage`
- `_targetPageRelatedKnowledgeInfo`
- `_enableReadAfterReward`
- `_referToLeftPageInspectData`
- `_inspectEffectInfoKey`
- `_inspectCompleteEffectInfoKey`

### InteractionActionOverrideData 🧠 —

**Category**: Skill/Action  
**Purpose**: records for interaction action override data  
**Parser**: not present
**Fields (2)**:

- `_socketBoneName`
- `_actionNameHash`

### InteractionConditionData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for interaction condition data  
**Parser**: not present
**Fields (7)**:

- `_conditionLogic`
- `_targetConditionLogic`
- `_onFailType`
- `_message`
- `_actionNameHash`
- `_disableOnTilt`
- `_isFailOnConditionSuccess`

### InteractionInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for interaction (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/interaction_info/`
**Fields (38)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_interactionType`
- `_interactionShowUIType`
- `_preemptionType`
- `_interactionName`
- `_pivotSelectionTarget`
- `_interactionPivotList`
- `_interactionConditionDataList`
- `_autoInteractionType`
- `_categoryInfo`
- `_inputKeyMapName`
- `_buttonClickType`
- `_keyboardClickType`
- `_autoMovingStopDistance`
- `_checkObjectOnTop`
- `_enableOnDockingOrCatch`
- `_showUIAtPivotSocket`
- `_sequencerStageChartDesc`
- `_onPreemptionSuccessAiEventKey`
- `_uiKeyTriggerSoundName`
- `_rewardDropSetInfo`
- `_interactionPopItemList`
- `_dialogSetInfo`
- `_interactionTag`
- `_showMainMenuPanelName`
- `_showMainMenuEventName`
- `_useFacingGotoTransform`
- `_showWhenTargeted`
- `_allowInteractionWhileInteraction`
- `_isCatchInteractionForEditor`
- `_isPlayerInterruptable`
- `_useActionGotoOffset`
- `_fixRotationWhileInteraction`
- `_cancelOnMoveFail`
- `_subInteraction`
- `_waitForInteraction`

### InteractionOverrideData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for interaction override data  
**Parser**: not present
**Fields (15)**:

- `_originInteractionInfo`
- `_interactionOverrideName`
- `_interactionOverrideDistance`
- `_interactionActionOverrideDataList`
- `_interactionPivotOverrideDataList`
- `_interactionConditionOverrideDataList`
- `_interactionPopItemOverrideDataList`
- `_subInteractionGimmickTagList`
- `_interactionDialogSetOverrideData`
- `_interactionDropSetOverrideData`
- `_isOverrideInteractionCheckObjectOnTop`
- `_interactionOverrideCheckObjectOnTop`
- `_isOverrideSubInteraction`
- `_interactionOverrideSubInteraction`
- `_findSubInteractionFromRoot`

### InteractionPivotOverrideData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for interaction pivot override data  
**Parser**: not present
**Fields (8)**:

- `_interactionPivotKey`
- `_targetGotoSocketBone`
- `_aiActionChartString`
- `_aiActionChart`
- `_targetGotoOffset`
- `_interactionUpperHeight`
- `_interactionLowerHeight`
- `_interactionDistance`

### InventoryChangeData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for inventory change data  
**Parser**: not present
**Fields (2)**:

- `_gameEventExecuteData`
- `_toInventoryInfo`

### InventoryInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: records for inventory (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/inventory_info/`
**Fields (17)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_pushableItemTypeList`
- `_excludedItemTypeList`
- `_inventoryMoveDataList`
- `_defaultSlotCount`
- `_maxSlotCount`
- `_pushItemAlertUIText`
- `_InventoryNameUIText`
- `_keyGuideLocalStringInfo`
- `_pushableCheckType`
- `_npcUsableData`
- `_isMoveableInventory`
- `_needSaveSlotCount`
- `_isPushableItemOnlyOne`
- `_collectionItemList`

### InventoryMoveData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for inventory move data  
**Parser**: not present
**Fields (10)**:

- `_type`
- `_fromInventoryInfo`
- `_toInventoryInfo`
- `_convertMoneyItemInfo`
- `_keyGuideText`
- `_moveAllkeyGuideText`
- `_modalText`
- `_itemMoveDataList`
- `_moveCondition`
- `_conditionFailText`

### InventoryNpcUsableData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for inventory npc usable data  
**Parser**: not present
**Fields (2)**:

- `_cooltimeMin_inGame`
- `_cooltimeMax_inGame`

### InventoryPushableData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for inventory pushable data  
**Parser**: not present
**Fields (2)**:

- `_itemGroup`
- `_itemType`

### ItemGroupInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: grouping/categorization for item (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/item_group_info/`
**Fields (14)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_groupName`
- `_itemGroupInfoList`
- `_itemInfoList`
- `_categoryTypeList`
- `_orderIndex`
- `_itemCageType`
- `_iconPath`
- `_isShowCategoryString`
- `_isGroupItemLockable`
- `_isMonsterOnlyEquip`
- `_isAlwaysFoldItemGroup`

### ItemIconData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item icon data (UI icon)  
**Parser**: not present
**Fields (3)**:

- `_iconPath`
- `_checkExistSealedData`
- `_gimmickStateList`

### ItemInfo 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (111)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_maxStackCount`
- `_itemName`
- `_brokenItemPrefixString`
- `_inventoryInfo`
- `_equipTypeInfo`
- `_occupiedEquipSlotDataList`
- `_itemTagList`
- `_equipAbleHash`
- `_consumableTypeList`
- `_itemUseInfoList`
- `_itemIconList`
- `_mapIconPath`
- `_moneyIconPath`
- `_useMapIconAlert`
- `_itemType`
- `_materialKey`
- `_materialMatchInfo`
- `_itemDesc`
- `_itemDesc2`
- `_equipableLevel`
- `_categoryInfo`
- `_knowledgeInfo`
- `_knowledgeObtainType`
- `_destroyEffecInfo`
- `_equipPassiveSkillList`
- `_useImmediately`
- `_applyMaxStackCap`
- `_extractMultiChangeInfo`
- `_extractAdditionalDropSetInfo`
- `_minimumExtractEnchantLevel`
- `_itemMemo`
- `_filterType`
- `_gimmickInfo`
- `_gimmickTagList`
- `_maxDropResultSubItemCount`
- `_useDropSetTarget`
- `_isAllGimmickSealable`
- `_sealableItemInfoList`
- `_sealableCharacterInfoList`
- `_sealableGimmickInfoList`
- `_sealableGimmickTagList`
- `_sealableTribeInfoList`
- `_sealableMoneyInfoList`
- `_deleteByGimmickUnlock`
- `_gimmickUnlockMessageLocalStringInfo`
- `_canDisassemble`
- `_transmutationMaterialGimmickList`
- `_transmutationMaterialItemList`
- `_transmutationMaterialItemGroupList`
- `_isRegisterTradeMarket`
- `_multiChangeInfoList`
- `_isEditorUsable`
- `_discardable`
- `_isDyeable`
- `_isEditableGrime`
- `_isDestoryWhenBroken`
- `_isHousingOnly`
- `_quickSlotIndex`
- `_reserveSlotTargetDataList`
- `_itemTier`
- `_isImportantItem`
- `_applyDropStatType`
- `_dropDefaultData`
- `_prefabDataList`
- `_enchantDataList`
- `_gimmickVisualPrefabDataList`
- `_priceList`
- `_dockingChildData`
- `_inventoryChangeData`
- `_defaultTexturePath`
- `_fixedPageDataList`
- `_dynamicPageDataList`
- `_inspectDataList`
- `_inspectAction`
- `_defaultSubItem`
- `_cooltime`
- `_itemChargeType`
- `_usableAlertType`
- `_sharpnessData`
- `_maxChargedUseableCount`
- `_hackableCharacterGroupInfoList`
- `_itemGroupInfoList`
- `_discardOffsetY`
- `_hideFromInventoryOnPopItem`
- `_isShieldItem`
- `_isTowerShieldItem`
- `_isWild`
- `_packedItemInfo`
- `_unpackedItemInfo`
- `_convertItemInfoByDropNPC`
- `_patternDescriptionDataList`
- `_lookDetailGameAdviceInfoWrapper`
- `_lookDetailMissionInfo`
- `_enableAlertSystemToUI`
- `_isSaveGameDataAtUseItem`
- `_isLogoutAtUseItem`
- `_sharedCoolTimeGroupNameHash`
- `_itemBundleDataList`
- `_moneyTypeDefine`
- `_emojiTextureID`
- `_enableEquipInCloneActor`
- `_isBlockedStoreSell`
- `_isPreorderItem`
- `_isHasItemUseDataInventoryBuff`
- `_isPreservedOnExtract`
- `_respawnTimeSeconds`
- `_maxEndurance`
- `_repairDataList`

### ItemInfo_PatternDescriptionData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item info pattern description data  
**Parser**: not present
**Fields (2)**:

- `_patternDescriptionInfo`
- `_paramStringList`

### ItemInfo_SharpnessData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item info sharpness data  
**Parser**: not present
**Fields (3)**:

- `_maxSharpness`
- `_craftToolInfo`
- `_statData`

### ItemMeshGroupData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item mesh group data  
**Parser**: not present
**Fields (1)**:

- `_partCombinationNameList`

### ItemMeshGroupInfo 🧠 —

**Category**: Item/Inventory  
**Purpose**: grouping/categorization for item mesh (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_itemMeshGroupDataList`

### ItemMoveData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for item move data  
**Parser**: not present
**Fields (4)**:

- `_itemInfo`
- `_convertItemInfo`
- `_cost`
- `_isConsumeSelf`

### ItemUseInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: records for item use (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/item_use_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_itemUseInfoData`

### JobInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for job (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/job_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_parentInfo`
- `_childList`
- `_hasChild`
- `_name`

### KeyMapSettingListInfo ✅ T1

**Category**: Platform/System  
**Purpose**: records for key map setting list (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/key_map_setting_list_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_keyMapSettingList`

### KeySetting 🧠 —

**Category**: Misc  
**Purpose**: records for key setting  
**Parser**: not present
**Fields (3)**:

- `_settingName`
- `_keyboardMapList`
- `_gamePadMapList`

### KnowledgeDescriptionData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for knowledge description data  
**Parser**: not present
**Fields (6)**:

- `_knowledgeName`
- `_knowledgeDesc`
- `_KeyMouseInputknowledgeDesc`
- `_uiTextureName`
- `_videoPath`
- `_uiLocalStringInfo`

### KnowledgeGroupInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: grouping/categorization for knowledge (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/knowledge_group_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_knowledgeGroupName`
- `_knowledgeGroupUnknownName`
- `_knowledgeGroupDesc`
- `_uiTextureName`
- `_knowledgeGroupIconPath`
- `_uiComponentName`
- `_knowledgeInfoList`
- `_childKnowledgeGroupInfoList`
- `_parentKnowledgeGroupInfo`
- `_isShowUI`
- `_isShowUIAlert`
- `_isMeditationLearnable`

### KnowledgeInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for knowledge (records can be individually blocked via is_blocked; skill references; NPC/character references)  
**Parser**: `dmm-parser/src/tables/knowledge_info/`
**Fields (29)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_uiTextureName`
- `_isDefault`
- `_expandMercenaryType`
- `_factionInfo`
- `_factionNodeInfo`
- `_skillInfo`
- `_characterInfoList`
- `_gimmickInfoList`
- `_regionInfoList`
- `_stageInfoList`
- `_isShowUI`
- `_isShowUIAlert`
- `_isLegendaryAnimal`
- `_uiComponentName`
- `_knowledgeFromList`
- `_knowledgeGroupList`
- `_knowledgeLevelDataList`
- `_meditationResourceList`
- `_sharedLevelMainKnowledgeInfo`
- `_sharedLevelKnowledgeInfoList`
- `_knowledgeAliasMap`
- `_itemInfo`
- `_bitmapColorR`
- `_learningPosition`
- `_learningStageInfo`
- `_learnApplySkillInfo`

### KnowledgeLearnableData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for knowledge learnable data  
**Parser**: not present
**Fields (10)**:

- `_activeConditionDataList`
- `_levelUpNeedItemList`
- `_learnNeedKnowledgeList`
- `_priorKnowledgeDataList`
- `_globalStageSequencerInfo`
- `_learnStyle`
- `_learnRequirementType`
- `_repeatCountForFollow`
- `_learnStartActionNameHash`
- `_manualLockOnString`

### KnowledgeLevelData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for knowledge level data  
**Parser**: not present
**Fields (12)**:

- `_level`
- `_knowledgeUnknownName`
- `_keyMouseInputknowledgeDesc`
- `_gimmickGateConnectionInfo`
- `_uiMapTextureInfoList`
- `_uiComponentName`
- `_gimmickAliasPointerList`
- `_knowledgeLearnableData`
- `_posteriorKnowledgeList`
- `_knowledgeDescriptionDataList`
- `_knowledgeName`
- `_knowledgeDesc`

### LevelActionPointActionSet 🧠 —

**Category**: Skill/Action  
**Purpose**: records for level action point action set  
**Parser**: not present
**Fields (3)**:

- `_startActionHash`
- `_ingActionHash`
- `_endActionHash`

### LevelActionPointGroup 🧠 —

**Category**: Skill/Action  
**Purpose**: records for level action point group  
**Parser**: not present
**Fields (2)**:

- `_tagHash`
- `_actionSetList`

### LevelActionPointInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for level action point (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/level_action_point_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_accessType`
- `_levelActionPointGroupList`

### LevelGimmickSceneObjectData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for level gimmick scene object data (spawn-related)  
**Parser**: not present
**Fields (13)**:

- `_levelGimmicKSceneObjectInfo`
- `_gimmickInfo`
- `_itemInfo`
- `_parentSpawningPoolAutoSpawnInfo`
- `_levelName`
- `_relatedGameLevelInfo`
- `_levelNameControlledByGameLevelInfo`
- `_sceneObjectUuid`
- `_spawnReason`
- `_gimmickAliasName`
- `_worldTransform`
- `_teleportOffsetTransform`
- `_guideEffectOffsetPosition`

### LevelGimmickSceneObjectInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for level gimmick scene object (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/level_gimmick_scene_object_info/`
**Fields (25)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_levelName`
- `_levelGimmickSceneObjectDataList`
- `_mapIconTextureInfo`
- `_discoverNearFog`
- `_fogMapIconTextureInfo`
- `_fogDistance`
- `_overAbyssIconTextureInfo`
- `_overAbyssFogMapIconTextureInfo`
- `_overAbyssFogDistance`
- `_discoverDistance`
- `_showIconConditionType`
- `_useTeleport`
- `_useGuideEffect`
- `_isSubInnerGimmick`
- `_checkGameLevelLoadState`
- `_completedDiscoverMapIconTextureInfo`
- `_overAbyssCompletedDiscoverMapIconTextureInfo`
- `_guideEffectSocketName`
- `_oreVeinIndex`
- `_discoverType`
- `_ignoreSameGimmickDiscoverDistance`
- `_discoverGimmickStateHash`

### LevelNameInfo 🧠 —

**Category**: Misc  
**Purpose**: records for level name  
**Parser**: not present
**Fields (4)**:

- `_hashKey`
- `_levelName`
- `_isSectorLevel`
- `_boundary`

### LightDataInfo 🧠 —

**Category**: Misc  
**Purpose**: data records for light (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_lightPresetNameString`

### LimitedHingeConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for limited hinge constraint data  
**Parser**: not present
**Fields (10)**:

- `_minAngularLimit`
- `_maxAngularLimit`
- `_maxFrictionTorque`
- `_angularLimitsTauFactor`
- `_angularLimitsDampFactor`
- `_useMotor`
- `_disableAngularLimitOnUsingVelocityMotor`
- `_disableAngularLimitForced`
- `_motorIndex`
- `_motorTargetAngle`

### LoadingTargetInfo 🧠 —

**Category**: Misc  
**Purpose**: records for loading target  
**Parser**: not present
**Fields (2)**:

- `_sequencerDesc`
- `_initSubTimeline`

### LocalStringInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for local string (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/local_string_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_gameString`
- `_isVisible`

### LocalVelocity_DEV 🧠 —

**Category**: Misc  
**Purpose**: records for local velocity dev  
**Parser**: not present
**Fields (3)**:

- `_local`
- `_parentID`
- `_parent`

### LootDropSubItemData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for loot drop sub item data  
**Parser**: not present
**Fields (2)**:

- `_itemInfo`
- `_count`

### MaterialBloodDecalInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: records for material blood decal (records can be individually blocked via is_blocked; skill references)  
**Parser**: `dmm-parser/src/tables/material_blood_decal_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_skillKey`
- `_bloodDecalVariationData`

### MaterialMatchInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: records for material match (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/material_match_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_effectWeaponKeyHash`
- `_effectArmorKeyHash`
- `_soundWeaponKeyHash`
- `_soundArmorKeyHash`
- `_physicsMaterialName`

### MaterialRelationInfo ✅ T1

**Category**: Crafting/Material  
**Purpose**: relations between material (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/material_relation_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_materialRelationMatchUpDataList`

### MaterialRelationMatchUpData 🧠 —

**Category**: Crafting/Material  
**Purpose**: records for material relation match up data  
**Parser**: not present
**Fields (2)**:

- `_materialKey`
- `_damagePercent`

### MercenaryGroupInfo 📚 P

**Category**: Character/NPC  
**Purpose**: grouping/categorization for mercenary (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/mercenary_group_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_mercenaryeInfoList`
- `_childMercenaryGroupInfoList`
- `_parentMercenaryGroupInfo`

### MercenaryInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for mercenary (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/mercenary_info/`
**Fields (19)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_defaultLimitSummonCount`
- `_defaultLimitHireCount`
- `_maxLimitHireCount`
- `_farFromLeaderOption`
- `_combatTargetingFlags`
- `_isControllable`
- `_isPlayable`
- `_setNewMercenaryIsMain`
- `_mainMercenaryPerTribe`
- `_isForceStackable`
- `_isSellable`
- `_useCampLevel`
- `_applyEquipItemStat`
- `_spawnPositionType`
- `_parentMercenaryGroupInfo`
- `_hiredSkillInfoList`

### MeshEffectInfoData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for mesh effect info data  
**Parser**: not present
**Fields (14)**:

- `_isValid`
- `_color`
- `_createDelayTime`
- `_duration`
- `_fadeInDuration`
- `_fadeOutDuration`
- `_offsetDistance`
- `_materialParameterOnValue`
- `_materialParameterOffValue`
- `_meshEffectType`
- `_materialName`
- `_partName`
- `_materialParameterName`
- `_materialParameterTimeName`

### MiniGameCharacterData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for mini game character data  
**Parser**: not present
**Fields (6)**:

- `_itemInfo`
- `_count`
- `_isEquip`
- `_isRetrieve`
- `_unequipSlotNameKey`
- `_fixedWeaponTypeList`

### MiniGameDataInfo ✅ T1

**Category**: Mini-game / Special  
**Purpose**: data records for mini game (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/mini_game_data_info/`
**Fields (16)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_scriptName`
- `_phasePanelTagName`
- `_uiViewID`
- `_useDeactiveResult`
- `_needChangeCharacterScale`
- `_entranceFeeList`
- `_defaultRewardDropSetInfo`
- `_playerDataList`
- `_npcDataList`
- `_spawnDataList`
- `_gameEventHandlerInfo`
- `_knowledgeInfo`
- `_gameAdviceInfoList`

### MiniGameParam 🧠 —

**Category**: Mini-game / Special  
**Purpose**: records for mini game param  
**Parser**: not present
**Fields (1)**:

- `_min`

### MiniGameSpawnDesc 🧠 —

**Category**: Mini-game / Special  
**Purpose**: records for mini game spawn desc  
**Parser**: not present
**Fields (2)**:

- `_miniGamePlaySkillInfoList`
- `_miniGamePlaySkillLevel`

### MissionBranchData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for mission branch data  
**Parser**: not present
**Fields (6)**:

- `_targetMissionInfo`
- `_conditionInfo`
- `_fromDelayTime`
- `_toDelayTime`
- `_useDelay`
- `_onStart`

### MissionFunctionData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for mission function data (quest references)  
**Parser**: not present
**Fields (12)**:

- `_funcType`
- `_gimmickControlTargetLevelName`
- `_gimmickControlTargetAliasName`
- `_housingRegionInfo`
- `_houseInfo`
- `_activateHousingRegionType`
- `_housingSavePresetName`
- `_factionInfoList`
- `_factionNodeInfoList`
- `_questInfoList`
- `_percent`
- `_onStart`

### MissionInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for mission (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/mission_info/`
**Fields (40)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_parentQuest`
- `_subMissionList`
- `_executeStageList`
- `_branchMissionList`
- `_startPlayerList`
- `_fieldReviveList`
- `_giveUpFieldReviveList`
- `_triggerVolumeData`
- `_rewardList`
- `_resultDataList`
- `_rewardInventoryKey`
- `_uiDesc`
- `_name`
- `_completeName`
- `_desc`
- `_completeLog`
- `_parentMissionInfo`
- `_missionFunctionList`
- `_challengeEventList`
- `_repeatCondition`
- `_limitTime`
- `_completeTime`
- `_completeCount`
- `_completeType`
- `_checkOverlapType`
- `_isShowAlertPlaying`
- `_optional`
- `_existStart`
- `_existHaveCount`
- `_existComplete`
- `_existFail`
- `_preCheck`
- `_checkCompleteCountAtOnce`
- `_showMiniMap`
- `_isOperationMission`
- `_ignoreRepeatOnDead`
- `_targetQuestDialogKey`

### MissionResultData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for mission result data  
**Parser**: not present
**Fields (11)**:

- `_missionResultType`
- `_tagList`
- `_dropSetInfo`
- `_popItemInfo`
- `_popItemCount`
- `_gimmickLevelName`
- `_gimmickAliasName`
- `_savePresetIndex`
- `_completeMissionInfo`
- `_showUI`
- `_isCheat`

### MissionUIDesc 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for mission ui desc  
**Parser**: not present
**Fields (18)**:

- `_stageIconPath`
- `_stageImagePath`
- `_completeImagePath`
- `_guideString`
- `_conditionInfo`
- `_targetMissionInfo`
- `_targetStageInfoList`
- `_scheduleNPCAliasNameList`
- `_targetFactionNodeInfo`
- `_pivotPosition`
- `_uiSize`
- `_uiType`
- `_alertType`
- `_showQuestList`
- `_showOnlyAbyss`
- `_useFindPath`
- `_randomFogPosition`
- `_uiHintEventHandlerInfo`

### MoneyTypeDefine 🧠 —

**Category**: Misc  
**Purpose**: records for money type define  
**Parser**: not present
**Fields (2)**:

- `_priceFloorValue`
- `_unitDataListMap`

### MultiChangeInfo ✅ T1

**Category**: Mini-game / Special  
**Purpose**: records for multi change (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/multi_change_info/`
**Fields (26)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_craftToolInfo`
- `_itemConsumeType`
- `_conditionList`
- `_needKnowledgeInfo`
- `_craftTagName`
- `_isFromItemInfo`
- `_isResultItemForWarehouse`
- `_isWithSealedItem`
- `_isApplyEnchantLevel`
- `_isMaterialItemOnlySameItemNo`
- `_isAllowMaterialItemSelfSame`
- `_fixedMaterialDataList`
- `_recipeItemGroupInfoList`
- `_elementalStatusInfo`
- `_elementalMaterialStateList`
- `_name`
- `_description`
- `_enchantRecipeDesc`
- `_groupStringInfo`
- `_subGroupStringInfo`
- `_complteDescription`
- `_resultDropInfoList`
- `_additionalDropInfoList`

### NighScheduleConvertingConditionData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for nigh schedule converting condition data  
**Parser**: not present
**Fields (8)**:

- `_actionKeywordList`
- `_tagList`
- `_tribeList`
- `_jobList`
- `_equipTypeList`
- `_factionList`
- `_actionAttributeFlag`
- `_andConditionDataList`

### NpcFriendlyInfo 🧠 —

**Category**: Character/NPC  
**Purpose**: records for npc friendly (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_npcFriendlyList`

### NpcInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for npc (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/npc_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_iconPath`
- `_storeInfo`
- `_couponItemInfo`
- `_npcGreetFriendly`
- `_npcFunctionTypeFlag`
- `_shopScenekey`
- `_exchangeGroupKey`
- `_exchangeButtonText`
- `_shopName`
- `_interactionName`
- `_dyeColorGroupDataList`
- `_dyeTextureSetDataList`

### OccupiedEquipSlotData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for occupied equip slot data  
**Parser**: not present
**Fields (2)**:

- `_equipSlotNameKey`
- `_equipSlotNameIndexList`

### OperationAdditionalData 🧠 —

**Category**: Misc  
**Purpose**: records for operation additional data  
**Parser**: not present
**Fields (3)**:

- `_knowledgeInfo`
- `_knowledgeLevel`
- `_additionalRatio`

### PageData 🧠 —

**Category**: Misc  
**Purpose**: records for page data  
**Parser**: not present
**Fields (4)**:

- `_leftPageTexturePath`
- `_rightPageTexturePath`
- `_leftPageRelatedKnowledgeInfo`
- `_rightPageRelatedKnowledgeInfo`

### PartPrefabDyeSlotInfo ✅ T1

**Category**: Platform/System  
**Purpose**: records for part prefab dye slot (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/part_prefab_dye_slot_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_subMeshList`
- `_meshFileName`

### PartPrefabDyeTexturePalleteInfo ✅ T1

**Category**: Platform/System  
**Purpose**: records for part prefab dye texture pallete (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/part_prefab_dye_texture_pallete_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_textureSetIndex`
- `_textureSetArray`

### PartPrefabDyeTextureSet 🧠 —

**Category**: Platform/System  
**Purpose**: records for part prefab dye texture set (UI icon)  
**Parser**: not present
**Fields (5)**:

- `_tag`
- `_iconPath`
- `_baseColorTexturePath`
- `_cltothCategory`
- `_clothSheen`

### PartSubMeshDyeData 🧠 —

**Category**: Misc  
**Purpose**: records for part sub mesh dye data  
**Parser**: not present
**Fields (4)**:

- `_subMeshName`
- `_dyeSlotNo`
- `_tag`
- `_useDyeGrime`

### PathFindTable_BaseData 🧠 —

**Category**: Misc  
**Purpose**: records for path find table base data  
**Parser**: not present
**Fields (8)**:

- `_tableNameHash`
- `_tableName`
- `_moveVoxelType`
- `_roadMoveVoxelType`
- `_limitAngleList`
- `_optimizePitchJumpList`
- `_moveStateList`
- `_roadStateList`

### PathFindTable_Hurdle_BaseData 🧠 —

**Category**: Misc  
**Purpose**: records for path find table hurdle base data  
**Parser**: not present
**Fields (7)**:

- `_handleHurdleState`
- `_forwardHurdleNaviVoxelCount`
- `_upperHurdleNaviVoxelCount`
- `_lowerHurdleNaviVoxelCount`
- `_nextMoveStateKey`
- `_pathSegmentHurdleType`
- `_condition`

### PathFindTable_MoveState_BaseData 🧠 —

**Category**: Misc  
**Purpose**: records for path find table move state base data  
**Parser**: not present
**Fields (3)**:

- `_moveStateKey`
- `_aiStateNameHash`
- `_hurdleDataList`

### PathFindTable_OptimizePitchJump 🧠 —

**Category**: Misc  
**Purpose**: records for path find table optimize pitch jump  
**Parser**: not present
**Fields (4)**:

- `_upperActionNameHash`
- `_lowerActionNameHash`
- `_aiStateNameHash`
- `_condition`

### PathFindTable_RoadBranch 🧠 —

**Category**: Misc  
**Purpose**: records for path find table road branch  
**Parser**: not present
**Fields (3)**:

- `_currentRoadMoveType`
- `_nextRoadMoveType`
- `_aiStateNameHash`

### PathFindTable_RoadHurdle 🧠 —

**Category**: Misc  
**Purpose**: records for path find table road hurdle  
**Parser**: not present
**Fields (3)**:

- `_destinationRoadMoveType`
- `_upperHeight`
- `_lowerHeight`

### PathFindTable_RoadState_BaseData 🧠 —

**Category**: Misc  
**Purpose**: records for path find table road state base data  
**Parser**: not present
**Fields (2)**:

- `_roadMoveType`
- `_roadBranchList`

### PathFindTable_SplineCurveLimitAngle 🧠 —

**Category**: Misc  
**Purpose**: records for path find table spline curve limit angle  
**Parser**: not present
**Fields (3)**:

- `_condition`
- `_voxelType`
- `_limitAngle`

### PathMoveAction 🧠 —

**Category**: Skill/Action  
**Purpose**: records for path move action  
**Parser**: not present
**Fields (5)**:

- `_actionDistance`
- `_speed`
- `_blendFrame`
- `_upperActionNameHash`
- `_lowerActionNameHash`

### PathMoveActionSet 🧠 —

**Category**: Skill/Action  
**Purpose**: records for path move action set  
**Parser**: not present
**Fields (3)**:

- `_actionSetList`
- `_actionSetMovableType`
- `_nameHash`

### PathMoveActionSetGroup 🧠 —

**Category**: Skill/Action  
**Purpose**: records for path move action set group  
**Parser**: not present
**Fields (2)**:

- `_nameHash`
- `_actionSetList`

### PathMoveActionSetOfMoveType 🧠 —

**Category**: Skill/Action  
**Purpose**: records for path move action set of move type  
**Parser**: not present
**Fields (10)**:

- `_standTurnAction`
- `_startActionList`
- `_ingAction`
- `_stopActionList`
- `_preWallDownActionList`
- `_preWallUpActionList`
- `_rapidPauseAction`
- `_transitionAction`
- `_moveType`
- `_prevMoveType`

### PatrolPartyData 🧠 —

**Category**: Misc  
**Purpose**: records for patrol party data (spawn-related)  
**Parser**: not present
**Fields (8)**:

- `_spawnPartyNameHash`
- `_minDistance`
- `_formationInfo`
- `_characterSpawnList`
- `_condition`
- `_navigationMoveType`
- `_moveTypeShareValueHash`
- `_isPartySameTeam`

### PatternDescriptionInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for pattern description (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/pattern_description_info/`
**Fields (10)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_stringFormat`
- `_descriptionParsed`
- `_iconName`
- `_priorityColorType`
- `_paramList`
- `_uiPassiveShowLevel`
- `_uiActiveShowLevel`

### PatternDescriptionParam 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for pattern description param  
**Parser**: not present
**Fields (2)**:

- `_paramType`
- `_isDisplayAbsoluteNumber`

### PlaneConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for plane constraint data  
**Parser**: not present
**Fields (1)**:

- `_rotationLock`

### PlatformAchievementInfo ✅ T1

**Category**: Platform/System  
**Purpose**: records for platform achievement (records can be individually blocked via is_blocked; quest references)  
**Parser**: `dmm-parser/src/tables/platform_achievement_info/`
**Fields (10)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_missionInfo`
- `_platformAchievementIds`
- `_type`
- `_questkey`
- `_questGroupkey`
- `_questGroupPlatformId`
- `_questLinkInfoList`

### PlatformEntitlementInfo ✅ T1

**Category**: Platform/System  
**Purpose**: records for platform entitlement (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/platform_entitlement_info/`
**Fields (9)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_entitlementName`
- `_entitlementDesc`
- `_iconPath`
- `_type`
- `_resultDropInfoList`
- `_platformIdList`

### PlayerActionLimitDesc 🧠 —

**Category**: Skill/Action  
**Purpose**: records for player action limit desc (skill references)  
**Parser**: not present
**Fields (8)**:

- `_moveLvLimit`
- `_weaponOutLimit`
- `_rideLimit`
- `_rideLimitByIndoor`
- `_rideOffLimit`
- `_unsetLimitOnSequencerControl`
- `_skillGroupLimitKey`
- `_skillGroupAllowKey`

### PositionConstraintMotor 🧠 —

**Category**: Misc  
**Purpose**: records for position constraint motor  
**Parser**: not present
**Fields (4)**:

- `_tau`
- `_damping`
- `_proportinalRecoveryVelocity`
- `_constantRecoveryVelocity`

### PrefabData 🧠 —

**Category**: Misc  
**Purpose**: records for prefab data  
**Parser**: not present
**Fields (4)**:

- `_prefabNames`
- `_equipSlotList`
- `_tribeGenderList`
- `_isCraftMaterial`

### PriceFloor 🧠 —

**Category**: Misc  
**Purpose**: records for price floor  
**Parser**: not present
**Fields (3)**:

- `_price`
- `_symNo`
- `_itemInfoWrapper`

### PrismaticConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for prismatic constraint data  
**Parser**: not present
**Fields (10)**:

- `_startPointOffset`
- `_endPointOffset`
- `_useWorldOffset`
- `_axis`
- `_minLinearLimit`
- `_maxLinearLimit`
- `_useWorldSpaceAxis`
- `_allowRotationAroundAxis`
- `_useMotor`
- `_motorTargetPositionRatio`

### PulleyConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for pulley constraint data  
**Parser**: not present
**Fields (3)**:

- `_pulleyPivotA`
- `_pulleyPivotB`
- `_leverageOnBodyB`

### QuestDialogData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog data  
**Parser**: not present
**Fields (1)**:

- `_dialogFlowList`

### QuestDialog_DialogFlow 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog dialog flow  
**Parser**: not present
**Fields (6)**:

- `_startOffsetSecond`
- `_dialogKnowledgeInfo`
- `_reward`
- `_selectDialogSetList`
- `_speakerList`
- `_dialogTextList`

### QuestDialog_FilterData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog filter data  
**Parser**: not present
**Fields (18)**:

- `_dialogType`
- `_interactionType`
- `_aiCategoryType`
- `_attractActionTypeHash`
- `_ownerQuestInfo`
- `_ownerFilterIndex`
- `_filterConditionList`
- `_filterConditionList_missionResult`
- `_questDialogDataList`
- `_selectSetDialogData`
- `_onHearingDialogData`
- `_interrogationDialogList`
- `_subSelectSetDialogList`
- `_interactionText`
- `_useOverhearing`
- `_isMissensceneDialog`
- `_useCameraLockOn`
- `_selectRatioLevel`

### QuestDialog_RewardData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog reward data  
**Parser**: not present
**Fields (6)**:

- `_pushDropSetInfoList`
- `_popItemInfoList`
- `_missionInfo`
- `_challengeIndex`
- `_questDialogKey`
- `_completeQuestDialog`

### QuestDialog_SelectDialogSet 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog select dialog set  
**Parser**: not present
**Fields (7)**:

- `_inputMapName`
- `_selectText`
- `_nextSubSelectSetName`
- `_failedSubSelectSetName`
- `_knowledgeGroupInfo`
- `_knowledgeInfoList`
- `_successKnowledgeInfo`

### QuestDialog_TextData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest dialog text data  
**Parser**: not present
**Fields (8)**:

- `_text`
- `_aiDialogType`
- `_aiDialogTag`
- `_speaker`
- `_aiEventKey`
- `_delayTimeAfterEnd`
- `_playTime`
- `_overrideDialogStrKey`

### QuestGaugeCountData 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest gauge count data  
**Parser**: not present
**Fields (3)**:

- `_stageList`
- `_totalCombatPower`
- `_totalCount`

### QuestGaugeCountData_Stage 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest gauge count data stage  
**Parser**: not present
**Fields (5)**:

- `_stageInfo`
- `_sequencerSpawnInfo`
- `_sequencerSpawnDataIndex`
- `_totalCombatPower`
- `_totalCount`

### QuestGaugeInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest gauge (records can be individually blocked via is_blocked; quest references)  
**Parser**: `dmm-parser/src/tables/quest_gauge_info/`
**Fields (12)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_parentQuest`
- `_startEventData`
- `_completeEventData`
- `_questInfoList`
- `_targetMissionInfoList`
- `_excludeStageInfoList`
- `_factionInfoList`
- `_factionNodeInfoList`
- `_percent`

### QuestGroupInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: grouping/categorization for quest (records can be individually blocked via is_blocked; quest references)  
**Parser**: `dmm-parser/src/tables/quest_group_info/`
**Fields (15)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_questType`
- `_name`
- `_questGroupDesc`
- `_questList`
- `_debugColor`
- `_stageIconPath`
- `_stageTextIconPath`
- `_stageImagePath`
- `_factionGroupInfo`
- `_isSave`
- `_isDev`
- `_isAutoSave`

### QuestInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest (records can be individually blocked via is_blocked; quest references)  
**Parser**: `dmm-parser/src/tables/quest_info/`
**Fields (35)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_questType`
- `_questCategory`
- `_name`
- `_desc`
- `_questGroupInfo`
- `_factionInfo`
- `_factionStateData`
- `_branchData`
- `_startPlayerList`
- `_branchDataList`
- `_executorQuestList`
- `_gaugeList`
- `_missionList`
- `_stageList`
- `_startMission`
- `_startStage`
- `_stageIconPath`
- `_stageTextIconPath`
- `_stageImagePath`
- `_playableMissionCount`
- `_playableStageCount`
- `_testTag`
- `_gameStartStage`
- `_gameStartSubTimeline`
- `_memo`
- `_questDialogFilterDataList`
- `_dialogMustMissionInfoList`
- `_npcDialogMustCondition`
- `_isSave`
- `_isContinuousMission`
- `_isRepeatable`
- `_debugColor`

### QuestPlatformInfoLInker 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for quest platform info l inker  
**Parser**: not present
**Fields (2)**:

- `_questKey`
- `_platformId`

### QuickTimeEventInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for quick time event (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/quick_time_event_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_quickTimeEventDataList`

### QuickTimeEventInfoData 🧠 —

**Category**: Skill/Action  
**Purpose**: records for quick time event info data (positional)  
**Parser**: not present
**Fields (12)**:

- `_quickTimeEventKeyType`
- `_pageIndex`
- `_inputMapQteKeyCode`
- `_inputMapQteGroup`
- `_InputMapFailKeycode`
- `_positionRangeMin`
- `_positionRangeMax`
- `_quickTimeEventEndTime`
- `_isRepeatable`
- `_isFailAtOtherKey`
- `_progressTime`
- `_qteWrapper`

### RackAndPinionConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for rack and pinion constraint data  
**Parser**: not present
**Fields (2)**:

- `_pinionRadiusOrScrewPitch`
- `_isScrewPinion`

### RagdollConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for ragdoll constraint data  
**Parser**: not present
**Fields (12)**:

- `_coneAngularLimit`
- `_minTwistAngularLimit`
- `_maxTwistAngularLimit`
- `_minPlaneAngularLimit`
- `_maxPlaneAngularLimit`
- `_maxFrictionTorque`
- `_angularLimitsTauFactor`
- `_angularLimitsDampFactor`
- `_useMotor`
- `_coneMotorIndex`
- `_twistMotorIndex`
- `_planeMotorIndex`

### RagdollEquipTableData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for ragdoll equip table data  
**Parser**: not present
**Fields (3)**:

- `_condition`
- `_toEquipSlotName`
- `_equipSlotNameIndex`

### RagdollEquipTableGroupData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for ragdoll equip table group data  
**Parser**: not present
**Fields (2)**:

- `_fromRagdollTag`
- `_ragdollEquipTableList`

### RegionDomainFactionData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for region domain faction data  
**Parser**: not present
**Fields (3)**:

- `_condition`
- `_domainFaction`
- `_prisonStage`

### RegionInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for region (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/region_info/`
**Fields (23)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_displayRegionName`
- `_knowledgeInfo`
- `_regionEnterknowledgeInfoList`
- `_parentRegionInfo`
- `_childRegionInfoList`
- `_bitmapColor`
- `_overriedMaxHeight`
- `_regionType`
- `_fogClearCondition`
- `_limitVehicleRun`
- `_isTown`
- `_isWild`
- `_isUIMapDisable`
- `_isHousingRegion`
- `_isNonePlayZone`
- `_vehicleMercenaryAllowType`
- `_isWorldMapRoadPathFindable`
- `_gimmickAliasPointerList`
- `_domainFactionList`
- `_tagList`

### RelationInfo ✅ T1

**Category**: Misc  
**Purpose**: relations between (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/relation_info/`
**Fields (11)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_relationReactionType`
- `_order`
- `_detectRestrictCount`
- `_detectMemorizeTime`
- `_doCompleteNotPriorityActor`
- `_detectValueRatio`
- `_isDetectEventOnly`
- `_gimmickTagDataList`

### RelationInfoGimmickTagData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for relation info gimmick tag data (spawn-related)  
**Parser**: not present
**Fields (3)**:

- `_gimmickTageHash`
- `_spawnReasonHashList`
- `_targetGimmickStateList`

### RepairData 🧠 —

**Category**: Misc  
**Purpose**: records for repair data  
**Parser**: not present
**Fields (4)**:

- `_resourceItemInfo`
- `_repairValue`
- `_repairStyle`
- `_resourceItemCount`

### ReserveSlotInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for reserve slot (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/reserve_slot_info/`
**Fields (17)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_timeLimit`
- `_coolTime`
- `_autoUseItemInfo`
- `_convertItemInfo`
- `_fillDataList`
- `_memo`
- `_reserveSlotType`
- `_usingType`
- `_enableTribeList`
- `_enableVehicleList`
- `_enableSpecialNameHashList`
- `_targetItemGroupList`
- `_sendGimmickEventKeyForSlotDataChanged`
- `_isSelfPlayerOnly`

### ReserveSlotTargetData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for reserve slot target data  
**Parser**: not present
**Fields (2)**:

- `_reserveSlotInfo`
- `_conditionInfo`

### RoyalSupplyInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for royal supply (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/royal_supply_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_royalSupplyRandomMap_Quest`
- `_royalSupplyRandomMap_Mission`
- `_defaultRandomList`
- `_stageInfo`

### RoyalSupplyRandomData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for royal supply random data  
**Parser**: not present
**Fields (4)**:

- `_activeQuestInfo`
- `_activeMissionInfo`
- `_itemInfo`
- `_count`

### ScheduleStageCompleteAIEventDesc 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for schedule stage complete ai event desc  
**Parser**: not present
**Fields (2)**:

- `_aiEventNameHash`
- `_targetFolderName`

### SequencerSpawnInfo ✅ T1

**Category**: Misc  
**Purpose**: spawn rules for sequencer (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/sequencer_spawn_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_description`
- `_sequencerSpawnDataList`
- `_stageType`
- `_isRandom`
- `_matchTagHash`

### SequencerStageBoundaryData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage boundary data (spawn-related)  
**Parser**: not present
**Fields (13)**:

- `_path`
- `_pivot`
- `_playerStartTransform`
- `_aabb`
- `_largeAabb`
- `_filterAabbList`
- `_uniqueCharacterList`
- `_playerCharacterList`
- `_sequencerControlPlayerCharacterList`
- `_gamePlayLevelAliasGimmickList`
- `_spawnActorCount`
- `_activeBoundary`
- `_type`

### SequencerStageSpawnData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage spawn data (spawn-related)  
**Parser**: not present
**Fields (9)**:

- `_gameCondition`
- `_spawnRate`
- `_spawnCharacterInfo`
- `_spawnCharacterGroupInfo`
- `_spawnRiderCharacterInfo`
- `_spawnRiderCharacterGroupInfo`
- `_rewardDropSetInfo`
- `_isMust`
- `_miniGameSpawnDesc`

### SequencerStageSpawnDataList 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage spawn data list  
**Parser**: not present
**Fields (1)**:

- `_characterSpawnDataList`

### SequencerStageTrackChangeData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage track change data (spawn-related)  
**Parser**: not present
**Fields (2)**:

- `_gameCondition`
- `_spawnRate`

### SequencerStageTrackChangeDataList 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage track change data list  
**Parser**: not present
**Fields (4)**:

- `_gameCondition`
- `_characterTrackChangeList`
- `_gimmickTrackChangeList`
- `_itemTrackChangeList`

### SequencerStageTrackChangeData_Character 🧠 —

**Category**: Character/NPC  
**Purpose**: records for sequencer stage track change data character (NPC/character references)  
**Parser**: not present
**Fields (4)**:

- `_characterInfo`
- `_changeCharacterInfo`
- `_changeCharacterGroupInfo`
- `_miniGamePlayCharacterParameter`

### SequencerStageTrackChangeData_Gimmick 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sequencer stage track change data gimmick  
**Parser**: not present
**Fields (2)**:

- `_gimmickInfo`
- `_changeGimmickInfo`

### SequencerStageTrackChangeData_Item 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for sequencer stage track change data item  
**Parser**: not present
**Fields (2)**:

- `_itemInfo`
- `_changeItemInfo`

### SheetMusicInfo 🧠 —

**Category**: Misc  
**Purpose**: records for sheet music (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (18)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_name`
- `_playMidiFilePath`
- `_successMusicFilePath`
- `_failMusicFilePath`
- `_musicSoundEventName`
- `_musicCompleteAiEventHash`
- `_noteSuccessAiEventHash`
- `_noteSuccessGimmickEventKey`
- `_noteMissGimmickEventKey`
- `_musicCompleteGimmickEventKey`
- `_musicFailGimmickEventKey`
- `_eventDistance`
- `_learnKnowledgeInfo`
- `_sheetMusicPlayDataList`
- `_midiNoteListToCheckPlayComplete`

### SheetMusicPlayData 🧠 —

**Category**: Misc  
**Purpose**: records for sheet music play data  
**Parser**: not present
**Fields (2)**:

- `_playTimeTickCount`
- `_noteLaneNoList`

### SkillGroupInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: grouping/categorization for skill (records can be individually blocked via is_blocked; skill references)  
**Parser**: `dmm-parser/src/tables/skill_group_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_groupName`
- `_skillKeyList`

### SkillInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for skill (records can be individually blocked via is_blocked; carries buff data; skill references; UI icon)  
**Parser**: `dmm-parser/src/tables/skill_info/`
**Fields (34)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_cooltime`
- `_buffLevelList`
- `_skillGroupKey`
- `_parentSkill`
- `_learnLevel`
- `_applyType`
- `_iconPath`
- `_needUpgradeItemInfo`
- `_needUpgradeItemCountGraph`
- `_needUpgradeExperienceGraph`
- `_usableCharacterInfoList`
- `_usableCondition`
- `_learnKnowledgeInfo`
- `_factionInfo`
- `_useResourceStatList`
- `_useResourceItemList`
- `_useDriverResourceStatList`
- `_useBatteryStat`
- `_isUiUseAllowed`
- `_isLearnUseArtifact`
- `_allowSkillWithLowResource`
- `_isUseChildPatternDescriptionBuffData`
- `_damageType`
- `_uiType`
- `_reserveSlotInfoList`
- `_maxLevel`
- `_skillGroupKeyList`
- `_buffSustainFlag`
- `_devSkillName`
- `_devSkillDesc`
- `_videoPath`

### SkillNode 🧠 —

**Category**: Skill/Action  
**Purpose**: records for skill node (skill references)  
**Parser**: not present
**Fields (17)**:

- `_id`
- `_skillInfoWrapper`
- `_skillLevel`
- `_knowledgeInfo`
- `_conditionInfo`
- `_uiPositionX`
- `_uiPositionY`
- `_decoLineNodeId`
- `_uiPosition`
- `_parentId`
- `_childIdList`
- `_uiParentDataList`
- `_uiChildIdForGuideline`
- `_nodeType`
- `_uiLearnNeedNodeList`
- `_color`
- `_factionResearchKey`

### SkillTreeGroupInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: grouping/categorization for skill tree (records can be individually blocked via is_blocked; skill references; NPC/character references)  
**Parser**: `dmm-parser/src/tables/skill_tree_group_info/`
**Fields (9)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_skillTreeInfoList`
- `_skillGroupName`
- `_skillGroupDesc`
- `_uiTextureIconPath`
- `_characterInfo`
- `_factionNodeInfo`

### SkillTreeInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for skill tree (records can be individually blocked via is_blocked; skill references; NPC/character references)  
**Parser**: `dmm-parser/src/tables/skill_tree_info/`
**Fields (16)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_characterInfo`
- `_factionInfo`
- `_itemInfo`
- `_uiGridSizeX`
- `_uiGridSizeY`
- `_uiTextureIconPath`
- `_uiPageName`
- `_skillNodeList`
- `_statNodeList`
- `_firstFocusSkillInfo`
- `_firstFocusZoom`
- `_firstFocusPosition`
- `_skillTreeArea`

### SocketGroupData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for socket group data  
**Parser**: not present
**Fields (2)**:

- `_socketSlotNo`
- `_socketInfo`

### SocketGroupInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: grouping/categorization for socket (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/socket_group_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_list`

### SocketInfo ✅ T1

**Category**: Item/Inventory  
**Purpose**: records for socket (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/socket_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_socketName`
- `_iconPath`

### SpawningPoolAutoSpawnInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: spawn rules for spawning pool auto (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/spawning_pool_auto_spawn_info/`
**Fields (16)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_spawnList`
- `_meshNameList`
- `_spawningPoolData`
- `_type`
- `_levelActionPointInfo`
- `_nearInnerRadius`
- `_nearOuterRadius`
- `_spawnSafetyDistance`
- `_useRandomRotation`
- `_checkForbiddenArea`
- `_attachToSocket`
- `_isExistIndoorType`
- `_collectFilter_Dev`

### SpecialModeInfo ✅ T1

**Category**: Mini-game / Special  
**Purpose**: records for special mode (records can be individually blocked via is_blocked; skill references)  
**Parser**: `dmm-parser/src/tables/special_mode_info/`
**Fields (24)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_type`
- `_activeConditionInfo`
- `_postProcessSequencerName`
- `_timeScale`
- `_playerTimeScale`
- `_modeRadius`
- `_passiveSkill`
- `_skillLevel`
- `_inputKeyHash`
- `_cancelInputKeyHash`
- `_hasNearByTargetOption`
- `_isHighPriority`
- `_exclusiveWithDetect`
- `_disableOcclusionCulling`
- `_disablePlayerTargetable`
- `_changeMinimapScale`
- `_isMinimapZoomOut`
- `_isAllowDialog`
- `_optionList`
- `_detectModeAreaData`
- `_playerActionLimitDesc`

### SpecialModeOptionData 🧠 —

**Category**: Mini-game / Special  
**Purpose**: records for special mode option data  
**Parser**: not present
**Fields (32)**:

- `_type`
- `_playerConditionInfo`
- `_targetConditionInfo`
- `_customRenderValueName`
- `_effectKey`
- `_paramName`
- `_paramUint32`
- `_onEventName`
- `_offEventName`
- `_repeatEventName`
- `_repeatIntervalRandomMin`
- `_repeatIntervalRandomMax`
- `_visualEquipItemInfo`
- `_pathTrailType`
- `_allowInteractionInfoList`
- `_subInnerGuideEffectList`
- `_levelGimmickSceneObjectInfo`
- `_guideEffectName`
- `_guideEffectType`
- `_guideEffectImmediatelyKill`
- `_forceSendGimmickEvent`
- `_illusionEffectColor`
- `_illusionEffectTime`
- `_lensFlareScaleValue`
- `_useDepthOfField`
- `_focusDistance`
- `_focalLength`
- `_aperture`
- `_bokehKernelSize`
- `_effectPosition_latitude`
- `_effectPosition_longtitude`
- `_disableActionAttributeFlag`

### StageBranchData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage branch data  
**Parser**: not present
**Fields (7)**:

- `_stageInfo`
- `_conditionInfo`
- `_fromDelayTime`
- `_toDelayTime`
- `_useDelay`
- `_isWaitBranch`
- `_onStart`

### StageChart_Function 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function  
**Parser**: not present
**Fields (4)**:

- `_condition`
- `_startFrame`
- `_endFrame`
- `_index`

### StageChart_Function_CameraPreset 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function camera preset  
**Parser**: not present
**Fields (5)**:

- `_cameraPresetSelectionType`
- `_cameraPresetName`
- `_pivotName`
- `_targetName`
- `_limitDistance`

### StageChart_Function_ChangePhasePanelTag 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function change phase panel tag  
**Parser**: not present
**Fields (2)**:

- `_tagName`
- `_operation`

### StageChart_Function_ChangePivot 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function change pivot  
**Parser**: not present
**Fields (1)**:

- `_attachPivot`

### StageChart_Function_ClearWanted 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function clear wanted  
**Parser**: not present
**Fields (2)**:

- `_wantedFaction`
- `_payPrice`

### StageChart_Function_ConnectActor 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function connect actor  
**Parser**: not present
**Fields (5)**:

- `_connectActorType`
- `_mercenaryFindType`
- `_mercenaryType`
- `_vehicleInfo`
- `_fromTag`

### StageChart_Function_CreateItem 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for stage chart function create item  
**Parser**: not present
**Fields (4)**:

- `_itemInfo`
- `_itemCount`
- `_itemCountVariableNameHash`
- `_isRefill`

### StageChart_Function_DeactivateMiniGame 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function deactivate mini game  
**Parser**: not present
**Fields (4)**:

- `_uiPanelName`
- `_uiSelectorName`
- `_miniGameInfo`
- `_isSuccess`

### StageChart_Function_DeleteItem 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for stage chart function delete item  
**Parser**: not present
**Fields (4)**:

- `_itemInfo`
- `_itemCount`
- `_itemCountVariableNameHash`
- `_deleteAll`

### StageChart_Function_DisconnectActor 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function disconnect actor  
**Parser**: not present
**Fields (1)**:

- `_logoutActor`

### StageChart_Function_DropGroup 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function drop group  
**Parser**: not present
**Fields (3)**:

- `_dropGroupType`
- `_dropInfoDataList`
- `_dropSetInfoList`

### StageChart_Function_EvadeTrigger 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function evade trigger  
**Parser**: not present
**Fields (1)**:

- `_isTriggerObstacle`

### StageChart_Function_ExchangeTradeItem 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for stage chart function exchange trade item  
**Parser**: not present
**Fields (2)**:

- `_exchangeResultItemInfo`
- `_fromInventoryInfo`

### StageChart_Function_ExecuteMiniGameEvent 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function execute mini game event  
**Parser**: not present
**Fields (1)**:

- `_parameter`

### StageChart_Function_FadeInOut 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function fade in out  
**Parser**: not present
**Fields (2)**:

- `_fadeValue`
- `_blendSeconds`

### StageChart_Function_ForceLockOn 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function force lock on  
**Parser**: not present
**Fields (5)**:

- `_lockOnTextInfo`
- `_rewardKnowledgeInfoWrapper`
- `_rewardKnowledgeLevel`
- `_exitDelay`
- `_isEnable`

### StageChart_Function_GameTrigger 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function game trigger (skill references)  
**Parser**: not present
**Fields (12)**:

- `_gamePlayTriggerType`
- `_subtitleGroupTarget`
- `_subtitleGroupName`
- `_blockInteraction`
- `_fixedWeaponType`
- `_fixedWeapon`
- `_characterWarningState`
- `_isSafeZone`
- `_isTargetAll`
- `_isEnable`
- `_playerActionLimitDesc`
- `_skill`

### StageChart_Function_HireMercenary 🧠 —

**Category**: Character/NPC  
**Purpose**: records for stage chart function hire mercenary  
**Parser**: not present
**Fields (5)**:

- `_useMountingMercenary`
- `_isConfirmed`
- `_changeMainMercenary`
- `_mercenaryType`
- `_hireTargetTag`

### StageChart_Function_InputBlock 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function input block  
**Parser**: not present
**Fields (2)**:

- `_inputBlockType`
- `_unsetOnSequencerControl`

### StageChart_Function_KeepAggro 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function keep aggro  
**Parser**: not present
**Fields (1)**:

- `_enemyName`

### StageChart_Function_LetterBox 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function letter box  
**Parser**: not present
**Fields (1)**:

- `_animationTime`

### StageChart_Function_Loading 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function loading  
**Parser**: not present
**Fields (9)**:

- `_targetStageInfo`
- `_targetFieldInfo`
- `_initSubTimelineName`
- `_loadingStageInfo`
- `_chapterTransitionQuestGroup`
- `_fieldRevive`
- `_isOnlyStageReload`
- `_useLoadingUI`
- `_noSave`

### StageChart_Function_LookAt 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function look at  
**Parser**: not present
**Fields (3)**:

- `_lookAtTargetName`
- `_lookAtTargetBoneName`
- `_limitDistance`

### StageChart_Function_MaterialParameter 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function material parameter  
**Parser**: not present
**Fields (3)**:

- `_targeTag`
- `_parameterName`
- `_parameterValue`

### StageChart_Function_MultiChange 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function multi change  
**Parser**: not present
**Fields (1)**:

- `_itemInfo`

### StageChart_Function_PassiveSkill 🧠 —

**Category**: Skill/Action  
**Purpose**: records for stage chart function passive skill (skill references)  
**Parser**: not present
**Fields (2)**:

- `_skillInfo`
- `_skillLevel`

### StageChart_Function_PushReward 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function push reward  
**Parser**: not present
**Fields (1)**:

- `_knowledgeInfo`

### StageChart_Function_RecoveryMercenary 🧠 —

**Category**: Character/NPC  
**Purpose**: records for stage chart function recovery mercenary  
**Parser**: not present
**Fields (3)**:

- `_mercenaryType`
- `_vehicleInfo`
- `_ignoreCost`

### StageChart_Function_Reward 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function reward  
**Parser**: not present
**Fields (3)**:

- `_dropResultList`
- `_isEquip`
- `_resultDataTag`

### StageChart_Function_Sell 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function sell  
**Parser**: not present
**Fields (3)**:

- `_shopNPCName`
- `_toInventoryInfo`
- `_exchangeWithDeadDrop`

### StageChart_Function_SequencerCamera 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function sequencer camera  
**Parser**: not present
**Fields (3)**:

- `_cameraName`
- `_isEnable`
- `_isDelay`

### StageChart_Function_SetAggro 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set aggro  
**Parser**: not present
**Fields (1)**:

- `_enemyName`

### StageChart_Function_SetBattleTarget 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set battle target  
**Parser**: not present
**Fields (1)**:

- `_enemyName`

### StageChart_Function_SetCustomMesh 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set custom mesh  
**Parser**: not present
**Fields (3)**:

- `_targetName`
- `_resourceName`
- `_targetNodeId`

### StageChart_Function_SetInteraction 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set interaction  
**Parser**: not present
**Fields (5)**:

- `_interactionCondition`
- `_interactionInfo`
- `_allowMultiTarget`
- `_useSequencerGotoTransform`
- `_textFromType`

### StageChart_Function_SetPhase 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set phase  
**Parser**: not present
**Fields (4)**:

- `_phaseValue`
- `_maxPhaseValue`
- `_autoPhase`
- `_increasePhase`

### StageChart_Function_SetPreviewTarget 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set preview target  
**Parser**: not present
**Fields (4)**:

- `_targetName`
- `_previewType`
- `_isEnable`
- `_isMercenary`

### StageChart_Function_SetQuestDialogAICategory 🧠 —

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for stage chart function set quest dialog ai category  
**Parser**: not present
**Fields (2)**:

- `_questDialogAICategory`
- `_isEnable`

### StageChart_Function_SetTimer 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set timer  
**Parser**: not present
**Fields (1)**:

- `_timeTickCount`

### StageChart_Function_SetWanted 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function set wanted  
**Parser**: not present
**Fields (4)**:

- `_wantedRegion`
- `_wantedCrimeType`
- `_wantedPrice`
- `_isArrest`

### StageChart_Function_SpecialMode 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function special mode  
**Parser**: not present
**Fields (2)**:

- `_specialModeInfo`
- `_isEnable`

### StageChart_Function_SummonActor 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function summon actor  
**Parser**: not present
**Fields (7)**:

- `_connectActorType`
- `_mercenaryFindType`
- `_mercenaryType`
- `_vehicleInfo`
- `_randomCharacterGroup`
- `_fromTag`
- `_isFromActor`

### StageChart_Function_UIControl 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui control  
**Parser**: not present
**Fields (4)**:

- `_viewID`
- `_selector`
- `_command`
- `_parameterList`

### StageChart_Function_UIControl_Parameter 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui control parameter  
**Parser**: not present
**Fields (3)**:

- `_parameterName`
- `_condition`
- `_attributeList`

### StageChart_Function_UIControl_ParameterAttribute 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui control parameter attribute  
**Parser**: not present
**Fields (3)**:

- `_attributeName`
- `_value`
- `_valueNameHash`

### StageChart_Function_UIFindPath 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui find path  
**Parser**: not present
**Fields (3)**:

- `_stageList`
- `_isEnable`
- `_findNear`

### StageChart_Function_UIHint 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui hint  
**Parser**: not present
**Fields (2)**:

- `_gameEventHandlerInfo`
- `_hideOnExit`

### StageChart_Function_UIShowMinimap 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui show minimap  
**Parser**: not present
**Fields (6)**:

- `_hideConditionString`
- `_uiMapTextureInfo`
- `_isDetectModeTarget`
- `_isEnable`
- `_showPath`
- `_isTriggerLine`

### StageChart_Function_UIStageGuide 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui stage guide  
**Parser**: not present
**Fields (5)**:

- `_localString`
- `_isEnable`
- `_isShowStep`
- `_isDisableAll`
- `_currentStep`

### StageChart_Function_UIStageIcon 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function ui stage icon  
**Parser**: not present
**Fields (1)**:

- `_isEnable`

### StageChart_Function_UnsummonActor 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function unsummon actor  
**Parser**: not present
**Fields (4)**:

- `_targetName`
- `_tribeInfo`
- `_vehicleInfo`
- `_mercenaryType`

### StageChart_Function_VarySharpness 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function vary sharpness  
**Parser**: not present
**Fields (3)**:

- `_inventoryInfoList`
- `_craftToolInfo`
- `_varyPercent`

### StageChart_Function_WithActor 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for stage chart function with actor  
**Parser**: not present
**Fields (2)**:

- `_targetName`
- `_isSummonCharacterTarget`

### StageChart_PassiveSkill 🧠 —

**Category**: Skill/Action  
**Purpose**: records for stage chart passive skill (skill references)  
**Parser**: not present
**Fields (3)**:

- `_targetName`
- `_skillInfo`
- `_skillLevel`

### StageInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for stage (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/stage_info/`
**Fields (85)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_name`
- `_stageDesc`
- `_completeLog`
- `_sequencerDesc`
- `_spawnFactionSpawnDataInfo`
- `_spawnFactionNodeInfo`
- `_disableFactionSpawnPartyNameHashList`
- `_stageCategory`
- `_closeFilter`
- `_closeFilterByGroup`
- `_globalFilterCharacterList`
- `_questType`
- `_stageDataType`
- `_parentQuest`
- `_parentStage`
- `_ownerMissionInfo`
- `_childStageList`
- `_executorMissionList`
- `_executorStageList`
- `_executeTargetStageList`
- `_playCondition`
- `_closeCondition`
- `_fieldInfo`
- `_startPlayerList`
- `_forbiddenCharacterList`
- `_platformCharacter`
- `_platformDockingTagHash`
- `_platformSocketName`
- `_isIgnoreDistance`
- `_isFactionSequencer`
- `_factionSequencerSpawnTagHash`
- `_resetSecond`
- `_randomSpawnCount`
- `_randomPercent`
- `_randomRepeatTime`
- `_completeCount`
- `_subTimelineBreakDescList`
- `_scheduleCompleteCondition`
- `_scheduleStageCompleteAIEventList`
- `_itemConditionAndRemoveArray`
- `_rewardDropSetInfoList`
- `_levelNameList`
- `_globalEffectData`
- `_guideEffectName`
- `_fieldReviveInfo`
- `_stageIconPath`
- `_stageTextIconPath`
- `_stageImagePath`
- `_completeImagePath`
- `_npcShopCharacterInfo`
- `_closeDialogSpeakerCharacter`
- `_closeDialogString`
- `_closeDialogSoundEventName`
- `_updatePriority`
- `_completeAlertType`
- `_stageKnowledge`
- `_stageGameEventDataList`
- `_spawnBlockTypeFlag`
- `_weatherInfo`
- `_gameLevelInfoForValidation`
- `_gameLevelDataNameForValidation`
- `_weatherStartBlendTime`
- `_weatherEndBlendTime`
- `_weatherIngTime`
- `_beginTime`
- `_endTime`
- `_changeTime`
- `_showStageIcon`
- `_isSave`
- `_saveSchedule`
- `_hasDynamicActor`
- `_isForceSpawnAfterRetreat`
- `_isForceSpawnNearDistance`
- `_isForceSpawnAllActor`
- `_disableGiveUp`
- `_reviveInPlaceHardDifficulty`
- `_evadeProjectile`
- `_followParentReaction`
- `_isPlayableOnWanted`
- `_useRevivePointForDead`
- `_ignoreFactionClose`
- `_useMercenaryLogout`

### StageInfo_GlobalEffect 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for stage info global effect  
**Parser**: not present
**Fields (4)**:

- `_triggerVolumeData`
- `_globalEffectInfo`
- `_priority`
- `_blendingDistance`

### StatNode 🧠 —

**Category**: Misc  
**Purpose**: records for stat node  
**Parser**: not present
**Fields (8)**:

- `_id`
- `_itemInfoWrapper`
- `_subLevelInfoWrapper`
- `_uiCommand`
- `_uiPosition`
- `_nodeType`
- `_decoLineNodeId`
- `_color`

### StatusGroupInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: grouping/categorization for status (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/status_group_info/`
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_regenerateStatusInfoList`
- `_statusInfoList`
- `_elementalStatusInfoList`
- `_statusIndexList`
- `_regenStatusIndexList`

### StatusInfo ✅ T1

**Category**: Buff/Effect/Condition  
**Purpose**: records for status (records can be individually blocked via is_blocked; carries buff data)  
**Parser**: `dmm-parser/src/tables/status_info/`
**Fields (34)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_regenerateType`
- `_statusIndexXXXXX`
- `_isHardCoded`
- `_useInitValueZero`
- `_minResistanceStatusInfo`
- `_maxResistanceStatusInfo`
- `_isResistanceStat`
- `_isElementalStat`
- `_blockRegenOnMinStatTick`
- `_decreaseOnItemBroken`
- `_buffInfo`
- `_actualStatusKeyToRefer`
- `_statType`
- `_staticStatType`
- `_elementalStatType`
- `_activeKnowledgeInfo`
- `_sendGimmickEventKeyForStatChanged`
- `_reserveSlotInfoList`
- `_useLimitHitMinStat`
- `_useLimitHitMaxStat`
- `_statusKeyHashCode32`
- `_minHashCode32`
- `_maxHashCode32`
- `_isFullRecoverWhenRevived`
- `_usePercent`
- `_isRepeatUpdateFromServer`
- `_statLevelData`
- `_isResetOnRevive`
- `_notEnoughResourceMessage`
- `_uiTemplateName`
- `_uiComponentName`

### StiffSpringConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for stiff spring constraint data  
**Parser**: not present
**Fields (2)**:

- `_minLength`
- `_maxLength`

### StockData 🧠 —

**Category**: Misc  
**Purpose**: records for stock data  
**Parser**: not present
**Fields (13)**:

- `_storeInfo`
- `_minPricePercent`
- `_maxPricePercent`
- `_maxRefillCount`
- `_stockIndex`
- `_importantSaveIndex`
- `_refillByResetStore`
- `_isStockSellable`
- `_isStockBuyable`
- `_dropInfoData`
- `_playerConditionInfo`
- `_conditionOption`
- `_orderCountDataList`

### StockOrderCountData 🧠 —

**Category**: Misc  
**Purpose**: records for stock order count data  
**Parser**: not present
**Fields (2)**:

- `_conditionInfo`
- `_minCount`

### StoreInfo ✅ T1

**Category**: Quest/Mission/Knowledge  
**Purpose**: records for store (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/store_info/`
**Fields (21)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_exchangeItemInfoForBuy`
- `_exchangeItemInfoListForSell`
- `_sellPercents`
- `_storeType`
- `_priceIncreasePercentList`
- `_sellableCharacterConditionLogic`
- `_resetHour`
- `_resetDay`
- `_buyableStockCount`
- `_sellableStockCount`
- `_sellableType`
- `_stockDataList`
- `_saleItemTypeList`
- `_notSaleItemTypeList`
- `_customMeshOBBMaxLength`
- `_fixedPrice`
- `_useHousingGimmick`
- `_reducePriceByLootedDeadBody`

### StringInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for string (records can be individually blocked via is_blocked; carries buff data)  
**Parser**: `dmm-parser/src/tables/string_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_buffer`

### SubInnerGuideEffectData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for sub inner guide effect data  
**Parser**: not present
**Fields (3)**:

- `_subInnerTypeName`
- `_effectName`
- `_isImmediatelyKill`

### SubLevelExpData 🧠 —

**Category**: Faction/Field/World  
**Purpose**: records for sub level exp data  
**Parser**: not present
**Fields (4)**:

- `_level`
- `_resourceItemList`
- `_expAmount`
- `_activeConditionDataList`

### SubLevelInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for sub level (records can be individually blocked via is_blocked; carries buff data)  
**Parser**: `dmm-parser/src/tables/sub_level_info/`
**Fields (23)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_minLevel`
- `_maxLevel`
- `_exp`
- `_conditionInfo`
- `_alertComponentName`
- `_alertComponentNameForVaryExp`
- `_knowledgeInfo`
- `_buffInfo`
- `_moneyInfo`
- `_rewardDropSetInfo`
- `_subLevelExpDataList`
- `_additionalRewardList`
- `_varyExperienceList`
- `_varyExpPerDonationDataList`
- `_additionalBuffApplyMercenaryInfo`
- `_factionInfoForContribution`
- `_globalStageSequencerInfo`
- `_buffAddPercentType`
- `_expIconPath`
- `_isRelativeWithCamp`

### SubTimelineBreakDesc 🧠 —

**Category**: Misc  
**Purpose**: records for sub timeline break desc  
**Parser**: not present
**Fields (4)**:

- `_eventType`
- `_npcReactionTag_NonBattle`
- `_npcReactionTag_Battle`
- `_subTimelineName`

### SummonCharacterData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for summon character data (positional; spawn-related)  
**Parser**: not present
**Fields (41)**:

- `_selectDataList`
- `_playerCondition`
- `_characterKey`
- `_characterGroupKey`
- `_position`
- `_yaw`
- `_isDead`
- `_appearanceName`
- `_summonDestroyType`
- `_rotateType`
- `_summonSpawnType`
- `_deadLimitTime`
- `_summonTagNameHash`
- `_summoneeCatchType`
- `_summoneeDockingType`
- `_summonerSocketName`
- `_summoneeSocketName`
- `_summoneeActionNameHash`
- `_summoneeDockingTagHashList`
- `_spawnReason`
- `_specialType`
- `_minigameCharacterOverrideDataIndex`
- `_terrainRegionAutoSpawnData`
- `_factionSpawnTag`
- `_spawnPercent`
- `_fromOperationReward`
- `_interactionKey`
- `_interactionPivotKey`
- `_isCaged`
- `_isLogoutWhenSummonerSequencerControl`
- `_isLockedOnlySummon`
- `_ignoreSummonerObstacle`
- `_findValidPositionType`
- `_findValidHeightRange`
- `_summonFormationKey`
- `_summonFormationLeaderActorKey`
- `_summonerEquipSlotNo`
- `_isCloneActor`
- `_isHideActorHelm`
- `_logoutDistanceType`
- `_summonAllyGroupType`

### SummonCharacterData_SelectData 🧠 —

**Category**: Character/NPC  
**Purpose**: records for summon character data select data  
**Parser**: not present
**Fields (2)**:

- `_characterGroupInfo`
- `_regionInfo`

### SummonCharacterData_TerrainRegionAutoSpawn 🧠 —

**Category**: Character/NPC  
**Purpose**: records for summon character data terrain region auto spawn (spawn-related)  
**Parser**: not present
**Fields (5)**:

- `_infoKey`
- `_tag`
- `_nearSpawnPosition`
- `_excludedCharacterGroupKey`
- `_spawnableCheckInterval`

### SummonGimmickData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for summon gimmick data (spawn-related)  
**Parser**: not present
**Fields (21)**:

- `_gimmickInfoKey`
- `_gimmickGroupKey`
- `_spawnPositionOffset`
- `_initLinearVelocity`
- `_spawnOffsetSocketName`
- `_spawnOffsetSocketGroupName`
- `_attachParentSocketName`
- `_attachParentSocketGroupName`
- `_attachChildSocketName`
- `_gimmickAliasName`
- `_summonTagNameHash`
- `_spawnReason`
- `_summonDestroyType`
- `_rotation`
- `_rotationParsed`
- `_randomRotation`
- `_applySummonerScale`
- `_applyParentOwnershipState`
- `_fromOperationReward`
- `_needSummonDeadTypeControlTrigger`
- `_spawnRateList`

### SummonGimmickData_SpawnRate 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for summon gimmick data spawn rate  
**Parser**: not present
**Fields (3)**:

- `_parentFertilizerPercent`
- `_minSpawnCount`
- `_maxSpawnCount`

### SummonItemData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for summon item data (spawn-related)  
**Parser**: not present
**Fields (13)**:

- `_itemKey`
- `_itemGroupKey`
- `_spawnPositionOffset`
- `_initLinearVelocity`
- `_spawnOffsetSocketName`
- `_summonTagNameHash`
- `_spawnReason`
- `_randomRotation`
- `_fromOperationReward`
- `_applyParentOwnershipState`
- `_boardInfoList`
- `_summonFailItem`
- `_summonFailItemGroup`

### TerrainRegionAutoSpawnInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: spawn rules for terrain region auto (records can be individually blocked via is_blocked; spawn-related)  
**Parser**: `dmm-parser/src/tables/terrain_region_auto_spawn_info/`
**Fields (24)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_possibleList`
- `_autoSpawnSplineName`
- `_autoSpawnSplineExceptName`
- `_regionInfoList`
- `_notSpawnRegionInfoList`
- `_spawnRegionTagList`
- `_notSpawnRegionTagList`
- `_spawnList`
- `_voxelType`
- `_roadGroupType`
- `_isOnlySummonData`
- `_isOnlyCheckData`
- `_stageCategory`
- `_tagList`
- `_isDefaultActivated`
- `_allTerrainRegion`
- `_bitmapPositionInfo`
- `_bitmapColorListForSpawn`
- `_spawnAtHeightFieldLandScape`
- `_fishSummonTimeFrquencyType`
- `_spawnReasonList`

### TerrainRegionNaviInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for terrain region navi (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/terrain_region_navi_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_isForestRegion`

### TerritoryInfo 🧠 —

**Category**: Misc  
**Purpose**: records for territory (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_territoryName`

### TextGuideInfo 🧠 —

**Category**: Misc  
**Purpose**: records for text guide (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (8)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_gameEventType`
- `_param1`
- `_conditionInfo`
- `_guideText`
- `_playTime`

### TradeMarketItemInfo 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for trade market item (records can be individually blocked via is_blocked)  
**Parser**: not present
**Fields (20)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_itemInfo`
- `_enchantLevel`
- `_mainCategoryNo`
- `_subCategoryNo`
- `_startPrice`
- `_maxPrice`
- `_minPrice`
- `_enchantGroup`
- `_enchantNeedCount`
- `_enchantMaterialInfo`
- `_tradeWeight`
- `_maxStackCount`
- `_tradeCountToUpdate`
- `_accumulatePassCount`
- `_registerCount`
- `_marketPriceGroup`
- `_isForceDisplay`

### TrapFoodData 🧠 —

**Category**: Misc  
**Purpose**: records for trap food data  
**Parser**: not present
**Fields (3)**:

- `_likeFoodInfoList`
- `_defaultChanceRate`
- `_likeFoodAppendRate`

### TribeInfo ✅ T1

**Category**: Character/NPC  
**Purpose**: records for tribe (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/tribe_info/`
**Fields (29)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_parentTribeInfo`
- `_footStepTypeEffectName`
- `_tribeMassLevel`
- `_bumpTypeHash`
- `_isHumanoid`
- `_isBird`
- `_isDeathByDrowning`
- `_hasChild`
- `_detectModeShowEnemy`
- `_isWagonDetour`
- `_ignoreOverlapPush`
- `_escapePlatform`
- `_ignoreWaterFall`
- `_detourMaxDegree`
- `_activityWaterDepth`
- `_velocityDampSpeed`
- `_tribeNameForEditor`
- `_weaponMaterialKey`
- `_baseMaterialKey`
- `_armorMaterialKey`
- `_footMaterialKey`
- `_wantedCrimeType`
- `_interactionUIDistanceLv`
- `_characterPauseType`
- `_ignoredReactionInSafeZoneFlag`
- `_tamedSkillList`

### TriggerRegionInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for trigger region (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/trigger_region_info/`
**Fields (4)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_presetList`

### UIFilterData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for ui filter data  
**Parser**: not present
**Fields (5)**:

- `_uiFilterIconDataList`
- `_uiFilterKey`
- `_uiIconPath`
- `_uiIconName`
- `_isIconVisible`

### UIFilterGroupInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: grouping/categorization for ui filter (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/uifilter_group_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_uiFilterDataList`
- `_uiGroupName`
- `_uiIconPath`
- `_filterType`

### UIFilterIconData 🧠 —

**Category**: UI/Audio/Localization  
**Purpose**: records for ui filter icon data  
**Parser**: not present
**Fields (3)**:

- `_uiMapTextureInfo`
- `_stageInfo`
- `_dataType`

### UIMapTextureInfo ✅ T1

**Category**: UI/Audio/Localization  
**Purpose**: records for ui map texture (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/uimap_texture_info/`
**Fields (50)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_worldPosition`
- `_uiTemplateName`
- `_uiTextureName`
- `_uiSmallTextureName`
- `_uiFilterGroupComponentName`
- `_uiFilterTextureName`
- `_uiMapLayerType`
- `_mapIconType`
- `_knowledgeInfo`
- `_gameplayTriggerInfo`
- `_filterGroupName`
- `_filterGroupParentInfo`
- `_zIndex`
- `_isFlexibleSize`
- `_isFlexibleIcon`
- `_isSimpleMaterial`
- `_tooltipText`
- `_autoRemoveDistance`
- `_maxScale`
- `_minScale`
- `_lerpIconMinSize`
- `_lerpMinZoom`
- `_lerpMaxZoom`
- `_lerpSize`
- `_changeScaleRatio`
- `_filterType`
- `_isShowTooltip`
- `_isRegionKnowledgeIcon`
- `_isUIMapQuestType`
- `_isUIMapDebugQuestType`
- `_isUIMapDebugQuestAreaType`
- `_isUIMapNPCType`
- `_isUIMapMissionType`
- `_isActorType`
- `_isPerspectiveIcon`
- `_isAlwayShowMinimap`
- `_checkHasOwnerActorIcon`
- `_isFixScaleIconImage`
- `_useChangeScale`
- `_useChangeScaleWhenZoomOut`
- `_useAutoAbyssLayer`
- `_minimapForceUpdateIcon`
- `_indoorStateForceShow`
- `_otherSpaceForceShow`
- `_isKeepShowByCharacterInfo`
- `_isDiscoverGimmickIcon`
- `_uiFilterGroupByInfo`

### UISocialActionInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for ui social action (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/ui_social_action_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_name`
- `_description`
- `_quickSlotUiTabIndex`
- `_quickSlotUiIndex`

### UnitData 🧠 —

**Category**: Misc  
**Purpose**: records for unit data (UI icon)  
**Parser**: not present
**Fields (5)**:

- `_uiComponent`
- `_minimum`
- `_iconPath`
- `_itemName`
- `_itemDesc`

### UpgradeActiveConditionData 🧠 —

**Category**: Buff/Effect/Condition  
**Purpose**: records for upgrade active condition data  
**Parser**: not present
**Fields (2)**:

- `_activeCondiiton`
- `_deactiveReasonLocalString`

### UseResourceItem 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for use resource item  
**Parser**: not present
**Fields (2)**:

- `_itemInfo`
- `_useItemCount`

### UseResourceStat 🧠 —

**Category**: Misc  
**Purpose**: records for use resource stat  
**Parser**: not present
**Fields (6)**:

- `_statType`
- `_statusInfo`
- `_isRegen`
- `_varyStatAmount`
- `_increaseStatusInfo`
- `_decreaseStatusInfo`

### ValidScheduleActionInfo ✅ T1

**Category**: Skill/Action  
**Purpose**: records for valid schedule action (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/valid_schedule_action_info/`
**Fields (7)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_actionNameHashList`
- `_type`
- `_keywordLowerStringList`
- `_convertingData`

### VaryExpPerDonationData 🧠 —

**Category**: Misc  
**Purpose**: records for vary exp per donation data  
**Parser**: not present
**Fields (3)**:

- `_donationItemInfo`
- `_perDonationCount`
- `_expAmount`

### VaryTradeItemPriceData 🧠 —

**Category**: Item/Inventory  
**Purpose**: records for vary trade item price data  
**Parser**: not present
**Fields (3)**:

- `_itemGroupInfoList`
- `_minPercent`
- `_maxPercent`

### VehicleInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for vehicle (records can be individually blocked via is_blocked; UI icon)  
**Parser**: `dmm-parser/src/tables/vehicle_info/`
**Fields (22)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_vehicleTypeNameHash`
- `_iconPath`
- `_maxVehicleSeat`
- `_vehicleSeatDataList`
- `_maxParentLinkAttachCount`
- `_parentLinkAttachDataList`
- `_riderSpawnUpperAction`
- `_riderSpawnLowerAction`
- `_vehicleSpawnUpperAction`
- `_escapeRoadGroupType`
- `_cargoSeatIndexList`
- `_callVehicleVoxelType`
- `_isMainDischargeable`
- `_showCountOnUI`
- `_uiMapTextureInfo`
- `_riderDetectInfo`
- `_sendDamageTo`
- `_characterSwitchable`
- `_maxAllowableHeight`

### VelocityConstraintMotor 🧠 —

**Category**: Misc  
**Purpose**: records for velocity constraint motor  
**Parser**: not present
**Fields (3)**:

- `_tau`
- `_damping`
- `_velocityTarget`

### VelocityInfo_DEV 🧠 —

**Category**: Misc  
**Purpose**: records for velocity info dev  
**Parser**: not present
**Fields (3)**:

- `_transform`
- `_linearVelocity`
- `_angularVelocity`

### VerticalPlaneConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for vertical plane constraint data  
**Parser**: not present
**Fields (5)**:

- `_yRange`
- `_zRange`
- `_pitchRange`
- `_yawRange`
- `_rollRange`

### VibratePatternInfo ✅ T1

**Category**: Gimmick/Trigger  
**Purpose**: records for vibrate pattern (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/vibrate_pattern_info/`
**Fields (6)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_easeType`
- `_reverseEase`
- `_vibratePatternDataList`

### VibratePatternInfoData 🧠 —

**Category**: Gimmick/Trigger  
**Purpose**: records for vibrate pattern info data  
**Parser**: not present
**Fields (4)**:

- `_vibrateDirection`
- `_startTime`
- `_duration`
- `_power`

### VisioningData 🧠 —

**Category**: Misc  
**Purpose**: records for visioning data  
**Parser**: not present
**Fields (2)**:

- `_visioningType`
- `_effectInfo`

### WantedInfo ✅ T1

**Category**: Faction/Field/World  
**Purpose**: records for wanted (records can be individually blocked via is_blocked)  
**Parser**: `dmm-parser/src/tables/wanted_info/`
**Fields (5)**:

- `_key`
- `_stringKey`
- `_isBlocked`
- `_increasePrice`
- `_useTargetPrice`

### YOnlyConstraintData 🧠 —

**Category**: Misc  
**Purpose**: records for y only constraint data  
**Parser**: not present
**Fields (3)**:

- `_limitDistance`
- `_angleLimit`
- `_useWorldAxis`
