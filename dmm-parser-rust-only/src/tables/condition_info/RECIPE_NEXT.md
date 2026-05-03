# ConditionInfo wiring roadmap

> **Status note (2026-04-30)** — most of the actions below are DONE.
> ConditionInfo is **Tier 1** (typed `game_condition: GameCondition<'a>`,
> 100% byte-perfect round-trip on 8,934 entries; 99.8% Decoded into a
> field-addressable tree, 0.2% Raw fallback for anti-disassembly tags).
> The optional subcond block is wired in `ConditionData::read_from`
> (see `condition_data.rs` `variant_skips_option_block` for class A/B/C
> classification). The active per-tag recipe verification work has
> moved upstream — see `docs/STATUS.md` "Stream-mode GameCondition"
> section for live state and the `interaction_info::diag_raw_entries`
> failure histogram. Keeping this file as a historical artifact of
> how the rollout was scoped; do not action steps from below without
> first confirming against current code.

The GameCondition expression tree is fully mapped via IDA + Rust infrastructure.
Historical baseline: ConditionInfo originally remained blob-tail to preserve
the 121/121 round-trip; that constraint is now resolved by the typed
GameCondition wrapper.

## What's done

### Meta-dispatcher mapped (sub_141E65330 — 9 cases)

| Tag | Function | Family | Implemented? |
|---:|---|---|---|
| 0 | sub_141E65740 | BinaryOp_A (recursive) | YES — `binary::variants::game_condition` |
| 1 | sub_141E65D40 | BinaryOp_B (recursive) | YES |
| 2 | sub_141E662D0 | UnaryOp (recursive) | YES |
| 3 | sub_141C87CE0 | ConditionData (405 leaves) | YES — typed enum + per-tag dispatch; per-tag recipe verification ongoing (see `docs/STATUS.md`) |
| 4 | sub_141D89730 | BranchConditionData (14 leaves) | codegen done — verify against data |
| 5 | sub_141D8B1A0 | ScheduleCompleteConditionData | YES — `binary::variants::schedule_complete_condition_data` |
| 6 | sub_141CB6480 | ConditionGimmickData | YES — `binary::variants::condition_gimmick_data` |
| 7 | sub_141DAC600 | StageChart / StageChart_Event | YES — `binary::variants::condition_data_stage_chart` (incl. GameExpression + IVariantItem) |
| 8 | sub_14114FF40 | GlobalEffectConditionData | YES — `binary::variants::global_effect_condition_data` |

### Sub-families for case 7

- `binary::variants::game_expression` — 7 GameExpression variants (UnaryOperator, BinaryOperator, MemberFunction, Actor, Primitive, ConstObject, Value), recursive
- `binary::variants::ivariant_item` — IVariantItem with 14 case-tag-driven payloads

### Recursive enum

`binary::variants::game_condition::GameConditionNode<'a>` ties everything together with a recursive `read_from`/`write_to` matching the case table above.

### Optional subcond on ConditionData (DONE)

`ConditionData::option_block: Option<ConditionDataOptionBlock<'a>>` is
now wired in `read_from`. Tags whose vtable[19] is the no-op
`0x1402D3A80` (Class A) or anti-disassembly thunk `sub_14F0D...`
(Class B) or empirical `0x1413B89E0` (Class C) skip the block via
`variant_skips_option_block(disc)`; everything else reads
`[u8 option_present][optional ConditionDataOptionData]`.

## What's blocking full wiring

Per the diagnostic test `binary::variants::diagnose_conditiondata::diagnose_conditiondata_variants`:

- **8934 total ConditionInfo entries**
- **108 unique ConditionData tags observed** (out of 405 in the recipe)
  - **55 are CONSTANT-size** — single byte count across all instances; SAFE TO CORRECT
  - **53 are VARIABLE-size** — multiple byte counts (have CStrings/CArrays inside); need per-variant IDA decompile
  - **297 are unobserved** — exist in binary but not used in vanilla; don't matter for round-trip

Output saved at `dmm-pabgb-aio/mac_extract/conditiondata_empirical_observations.json`. Format per tag:
```json
"206": { "count": 1, "min": 5, "max": 5, "unique_sizes": [5], "kind": "CONSTANT" }
```

The recipe `conditiondata_recipes.json` claims tag 206 has `tail_bytes: 0` — wrong by 5. The obfuscated readers in the `0x14F0xxxxx` range XOR-pack their stream-size constants, and the recipe extractor recorded 0 when it couldn't resolve.

## Steps to finish wiring

1. **Fix the 55 CONSTANT tags first** (highest ROI, no IDA needed):
   - For each CONSTANT tag in the empirical observations file, set the variant payload size in `binary/variants/condition_data.rs` to the observed value.
   - Easiest path: replace existing `tail_fields` with a single `raw_bytes: [u8; N]` field (preserves bytes for round-trip).
   - Unlocks single-leaf entries that use only CONSTANT tags — likely 60-70% coverage.

2. **Decompile the 53 VARIABLE tags** (one IDA decompile per tag):
   - For each VARIABLE tag, decompile its slot-16 read function (per `conditiondata_recipes.json` field `read_fn`).
   - Trace stream reads: u8/u16/u32 + CString + sub-calls.
   - Update the variant's payload struct.

3. **Verify the optional_subcond conditions**: Re-enable in `ConditionData::read_from`, identify breaks, determine if slot 19 is unconditional or has a guard.

4. **Switch `ConditionInfo` to use `GameConditionNode`** (DONE — see
   `condition_info::info::ConditionInfo.game_condition: GameCondition<'a>`).
   Round-trip is byte-perfect on 8,934/8,934 entries.

5. **Update v3 docs** (n/a — `mod-authors-guide.md` no longer exists in
   this repo; per-table tier status now lives in `docs/STATUS.md` and
   `docs/449_TABLE_CATALOG.md`).

## Why this matters

ConditionInfo is the highest-mod-author-value Tier 2 table — defines every quest condition, dialog trigger, and buff applicability rule. Promoting blob-tail → fully field-decoded means v3 mods can edit individual conditions instead of cloning whole condition blobs.

## See also

- `dmm-pabgb-aio/mac_extract/game_condition_tree_recipe.json` — full meta-dispatcher map
- `dmm-pabgb-aio/mac_extract/conditiondata_empirical_observations.json` — per-tag byte counts from real data
- `dmm-pabgb-aio/mac_extract/conditiondata_recipes.json` — auto-extracted recipe (had bugs in many VARIABLE tags; superseded by per-tag Win-IDA verification this session)
- `docs/STATUS.md` — current state, per-tag fix log, regression-cycle history
