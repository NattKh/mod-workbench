# dmm-parser 1.0.5 Roundtrip Fix — Work Split

## Status: 92/97 tables pass, 5 failing

## Shared Resources
- **IDA MCP**: single-connection, coordinate — only one CLI uses it at a time. Write "IDA: CLI-X USING" below when you start, "IDA: FREE" when done.
- **Parser crate**: `C:\Users\Coding\CrimsonDesertModding\CrimsonGameMods\tools\dmm-parser-main\`
- **Game dir**: `C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert`
- **IDA LOCK**: FREE

---

## CLI-1 Instructions

You are CLI-1. Your job: fix **gimmick_info** and **action_point_info** roundtrip parsers.

For each table:
1. Update IDA LOCK above to "CLI-1 USING" before touching IDA MCP
2. Use IDA MCP to find the reader function. Search for the Korean error string containing the table class name (e.g. `GimmickInfo의` or `ActionPointInfo의`). Use `mcp__ida-pro-mcp__find_regex` with just the class name — don't search the full Korean string.
3. Decompile the reader function with `mcp__ida-pro-mcp__decompile`
4. List every field in read order with types
5. Set IDA LOCK back to "FREE"
6. Read the current struct in `src/tables/<name>/info.rs`
7. Compare decompiled fields vs current struct. Find what 1.0.5 added.
8. Add the missing field(s). For `py_binary_struct!` tables just add the field line. For manual structs update `read_from`, `write_to`, `to_json_dict`, `write_from_json`, `FIELD_NAMES`.
9. Verify with:
```python
import sys; sys.path.insert(0, r'C:\Users\Coding\CrimsonDesertModding\CrimsonGameMods')
import crimson_rs
from dmm_parser import parse_table, serialize_table
game_dir = r'C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert'
# For gimmick_info (pabgh-bounded):
body = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'gimmickinfo.pabgb')
pabgh = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'gimmickinfo.pabgh')
items = parse_table('gimmick_info', body, pabgh)
out = serialize_table('gimmick_info', items)
assert out == body, f"FAIL delta={len(out)-len(body)}"
print(f"PASS {len(items)} entries")
# For action_point_info (sequential, no pabgh):
body = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'actionpointinfo.pabgb')
items = parse_table('action_point_info', body, None)
out = serialize_table('action_point_info', items)
assert out == body, f"FAIL delta={len(out)-len(body)}"
print(f"PASS {len(items)} entries")
```
10. You MUST run `maturin develop` before testing with Python.
11. Update status below to [x] DONE with entry count.
12. Commit your changes when both tables pass.

### gimmick_info
- **File**: `src/tables/gimmick_info/info.rs`
- **Error**: roundtrip mismatch (parses OK but serialized bytes differ)
- **Type**: pabgh-bounded (`p!()` macro in dispatch.rs)
- **Game files**: `gimmickinfo.pabgb` + `gimmickinfo.pabgh`
- **Status**: [ ] NOT STARTED

### action_point_info
- **File**: `src/tables/action_point_info/info.rs`
- **Error**: "offset 0x9e: not enough data"
- **Type**: sequential (`s!()` macro, no pabgh needed)
- **Game file**: `actionpointinfo.pabgb`
- **Status**: [ ] NOT STARTED

---

## CLI-2 Instructions

You are CLI-2. Your job: fix **game_advice_info** and **mercenary_group_info** roundtrip parsers.

For each table:
1. Check IDA LOCK above. Wait if another CLI is using it. Update to "CLI-2 USING" before touching IDA MCP.
2. Use IDA MCP to find the reader function. Search for the Korean error string containing the table class name (e.g. `GameAdviceInfo의` or `MercenaryGroupInfo의`). Use `mcp__ida-pro-mcp__find_regex` with just the class name.
3. Decompile the reader function with `mcp__ida-pro-mcp__decompile`
4. List every field in read order with types
5. Set IDA LOCK back to "FREE"
6. Read the current struct in `src/tables/<name>/info.rs`
7. Compare decompiled fields vs current struct. Find what 1.0.5 added.
8. Add the missing field(s). For `py_binary_struct!` tables just add the field line. For manual structs update `read_from`, `write_to`, `to_json_dict`, `write_from_json`, `FIELD_NAMES`.
9. Verify with:
```python
import sys; sys.path.insert(0, r'C:\Users\Coding\CrimsonDesertModding\CrimsonGameMods')
import crimson_rs
from dmm_parser import parse_table, serialize_table
game_dir = r'C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert'
# For game_advice_info (sequential):
body = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'gameadviceinfo.pabgb')
items = parse_table('game_advice_info', body, None)
out = serialize_table('game_advice_info', items)
assert out == body, f"FAIL delta={len(out)-len(body)}"
print(f"PASS {len(items)} entries")
# For mercenary_group_info (sequential):
body = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'mercenarygroupinfo.pabgb')
items = parse_table('mercenary_group_info', body, None)
out = serialize_table('mercenary_group_info', items)
assert out == body, f"FAIL delta={len(out)-len(body)}"
print(f"PASS {len(items)} entries")
```
10. You MUST run `maturin develop` before testing with Python.
11. Update status below to [x] DONE with entry count.
12. Commit your changes when both tables pass.

### game_advice_info
- **File**: `src/tables/game_advice_info/info.rs`
- **Error**: "offset 0x94: not enough data"
- **Type**: sequential (`s!()` macro, no pabgh needed)
- **Game file**: `gameadviceinfo.pabgb`
- **Status**: [ ] NOT STARTED

### mercenary_group_info
- **File**: `src/tables/mercenary_group_info/info.rs`
- **Error**: "offset 0x23: not enough data"
- **Type**: sequential (`s!()` macro, no pabgh needed)
- **Game file**: `mercenarygroupinfo.pabgb`
- **Status**: [ ] NOT STARTED

---

## CLI-3 Instructions

You are CLI-3. Your job: fix **quest_group_info**, then run final verification on ALL 122 tables.

For quest_group_info:
1. Check IDA LOCK above. Wait if another CLI is using it. Update to "CLI-3 USING" before touching IDA MCP.
2. Use IDA MCP to find the reader function. Search for `QuestGroupInfo의` with `mcp__ida-pro-mcp__find_regex`.
3. Decompile the reader function with `mcp__ida-pro-mcp__decompile`
4. List every field in read order with types
5. Set IDA LOCK back to "FREE"
6. Read the current struct in `src/tables/quest_group_info/info.rs`
7. Compare decompiled fields vs current struct. Find what 1.0.5 added.
8. Add the missing field(s). For `py_binary_struct!` tables just add the field line.
9. Verify with:
```python
import sys; sys.path.insert(0, r'C:\Users\Coding\CrimsonDesertModding\CrimsonGameMods')
import crimson_rs
from dmm_parser import parse_table, serialize_table
game_dir = r'C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert'
body = crimson_rs.extract_file(game_dir, '0008', 'gamedata/binary__/client/bin', 'questgroupinfo.pabgb')
items = parse_table('quest_group_info', body, None)
out = serialize_table('quest_group_info', items)
assert out == body, f"FAIL delta={len(out)-len(body)}"
print(f"PASS {len(items)} entries")
```
10. You MUST run `maturin develop` before testing with Python.
11. Update status below to [x] DONE.

After quest_group_info passes, wait for CLI-1 and CLI-2 to mark DONE, then:

12. Run `maturin develop --release` to rebuild the full wheel
13. Run the full 122-table verification:
```python
import sys, os
sys.path.insert(0, r'C:\Users\Coding\CrimsonDesertModding\CrimsonGameMods')
import crimson_rs
from dmm_parser import parse_table, serialize_table

game_dir = r'C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert'
tables = [
    'ai_dialog_string_info','buff_info','character_info','condition_info',
    'drop_set_info','effect_info','elemental_material_info','equip_slot_info',
    'faction_node_spawn_info','faction_spawn_data_info','frame_event_attr_group_info',
    'game_global_effect_info','gimmick_group_info','gimmick_info',
    'global_stage_sequencer_info','interaction_info','item_use_info',
    'knowledge_info','level_gimmick_scene_object_info','mini_game_data_info',
    'mission_info','multi_change_info','npc_info','quest_info','region_info',
    'sequencer_spawn_info','spawning_pool_auto_spawn_info','stage_info',
    'store_info','sub_level_info','terrain_region_auto_spawn_info',
    'action_point_info','action_restriction_order_info','aiaction_attribute_info',
    'aidialog_type_info','aievent_table_info','aimemory_info','aimove_speed_info',
    'ally_group_info','auto_spawn_filter_info','breakable_object_info',
    'category_group_info','category_info','character_appearance_index_info',
    'character_group_info','craft_tool_group_info','craft_tool_info',
    'detect_detail_info','detect_info','detect_reaction_info','dialog_voice_info',
    'dye_color_group_info','equip_type_info','fail_message_info','field_info',
    'field_level_name_table_info','formation_info','game_advice_group_info',
    'game_advice_info','game_play_variable_info','gimmick_event_table_info',
    'gimmick_gate_info','house_info','item_group_info','job_info',
    'knowledge_group_info','level_action_point_info','local_string_info',
    'material_blood_decal_info','material_match_info','material_relation_info',
    'mercenary_group_info','mercenary_info','part_prefab_dye_slot_info',
    'part_prefab_dye_texture_pallete_info','pattern_description_info',
    'platform_achievement_info','quest_gauge_info','quest_group_info',
    'quick_time_event_info','relation_info','skill_group_info',
    'skill_tree_group_info','skill_tree_info','socket_group_info','socket_info',
    'status_group_info','status_info','string_info','terrain_region_navi_info',
    'tribe_info','trigger_region_info','uifilter_group_info','uimap_texture_info',
    'vehicle_info','vibrate_pattern_info','wanted_info',
]

passed = 0
failed = 0
for name in tables:
    pabgb_file = name.replace('_', '') + '.pabgb'
    pabgh_file = name.replace('_', '') + '.pabgh'
    body = None
    pabgh = None
    for grp in ['0008','0001','0002','0003','0004','0005','0006','0007','0009']:
        try:
            body = crimson_rs.extract_file(game_dir, grp, 'gamedata/binary__/client/bin', pabgb_file)
            try:
                pabgh = crimson_rs.extract_file(game_dir, grp, 'gamedata/binary__/client/bin', pabgh_file)
            except:
                pass
            break
        except:
            continue
    if body is None:
        continue
    try:
        items = parse_table(name, body, pabgh)
        out = serialize_table(name, items)
        if out == body:
            passed += 1
        else:
            print(f"FAIL {name}: delta={len(out)-len(body)}")
            failed += 1
    except Exception as e:
        print(f"FAIL {name}: {str(e)[:80]}")
        failed += 1

print(f"\n=== FINAL: {passed} passed, {failed} failed ===")
```
14. Update final status below.

### quest_group_info
- **File**: `src/tables/quest_group_info/info.rs`
- **Error**: "offset 0x873: not enough data"
- **Type**: sequential (`s!()` macro, no pabgh needed)
- **Game file**: `questgroupinfo.pabgb`
- **Status**: [ ] NOT STARTED

### Final verification
- **Status**: [ ] WAITING FOR CLI-1 + CLI-2

---

## Rules
- Only edit files in YOUR section. Never touch another CLI's table files.
- Don't touch `dispatch.rs`, `lib.rs`, `python.rs` — no routing changes needed.
- IDA LOCK: check before using, update when taking/releasing. ONE AT A TIME.
- After fixing, run `maturin develop` then the verify script.
- Commit with message: `fix(<table_name>): add 1.0.5 field <field_name>`
- If you find a table needs sub-struct changes in `src/binary/`, coordinate — note it here and let CLI-3 handle shared files.
