use crate::state::TableMeta;

/// Build the full registry of supported tables from dmm_parser_rust_only's dispatch list.
///
/// For each dispatch name (e.g. "gimmick_info"), compute the pabgb filename
/// on disk (e.g. "gimmickinfo.pabgb"). Most tables follow the rule of simply
/// stripping underscores and appending "info.pabgb", but several have special
/// filename mappings.
///
/// In addition to the dispatch list, we add a few "manual extras" — tables
/// like `item_info` (iteminfo.pabgb) that have a dedicated parser module in
/// dmm-parser-rust-only (`src/item_info/`) instead of going through the
/// generic dispatch. These need a special-case route in
/// [`crate::table_loader::load_table`].
pub fn build_registry() -> Vec<TableMeta> {
    let mut registry: Vec<TableMeta> = Vec::new();

    // Manual extras: tables that have dedicated parsers in dmm-parser-rust-only
    // and aren't returned by `supported_tables()`. They go through special-case
    // routing in `table_loader::load_table`. iteminfo is the most-used modding
    // target (6,022 items) so it has to be present in the table list.
    registry.push(TableMeta {
        dispatch_name: "item_info".to_string(),
        pabgb_filename: "iteminfo.pabgb".to_string(),
        pabgh_filename: Some("iteminfo.pabgh".to_string()),
    });

    // Dispatch tables (already wired up via supported_tables).
    let dispatch_names = dmm_parser_rust_only::supported_tables();
    for &name in dispatch_names {
        let stem = dispatch_name_to_pabgb_stem(name);
        let pabgb_filename = format!("{}.pabgb", stem);
        let pabgh_filename = Some(format!("{}.pabgh", stem));

        registry.push(TableMeta {
            dispatch_name: name.to_string(),
            pabgb_filename,
            pabgh_filename,
        });
    }

    // Sort alphabetically by dispatch_name so item_info sits in its expected
    // alphabetical slot in the table list rather than floating at the top.
    registry.sort_by(|a, b| a.dispatch_name.cmp(&b.dispatch_name));
    registry
}

/// Convert a dispatch name like "gimmick_info" to the pabgb file stem
/// like "gimmickinfo". Handles known special cases where the filename
/// diverges from the simple "remove underscores" rule.
fn dispatch_name_to_pabgb_stem(dispatch_name: &str) -> String {
    match dispatch_name {
        "faction_info" => "faction".to_string(),
        "skill_info" => "skill".to_string(),
        "board_info" => "board".to_string(),
        "inventory_info" => "inventory".to_string(),
        "reserve_slot_info" => "reserveslot".to_string(),
        "field_revive_info" => "reviepointinfo".to_string(),
        "game_level_info" => "levelinfo".to_string(),
        _ => dispatch_name.replace('_', ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_cases() {
        assert_eq!(dispatch_name_to_pabgb_stem("faction_info"), "faction");
        assert_eq!(dispatch_name_to_pabgb_stem("skill_info"), "skill");
        assert_eq!(dispatch_name_to_pabgb_stem("board_info"), "board");
        assert_eq!(dispatch_name_to_pabgb_stem("inventory_info"), "inventory");
        assert_eq!(dispatch_name_to_pabgb_stem("reserve_slot_info"), "reserveslot");
        assert_eq!(dispatch_name_to_pabgb_stem("field_revive_info"), "reviepointinfo");
        assert_eq!(dispatch_name_to_pabgb_stem("game_level_info"), "levelinfo");
    }

    #[test]
    fn test_normal_case() {
        assert_eq!(dispatch_name_to_pabgb_stem("gimmick_info"), "gimmickinfo");
        assert_eq!(dispatch_name_to_pabgb_stem("buff_info"), "buffinfo");
        assert_eq!(dispatch_name_to_pabgb_stem("character_info"), "characterinfo");
    }

    #[test]
    fn test_registry_has_all_tables() {
        let registry = build_registry();
        // dispatch tables + manual extras (item_info)
        let expected_count = dmm_parser_rust_only::supported_tables().len() + 1;
        assert_eq!(registry.len(), expected_count);
    }

    #[test]
    fn test_registry_includes_item_info() {
        let registry = build_registry();
        let item_info = registry.iter().find(|m| m.dispatch_name == "item_info");
        assert!(item_info.is_some(), "item_info must be in the registry");
        let m = item_info.unwrap();
        assert_eq!(m.pabgb_filename, "iteminfo.pabgb");
        assert_eq!(m.pabgh_filename.as_deref(), Some("iteminfo.pabgh"));
    }

    #[test]
    fn test_registry_is_sorted() {
        let registry = build_registry();
        let names: Vec<&str> = registry.iter().map(|m| m.dispatch_name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "registry should be alphabetically sorted");
    }
}
