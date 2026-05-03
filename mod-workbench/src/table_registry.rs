use crate::state::TableMeta;

/// Build the full registry of supported tables from dmm_parser_rust_only's dispatch list.
///
/// For each dispatch name (e.g. "gimmick_info"), compute the pabgb filename
/// on disk (e.g. "gimmickinfo.pabgb"). Most tables follow the rule of simply
/// stripping underscores and appending "info.pabgb", but several have special
/// filename mappings.
pub fn build_registry() -> Vec<TableMeta> {
    let dispatch_names = dmm_parser_rust_only::supported_tables();
    let mut registry = Vec::with_capacity(dispatch_names.len());

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
        let expected_count = dmm_parser_rust_only::supported_tables().len();
        assert_eq!(registry.len(), expected_count);
    }
}
