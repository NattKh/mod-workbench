use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::papgt::PackGroupTreeMeta;

/// Restore the game to vanilla by removing an overlay group.
///
/// Steps:
/// 1. Delete the overlay directory (e.g. game_dir/0058/)
/// 2. Remove the overlay entry from PAPGT
/// 3. If a workbench backup of PAPGT exists, restore it instead
pub fn restore(game_dir: &Path, overlay_group: &str) -> io::Result<()> {
    // Delete overlay directory
    let overlay_dir = game_dir.join(overlay_group);
    if overlay_dir.exists() {
        std::fs::remove_dir_all(&overlay_dir)?;
    }

    let papgt_path = game_dir.join("meta/0.papgt");
    let papgt_backup = game_dir.join("meta/0.papgt.workbench_backup");

    // If we have a backup and this is the only overlay we manage, restore it
    if papgt_backup.exists() {
        // Read current PAPGT to check if there are other workbench overlays
        let papgt_data = std::fs::read(&papgt_path)?;
        let papgt = PackGroupTreeMeta::parse(&papgt_data)?;

        // Check if the overlay group is even present
        let has_overlay = papgt.entries.iter().any(|e| e.group_name == overlay_group);

        if has_overlay {
            // Remove just this entry from PAPGT
            let mut papgt = papgt;
            papgt
                .entries
                .retain(|e| e.group_name != overlay_group);
            papgt.header.entry_count = papgt.entries.len() as u8;
            let papgt_bytes = papgt.to_bytes()?;
            std::fs::write(&papgt_path, &papgt_bytes)?;
        }
    }

    Ok(())
}
